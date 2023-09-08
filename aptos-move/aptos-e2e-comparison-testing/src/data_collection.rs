// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    check_aptos_packages_availability, compile_aptos_packages,
    dump_and_compile_from_package_metadata, is_aptos_package, CompilationCache, PackageInfo,
    TxnIndex, APTOS_COMMONS, INDEX_FILE, ROCKS_INDEX_DB, STATE_DATA, TXN_DATA,
};
use anyhow::{format_err, Result};
use aptos_framework::natives::code::PackageRegistry;
use aptos_language_e2e_tests::data_store::FakeDataStore;
use aptos_rest_client::Client;
use aptos_types::{
    account_address::AccountAddress,
    transaction::{
        signature_verified_transaction::SignatureVerifiedTransaction, Transaction,
        TransactionOutput, Version,
    },
};
use aptos_validator_interface::{
    AptosValidatorInterface, DebuggerStateView, RestDebuggerInterface,
};
use aptos_vm::{AptosVM, VMExecutor};
use rocksdb::DB;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
};

pub struct DataCollection {
    debugger: Arc<dyn AptosValidatorInterface + Send>,
    current_dir: PathBuf,
    batch_size: u64,
    _overwrite: bool,
}

impl DataCollection {
    pub fn new(
        debugger: Arc<dyn AptosValidatorInterface + Send>,
        current_dir: PathBuf,
        batch_size: u64,
        _overwrite: bool,
    ) -> Self {
        Self {
            debugger,
            current_dir,
            batch_size,
            _overwrite,
        }
    }

    pub fn new_with_rest_client(
        rest_client: Client,
        current_dir: PathBuf,
        batch_size: u64,
        _overwrite: bool,
    ) -> Result<Self> {
        Ok(Self::new(
            Arc::new(RestDebuggerInterface::new(rest_client)),
            current_dir,
            batch_size,
            _overwrite,
        ))
    }

    fn execute_transactions_at_version_with_state_view(
        &self,
        txns: Vec<Transaction>,
        debugger_stateview: &DebuggerStateView,
    ) -> Result<Vec<TransactionOutput>> {
        let sig_verified_txns: Vec<SignatureVerifiedTransaction> =
            txns.into_iter().map(|x| x.into()).collect::<Vec<_>>();
        AptosVM::execute_block(&sig_verified_txns, debugger_stateview, None)
            .map_err(|err| format_err!("Unexpected VM Error: {:?}", err))
    }

    pub async fn dump_data(&self, begin: Version, limit: u64) -> anyhow::Result<()> {
        let aptos_commons_path = self.current_dir.join(APTOS_COMMONS);
        if !check_aptos_packages_availability(aptos_commons_path.clone()) {
            return Err(anyhow::Error::msg("aptos packages are missing"));
        }
        let mut compilation_cache = CompilationCache::default();
        compile_aptos_packages(
            &aptos_commons_path,
            &mut compilation_cache.compiled_package_map,
            false,
        )?;

        let index_path = self.current_dir.join(INDEX_FILE);
        let index_file = if !index_path.exists() {
            File::create(index_path).expect("Error encountered while creating file!")
        } else {
            OpenOptions::new()
                .write(true)
                .append(true)
                .open(index_path)
                .unwrap()
        };
        let mut index_writer =
            std::io::BufWriter::with_capacity(4096 * 1024 /* 4096KB */, index_file);

        let state_data_dir_path = self.current_dir.join(STATE_DATA);
        if !state_data_dir_path.exists() {
            std::fs::create_dir_all(state_data_dir_path.as_path()).unwrap();
        }

        let txn_dir_path = self.current_dir.join(TXN_DATA);
        if !txn_dir_path.exists() {
            std::fs::create_dir_all(txn_dir_path.as_path()).unwrap();
        }

        let mut cur_version = begin;
        let mut count = 0;
        let mut package_registry_cache: HashMap<AccountAddress, PackageRegistry> = HashMap::new();

        let db_data_path = self.current_dir.join(ROCKS_INDEX_DB);
        let db = DB::open_default(db_data_path).unwrap();

        while count < limit {
            let v = self
                .debugger
                .get_committed_transactions_with_available_src(
                    cur_version,
                    self.batch_size,
                    &mut package_registry_cache,
                )
                .await
                .unwrap_or_default();
            if !v.is_empty() {
                for (version, txn, (address, package_name), map) in v {
                    println!("get txn at version:{}", version);

                    // Obtain the state before execution of this txn
                    let state_view =
                        DebuggerStateView::new_with_data_reads(self.debugger.clone(), version);

                    let epoch_result_res = self.execute_transactions_at_version_with_state_view(
                        vec![txn.clone()],
                        &state_view,
                    );
                    if let Err(err) = epoch_result_res {
                        println!(
                            "execution error during transaction at version:{} :{}",
                            version, err
                        );
                        continue;
                    }
                    let epoch_result = epoch_result_res.unwrap();
                    assert_eq!(epoch_result.len(), 1);

                    let output = &epoch_result[0];
                    if output.status().is_discarded() || output.status().is_retry() {
                        continue;
                    }
                    let status = output.status().status().unwrap();
                    if !status.is_success() {
                        println!("skip unsucessful txn:{}", version);
                        continue;
                    }

                    let upgrade_number = if is_aptos_package(&package_name) {
                        None
                    } else {
                        let package = map.get(&(address, package_name.clone())).unwrap();
                        Some(package.upgrade_number)
                    };

                    let package_info = PackageInfo {
                        address,
                        package_name: package_name.clone(),
                        upgrade_number,
                    };

                    // Dump source code
                    if !is_aptos_package(&package_name)
                        && !compilation_cache
                            .compiled_package_map
                            .contains_key(&package_info)
                    {
                        if compilation_cache.failed_packages.contains(&package_info) {
                            continue;
                        }
                        let res = dump_and_compile_from_package_metadata(
                            package_info.clone(),
                            self.current_dir.clone(),
                            &map,
                            &mut compilation_cache,
                            None,
                        );
                        if res.is_err() {
                            println!("compile package failed at:{}", version);
                            continue;
                        }
                    }

                    // Dump version
                    index_writer
                        .write_fmt(format_args!("{}\n", version))
                        .unwrap();

                    // Dump txn
                    let txn_path = txn_dir_path.join(format!("{}_txn", version));
                    if !txn_path.exists() {
                        let mut txn_file = File::create(txn_path).unwrap();
                        txn_file.write_all(&bcs::to_bytes(&txn).unwrap()).unwrap();
                    } else {
                        // TODO: overwrite the data state
                    }

                    // Dump data state
                    let data_state = state_view.data_read_stake_keys.unwrap();
                    let state_path = state_data_dir_path.join(format!("{}_state", version));
                    if !state_path.exists() {
                        let mut data_state_file = File::create(state_path).unwrap();
                        let state_store = FakeDataStore::new_with_state_value(
                            data_state.lock().unwrap().to_owned(),
                        );
                        data_state_file
                            .write_all(&bcs::to_bytes(&state_store).unwrap())
                            .unwrap();
                    } else {
                        // TODO: overwrite the data state
                    }

                    // Dump TxnIndex
                    let version_idx = TxnIndex {
                        version,
                        package_info,
                        txn,
                    };
                    db.put(
                        &bcs::to_bytes(&version).unwrap(),
                        &bcs::to_bytes(&version_idx).unwrap(),
                    )
                    .unwrap();

                    count += 1;
                    if count >= limit {
                        break;
                    }
                }
            }
            cur_version += self.batch_size;
        }
        index_writer.flush().unwrap();
        Ok(())
    }
}
