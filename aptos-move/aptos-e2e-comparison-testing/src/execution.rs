// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    check_aptos_packages_availability, compile_aptos_packages, compile_package, is_aptos_package,
    PackageInfo, TxnIndex, APTOS_COMMONS, INDEX_FILE, ROCKS_INDEX_DB, STATE_DATA, TXN_DATA,
};
use anyhow::Result;
use aptos_language_e2e_tests::{data_store::FakeDataStore, executor::FakeExecutor};
use aptos_types::{
    contract_event::ContractEvent,
    on_chain_config::{FeatureFlag, Features, OnChainConfig},
    transaction::{Transaction, TransactionPayload, Version},
    vm_status::VMStatus,
    write_set::WriteSet,
};
use aptos_vm::data_cache::AsMoveResolver;
use itertools::Itertools;
use move_compiler::compiled_unit::CompiledUnitEnum;
use move_package::{compilation::compiled_package::CompiledPackage, CompilerVersion};
use rocksdb::{Options, DB};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
};

pub struct Execution {
    input_path: PathBuf,
    compare: bool,
    bytecode_version: u32,
}

impl Execution {
    pub fn new(input_path: PathBuf, compare: bool) -> Self {
        Self {
            input_path,
            compare,
            bytecode_version: 6,
        }
    }

    fn set_enable(features: &mut Features, flag: FeatureFlag) {
        let val = flag as u64;
        let byte_index = (val / 8) as usize;
        let bit_mask = 1 << (val % 8);
        if byte_index < features.features.len() {
            features.features[byte_index] |= bit_mask;
        }
    }

    pub async fn exec(&self, begin: Version, limit: u64) -> Result<()> {
        let aptos_commons_path = self.input_path.join(APTOS_COMMONS);
        if !check_aptos_packages_availability(aptos_commons_path.clone()) {
            return Err(anyhow::Error::msg("aptos packages are missing"));
        }
        let mut compiled_package_cache: HashMap<PackageInfo, CompiledPackage> = HashMap::new();
        let mut compiled_package_cache_v2: HashMap<PackageInfo, CompiledPackage> = HashMap::new();

        compile_aptos_packages(&aptos_commons_path, &mut compiled_package_cache, false)?;
        if self.compare {
            compile_aptos_packages(&aptos_commons_path, &mut compiled_package_cache_v2, true)?;
        }

        let state_data_dir_path = self.input_path.join(STATE_DATA);
        if !state_data_dir_path.exists() {
            return Err(anyhow::Error::msg("state data is missing"));
        }

        let txn_dir_path = self.input_path.join(TXN_DATA);
        if !txn_dir_path.exists() {
            return Err(anyhow::Error::msg("txn data is missing"));
        }

        let db_data_path = self.input_path.join(ROCKS_INDEX_DB);
        let opt = Options::default();
        let db_res = DB::open(&opt, db_data_path);
        if db_res.is_err() {
            return Err(anyhow::Error::msg("db is missing"));
        }
        let db = db_res.unwrap();

        let index_path = self.input_path.join(INDEX_FILE);
        if !index_path.exists() {
            return Err(anyhow::Error::msg("index file is missing"));
        }
        let index_file = File::open(index_path)?;
        let mut idx_reader = BufReader::new(index_file);

        let mut cur_version;
        let mut count = 0;
        let mut cur_idx = String::new();

        // get the first idx from the version_index file
        loop {
            let num_bytes = idx_reader.read_line(&mut cur_idx)?;
            if num_bytes == 0 {
                return Err(anyhow::Error::msg(
                    "cannot find a version greater than or equal to the specified begin version",
                ));
            }
            cur_version = cur_idx.trim().parse().unwrap();
            if cur_version >= begin {
                break;
            }
            cur_idx = String::new();
        }

        while count < limit {
            // read the txn index data from the database
            let db_val = db.get(&bcs::to_bytes(&cur_version).unwrap());
            if let Ok(Some(val)) = db_val {
                count += 1;
                let txn_idx = bcs::from_bytes::<TxnIndex>(&val).unwrap();
                // If the package is not from Aptos, compile it
                if !is_aptos_package(&txn_idx.package_info.package_name) {
                    let package_name = format!("{}", txn_idx.package_info,);
                    let package_dir = self.input_path.join(package_name);
                    // 1) retrieve the source folder;
                    if !package_dir.exists() {
                        return Err(anyhow::Error::msg("source code is not available"));
                    }
                    // 2) compile the code;
                    let package_info = PackageInfo {
                        address: txn_idx.package_info.address,
                        package_name: txn_idx.package_info.package_name.clone(),
                        upgrade_number: txn_idx.package_info.upgrade_number,
                    };
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        compiled_package_cache.entry(package_info.clone())
                    {
                        let compiled_res =
                            compile_package(package_dir.clone(), &package_info, None)?;
                        e.insert(compiled_res);
                    }

                    if self.compare && !compiled_package_cache_v2.contains_key(&package_info) {
                        let compiled_res =
                            compile_package(package_dir, &package_info, Some(CompilerVersion::V2))?;
                        compiled_package_cache_v2.insert(package_info, compiled_res);
                    }
                }

                // 3) read the state data;
                let state_path = state_data_dir_path.join(format!("{}_state", cur_version));
                let mut data_state_file = File::open(state_path).unwrap();
                let mut buffer = Vec::<u8>::new();
                data_state_file.read_to_end(&mut buffer).unwrap();
                let state = bcs::from_bytes::<FakeDataStore>(&buffer).unwrap();
                let state_view = state.as_move_resolver();

                // 4) set feature;
                let mut features = Features::fetch_config(&state_view).unwrap_or_default();
                if self.bytecode_version == 6 {
                    Self::set_enable(&mut features, FeatureFlag::VM_BINARY_FORMAT_V6);
                }

                // 5) execute
                let executor = FakeExecutor::no_genesis();
                let mut executor = executor.set_not_parallel();
                *executor.data_store_mut() = state.clone();

                let res_1_opt = self.execute_code(
                    &mut executor,
                    &features,
                    cur_version,
                    &txn_idx.package_info,
                    &mut compiled_package_cache,
                );
                if !self.compare {
                    if let Some(res) = res_1_opt {
                        if res.is_err() {
                            println!(
                                "execution error {} at version: {}, error",
                                res.unwrap_err(),
                                cur_version
                            );
                        } else {
                            let res_unwrapped = res.unwrap();
                            println!(
                                "version:{}\nwrite set:{:?}\n events:{:?}\n",
                                cur_version, res_unwrapped.0, res_unwrapped.1
                            );
                        }
                    }
                } else {
                    // execute V2 and compare results
                    let executor = FakeExecutor::no_genesis();
                    let mut executor = executor.set_not_parallel();
                    *executor.data_store_mut() = state.clone();
                    let res_2_opt = self.execute_code(
                        &mut executor,
                        &features,
                        cur_version,
                        &txn_idx.package_info,
                        &mut compiled_package_cache_v2,
                    );
                    Self::print_mismatches(cur_version, &res_1_opt.unwrap(), &res_2_opt.unwrap());
                }
            }

            // get next value from the index file
            cur_idx = String::new();
            let num_bytes = idx_reader.read_line(&mut cur_idx)?;
            if num_bytes == 0 {
                break;
            }
            cur_version = cur_idx.trim().parse().unwrap();
        }

        Ok(())
    }

    fn execute_code(
        &self,
        executor: &mut FakeExecutor,
        features: &Features,
        cur_version: u64,
        package_info: &PackageInfo,
        compiled_package_cache: &mut HashMap<PackageInfo, CompiledPackage>,
    ) -> Option<Result<(WriteSet, Vec<ContractEvent>), VMStatus>> {
        let txn_path = self
            .input_path
            .join(TXN_DATA)
            .join(format!("{}_txn", cur_version));
        let mut txn_file = File::open(txn_path).unwrap();
        let mut buffer = Vec::<u8>::new();
        txn_file.read_to_end(&mut buffer).unwrap();
        let txn = bcs::from_bytes::<Transaction>(&buffer).unwrap();
        let compiled_package = compiled_package_cache.get(package_info).unwrap();
        if let Transaction::UserTransaction(signed_trans) = &txn {
            let sender = signed_trans.sender();
            let payload = signed_trans.payload();
            if let TransactionPayload::EntryFunction(entry_function) = payload {
                let root_modules = compiled_package.all_modules();
                for compiled_module in root_modules {
                    if let CompiledUnitEnum::Module(module) = &compiled_module.unit {
                        let module_blob = compiled_module.unit.serialize(None);
                        executor.add_module(&module.module.self_id(), module_blob);
                    }
                }
                return Some(executor.try_exec_entry_with_features(
                    vec![sender],
                    entry_function,
                    features,
                ));
            }
        }
        None
    }

    // TODO: test and refactor it once V2 is feature complete
    fn print_mismatches(
        cur_version: u64,
        res_1: &Result<(WriteSet, Vec<ContractEvent>), VMStatus>,
        res_2: &Result<(WriteSet, Vec<ContractEvent>), VMStatus>,
    ) {
        if res_1.is_err() && res_2.is_err() {
            let res_1_err = res_1.as_ref().unwrap_err();
            let res_2_err = res_2.as_ref().unwrap_err();
            if res_1_err != res_2_err {
                println!("error is different at {}", cur_version);
                println!("error {} is raised from V1", res_1_err);
                println!("error {} is raised from V2", res_2_err);
            }
        } else if res_1.is_err() && res_2.is_ok() {
            println!(
                "error {} is raised from V1 at {}",
                res_1.as_ref().unwrap_err(),
                cur_version
            );
            let res_2_unwrapped = res_2.as_ref().unwrap();
            println!(
                "output from V2 at version:{}\nwrite set:{:?}\n events:{:?}\n",
                cur_version, res_2_unwrapped.0, res_2_unwrapped.1
            );
        } else if res_1.is_ok() && res_2.is_err() {
            println!(
                "error {} is raised from V2 at {}",
                res_2.as_ref().unwrap_err(),
                cur_version
            );
            let res_1_unwrapped = res_1.as_ref().unwrap();
            println!(
                "output from V1 at version:{}\nwrite set:{:?}\n events:{:?}\n",
                cur_version, res_1_unwrapped.0, res_1_unwrapped.1
            );
        } else {
            let res_1 = res_1.as_ref().unwrap();
            let res_2 = res_2.as_ref().unwrap();

            // compare events
            for idx in 0..res_1.1.len() {
                let event_1 = &res_1.1[idx];
                let event_2 = &res_2.1[idx];
                if event_1 != event_2 {
                    println!("event is different at version {}", cur_version);
                    println!("event raised from V1: {} at index:{}", event_1, idx);
                    println!("event raised from V2: {} at index:{}", event_2, idx);
                }
            }

            // compare write set
            let res_1_write_set_vec = res_1.0.iter().collect_vec();
            let res_2_write_set_vec = res_2.0.iter().collect_vec();

            for idx in 0..res_1_write_set_vec.len() {
                let write_set_1 = res_1_write_set_vec[0];
                let write_set_2 = res_2_write_set_vec[0];
                if write_set_1.0 != write_set_2.0 {
                    println!("write set key is different at version {}", cur_version);
                    println!("state key at V1: {:?} at index:{}", write_set_1.0, idx);
                    println!("state key at V2: {:?} at index:{}", write_set_2.0, idx);
                }
                if write_set_1.1 != write_set_2.1 {
                    println!("write set value is different at version {}", cur_version);
                    println!("state value at V1: {:?} at index {}", write_set_1.1, idx);
                    println!("state value at V2: {:?} at index {}", write_set_2.1, idx);
                }
            }
        }
    }
}
