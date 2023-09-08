// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::AptosValidatorInterface;
use anyhow::{anyhow, Result};
use aptos_api_types::{AptosError, AptosErrorCode};
use aptos_framework::{
    natives::code::{PackageMetadata, PackageRegistry},
    APTOS_PACKAGES,
};
use aptos_rest_client::{
    error::{AptosErrorResponse, RestError},
    Client,
};
use aptos_types::{
    account_address::AccountAddress,
    account_state::AccountState,
    state_store::{state_key::StateKey, state_value::StateValue},
    transaction::{Transaction, TransactionInfo, Version},
};
use async_recursion::async_recursion;
use move_core_types::language_storage::ModuleId;
use std::collections::{BTreeMap, HashMap};

pub struct RestDebuggerInterface(pub Client);

impl RestDebuggerInterface {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

#[async_trait::async_trait]
impl AptosValidatorInterface for RestDebuggerInterface {
    async fn get_account_state_by_version(
        &self,
        account: AccountAddress,
        version: Version,
    ) -> Result<Option<AccountState>> {
        let resource = self
            .0
            .get_account_resources_at_version_bcs(account, version)
            .await
            .map_err(|err| anyhow!("Failed to get account states: {:?}", err))?
            .into_inner()
            .into_iter()
            .map(|(key, value)| (key.access_vector(), value))
            .collect::<BTreeMap<_, _>>();

        Ok(Some(AccountState::new(account, resource)))
    }

    async fn get_state_value_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<StateValue>> {
        match self.0.get_raw_state_value(state_key, version).await {
            Ok(resp) => Ok(Some(bcs::from_bytes(&resp.into_inner())?)),
            Err(err) => match err {
                RestError::Api(AptosErrorResponse {
                    error:
                        AptosError {
                            error_code: AptosErrorCode::StateValueNotFound,
                            ..
                        },
                    ..
                }) => Ok(None),
                _ => Err(anyhow!(err)),
            },
        }
    }

    async fn get_committed_transactions(
        &self,
        start: Version,
        limit: u64,
    ) -> Result<(Vec<Transaction>, Vec<TransactionInfo>)> {
        let mut txns = Vec::with_capacity(limit as usize);
        let mut txn_infos = Vec::with_capacity(limit as usize);

        while txns.len() < limit as usize {
            self.0
                .get_transactions_bcs(
                    Some(start + txns.len() as u64),
                    Some(limit as u16 - txns.len() as u16),
                )
                .await?
                .into_inner()
                .into_iter()
                .for_each(|txn| {
                    txns.push(txn.transaction);
                    txn_infos.push(txn.info);
                });
            println!("Got {}/{} txns from RestApi.", txns.len(), limit);
        }

        Ok((txns, txn_infos))
    }

    async fn get_committed_transactions_with_available_src(
        &self,
        start: Version,
        limit: u64,
        package_registry_cache: &mut HashMap<AccountAddress, PackageRegistry>,
    ) -> Result<
        Vec<(
            u64,
            Transaction,
            (AccountAddress, String),
            HashMap<(AccountAddress, String), PackageMetadata>,
        )>,
    > {
        let locate_package_with_src = |module: &ModuleId,
                                       packages: &[PackageMetadata]|
         -> Option<PackageMetadata> {
            for package in packages {
                for module_metadata in &package.modules {
                    if module_metadata.name == module.name().as_str() {
                        if module_metadata.source.is_empty() || package.upgrade_policy.policy == 0 {
                            return None;
                        } else {
                            return Some(package.clone());
                        }
                    }
                }
            }
            None
        };

        #[async_recursion]
        async fn retrieve_available_src(
            client: &Client,
            version: u64,
            package: &PackageMetadata,
            account_address: AccountAddress,
            data: &mut HashMap<(AccountAddress, String), PackageMetadata>,
            package_registry_cache: &mut HashMap<AccountAddress, PackageRegistry>,
        ) -> Result<()> {
            if package.modules.is_empty() || package.modules[0].source.is_empty() {
                Err(anyhow::anyhow!("no src available"))
            } else {
                let package_name = package.clone().name;
                if let std::collections::hash_map::Entry::Vacant(e) =
                    data.entry((account_address, package_name.clone()))
                {
                    e.insert(package.clone());
                    retrieve_dep_packages_with_src(
                        client,
                        version,
                        package,
                        data,
                        package_registry_cache,
                    )
                    .await
                } else {
                    Ok(())
                }
            }
        }

        #[async_recursion]
        async fn get_or_update_package_registry<'a>(
            client: &Client,
            version: u64,
            addr: &AccountAddress,
            package_registry_cache: &'a mut HashMap<AccountAddress, PackageRegistry>,
        ) -> &'a PackageRegistry {
            if package_registry_cache.contains_key(addr) {
                package_registry_cache.get(addr).unwrap()
            } else {
                let packages = client
                    .get_account_resource_at_version_bcs::<PackageRegistry>(
                        *addr,
                        "0x1::code::PackageRegistry",
                        version,
                    )
                    .await
                    .unwrap()
                    .into_inner();
                package_registry_cache.insert(*addr, packages);
                package_registry_cache.get(addr).unwrap()
            }
        }

        #[async_recursion]
        async fn retrieve_dep_packages_with_src(
            client: &Client,
            version: u64,
            root_package: &PackageMetadata,
            data: &mut HashMap<(AccountAddress, String), PackageMetadata>,
            package_registry_cache: &mut HashMap<AccountAddress, PackageRegistry>,
        ) -> Result<()> {
            for dep in &root_package.deps {
                let package_registry = get_or_update_package_registry(
                    client,
                    version,
                    &dep.account,
                    package_registry_cache,
                )
                .await;
                for package in &package_registry.packages {
                    if package.name == dep.package_name {
                        retrieve_available_src(
                            client,
                            version,
                            &package.clone(),
                            dep.account,
                            data,
                            package_registry_cache,
                        )
                        .await?;
                        break;
                    }
                }
            }
            Ok(())
        }

        let mut txns = Vec::with_capacity(limit as usize);
        let temp_txns = self
            .0
            .get_transactions_bcs(Some(start), Some(limit as u16))
            .await?
            .into_inner();

        for txn in temp_txns {
            if let Transaction::UserTransaction(signed_trans) = txn.transaction.clone() {
                let payload = signed_trans.payload();
                if let aptos_types::transaction::TransactionPayload::EntryFunction(entry_function) =
                    payload
                {
                    let m = entry_function.module();
                    let addr = m.address();
                    if entry_function.function().as_str() == "publish_package_txn" {
                        println!("skip publish txn");
                        continue;
                    }
                    let package_registry = get_or_update_package_registry(
                        &self.0,
                        txn.version,
                        addr,
                        package_registry_cache,
                    )
                    .await;
                    let target_package_opt = locate_package_with_src(m, &package_registry.packages);
                    // target_package is the root package
                    if let Some(target_package) = target_package_opt {
                        let mut map = HashMap::new();
                        if APTOS_PACKAGES.contains(&target_package.name.as_str()) {
                            // if the function is from 0x1, continue
                            txns.push((
                                txn.version,
                                txn.transaction.clone(),
                                (AccountAddress::ONE, target_package.name), // all packages are stored under 0x1
                                HashMap::new(), // do not need to store the package registry for aptos packages
                            ));
                        } else if let Ok(()) = retrieve_dep_packages_with_src(
                            &self.0,
                            txn.version,
                            &target_package,
                            &mut map,
                            package_registry_cache,
                        )
                        .await
                        {
                            map.insert(
                                (*addr, target_package.clone().name),
                                target_package.clone(),
                            );
                            txns.push((
                                txn.version,
                                txn.transaction,
                                (*addr, target_package.name),
                                map,
                            ));
                        }
                    }
                }
            }
        }
        return Ok(txns);
    }

    async fn get_latest_version(&self) -> Result<Version> {
        Ok(self.0.get_ledger_information().await?.into_inner().version)
    }

    async fn get_version_by_account_sequence(
        &self,
        account: AccountAddress,
        seq: u64,
    ) -> Result<Option<Version>> {
        Ok(Some(
            self.0
                .get_account_transactions_bcs(account, Some(seq), None)
                .await?
                .into_inner()[0]
                .version,
        ))
    }
}
