// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use aptos_framework::{
    natives::code::PackageMetadata, unzip_metadata_str, BuildOptions, BuiltPackage, APTOS_PACKAGES,
};
use aptos_types::{account_address::AccountAddress, transaction::Transaction};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    path::{Path, PathBuf},
};
// use url::Url;
// use aptos_framework::natives::code::PackageRegistry;
// use aptos_rest_client::Client;
// use aptos::move_tool::CachedPackageRegistry;

mod data_collection;
mod execution;

pub use data_collection::*;
pub use execution::*;
use move_package::{
    compilation::compiled_package::CompiledPackage,
    source_package::{
        manifest_parser::{parse_move_manifest_string, parse_source_manifest},
        parsed_manifest::Dependency,
    },
    CompilerVersion,
};

const STATE_DATA: &str = "state_data";
const TXN_DATA: &str = "txn_data";
const INDEX_FILE: &str = "version_index.txt";
const ROCKS_INDEX_DB: &str = "rocks_txn_idx_db";
const APTOS_COMMONS: &str = "aptos-commons";
// const APTOS_TOKEN: &str = "AptosToken";
// const APTOS_TOKEN_OBJECTS: &str = "AptosTokenObjects";
//
//
//
// async fn download_aptos_packages(path: PathBuf, endpoint: &str) {
//     if !path.exists() {
//         File::create(path).expect("failed to create the directory");
//     }
//
//     for package in APTOS_PACKAGES {
//         let addr = if package == APTOS_TOKEN {
//             AccountAddress::THREE
//         } else if package == APTOS_TOKEN_OBJECTS {
//             AccountAddress::FOUR
//         } else {
//             AccountAddress::ONE
//         };
//         let registry = CachedPackageRegistry::create(Url::parse(endpoint).unwrap(), addr).await.unwrap();
//
//     }
// }

fn check_aptos_packages_availability(path: PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    for package in APTOS_PACKAGES {
        if !path.join(package).exists() {
            return false;
        }
    }
    true
}

#[derive(Default)]
struct CompilationCache {
    compiled_package_map: HashMap<PackageInfo, CompiledPackage>,
    failed_packages: HashSet<PackageInfo>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
struct PackageInfo {
    address: AccountAddress,
    package_name: String,
    upgrade_number: Option<u64>,
}

impl fmt::Display for PackageInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut name = format!("{}.{}", self.package_name, self.address);
        if self.upgrade_number.is_some() {
            name = format!("{}.{}", name, self.upgrade_number.unwrap());
        }
        write!(f, "{}", name)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxnIndex {
    version: u64,
    package_info: PackageInfo,
    txn: Transaction,
}

fn is_aptos_package(package_name: &str) -> bool {
    APTOS_PACKAGES.contains(&package_name)
}

fn compile_aptos_packages(
    aptos_commons_path: &Path,
    compiled_package_map: &mut HashMap<PackageInfo, CompiledPackage>,
    v2_flag: bool,
) -> anyhow::Result<()> {
    for package in APTOS_PACKAGES {
        let mut build_options = BuildOptions::default();
        let root_package_dir = aptos_commons_path.join(package);
        if v2_flag {
            build_options.compiler_version = Some(CompilerVersion::V2);
        }
        let compiled_package = BuiltPackage::build(root_package_dir, build_options);
        if let Ok(built_package) = compiled_package {
            let package_info = PackageInfo {
                address: AccountAddress::ONE,
                package_name: package.to_string(),
                upgrade_number: None,
            };
            // For simplicity, all packages including aptos token are stored under 0x1 in the map
            compiled_package_map.insert(package_info, built_package.package);
        } else {
            return Err(anyhow::Error::msg(format!(
                "package {} cannot be compiled",
                package
            )));
        }
    }
    Ok(())
}

fn compile_package(
    root_dir: PathBuf,
    package_info: &PackageInfo,
    compiler_verion: Option<CompilerVersion>,
) -> anyhow::Result<CompiledPackage> {
    let mut build_options = aptos_framework::BuildOptions {
        compiler_version: compiler_verion,
        ..Default::default()
    };
    build_options
        .named_addresses
        .insert(package_info.package_name.clone(), package_info.address);
    let compiled_package = BuiltPackage::build(root_dir, build_options);
    if let Ok(built_package) = compiled_package {
        Ok(built_package.package)
    } else {
        Err(anyhow::Error::msg("compilation failed"))
    }
}

fn dump_and_compile_from_package_metadata(
    package_info: PackageInfo,
    root_dir: PathBuf,
    dep_map: &HashMap<(AccountAddress, String), PackageMetadata>,
    compilation_cache: &mut CompilationCache,
    compiler_verion: Option<CompilerVersion>,
) -> anyhow::Result<()> {
    let root_package_dir = root_dir.join(format!("{}", package_info,));
    if compilation_cache.failed_packages.contains(&package_info) {
        return Err(anyhow::Error::msg("compilation failed"));
    }
    if !root_package_dir.exists() {
        std::fs::create_dir_all(root_package_dir.as_path())?;
    }
    let root_package_metadata = dep_map
        .get(&(package_info.address, package_info.package_name.clone()))
        .unwrap();
    // step 1: unzip and save the source code into src into corresponding folder: txn_version/package-name
    let sources_dir = root_package_dir.join("sources");
    std::fs::create_dir_all(sources_dir.as_path())?;
    let modules = root_package_metadata.modules.clone();
    for module in modules {
        let module_path = sources_dir.join(format!("{}.move", module.name));
        if !module_path.exists() {
            File::create(module_path.clone()).expect("Error encountered while creating file!");
        };
        let source_str = unzip_metadata_str(&module.source).unwrap();
        std::fs::write(&module_path.clone(), source_str).unwrap();
    }

    // step 2: unzip, parse the manifest file
    let manifest_u8 = root_package_metadata.manifest.clone();
    let manifest_str = unzip_metadata_str(&manifest_u8).unwrap();
    let mut manifest =
        parse_source_manifest(parse_move_manifest_string(manifest_str.clone()).unwrap()).unwrap();

    let fix_manifest_dep = |dep: &mut Dependency, local_str: &str| {
        dep.git_info = None;
        dep.subst = None;
        dep.version = None;
        dep.digest = None;
        dep.node_info = None;
        dep.local = PathBuf::from("..").join(local_str); // PathBuf::from(local_str);
    };

    // step 3:
    let manifest_deps = &mut manifest.dependencies;
    for manifest_dep in manifest_deps {
        let manifest_dep_name = manifest_dep.0.as_str();
        let dep = manifest_dep.1;
        for pack_dep in &root_package_metadata.deps {
            let pack_dep_address = pack_dep.account;
            let pack_dep_name = pack_dep.clone().package_name;
            if pack_dep_name == manifest_dep_name {
                if is_aptos_package(&pack_dep_name) {
                    fix_manifest_dep(dep, &format!("{}/{}", APTOS_COMMONS, &pack_dep_name));
                    break;
                }
                let dep_metadata_opt = dep_map.get(&(pack_dep_address, pack_dep_name.clone()));
                if let Some(dep_metadata) = dep_metadata_opt {
                    let package_info = PackageInfo {
                        address: pack_dep_address,
                        package_name: pack_dep_name.clone(),
                        upgrade_number: Some(dep_metadata.clone().upgrade_number),
                    };
                    let path_str = format!("{}", package_info);
                    fix_manifest_dep(dep, &path_str);
                    dump_and_compile_from_package_metadata(
                        package_info,
                        root_dir.clone(),
                        dep_map,
                        compilation_cache,
                        compiler_verion,
                    )?;
                }
                break;
            }
        }
    }

    // Dump the fixed manifest file
    let toml_path = root_package_dir.join("Move.toml");

    std::fs::write(toml_path, manifest.to_string()).unwrap();
    if let std::collections::hash_map::Entry::Vacant(e) = compilation_cache
        .compiled_package_map
        .entry(package_info.clone())
    {
        let mut build_options = BuildOptions::default();
        build_options
            .named_addresses
            .insert(package_info.package_name.clone(), package_info.address);
        build_options.compiler_version = compiler_verion;
        let compiled_package = BuiltPackage::build(root_package_dir, build_options);
        if let Ok(built_package) = compiled_package {
            e.insert(built_package.package);
        } else {
            if !compilation_cache.failed_packages.contains(&package_info) {
                compilation_cache.failed_packages.insert(package_info);
            }
            return Err(anyhow::Error::msg("compilation failed"));
        }
    }
    Ok(())
}
