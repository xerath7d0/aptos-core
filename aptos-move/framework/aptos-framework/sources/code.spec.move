spec aptos_framework::code {
    /// <high-level-req>
    /// No.: 1
    /// Property: Updating a package should fail if the user is not the owner of it.
    /// Criticality: Critical
    /// Implementation: The publish_package function may only be able to update the package if the signer is the actual
    /// owner of the package.
    /// Enforcement: The Aptos upgrade native functions have been manually audited.
    ///
    /// No.: 2
    /// Property: The arbitrary upgrade policy should never be used.
    /// Criticality: Critical
    /// Implementation: There should never be a pass of an arbitrary upgrade policy to the
    /// request_publish native function.
    /// Enforcement: Manually audited that it aborts if package.upgrade_policy.policy == 0.
    ///
    /// No.: 3
    /// Property: Should perform accurate compatibility checks when the policy indicates
    /// compatibility, ensuring it meets the required conditions.
    /// Criticality: Critical
    /// Implementation: Specifies if it should perform compatibility checks for upgrades. The check
    /// only passes if a new module has (a) the same public functions, and (b) for existing resources,
    /// no layout change.
    /// Enforcement: The Move upgradability patterns have been manually audited.
    ///
    /// No.: 4
    /// Property: Package upgrades should abide by policy change rules. In particular, The new
    /// upgrade policy must be equal to or stricter when compared to the old one. The original
    /// upgrade policy must not be immutable. The new package must contain all modules contained
    /// in the old package.
    /// Criticality: Medium
    /// Implementation: A package may only be updated using the publish_package function when the
    /// check_upgradability function returns true.
    /// Enforcement: This is audited by a manual review of the check_upgradability patterns.
    ///
    /// No.: 5
    /// Property: The upgrade policy of a package must not exceed the strictness level imposed by
    /// its dependencies.
    /// Criticality: Medium
    /// Implementation: The upgrade_policy of a package may only be less than its dependencies
    /// throughout the upgrades. In addition, the native code properly restricts the use of
    /// dependencies outside the passed-in metadata.
    /// Enforcement: This has been manually audited.
    ///
    /// No.: 6
    /// Property: The extension for package metadata is currently unused.
    /// Criticality: Medium
    /// Implementation: The extension field in PackageMetadata should be unused.
    /// Enforcement: Data invariant on the extension field has been manually audited.
    ///
    /// No.: 7
    /// Property: The upgrade number of a package increases incrementally in a monotonic manner
    /// with each subsequent upgrade.
    /// Criticality: Low
    /// Implementation: On each upgrade of a particular package, the publish_package function
    /// updates the upgrade_number for that package.
    /// Enforcement: Post condition on upgrade_number has been manually audited.
    /// </high-level-req>
    ///
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    spec request_publish {
        // TODO: temporary mockup.
        pragma opaque;
    }

    spec request_publish_with_allowed_deps {
        // TODO: temporary mockup.
        pragma opaque;
    }

    spec initialize(aptos_framework: &signer, package_owner: &signer, metadata: PackageMetadata) {
        let aptos_addr = signer::address_of(aptos_framework);
        let owner_addr = signer::address_of(package_owner);
        aborts_if !system_addresses::is_aptos_framework_address(aptos_addr);

        ensures exists<PackageRegistry>(owner_addr);
    }

    spec publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) {
        // TODO: Can't verify 'vector::enumerate' loop.
        pragma aborts_if_is_partial;
        let addr = signer::address_of(owner);
        modifies global<PackageRegistry>(addr);
        aborts_if pack.upgrade_policy.policy <= upgrade_policy_arbitrary().policy;
    }

    spec publish_package_txn {
        // TODO: Calls `publish_package`.
        pragma verify = false;
    }

    spec check_upgradability(old_pack: &PackageMetadata, new_pack: &PackageMetadata, new_modules: &vector<String>) {
        // TODO: Can't verify 'vector::enumerate' loop.
        pragma aborts_if_is_partial;
        aborts_if old_pack.upgrade_policy.policy >= upgrade_policy_immutable().policy;
        aborts_if !can_change_upgrade_policy_to(old_pack.upgrade_policy, new_pack.upgrade_policy);
    }

    spec check_dependencies(publish_address: address, pack: &PackageMetadata): vector<AllowedDep> {
        // TODO: Can't verify 'vector::enumerate' loop.
        pragma verify = false;
    }

    spec check_coexistence(old_pack: &PackageMetadata, new_modules: &vector<String>) {
        // TODO: Can't verify 'vector::enumerate' loop.
        pragma verify = false;
    }

    spec get_module_names(pack: &PackageMetadata): vector<String> {
        pragma opaque;
        aborts_if [abstract] false;
        ensures [abstract] len(result) == len(pack.modules);
        ensures [abstract] forall i in 0..len(result): result[i] == pack.modules[i].name;
    }
}
