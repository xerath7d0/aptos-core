spec aptos_framework::chain_id {
    /// <high-level-req>
    /// No.: 1
    /// Property: During genesis, the ChainId resource should be created and moved under the Aptos framework account
    /// with the specified chain id.
    /// Criticality: Medium
    /// Implementation: The chain_id::initialize function is responsible for generating the ChainId resource and then
    /// storing it under the aptos_framework account.
    /// Enforcement: Formally verified via [high-level-req-1](initialize).
    ///
    /// No.: 2
    /// Property: The chain id can only be fetched if the chain id resource exists under the Aptos
    /// framework account.
    /// Criticality: Low
    /// Implementation: The chain_id::get function fetches the chain id by borrowing the ChainId
    /// resource from the aptos_framework account.
    /// Enforcement: Formally verified via [high-level-req-2](get).
    /// </high-level-req>
    ///
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    spec initialize {
        use std::signer;
        let addr = signer::address_of(aptos_framework);
        aborts_if addr != @aptos_framework;
        aborts_if exists<ChainId>(@aptos_framework);
        /// [high-level-req-1]
        ensures exists<ChainId>(addr);
        ensures global<ChainId>(addr).id == id;
    }

    spec get {
        /// [high-level-req-2]
        aborts_if !exists<ChainId>(@aptos_framework);
    }
}
