// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{bootstrap_genesis, gen_block_id, gen_ledger_info_with_sigs};
use anyhow::{ensure, Result};
use aptos_cached_packages::aptos_stdlib;
use aptos_config::config::DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD;
use aptos_consensus_types::block::Block;
use aptos_db::AptosDB;
use aptos_executor::block_executor::BlockExecutor;
use aptos_executor_types::BlockExecutorTrait;
use aptos_sdk::{
    transaction_builder::TransactionFactory,
    types::{AccountKey, LocalAccount},
};
use aptos_state_view::account_with_state_view::{AccountWithStateView, AsAccountWithStateView};
use aptos_storage_interface::{state_view::DbStateViewAtVersion, DbReaderWriter, Order};
use aptos_types::{
    account_config::aptos_test_root_address,
    account_view::AccountView,
    block_metadata::BlockMetadata,
    chain_id::ChainId,
    event::EventKey,
    test_helpers::transaction_test_helpers::{block, TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG},
    transaction::{
        signature_verified_transaction::{
            into_signature_verified_block, SignatureVerifiedTransaction,
        },
        Transaction,
        Transaction::UserTransaction,
        TransactionListWithProof, TransactionWithProof, WriteSetPayload,
    },
    trusted_state::{TrustedState, TrustedStateChange},
    waypoint::Waypoint,
};
use aptos_vm::AptosVM;
use rand::SeedableRng;
use std::{path::Path, sync::Arc};

pub fn test_execution_with_storage_impl() -> Arc<AptosDB> {
    let path = aptos_temppath::TempPath::new();
    path.create_as_dir().unwrap();
    test_execution_with_storage_impl_inner(false, path.path())
}

pub fn test_execution_with_storage_impl_inner(
    force_sharding: bool,
    db_path: &Path,
) -> Arc<AptosDB> {
    const B: u64 = 1_000_000_000;

    let (genesis, validators) = aptos_vm_genesis::test_genesis_change_set_and_validators(Some(1));
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis));

    let core_resources_account: LocalAccount = LocalAccount::new(
        aptos_test_root_address(),
        AccountKey::from_private_key(aptos_vm_genesis::GENESIS_KEYPAIR.0.clone()),
        0,
    );

    let (aptos_db, db, executor, waypoint) =
        create_db_and_executor(db_path, &genesis_txn, force_sharding);

    let parent_block_id = executor.committed_block_id();
    let signer = aptos_types::validator_signer::ValidatorSigner::new(
        validators[0].data.owner_address,
        validators[0].consensus_key.clone(),
    );

    // This generates accounts that do not overlap with genesis
    let seed = [3u8; 32];
    let mut rng = ::rand::rngs::StdRng::from_seed(seed);

    let account1 = LocalAccount::generate(&mut rng);
    let account2 = LocalAccount::generate(&mut rng);
    let account3 = LocalAccount::generate(&mut rng);
    let account4 = LocalAccount::generate(&mut rng);

    let account1_address = account1.address();
    let account2_address = account2.address();
    let account3_address = account3.address();

    let txn_factory = TransactionFactory::new(ChainId::test());

    let block1_id = gen_block_id(1);
    let block1_meta = Transaction::BlockMetadata(BlockMetadata::new(
        block1_id,
        1,
        0,
        signer.author(),
        vec![0],
        vec![],
        1,
    ));
    let tx1 = core_resources_account
        .sign_with_transaction_builder(txn_factory.create_user_account(account1.public_key()));
    let tx2 = core_resources_account
        .sign_with_transaction_builder(txn_factory.create_user_account(account2.public_key()));
    let tx3 = core_resources_account
        .sign_with_transaction_builder(txn_factory.create_user_account(account3.public_key()));

    // Create account1 with 2T coins.
    let txn1 = core_resources_account
        .sign_with_transaction_builder(txn_factory.mint(account1.address(), 2_000 * B));
    // Create account2 with 1.2T coins.
    let txn2 = core_resources_account
        .sign_with_transaction_builder(txn_factory.mint(account2.address(), 1_200 * B));
    // Create account3 with 1T coins.
    let txn3 = core_resources_account
        .sign_with_transaction_builder(txn_factory.mint(account3.address(), 1_000 * B));

    // Transfer 20B coins from account1 to account2.
    // balance: <1.98T, 1.22T, 1T
    let txn4 =
        account1.sign_with_transaction_builder(txn_factory.transfer(account2.address(), 20 * B));

    // Transfer 10B coins from account2 to account3.
    // balance: <1.98T, <1.21T, 1.01T
    let txn5 =
        account2.sign_with_transaction_builder(txn_factory.transfer(account3.address(), 10 * B));

    // Transfer 70B coins from account1 to account3.
    // balance: <1.91T, <1.21T, 1.08T
    let txn6 =
        account1.sign_with_transaction_builder(txn_factory.transfer(account3.address(), 70 * B));

    let reconfig1 = core_resources_account
        .sign_with_transaction_builder(txn_factory.payload(aptos_stdlib::version_set_version(100)));

    let block1: Vec<_> = into_signature_verified_block(vec![
        block1_meta,
        UserTransaction(tx1),
        UserTransaction(tx2),
        UserTransaction(tx3),
        UserTransaction(txn1),
        UserTransaction(txn2),
        UserTransaction(txn3),
        UserTransaction(txn4),
        UserTransaction(txn5),
        UserTransaction(txn6),
        UserTransaction(reconfig1),
    ]);

    let block2_id = gen_block_id(2);
    let block2_meta = Transaction::BlockMetadata(BlockMetadata::new(
        block2_id,
        2,
        0,
        signer.author(),
        vec![0],
        vec![],
        2,
    ));
    let reconfig2 = core_resources_account
        .sign_with_transaction_builder(txn_factory.payload(aptos_stdlib::version_set_version(200)));
    let block2 = vec![block2_meta, UserTransaction(reconfig2)];

    let block3_id = gen_block_id(3);
    let block3_meta = Transaction::BlockMetadata(BlockMetadata::new(
        block3_id,
        2,
        1,
        signer.author(),
        vec![0],
        vec![],
        3,
    ));
    let mut block3 = vec![block3_meta];
    // Create 14 txns transferring 10k from account1 to account3 each.
    for _ in 2..=15 {
        block3.push(UserTransaction(account1.sign_with_transaction_builder(
            txn_factory.transfer(account3.address(), 10 * B),
        )));
    }
    let block3 = block(block3); // append state checkpoint txn

    let output1 = executor
        .execute_block(
            (block1_id, block1.clone()).into(),
            parent_block_id,
            TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
        )
        .unwrap();
    let li1 = gen_ledger_info_with_sigs(1, &output1, block1_id, &[signer.clone()]);
    let epoch2_genesis_id = Block::make_genesis_block_from_ledger_info(li1.ledger_info()).id();
    executor.commit_blocks(vec![block1_id], li1).unwrap();

    let state_proof = db.reader.get_state_proof(0).unwrap();
    let trusted_state = TrustedState::from_epoch_waypoint(waypoint);
    let trusted_state = match trusted_state.verify_and_ratchet(&state_proof) {
        Ok(TrustedStateChange::Epoch { new_state, .. }) => new_state,
        _ => panic!("unexpected state change"),
    };
    let current_version = state_proof.latest_ledger_info().version();
    assert_eq!(trusted_state.version(), 11);

    let t5 = db
        .reader
        .get_transaction_by_version(5, current_version, false)
        .unwrap();
    verify_committed_txn_status(&t5, &block1[4]).unwrap();

    let t6 = db
        .reader
        .get_transaction_by_version(6, current_version, false)
        .unwrap();
    verify_committed_txn_status(&t6, &block1[5]).unwrap();

    let t7 = db
        .reader
        .get_transaction_by_version(7, current_version, false)
        .unwrap();
    verify_committed_txn_status(&t7, &block1[6]).unwrap();

    let reconfig1 = db
        .reader
        .get_transaction_by_version(11, current_version, false)
        .unwrap();
    verify_committed_txn_status(&reconfig1, &block1[10]).unwrap();

    let t8 = db
        .reader
        .get_transaction_by_version(8, current_version, true)
        .unwrap();
    verify_committed_txn_status(&t8, &block1[7]).unwrap();
    // We requested the events to come back from this one, so verify that they did
    assert_eq!(t8.events.unwrap().len(), 3);

    let t9 = db
        .reader
        .get_transaction_by_version(9, current_version, false)
        .unwrap();
    verify_committed_txn_status(&t9, &block1[8]).unwrap();

    let t10 = db
        .reader
        .get_transaction_by_version(10, current_version, true)
        .unwrap();
    verify_committed_txn_status(&t10, &block1[9]).unwrap();

    // test the initial balance.
    let db_state_view = db.reader.state_view_at_version(Some(7)).unwrap();
    let account1_view = db_state_view.as_account_with_state_view(&account1_address);
    verify_account_balance(get_account_balance(&account1_view), |x| x == 2_000 * B).unwrap();

    let account2_view = db_state_view.as_account_with_state_view(&account2_address);
    verify_account_balance(get_account_balance(&account2_view), |x| x == 1_200 * B).unwrap();

    let account3_view = db_state_view.as_account_with_state_view(&account3_address);
    verify_account_balance(get_account_balance(&account3_view), |x| x == 1_000 * B).unwrap();

    // test the final balance.
    let db_state_view = db
        .reader
        .state_view_at_version(Some(current_version))
        .unwrap();
    let account1_view = db_state_view.as_account_with_state_view(&account1_address);
    verify_account_balance(get_account_balance(&account1_view), |x| {
        approx_eq(x, 1_910 * B)
    })
    .unwrap();

    let account2_view = db_state_view.as_account_with_state_view(&account2_address);
    verify_account_balance(get_account_balance(&account2_view), |x| {
        approx_eq(x, 1_210 * B)
    })
    .unwrap();

    let account3_view = db_state_view.as_account_with_state_view(&account3_address);
    verify_account_balance(get_account_balance(&account3_view), |x| {
        approx_eq(x, 1_080 * B)
    })
    .unwrap();

    let transaction_list_with_proof = db
        .reader
        .get_transactions(3, 12, current_version, false)
        .unwrap();
    let expected_txns: Vec<Transaction> = block1[2..]
        .iter()
        .map(|t| t.expect_valid().clone())
        .collect();
    verify_transactions(&transaction_list_with_proof, &expected_txns).unwrap();

    // With sharding enabled, we won't have indices for event, skip the checks.
    if !force_sharding {
        let account1_sent_events = db
            .reader
            .get_events(
                &account1.sent_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account1_sent_events.len(), 2);

        let account2_sent_events = db
            .reader
            .get_events(
                &account2.sent_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account2_sent_events.len(), 1);

        let account3_sent_events = db
            .reader
            .get_events(
                &account3.sent_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account3_sent_events.len(), 0);

        let account1_received_events = db
            .reader
            .get_events(
                &account1.received_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        // Account1 has one deposit event since AptosCoin was minted to it.
        assert_eq!(account1_received_events.len(), 1);

        let account2_received_events = db
            .reader
            .get_events(
                &account2.received_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        // Account2 has two deposit events: from being minted to and from one transfer.
        assert_eq!(account2_received_events.len(), 2);

        let account3_received_events = db
            .reader
            .get_events(
                &account3.received_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        // Account3 has three deposit events: from being minted to and from two transfers.
        assert_eq!(account3_received_events.len(), 3);
        let account4_resource = db
            .reader
            .state_view_at_version(Some(current_version))
            .unwrap()
            .as_account_with_state_view(&account4.address())
            .get_account_resource()
            .unwrap();
        assert!(account4_resource.is_none());

        let account4_sent_events = db
            .reader
            .get_events(
                &account4.sent_event_key(),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        assert!(account4_sent_events.is_empty());
    }

    // Execute block 2, 3, 4
    let output2 = executor
        .execute_block(
            (block2_id, block2).into(),
            epoch2_genesis_id,
            TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
        )
        .unwrap();
    let li2 = gen_ledger_info_with_sigs(2, &output2, block2_id, &[signer.clone()]);
    let epoch3_genesis_id = Block::make_genesis_block_from_ledger_info(li2.ledger_info()).id();
    executor.commit_blocks(vec![block2_id], li2).unwrap();

    let state_proof = db.reader.get_state_proof(trusted_state.version()).unwrap();
    let trusted_state = match trusted_state.verify_and_ratchet(&state_proof) {
        Ok(TrustedStateChange::Epoch { new_state, .. }) => new_state,
        _ => panic!("unexpected state change"),
    };
    let current_version = state_proof.latest_ledger_info().version();
    assert_eq!(current_version, 13);

    let output3 = executor
        .execute_block(
            (block3_id, block3.clone()).into(),
            epoch3_genesis_id,
            TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
        )
        .unwrap();
    let li3 = gen_ledger_info_with_sigs(3, &output3, block3_id, &[signer]);
    executor.commit_blocks(vec![block3_id], li3).unwrap();

    let state_proof = db.reader.get_state_proof(trusted_state.version()).unwrap();
    let _trusted_state = match trusted_state.verify_and_ratchet(&state_proof) {
        Ok(TrustedStateChange::Version { new_state, .. }) => new_state,
        _ => panic!("unexpected state change"),
    };
    let current_version = state_proof.latest_ledger_info().version();
    assert_eq!(current_version, 29);

    // More verification
    let t15 = db
        .reader
        .get_transaction_by_version(15, current_version, false)
        .unwrap();
    verify_committed_txn_status(&t15, &block3[1]).unwrap();

    let t28 = db
        .reader
        .get_transaction_by_version(28, current_version, false)
        .unwrap();
    verify_committed_txn_status(&t28, &block3[14]).unwrap();

    let db_state_view = db
        .reader
        .state_view_at_version(Some(current_version))
        .unwrap();

    let account1_view = db_state_view.as_account_with_state_view(&account1_address);
    verify_account_balance(get_account_balance(&account1_view), |x| {
        approx_eq(x, 1_770 * B)
    })
    .unwrap();

    let account3_view = db_state_view.as_account_with_state_view(&account3_address);
    verify_account_balance(get_account_balance(&account3_view), |x| {
        approx_eq(x, 1_220 * B)
    })
    .unwrap();

    let transaction_list_with_proof = db
        .reader
        .get_transactions(14, 15, current_version, false)
        .unwrap();
    let expected_txns: Vec<Transaction> = block3.iter().map(|t| t.expect_valid().clone()).collect();
    verify_transactions(&transaction_list_with_proof, &expected_txns).unwrap();

    // With sharding enabled, we won't have indices for event, skip the checks.
    if !force_sharding {
        let account1_sent_events_batch1 = db
            .reader
            .get_events(
                &EventKey::new(3, account1.address()),
                0,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account1_sent_events_batch1.len(), 10);

        let account1_sent_events_batch2 = db
            .reader
            .get_events(
                &EventKey::new(3, account1.address()),
                10,
                Order::Ascending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account1_sent_events_batch2.len(), 6);

        let account3_received_events_batch1 = db
            .reader
            .get_events(
                &EventKey::new(2, account3.address()),
                u64::MAX,
                Order::Descending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account3_received_events_batch1.len(), 10);
        // Account3 has one extra deposit event from being minted to.
        assert_eq!(
            account3_received_events_batch1[0]
                .event
                .v1()
                .unwrap()
                .sequence_number(),
            16
        );

        let account3_received_events_batch2 = db
            .reader
            .get_events(
                &EventKey::new(2, account3.address()),
                6,
                Order::Descending,
                10,
                current_version,
            )
            .unwrap();
        assert_eq!(account3_received_events_batch2.len(), 7);
        assert_eq!(
            account3_received_events_batch2[0]
                .event
                .v1()
                .unwrap()
                .sequence_number(),
            6
        );
    }

    aptos_db
}

fn approx_eq(a: u64, b: u64) -> bool {
    const M: u64 = 10_000_000;
    a + M > b && b + M > a
}

pub fn create_db_and_executor<P: AsRef<std::path::Path>>(
    path: P,
    genesis: &Transaction,
    force_sharding: bool, // if true force sharding db otherwise using default db
) -> (
    Arc<AptosDB>,
    DbReaderWriter,
    BlockExecutor<AptosVM>,
    Waypoint,
) {
    let (db, dbrw) = force_sharding
        .then(|| {
            DbReaderWriter::wrap(AptosDB::new_for_test_with_sharding(
                &path,
                DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
            ))
        })
        .unwrap_or_else(|| DbReaderWriter::wrap(AptosDB::new_for_test(&path)));
    let waypoint = bootstrap_genesis::<AptosVM>(&dbrw, genesis).unwrap();
    let executor = BlockExecutor::new(dbrw.clone());

    (db, dbrw, executor, waypoint)
}

pub fn get_account_balance(account_state_view: &AccountWithStateView) -> u64 {
    account_state_view
        .get_coin_store_resource()
        .unwrap()
        .map(|b| b.coin())
        .unwrap_or(0)
}

pub fn verify_account_balance<F>(balance: u64, f: F) -> Result<()>
where
    F: Fn(u64) -> bool,
{
    ensure!(
        f(balance),
        "balance {} doesn't satisfy the condition passed in",
        balance
    );
    Ok(())
}

pub fn verify_transactions(
    txn_list_with_proof: &TransactionListWithProof,
    expected_txns: &[Transaction],
) -> Result<()> {
    let txns = &txn_list_with_proof.transactions;
    ensure!(
        *txns == expected_txns,
        "expected txns {:?} doesn't equal to returned txns {:?}",
        expected_txns,
        txns
    );
    Ok(())
}

pub fn verify_committed_txn_status(
    txn_with_proof: &TransactionWithProof,
    expected_txn: &SignatureVerifiedTransaction,
) -> Result<()> {
    let txn = &txn_with_proof.transaction;

    ensure!(
        expected_txn.expect_valid() == txn,
        "The two transactions do not match. Expected txn: {:?}, returned txn: {:?}",
        expected_txn,
        txn,
    );

    Ok(())
}
