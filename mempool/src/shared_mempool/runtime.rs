// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    core_mempool::CoreMempool,
    network::MempoolSyncMsg,
    shared_mempool::{
        broadcast_peers_selector::{
            BroadcastPeersSelector, FreshPeersSelector, PrioritizedPeersSelector,
        },
        coordinator::{coordinator, gc_coordinator, snapshot_job},
        types::{MempoolEventsReceiver, SharedMempool, SharedMempoolNotification},
    },
    QuorumStoreRequest,
};
use aptos_config::config::{BroadcastPeersSelectorConfig, NodeConfig};
use aptos_event_notifications::{DbBackedOnChainConfig, ReconfigNotificationListener};
use aptos_infallible::{Mutex, RwLock};
use aptos_logger::Level;
use aptos_mempool_notifications::MempoolNotificationListener;
use aptos_network::application::{
    interface::{NetworkClient, NetworkServiceEvents},
    storage::PeersAndMetadata,
};
use aptos_storage_interface::DbReader;
use aptos_types::on_chain_config::OnChainConfigProvider;
use aptos_vm_validator::vm_validator::{TransactionValidation, VMValidator};
use futures::channel::mpsc::{Receiver, UnboundedSender};
use std::sync::Arc;
use tokio::runtime::{Handle, Runtime};

/// Bootstrap of SharedMempool.
/// Creates a separate Tokio Runtime that runs the following routines:
///   - outbound_sync_task (task that periodically broadcasts transactions to peers).
///   - inbound_network_task (task that handles inbound mempool messages and network events).
///   - gc_task (task that performs GC of all expired transactions by SystemTTL).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_shared_mempool<TransactionValidator, ConfigProvider>(
    executor: &Handle,
    config: &NodeConfig,
    mempool: Arc<Mutex<CoreMempool>>,
    network_client: NetworkClient<MempoolSyncMsg>,
    network_service_events: NetworkServiceEvents<MempoolSyncMsg>,
    client_events: MempoolEventsReceiver,
    quorum_store_requests: Receiver<QuorumStoreRequest>,
    mempool_listener: MempoolNotificationListener,
    mempool_reconfig_events: ReconfigNotificationListener<ConfigProvider>,
    db: Arc<dyn DbReader>,
    validator: Arc<RwLock<TransactionValidator>>,
    subscribers: Vec<UnboundedSender<SharedMempoolNotification>>,
    peers_and_metadata: Arc<PeersAndMetadata>,
    broadcast_peers_selector: Arc<RwLock<Box<dyn BroadcastPeersSelector>>>,
) where
    TransactionValidator: TransactionValidation + 'static,
    ConfigProvider: OnChainConfigProvider,
{
    let smp: SharedMempool<NetworkClient<MempoolSyncMsg>, TransactionValidator> =
        SharedMempool::new(
            mempool.clone(),
            config.mempool.clone(),
            network_client,
            db,
            validator,
            subscribers,
            config.base.role,
        );

    executor.spawn(coordinator(
        smp,
        executor.clone(),
        network_service_events,
        client_events,
        quorum_store_requests,
        mempool_listener,
        mempool_reconfig_events,
        config.mempool.shared_mempool_peer_update_interval_ms,
        peers_and_metadata,
        broadcast_peers_selector,
    ));

    executor.spawn(gc_coordinator(
        mempool.clone(),
        config.mempool.system_transaction_gc_interval_ms,
    ));

    if aptos_logger::enabled!(Level::Trace) {
        executor.spawn(snapshot_job(
            mempool,
            config.mempool.mempool_snapshot_interval_secs,
        ));
    }
}

pub fn bootstrap(
    config: &NodeConfig,
    db: Arc<dyn DbReader>,
    network_client: NetworkClient<MempoolSyncMsg>,
    network_service_events: NetworkServiceEvents<MempoolSyncMsg>,
    client_events: MempoolEventsReceiver,
    quorum_store_requests: Receiver<QuorumStoreRequest>,
    mempool_listener: MempoolNotificationListener,
    mempool_reconfig_events: ReconfigNotificationListener<DbBackedOnChainConfig>,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Runtime {
    let runtime = aptos_runtimes::spawn_named_runtime("shared-mem".into(), None);

    let broadcast_peers_selector = {
        let inner_selector: Box<dyn BroadcastPeersSelector> =
            match config.mempool.broadcast_peers_selector {
                BroadcastPeersSelectorConfig::FreshPeers(
                    num_peers_to_select,
                    version_threshold,
                ) => Box::new(FreshPeersSelector::new(
                    num_peers_to_select,
                    version_threshold,
                )),
                BroadcastPeersSelectorConfig::PrioritizedPeers(num_peers_to_select) => {
                    Box::new(PrioritizedPeersSelector::new(num_peers_to_select))
                },
            };
        Arc::new(RwLock::new(inner_selector))
    };

    let mempool = Arc::new(Mutex::new(CoreMempool::new(
        config,
        broadcast_peers_selector.clone(),
    )));
    let vm_validator = Arc::new(RwLock::new(VMValidator::new(Arc::clone(&db))));
    start_shared_mempool(
        runtime.handle(),
        config,
        mempool,
        network_client,
        network_service_events,
        client_events,
        quorum_store_requests,
        mempool_listener,
        mempool_reconfig_events,
        db,
        vm_validator,
        vec![],
        peers_and_metadata,
        broadcast_peers_selector,
    );
    runtime
}
