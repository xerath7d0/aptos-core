// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use aptos_config::{
    config::{NodeConfig, StateSyncConfig, StorageServiceConfig},
    network_id::NetworkId,
};
use aptos_consensus_notifications::ConsensusNotifier;
use aptos_data_client::aptosnet::AptosNetDataClient;
use aptos_data_streaming_service::{
    streaming_client::{new_streaming_service_client_listener_pair, StreamingServiceClient},
    streaming_service::DataStreamingService,
};
use aptos_event_notifications::{EventSubscriptionService, ReconfigNotificationListener};
use aptos_executor::chunk_executor::ChunkExecutor;
use aptos_infallible::RwLock;
use aptos_mempool_notifications::MempoolNotificationListener;
use aptos_network::{
    application::{interface::NetworkClient, storage::PeerMetadataStorage},
    protocols::network::NetworkSender,
    ProtocolId,
};
use aptos_state_sync_driver::{
    driver_factory::{DriverFactory, StateSyncRuntimes},
    metadata_storage::PersistentMetadataStorage,
};
use aptos_storage_interface::DbReaderWriter;
use aptos_storage_service_client::StorageServiceClient;
use aptos_storage_service_server::{
    network::StorageServiceNetworkEvents, StorageReader, StorageServiceServer,
};
use aptos_storage_service_types::StorageServiceMessage;
use aptos_time_service::TimeService;
use aptos_types::{on_chain_config::ON_CHAIN_CONFIG_REGISTRY, waypoint::Waypoint};
use aptos_vm::AptosVM;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::runtime::{Builder, Runtime};

/// Creates the event subscription service and two reconfiguration
/// notification listeners (for mempool and consensus, respectively).
pub fn create_event_subscription_service(
    node_config: &NodeConfig,
    db_rw: &DbReaderWriter,
) -> (
    EventSubscriptionService,
    ReconfigNotificationListener,
    Option<ReconfigNotificationListener>,
) {
    // Create the event subscription service
    let mut event_subscription_service = EventSubscriptionService::new(
        ON_CHAIN_CONFIG_REGISTRY,
        Arc::new(RwLock::new(db_rw.clone())),
    );

    // Create a reconfiguration subscription for mempool
    let mempool_reconfig_subscription = event_subscription_service
        .subscribe_to_reconfigurations()
        .expect("Mempool must subscribe to reconfigurations");

    // Create a reconfiguration subscription for consensus (if this is a validator)
    let consensus_reconfig_subscription = if node_config.base.role.is_validator() {
        Some(
            event_subscription_service
                .subscribe_to_reconfigurations()
                .expect("Consensus must subscribe to reconfigurations"),
        )
    } else {
        None
    };

    (
        event_subscription_service,
        mempool_reconfig_subscription,
        consensus_reconfig_subscription,
    )
}

/// Sets up all state sync runtimes and return the notification endpoints
pub fn start_state_sync_and_get_notification_handles(
    node_config: &NodeConfig,
    storage_service_server_network_handles: Vec<StorageServiceNetworkEvents>,
    storage_client_network_senders: HashMap<NetworkId, NetworkSender<StorageServiceMessage>>,
    peer_metadata_storage: Arc<PeerMetadataStorage>,
    waypoint: Waypoint,
    event_subscription_service: EventSubscriptionService,
    db_rw: DbReaderWriter,
) -> anyhow::Result<(
    StateSyncRuntimes,
    MempoolNotificationListener,
    ConsensusNotifier,
)> {
    // Start the state sync storage service
    let storage_service_runtime = setup_state_sync_storage_service(
        node_config.state_sync.storage_service,
        storage_service_server_network_handles,
        &db_rw,
    )?;

    // Start the data client
    let (aptos_data_client, aptos_data_client_runtime) = setup_aptos_data_client(
        node_config,
        storage_client_network_senders,
        peer_metadata_storage,
    )?;

    // Start the data streaming service
    let (streaming_service_client, streaming_service_runtime) =
        setup_data_streaming_service(node_config.state_sync.clone(), aptos_data_client.clone())?;

    // Create the chunk executor and persistent storage
    let chunk_executor = Arc::new(ChunkExecutor::<AptosVM>::new(db_rw.clone()));
    let metadata_storage = PersistentMetadataStorage::new(&node_config.storage.dir());

    // Create notification senders and listeners for mempool and consensus
    let (mempool_notifier, mempool_listener) =
        aptos_mempool_notifications::new_mempool_notifier_listener_pair();
    let (consensus_notifier, consensus_listener) =
        aptos_consensus_notifications::new_consensus_notifier_listener_pair(
            node_config
                .state_sync
                .state_sync_driver
                .commit_notification_timeout_ms,
        );

    // Create the state sync driver factory
    let state_sync = DriverFactory::create_and_spawn_driver(
        true,
        node_config,
        waypoint,
        db_rw,
        chunk_executor,
        mempool_notifier,
        metadata_storage,
        consensus_listener,
        event_subscription_service,
        aptos_data_client,
        streaming_service_client,
        TimeService::real(),
    );

    // Create a new state sync runtime handle
    let state_sync_runtimes = StateSyncRuntimes::new(
        aptos_data_client_runtime,
        state_sync,
        storage_service_runtime,
        streaming_service_runtime,
    );

    Ok((state_sync_runtimes, mempool_listener, consensus_notifier))
}

/// Sets up the data streaming service runtime
fn setup_data_streaming_service(
    state_sync_config: StateSyncConfig,
    aptos_data_client: AptosNetDataClient,
) -> anyhow::Result<(StreamingServiceClient, Runtime)> {
    // Create the data streaming service
    let (streaming_service_client, streaming_service_listener) =
        new_streaming_service_client_listener_pair();
    let data_streaming_service = DataStreamingService::new(
        state_sync_config.aptos_data_client,
        state_sync_config.data_streaming_service,
        aptos_data_client,
        streaming_service_listener,
    );

    // Start the data streaming service
    let streaming_service_runtime = Builder::new_multi_thread()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("stream-serv-{}", id)
        })
        .disable_lifo_slot()
        .enable_all()
        .build()
        .map_err(|err| anyhow!("Failed to create data streaming service {}", err))?;
    streaming_service_runtime.spawn(data_streaming_service.start_service());

    Ok((streaming_service_client, streaming_service_runtime))
}

/// Sets up the aptos data client runtime
fn setup_aptos_data_client(
    node_config: &NodeConfig,
    network_senders: HashMap<NetworkId, NetworkSender<StorageServiceMessage>>,
    peer_metadata_storage: Arc<PeerMetadataStorage>,
) -> anyhow::Result<(AptosNetDataClient, Runtime)> {
    // Create the storage service client
    let network_client = NetworkClient::new(
        vec![],
        vec![ProtocolId::StorageServiceRpc],
        network_senders,
        peer_metadata_storage,
    );
    let network_client = StorageServiceClient::new(network_client);

    // Create a new runtime for the data client
    let aptos_data_client_runtime = Builder::new_multi_thread()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("data-client-{}", id)
        })
        .disable_lifo_slot()
        .enable_all()
        .build()
        .map_err(|err| anyhow!("Failed to create aptos data client {}", err))?;

    // Create the data client and spawn the data poller
    let (aptos_data_client, data_summary_poller) = AptosNetDataClient::new(
        node_config.state_sync.aptos_data_client,
        node_config.base.clone(),
        node_config.state_sync.storage_service,
        TimeService::real(),
        network_client,
        Some(aptos_data_client_runtime.handle().clone()),
    );
    aptos_data_client_runtime.spawn(data_summary_poller.start_poller());

    Ok((aptos_data_client, aptos_data_client_runtime))
}

/// Sets up the state sync storage service runtime
fn setup_state_sync_storage_service(
    config: StorageServiceConfig,
    network_handles: Vec<StorageServiceNetworkEvents>,
    db_rw: &DbReaderWriter,
) -> anyhow::Result<Runtime> {
    // Create a new state sync storage service runtime
    let storage_service_runtime = Builder::new_multi_thread()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("stor-server-{}", id)
        })
        .disable_lifo_slot()
        .enable_all()
        .build()
        .map_err(|err| anyhow!("Failed to start state sync storage service {}", err))?;

    // Spawn all state sync storage service servers on the same runtime
    let storage_reader = StorageReader::new(config, Arc::clone(&db_rw.reader));
    for events in network_handles {
        let service = StorageServiceServer::new(
            config,
            storage_service_runtime.handle().clone(),
            storage_reader.clone(),
            TimeService::real(),
            events,
        );
        storage_service_runtime.spawn(service.start());
    }

    Ok(storage_service_runtime)
}