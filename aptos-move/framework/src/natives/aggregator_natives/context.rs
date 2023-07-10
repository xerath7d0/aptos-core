// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use aptos_aggregator::{
    aggregator_extension::{AggregatorData, AggregatorID, AggregatorState},
    delta_change_set::{DeltaOp, DeltaUpdate},
    resolver::AggregatorResolver,
};
use aptos_types::vm_status::VMStatus;
use better_any::{Tid, TidAble};
use move_binary_format::errors::Location;
use std::{
    cell::RefCell,
    collections::{btree_map, BTreeMap},
};

pub type TxnIndex = u32;

/// Represents a single aggregator change.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AggregatorChange {
    // A value should be written to storage.
    Write(u128),
    // A delta should be merged with the value from storage.
    Merge(DeltaOp),
    // A value should be deleted from the storage.
    Delete,
}

/// Represents changes made by all aggregators during this context. This change
/// set can be converted into appropriate `WriteSet` and `DeltaChangeSet` by the
/// user, e.g. VM session.
pub struct AggregatorChangeSet {
    pub changes: BTreeMap<AggregatorID, AggregatorChange>,
}

/// Native context that can be attached to VM `NativeContextExtensions`.
///
/// Note: table resolver is reused for fine-grained storage access.
#[derive(Tid)]
pub struct NativeAggregatorContext<'a> {
    txn_hash: [u8; 32],
    pub(crate) resolver: &'a dyn AggregatorResolver,
    pub(crate) aggregator_data: RefCell<AggregatorData>,
    pub(crate) aggregator_enabled: bool,
}

impl<'a> NativeAggregatorContext<'a> {
    /// Creates a new instance of a native aggregator context. This must be
    /// passed into VM session.
    pub fn new(
        txn_idx: TxnIndex,
        txn_hash: [u8; 32],
        resolver: &'a dyn AggregatorResolver,
        aggregator_enabled: bool,
    ) -> Self {
        Self {
            txn_hash,
            resolver,
            aggregator_data: RefCell::new(AggregatorData::new(((txn_idx + 1) as u64) << 32)),
            aggregator_enabled,
        }
    }

    /// Returns the hash of transaction associated with this context.
    pub fn txn_hash(&self) -> [u8; 32] {
        self.txn_hash
    }

    /// Returns all changes made within this context (i.e. by a single
    /// transaction).
    pub fn into_change_set(self) -> AggregatorChangeSet {
        let NativeAggregatorContext {
            aggregator_data, ..
        } = self;
        let (_, destroyed_aggregators, aggregators) = aggregator_data.into_inner().into();

        let mut changes = BTreeMap::new();

        // First, process all writes and deltas.
        for (id, aggregator) in aggregators {
            let (value, state, limit, history) = aggregator.into();

            let change = match state {
                AggregatorState::Data => AggregatorChange::Write(value),
                AggregatorState::PositiveDelta => {
                    // Aggregator state can be a delta only if aggregators are enabled.
                    assert!(self.aggregator_enabled);
                    let history = history.unwrap();
                    let plus = DeltaUpdate::Plus(value);
                    let delta_op =
                        DeltaOp::new(plus, limit, history.max_positive, history.min_negative);
                    AggregatorChange::Merge(delta_op)
                },
                AggregatorState::NegativeDelta => {
                    // Aggregator state can be a delta only if aggregators are enabled.
                    assert!(self.aggregator_enabled);
                    let history = history.unwrap();
                    let minus = DeltaUpdate::Minus(value);
                    let delta_op =
                        DeltaOp::new(minus, limit, history.max_positive, history.min_negative);
                    AggregatorChange::Merge(delta_op)
                },
            };
            changes.insert(id, change);
        }

        // Additionally, do not forget to delete destroyed values from storage.
        for id in destroyed_aggregators {
            changes.insert(id, AggregatorChange::Delete);
        }

        AggregatorChangeSet { changes }
    }
}

impl AggregatorChangeSet {
    pub fn squash(&mut self, other: Self) -> Result<(), VMStatus> {
        for (other_id, other_change) in other.changes {
            match self.changes.entry(other_id) {
                // If something was changed only in `other` session, add it.
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(other_change);
                },
                // Otherwise, we might need to aggregate deltas.
                btree_map::Entry::Occupied(mut entry) => {
                    use AggregatorChange::*;

                    let entry_mut = entry.get_mut();
                    match (*entry_mut, other_change) {
                        (Write(_) | Merge(_), Write(data)) => *entry_mut = Write(data),
                        (Write(_) | Merge(_), Delete) => *entry_mut = Delete,
                        (Write(data), Merge(delta)) => {
                            let new_data = delta
                                .apply_to(data)
                                .map_err(|e| e.finish(Location::Undefined).into_vm_status())?;
                            *entry_mut = Write(new_data);
                        },
                        (Merge(delta1), Merge(mut delta2)) => {
                            // `delta1` occurred before `delta2`, therefore we must ensure we merge the latter
                            // one to the initial delta.
                            delta2
                                .merge_with_previous_delta(delta1)
                                .map_err(|e| e.finish(Location::Undefined).into_vm_status())?;
                            *entry_mut = Merge(delta2)
                        },
                        // Hashing properties guarantee that aggregator keys should
                        // not collide, making this case impossible.
                        (Delete, _) => unreachable!("resource cannot be accessed after deletion"),
                    }
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use aptos_aggregator::{aggregator_id_for_test, AggregatorStore};
    use claims::{assert_matches, assert_ok};

    fn get_test_resolver() -> AggregatorStore {
        let mut state_view = AggregatorStore::default();
        state_view.set_from_id(aggregator_id_for_test(500), 150);
        state_view.set_from_id(aggregator_id_for_test(600), 100);
        state_view.set_from_id(aggregator_id_for_test(700), 200);
        state_view
    }

    // All aggregators are initialized deterministically based on their ID,
    // with the following spec.
    //
    //     +-------+---------------+-----------+-----+---------+
    //     |  key  | storage value |  create   | get | remove  |
    //     +-------+---------------+-----------+-----+---------+
    //     |  100  |               |   yes     | yes |   yes   |
    //     |  200  |               |   yes     | yes |         |
    //     |  300  |               |   yes     |     |   yes   |
    //     |  400  |               |   yes     |     |         |
    //     |  500  |               |           | yes |   yes   |
    //     |  600  |               |           | yes |         |
    //     |  700  |               |           | yes |         |
    //     |  800  |               |           |     |   yes   |
    //     +-------+---------------+-----------+-----+---------+
    fn test_set_up(context: &NativeAggregatorContext, aggregator_enabled: bool) {
        let mut aggregator_data = context.aggregator_data.borrow_mut();

        aggregator_data.create_new_aggregator(aggregator_id_for_test(100), 100);
        aggregator_data.create_new_aggregator(aggregator_id_for_test(200), 200);
        aggregator_data.create_new_aggregator(aggregator_id_for_test(300), 300);
        aggregator_data.create_new_aggregator(aggregator_id_for_test(400), 400);

        assert_ok!(aggregator_data.get_aggregator(
            aggregator_id_for_test(100),
            100,
            context.resolver,
            aggregator_enabled,
        ));
        assert_ok!(aggregator_data.get_aggregator(
            aggregator_id_for_test(200),
            200,
            context.resolver,
            aggregator_enabled,
        ));
        aggregator_data
            .get_aggregator(
                aggregator_id_for_test(500),
                500,
                context.resolver,
                aggregator_enabled,
            )
            .unwrap()
            .add(150)
            .unwrap();
        aggregator_data
            .get_aggregator(
                aggregator_id_for_test(600),
                600,
                context.resolver,
                aggregator_enabled,
            )
            .unwrap()
            .add(100)
            .unwrap();
        aggregator_data
            .get_aggregator(
                aggregator_id_for_test(700),
                700,
                context.resolver,
                aggregator_enabled,
            )
            .unwrap()
            .add(200)
            .unwrap();

        aggregator_data.remove_aggregator(aggregator_id_for_test(100));
        aggregator_data.remove_aggregator(aggregator_id_for_test(300));
        aggregator_data.remove_aggregator(aggregator_id_for_test(500));
        aggregator_data.remove_aggregator(aggregator_id_for_test(800));
    }

    #[test]
    fn test_into_change_set() {
        let resolver = get_test_resolver();
        let context = NativeAggregatorContext::new(30, [0; 32], &resolver, true);

        test_set_up(&context, true);
        let AggregatorChangeSet { changes } = context.into_change_set();

        assert!(!changes.contains_key(&aggregator_id_for_test(100)));
        assert_matches!(
            changes.get(&aggregator_id_for_test(200)).unwrap(),
            AggregatorChange::Write(0)
        );
        assert!(!changes.contains_key(&aggregator_id_for_test(300)));
        assert_matches!(
            changes.get(&aggregator_id_for_test(400)).unwrap(),
            AggregatorChange::Write(0)
        );
        assert_matches!(
            changes.get(&aggregator_id_for_test(500)).unwrap(),
            AggregatorChange::Delete
        );
        let delta_100 = DeltaOp::new(DeltaUpdate::Plus(100), 600, 100, 0);
        assert_eq!(
            *changes.get(&aggregator_id_for_test(600)).unwrap(),
            AggregatorChange::Merge(delta_100)
        );
        let delta_200 = DeltaOp::new(DeltaUpdate::Plus(200), 700, 200, 0);
        assert_eq!(
            *changes.get(&aggregator_id_for_test(700)).unwrap(),
            AggregatorChange::Merge(delta_200)
        );
        assert_matches!(
            changes.get(&aggregator_id_for_test(800)).unwrap(),
            AggregatorChange::Delete
        );
    }

    #[test]
    fn test_into_change_set_aggregator_disabled() {
        let resolver = get_test_resolver();
        let context = NativeAggregatorContext::new(30, [0; 32], &resolver, false);

        test_set_up(&context, false);
        let AggregatorChangeSet { changes } = context.into_change_set();

        assert!(!changes.contains_key(&aggregator_id_for_test(100)));
        assert_matches!(
            changes.get(&aggregator_id_for_test(200)).unwrap(),
            AggregatorChange::Write(0)
        );
        assert!(!changes.contains_key(&aggregator_id_for_test(300)));
        assert_matches!(
            changes.get(&aggregator_id_for_test(400)).unwrap(),
            AggregatorChange::Write(0)
        );
        assert_matches!(
            changes.get(&aggregator_id_for_test(500)).unwrap(),
            AggregatorChange::Delete
        );
        assert_matches!(
            changes.get(&aggregator_id_for_test(600)).unwrap(),
            AggregatorChange::Write(200)
        );
        assert_matches!(
            changes.get(&aggregator_id_for_test(700)).unwrap(),
            AggregatorChange::Write(400)
        );
        assert_matches!(
            changes.get(&aggregator_id_for_test(800)).unwrap(),
            AggregatorChange::Delete
        );
    }
}
