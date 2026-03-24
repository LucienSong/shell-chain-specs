use core::cell::RefCell;

use shell_primitives::Root;

use crate::accumulator::{InMemoryAccumulator, StateAccumulator};
use crate::errors::{RootContinuityError, StateError};
use crate::transition::{StatePatch, StateTransitionApplier, StateTransitionOutcome};

#[derive(Debug, Default)]
pub struct ReferenceStateApplier {
    accumulator: RefCell<InMemoryAccumulator>,
}

impl ReferenceStateApplier {
    pub fn new(accumulator: InMemoryAccumulator) -> Self {
        Self {
            accumulator: RefCell::new(accumulator),
        }
    }

    pub fn state_root(&self) -> Root {
        self.accumulator.borrow().state_root()
    }
}

impl StateTransitionApplier for ReferenceStateApplier {
    fn apply_transition(
        &self,
        pre_state_root: &Root,
        patch: &StatePatch,
    ) -> Result<StateTransitionOutcome, StateError> {
        let mut accumulator = self.accumulator.try_borrow_mut().map_err(|_| {
            StateError::Backend("reference state applier accumulator is already borrowed")
        })?;
        let actual_root = accumulator.state_root();

        if actual_root != *pre_state_root {
            return Err(StateError::RootContinuityMismatch(RootContinuityError {
                expected: *pre_state_root,
                actual: actual_root,
            }));
        }

        let post_state_root = accumulator.apply_transition(patch)?;
        Ok(StateTransitionOutcome { post_state_root })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use shell_primitives::{ExecutionAddress, StateKey};

    use super::*;

    #[test]
    fn reference_state_applier_applies_canonical_transitions_sequentially() {
        let address: ExecutionAddress = [0x42; 20];
        let first_key = StateKey::AccountHeader(address);
        let second_key = StateKey::StorageSlot {
            address,
            slot: [0x07; 32],
        };
        let applier = ReferenceStateApplier::default();

        let first = applier
            .apply_transition(
                &[0; 32],
                &StatePatch {
                    accesses: vec![first_key],
                    new_values: vec![vec![1, 2, 3]],
                },
            )
            .expect("empty reference applier should accept a matching initial root");

        let second = applier
            .apply_transition(
                &first.post_state_root,
                &StatePatch {
                    accesses: vec![second_key],
                    new_values: vec![vec![4, 5, 6]],
                },
            )
            .expect("follow-on transition should apply from the previous root");

        assert_eq!(applier.state_root(), second.post_state_root);
        assert_ne!(first.post_state_root, second.post_state_root);
    }

    #[test]
    fn reference_state_applier_rejects_root_continuity_mismatches() {
        let applier = ReferenceStateApplier::new(InMemoryAccumulator::new());
        let patch = StatePatch {
            accesses: vec![StateKey::RawTreeKey([0x11; 32])],
            new_values: vec![vec![0xAA]],
        };

        let err = applier
            .apply_transition(&[0xFF; 32], &patch)
            .expect_err("mismatched pre-state root must be rejected");

        assert_eq!(
            err,
            StateError::RootContinuityMismatch(RootContinuityError {
                expected: [0xFF; 32],
                actual: [0; 32],
            })
        );
        assert_eq!(applier.state_root(), [0; 32]);
    }

    #[test]
    fn reference_state_applier_preserves_state_when_patch_application_fails() {
        let address: ExecutionAddress = [0x24; 20];
        let key = StateKey::AccountHeader(address);
        let applier = ReferenceStateApplier::default();
        let established_root = applier
            .apply_transition(
                &[0; 32],
                &StatePatch {
                    accesses: vec![key.clone()],
                    new_values: vec![vec![9]],
                },
            )
            .expect("initial transition should establish state")
            .post_state_root;

        let err = applier
            .apply_transition(
                &established_root,
                &StatePatch {
                    accesses: vec![
                        StateKey::StorageSlot {
                            address,
                            slot: [0xFF; 32],
                        },
                        key,
                    ],
                    new_values: vec![vec![1], vec![2]],
                },
            )
            .expect_err("non-canonical patches should fail through the accumulator");

        assert_eq!(
            err,
            StateError::NonCanonicalWitnessOrdering(crate::WitnessOrderingError {
                index: 1,
                context: "access keys must be strictly increasing in canonical StateKey order",
            })
        );
        assert_eq!(applier.state_root(), established_root);
    }
}
