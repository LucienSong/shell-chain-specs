use shell_primitives::{Root, StateWitness, WitnessProofShape};

use crate::errors::{StateError, WitnessOrderingError};
use crate::keys::compare_state_keys;

pub const REFERENCE_BACKEND_PROOF_SHAPE_CONTEXT: &str =
    "reference backend derives proof paths locally and does not interpret committed proof bytes";

pub trait WitnessVerifier {
    fn verify_witness(
        &self,
        witness: &StateWitness,
        expected_state_root: &Root,
    ) -> Result<(), StateError>;

    fn verify_witnesses(
        &self,
        witnesses: &[StateWitness],
        expected_state_root: &Root,
    ) -> Result<(), StateError> {
        ensure_canonical_witness_order(witnesses)?;

        for witness in witnesses {
            self.verify_witness(witness, expected_state_root)?;
        }

        Ok(())
    }
}

pub fn ensure_canonical_witness_order(witnesses: &[StateWitness]) -> Result<(), StateError> {
    for (index, pair) in witnesses.windows(2).enumerate() {
        if !compare_state_keys(&pair[0].key, &pair[1].key).is_lt() {
            return Err(StateError::NonCanonicalWitnessOrdering(
                WitnessOrderingError {
                    index: index + 1,
                    context: "witness keys must be strictly increasing in canonical StateKey order",
                },
            ));
        }
    }

    Ok(())
}

pub fn ensure_reference_backend_proof_shape(witness: &StateWitness) -> Result<(), StateError> {
    match witness.proof_shape() {
        WitnessProofShape::ReferenceEmpty => Ok(()),
        WitnessProofShape::PlaceholderCommittedNodes => Err(StateError::UnsupportedProofShape(
            REFERENCE_BACKEND_PROOF_SHAPE_CONTEXT,
        )),
    }
}
