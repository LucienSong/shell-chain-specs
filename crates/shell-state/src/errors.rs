use shell_primitives::Root;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessOrderingError {
    pub index: usize,
    pub context: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootContinuityError {
    pub expected: Root,
    pub actual: Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InvalidStateKeyEncoding(&'static str),
    NonCanonicalWitnessOrdering(WitnessOrderingError),
    RootContinuityMismatch(RootContinuityError),
    WitnessVerificationFailed(&'static str),
    UnsupportedProofShape(&'static str),
    TransitionShapeMismatch { accesses: usize, new_values: usize },
    Backend(&'static str),
}
