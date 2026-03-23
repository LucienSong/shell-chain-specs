use shell_primitives::{PrimitiveError, Root};
use shell_state::StateError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    TransactionRoot(PrimitiveError),
    StateTransition(StateError),
    Executor(&'static str),
    PostStateRootMismatch { expected: Root, actual: Root },
    ReceiptsRootMismatch { expected: Root, actual: Root },
}
