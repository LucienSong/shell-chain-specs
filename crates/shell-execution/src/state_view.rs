use shell_primitives::{Root, StateMetadata};

pub trait ExecutionStateView: StateMetadata {
    fn state_root(&self) -> Root;
}
