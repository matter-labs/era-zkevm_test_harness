use std::ops::RangeInclusive;

use super::*;
use zk_evm::vm_state::VmLocalState;

use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct VmSnapshot {
    pub local_state: VmLocalState,
    pub at_cycle: u32,
}

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct VmTransition {
    pub from_state: VmLocalState,
    pub to_state: VmLocalState,
    pub cycles_range_exclusive: std::ops::Range<u32>,
}
