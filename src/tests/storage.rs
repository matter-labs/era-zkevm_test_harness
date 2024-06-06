use std::{cell::RefCell, rc::Rc};

use circuit_definitions::zk_evm::{
    abstractions::{Storage, StorageAccessRefund},
    aux_structures::{LogQuery, PubdataCost, Timestamp},
    testing::storage::InMemoryStorage,
};

/// Enum holding the types of storage refunds
#[derive(Debug, Copy, Clone)]
pub(crate) enum StorageRefund {
    Cold,
    Warm,
}

/// Used to control updates to the slot refunds within InMemoryCustomRefundStorage
#[derive(Debug, Clone)]
pub struct RefundController {
    slot_refund: Rc<RefCell<(StorageRefund, u32)>>,
}

impl RefundController {
    pub fn new(slot_refund: Rc<RefCell<(StorageRefund, u32)>>) -> Self {
        Self { slot_refund }
    }

    pub fn set_storage_refund(&self, storage_refund_type: StorageRefund, refund_value: u32) {
        let new_value = if let StorageRefund::Warm = storage_refund_type {
            refund_value
        } else {
            0
        };
        *self.slot_refund.borrow_mut() = (storage_refund_type, new_value);
    }
}

/// Wrapper around the base InMemoryStorage implementation that allows for the setting of custom refunds for more
/// control over storage slot refund testing.
#[derive(Debug, Clone)]
pub struct InMemoryCustomRefundStorage {
    pub storage: InMemoryStorage,
    pub slot_refund: Rc<RefCell<(StorageRefund, u32)>>,
}

impl InMemoryCustomRefundStorage {
    pub fn new() -> Self {
        Self {
            storage: InMemoryStorage::new(),
            slot_refund: Rc::new(RefCell::new((StorageRefund::Cold, 0u32))),
        }
    }

    pub fn create_refund_controller(&self) -> RefundController {
        RefundController::new(Rc::clone(&self.slot_refund))
    }
}

impl Storage for InMemoryCustomRefundStorage {
    #[track_caller]
    fn get_access_refund(
        &mut self, // to avoid any hacks inside, like prefetch
        _monotonic_cycle_counter: u32,
        _partial_query: &LogQuery,
    ) -> StorageAccessRefund {
        let storage_refund = self.slot_refund.borrow();
        match storage_refund.0 {
            StorageRefund::Cold => dbg!(StorageAccessRefund::Cold),
            StorageRefund::Warm => dbg!(StorageAccessRefund::Warm {
                ergs: storage_refund.1
            }),
        }
    }

    #[track_caller]
    fn execute_partial_query(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
    ) -> (LogQuery, PubdataCost) {
        self.storage
            .execute_partial_query(monotonic_cycle_counter, query)
    }

    #[track_caller]
    fn start_frame(&mut self, timestamp: Timestamp) {
        self.storage.start_frame(timestamp)
    }

    #[track_caller]
    fn finish_frame(&mut self, timestamp: Timestamp, panicked: bool) {
        self.storage.finish_frame(timestamp, panicked)
    }

    #[track_caller]
    fn start_new_tx(&mut self, timestamp: Timestamp) {
        self.storage.start_new_tx(timestamp)
    }
}
