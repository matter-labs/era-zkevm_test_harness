use circuit_definitions::boojum::utils::PipeOp;
use circuit_definitions::ethereum_types::H160;
use circuit_definitions::zk_evm::vm_state::ErrorFlags;
use circuit_definitions::zk_evm::vm_state::PrimitiveValue;
use std::fmt;
use std::str;
use std::usize;
use zkevm_assembly::zkevm_opcode_defs::decoding::{
    AllowedPcOrImm, EncodingModeProduction, VmEncodingMode,
};
use zkevm_assembly::zkevm_opcode_defs::AddOpcode;
use zkevm_assembly::zkevm_opcode_defs::DecodedOpcode;
use zkevm_assembly::zkevm_opcode_defs::NopOpcode;
use zkevm_assembly::zkevm_opcode_defs::Opcode;
use zkevm_assembly::zkevm_opcode_defs::PtrOpcode;
use zkevm_assembly::zkevm_opcode_defs::RetOpcode;

use crate::ethereum_types::U256;
use crate::tests::storage::RefundController;
use crate::tests::storage::StorageRefund;
use crate::zk_evm::reference_impls::memory::SimpleMemory;
use crate::zk_evm::tracing::*;

use crate::tests::utils::preprocess_asm::EXCEPTION_PREFIX;
use crate::tests::utils::preprocess_asm::PRINT_PREFIX;
use crate::tests::utils::preprocess_asm::PRINT_PTR_PREFIX;
use crate::tests::utils::preprocess_asm::PRINT_REG_PREFIX;
use crate::tests::utils::preprocess_asm::STORAGE_REFUND_COLD_PREFIX;
use crate::tests::utils::preprocess_asm::STORAGE_REFUND_WARM_PREFIX;

#[derive(Debug, Clone, PartialEq, Default)]
enum TracerState {
    /// will try to parse next value from VM as command
    #[default]
    ExpectingCommand,
    /// will print next value from VM
    ExpectingValueToPrint(ExpectedValueType),
}

#[derive(Debug, Clone, PartialEq)]
enum ExpectedValueType {
    /// expecting raw register value
    Register,
    /// expecting fat pointer
    Pointer,
}

#[derive(Debug, Clone, Default)]
pub struct OutOfCircuitException<const N: usize, E: VmEncodingMode<N>> {
    pub exception_message: Option<String>,
    pub opcode: Option<DecodedOpcode<N, E>>,
    pub contract_address: Option<H160>,
}

impl<const N: usize, E: VmEncodingMode<N>> OutOfCircuitException<N, E> {
    pub fn new(
        exception_message: Option<String>,
        opcode: Option<DecodedOpcode<N, E>>,
        contract_address: Option<H160>,
    ) -> Self {
        Self {
            exception_message,
            opcode,
            contract_address,
        }
    }
}

impl<const N: usize, E: VmEncodingMode<N>> fmt::Display for OutOfCircuitException<N, E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        if let Some(message) = &self.exception_message {
            write!(f, "{}", message)?
        };

        if let Some(address) = &self.contract_address {
            write!(f, "\nIn contract: {:?}", address)?
        };

        if let Some(opcode) = &self.opcode {
            write!(f, "\nFailed opcode:\n{}", opcode)?
        };

        Ok(())
    }
}

/// Tracks prints and exceptions during VM execution cycles.
#[derive(Debug, Clone)]
pub struct TestingTracer<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    /// the last uncatched exception
    pub exception: Option<OutOfCircuitException<N, E>>,
    /// the inner state, affects the interpretation of values from the VM
    tracer_state: TracerState,
    /// stores pending messages that should be printed
    message_buffer: Option<String>,
    /// Optional controller to set the type/amount of refund for storage slot access
    storage_refund_controller: Option<RefundController>,
}

/// TestingTracer interprets valid x values in `add x r0 r0` and `ptr.add x r0 r0` instructions as commands to execute.
/// Commands have following structure: "PREFIX:arg"
/// Allowed commands:
/// "EXCEPTION_PREFIX:<text>" - save <text> in exception_message field
/// "PRINT_PREFIX:<text>" - print <text> in the console
/// "PRINT_REG_PREFIX:" - print raw "x" value of next command in the console
/// "PRINT_PTR_PREFIX:" - print raw "x" pointer value of next command in the console (currently same result as previous command)
/// "STORAGE_REFUND_COLD_PREFIX:" - If used in conjuction with RefundController from InMemoryCustomRefundStorage::create_refund_controller will set the next
///                                 storage slot access refund to Cold
/// STORAGE_REFUND_WARM_PREFIX:<u32> - If used in conjuction with RefundController from InMemoryCustomRefundStorage::create_refund_controller will set the next
///                                    storage slot access refund to Warm with the specified amount of ergs
impl<const N: usize, E: VmEncodingMode<N>> TestingTracer<N, E> {
    pub fn new(storage_refund_controller: Option<RefundController>) -> Self {
        Self {
            exception: None,
            tracer_state: TracerState::default(),
            message_buffer: None,
            storage_refund_controller,
        }
    }

    fn reset_exception(&mut self) {
        self.exception = None;
    }

    fn set_exception(
        &mut self,
        message: Option<String>,
        opcode: Option<DecodedOpcode<N, E>>,
        contract_address: Option<H160>,
    ) {
        self.exception = Some(OutOfCircuitException::new(
            message,
            opcode,
            contract_address,
        ));
    }

    fn execute_print(&self, message: &str) {
        println!("{}", message);
    }

    fn execute_print_from_register(&self, val: PrimitiveValue) {
        if let TracerState::ExpectingCommand = self.tracer_state {
            panic!("Unexpected execute_print_from_register command");
        }

        if let Some(message) = &self.message_buffer {
            println!("{message} {}", val.value);
        } else {
            println!("{}", val.value);
        }
    }

    fn set_storage_refund(&self, storage_refund_type: StorageRefund, value: &str) {
        if let Some(controller) = &self.storage_refund_controller {
            match storage_refund_type {
                StorageRefund::Cold => controller.set_storage_refund(StorageRefund::Cold, 0u32),
                StorageRefund::Warm => {
                    let refund_value =
                        u32::from_str_radix(value, 10).expect("Refund parsing error");

                    controller.set_storage_refund(StorageRefund::Warm, refund_value);
                }
            }
        }
    }

    fn handle_value_from_vm(&mut self, value: PrimitiveValue) -> TracerState {
        let mut new_state = TracerState::ExpectingCommand;
        let mut new_message_buffer_value = None;

        match self.tracer_state {
            TracerState::ExpectingValueToPrint(..) => {
                self.execute_print_from_register(value);
            }
            TracerState::ExpectingCommand => {
                if let Some((command_prefix, arg)) = self.parse_command_from_register(value) {
                    match command_prefix.as_str() {
                        EXCEPTION_PREFIX => {
                            self.set_exception(Some(arg), None, None);
                        }
                        PRINT_PREFIX => {
                            self.execute_print(&arg);
                        }
                        PRINT_REG_PREFIX => {
                            if !arg.is_empty() {
                                new_message_buffer_value = Some(arg);
                            }
                            new_state =
                                TracerState::ExpectingValueToPrint(ExpectedValueType::Register);
                        }
                        PRINT_PTR_PREFIX => {
                            if !arg.is_empty() {
                                new_message_buffer_value = Some(arg);
                            }
                            new_state =
                                TracerState::ExpectingValueToPrint(ExpectedValueType::Pointer);
                        }
                        STORAGE_REFUND_COLD_PREFIX => {
                            self.set_storage_refund(StorageRefund::Cold, &arg);
                        }
                        STORAGE_REFUND_WARM_PREFIX => {
                            self.set_storage_refund(StorageRefund::Warm, &arg);
                        }
                        _ => {
                            // ignore invalid command
                        }
                    }
                }
            }
        }

        self.message_buffer = new_message_buffer_value;
        new_state
    }

    /// Returns (command_prefix, arg) if parsed command successfully
    /// None otherwise
    fn parse_command_from_register(&self, val: PrimitiveValue) -> Option<(String, String)> {
        if val.value == U256::from(0) {
            return None;
        }

        let mut bytes: [u8; 32] = [0; 32];
        val.value.to_big_endian(&mut bytes);

        if let Ok(message) = std::str::from_utf8(&bytes) {
            let message_trimmed = message.trim_matches(char::from(0));

            for prefix in [
                EXCEPTION_PREFIX,
                PRINT_PREFIX,
                PRINT_REG_PREFIX,
                PRINT_PTR_PREFIX,
                STORAGE_REFUND_COLD_PREFIX,
                STORAGE_REFUND_WARM_PREFIX,
            ] {
                if message_trimmed.starts_with(prefix) {
                    let arg = message_trimmed.strip_prefix(prefix).unwrap();
                    return Some((prefix.to_owned(), arg.to_owned()));
                }
            }
        }

        None
    }
}

impl<const N: usize, E: VmEncodingMode<N>> Tracer<N, E> for TestingTracer<N, E> {
    type SupportedMemory = SimpleMemory;
    const CALL_BEFORE_EXECUTION: bool = true;
    const CALL_AFTER_DECODING: bool = true;

    #[inline]
    fn before_decoding(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        _memory: &Self::SupportedMemory,
    ) {
    }

    fn after_decoding(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        data: AfterDecodingData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        if let Opcode::Ret(RetOpcode::Panic | RetOpcode::Revert) =
            data.opcode_masked.inner.variant.opcode
        {
            if let Some(exception) = &self.exception {
                if exception.opcode.is_some() {
                    return;
                }
            }

            let (raw_opcode, _) =
                E::parse_preliminary_variant_and_absolute_number(data.raw_opcode_unmasked);

            let message = if data.error_flags_accumulated.is_empty() {
                if let Some(exception) = &self.exception {
                    exception.exception_message.clone()
                } else {
                    None
                }
            } else {
                // check for built-in panics
                let (panic_name, _) = data.error_flags_accumulated.iter_names().nth(0).unwrap();
                Some(panic_name.to_owned())
            };

            self.set_exception(
                message,
                Some(raw_opcode),
                Some(state.vm_local_state.callstack.current.this_address),
            );
        };
    }

    fn before_execution(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        data: BeforeExecutionData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
        let inner_opcode = data.opcode.inner.variant.opcode;

        // Propagate error message if Nop, ret.panic, ret.revert; reset otherwise
        match inner_opcode {
            Opcode::Nop(NopOpcode) => {}
            Opcode::Ret(RetOpcode::Panic | RetOpcode::Revert) => {}
            _ => {
                self.reset_exception();
            }
        }

        // check if we have a valid command for TestingTracer and execute the command if any.
        // commands always have r0 as src1 and dst0
        let new_state = if data.opcode.src1_reg_idx == 0 && data.opcode.dst0_reg_idx == 0 {
            match inner_opcode {
                Opcode::Add(AddOpcode::Add) | Opcode::Ptr(PtrOpcode::Add) => {
                    // `add x r0 r0` is used to pass "x" to TestingTracer
                    // `ptr.add x r0 r0` is used to pass "x" pointer to TestingTracer
                    self.handle_value_from_vm(data.src0_value)
                }
                _ => TracerState::ExpectingCommand,
            }
        } else {
            TracerState::ExpectingCommand
        };

        self.tracer_state = new_state;

        // pc 0 means VM finished without any panics
        if data.new_pc == E::PcOrImm::from_u64_clipped(0) {
            self.reset_exception();
        }
    }

    #[inline]
    fn after_execution(
        &mut self,
        _state: VmLocalStateData<'_, N, E>,
        _data: AfterExecutionData<N, E>,
        _memory: &Self::SupportedMemory,
    ) {
    }
}
