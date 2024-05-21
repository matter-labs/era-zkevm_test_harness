use circuit_definitions::zk_evm::vm_state::ErrorFlags;
use zkevm_assembly::zkevm_opcode_defs::AddOpcode;
use zkevm_assembly::zkevm_opcode_defs::NopOpcode;
use zkevm_assembly::zkevm_opcode_defs::Opcode;
use zkevm_assembly::zkevm_opcode_defs::PtrOpcode;
use zkevm_assembly::zkevm_opcode_defs::RetOpcode;

use crate::ethereum_types::U256;
use crate::zk_evm::opcodes::DecodedOpcode;
use crate::zk_evm::reference_impls::memory::SimpleMemory;
use crate::zk_evm::tracing::*;

use crate::asm_templates::EXCEPTION_PREFIX;
use crate::asm_templates::PRINT_PREFIX;
use crate::asm_templates::PRINT_REG_PREFIX;

#[derive(Debug, Clone)]
pub struct TestingTracer {
    expecting_register_value: bool,

    pub has_exception: bool,
    pub exception_message: String,
}

impl TestingTracer {
    pub fn new() -> Self {
        Self {
            expecting_register_value: false,
            has_exception: false,
            exception_message: "".to_owned(),
        }
    }

    fn reset_exception(&mut self) {
        self.has_exception = false;
        self.exception_message = "".to_owned();
    }

    fn update_exception_message(&mut self, message: &str) {
        if message.starts_with(EXCEPTION_PREFIX) {
            self.exception_message = message[2..].to_owned();
        } else {
            self.reset_exception();
        }
    }

    fn update_expecting_register_value(&mut self, message: &str) {
        if message.starts_with(PRINT_REG_PREFIX) {
            self.expecting_register_value = true;
        } else {
            self.expecting_register_value = false;
        }
    }
}

impl Tracer for TestingTracer {
    type SupportedMemory = SimpleMemory;
    const CALL_BEFORE_EXECUTION: bool = true;
    const CALL_AFTER_DECODING: bool = true;

    #[inline]
    fn before_decoding(&mut self, _state: VmLocalStateData<'_>, _memory: &Self::SupportedMemory) {}

    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: AfterDecodingData,
        _memory: &Self::SupportedMemory,
    ) {
        if _data.error_flags_accumulated.is_empty() {
            return;
        }

        self.has_exception = true;

        if _data
            .error_flags_accumulated
            .contains(ErrorFlags::NOT_ENOUGH_ERGS)
        {
            self.exception_message = "NOT_ENOUGH_ERGS".to_owned();
        }
        if _data
            .error_flags_accumulated
            .contains(ErrorFlags::INVALID_OPCODE)
        {
            self.exception_message = "INVALID OPCODE".to_owned();
        }
        if _data
            .error_flags_accumulated
            .contains(ErrorFlags::PRIVILAGED_ACCESS_NOT_FROM_KERNEL)
        {
            self.exception_message = "PRIVILAGED_ACCESS_NOT_FROM_KERNEL".to_owned();
        }
        if _data
            .error_flags_accumulated
            .contains(ErrorFlags::WRITE_IN_STATIC_CONTEXT)
        {
            self.exception_message = "WRITE_IN_STATIC_CONTEXT".to_owned();
        }
        if _data
            .error_flags_accumulated
            .contains(ErrorFlags::CALLSTACK_IS_FULL)
        {
            self.exception_message = "CALLSTACK_IS_FULL".to_owned();
        }
    }

    fn before_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: BeforeExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
        /*
        println!("{}", _data.opcode);
        println!("New pc: {}", _data.new_pc);
        println!("Val: {}", _data.src0_value.value);
        println!("");
        */
        let inner_opcode = _data.opcode.inner.variant.opcode;

        match inner_opcode {
            Opcode::Ret(RetOpcode::Panic) => {
                if self.exception_message != "" {
                    self.has_exception = true;
                }
            }
            Opcode::Add(AddOpcode::Add) => {
                // `add x r0 r0` is used as "print" statement
                if _data.opcode.dst0_reg_idx == 0 {
                    if self.expecting_register_value {
                        println!("{}", _data.src0_value.value);
                        self.expecting_register_value = false;
                    } else {
                        let message = check_for_print(_data.src0_value.value);
                        self.update_exception_message(&message); // try to parse error message
                        self.update_expecting_register_value(&message); // try to parse "expect_register" command
                    }
                }
            }
            Opcode::Ptr(PtrOpcode::Add) => {
                // `ptr.add x r0 r0` is used as "print" statement for pointers
                if _data.opcode.dst0_reg_idx == 0 {
                    if self.expecting_register_value {
                        println!("{}", _data.src0_value.value);
                    }
                }
                self.reset_exception();
            }
            Opcode::Nop(NopOpcode) => {}
            _ => {
                self.reset_exception();
            }
        };

        if inner_opcode != Opcode::Add(AddOpcode::Add)
            && inner_opcode != Opcode::Ptr(PtrOpcode::Add)
        {
            self.expecting_register_value = false;
        }

        // pc 0 means VM finished without any panics
        if _data.new_pc == 0 {
            self.reset_exception();
        }
    }

    #[inline]
    fn after_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: AfterExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
    }
}

fn check_for_print(val: U256) -> String {
    let print_line = decode_message_from_register(val);
    if print_line.starts_with(PRINT_PREFIX) {
        println!("{}", print_line[2..].to_owned());
    }

    print_line
}

fn decode_message_from_register(val: U256) -> String {
    if val == U256::from(0) {
        return "".to_owned();
    }

    let bytes: &mut [u8; 32] = &mut [0; 32];
    val.to_big_endian(bytes);

    match std::str::from_utf8(bytes) {
        Ok(message) => {
            let message_trimed = message.trim_matches(char::from(0));

            if [EXCEPTION_PREFIX, PRINT_PREFIX, PRINT_REG_PREFIX]
                .iter()
                .any(|s| message_trimed.starts_with(*s))
            {
                return message_trimed.to_owned();
            }
        }
        Err(_) => {}
    };
    return "".to_owned();
}
