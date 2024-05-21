use circuit_definitions::zk_evm::vm_state::ErrorFlags;
use circuit_definitions::zk_evm::vm_state::PrimitiveValue;
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
use crate::asm_templates::PRINT_PTR_PREFIX;
use crate::asm_templates::PRINT_REG_PREFIX;

/// Tracks prints and exceptions during VM execution cycles.
#[derive(Debug, Clone)]
pub struct TestingTracer {
    /// the last uncatched exception message
    pub exception_message: Option<String>,
    /// true if next command should be interpreted as printable value and printed
    expecting_register_value: bool,
}

/// TestingTracer interprets valid x values in `add x r0 r0` and `ptr.add x r0 r0` instructions as commands to execute.
/// Commands have following structure: "PREFIX:arg"
/// Allowed commands:
/// "EXCEPTION_PREFIX:<text>" - save <text> in exception_message field
/// "PRINT_PREFIX:<text>" - print <text> in the console
/// "PRINT_REG_PREFIX:" - print raw "x" value of next command in the console
/// "PRINT_PTR_PREFIX:" - print raw "x" pointer value of next command in the console (currently same result as previous command)
impl TestingTracer {
    pub fn new() -> Self {
        Self {
            exception_message: None,
            expecting_register_value: false,
        }
    }

    fn reset_exception(&mut self) {
        self.exception_message = None;
    }

    fn set_exception_message(&mut self, message: &str) {
        self.exception_message = Some(message.to_owned());
    }

    fn execute_print(&mut self, message: &str) {
        println!("{}", message);
    }

    fn execute_print_from_register(&mut self, val: PrimitiveValue) {
        assert!(
            self.expecting_register_value,
            "Unexpected print_from_register command"
        );
        self.expecting_register_value = false;
        println!("{}", val.value);
    }

    fn parse_command_from_register(
        &mut self,
        val: PrimitiveValue,
    ) -> (Option<String>, Option<String>) {
        if val.value == U256::from(0) {
            return (None, None);
        }

        let bytes: &mut [u8; 32] = &mut [0; 32];
        val.value.to_big_endian(bytes);

        if let Ok(message) = std::str::from_utf8(bytes) {
            let message_trimmed = message.trim_matches(char::from(0));

            for prefix in [
                EXCEPTION_PREFIX,
                PRINT_PREFIX,
                PRINT_REG_PREFIX,
                PRINT_PTR_PREFIX,
            ]
            .iter()
            {
                if message_trimmed.starts_with(*prefix) {
                    let arg = message_trimmed.strip_prefix(prefix).unwrap();
                    return (Some((*prefix).to_string()), Some(arg.to_owned()));
                }
            }
        }

        return (None, None);
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
        // check for built-in panics
        if !_data.error_flags_accumulated.is_empty() {
            // last accumulated panic will be used as exception_message
            for (panic, _) in _data.error_flags_accumulated.iter_names() {
                self.exception_message = Some(panic.to_owned());
            }
        }
    }

    fn before_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: BeforeExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
        let inner_opcode = _data.opcode.inner.variant.opcode;

        // Propagate error message if Nop, ret.panic, ret.revert; reset otherwise
        match inner_opcode {
            Opcode::Nop(NopOpcode) => {}
            Opcode::Ret(RetOpcode::Panic) => {}
            Opcode::Ret(RetOpcode::Revert) => {}
            _ => {
                self.reset_exception();
            }
        }

        // Try to execute commands
        // commands always have r0 as src1 and dst0
        if _data.opcode.src1_reg_idx == 0 && _data.opcode.dst0_reg_idx == 0 {
            match inner_opcode {
                Opcode::Add(AddOpcode::Add) => {
                    // `add x r0 r0` is used as "execute x command" statement
                    if self.expecting_register_value {
                        self.execute_print_from_register(_data.src0_value);
                    } else {
                        if let (Some(command_prefix), Some(arg)) =
                            self.parse_command_from_register(_data.src0_value)
                        {
                            if command_prefix == EXCEPTION_PREFIX {
                                self.set_exception_message(&arg);
                            } else if command_prefix == PRINT_PREFIX {
                                self.execute_print(&arg);
                            } else if command_prefix == PRINT_REG_PREFIX {
                                self.expecting_register_value = true;
                            } else if command_prefix == PRINT_PTR_PREFIX {
                                self.expecting_register_value = true;
                            }
                        }
                    }
                }
                Opcode::Ptr(PtrOpcode::Add) => {
                    // `ptr.add x r0 r0` is used as "print" statement for pointers
                    if self.expecting_register_value {
                        self.execute_print_from_register(_data.src0_value);
                    }
                }
                _ => {
                    self.expecting_register_value = false;
                }
            };
        } else {
            // not a command
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
