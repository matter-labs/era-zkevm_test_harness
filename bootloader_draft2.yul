// This bootloader is used to perform the single contract call with ability to specify the params/context values.
// Memory layout:
// 0-32: `to` address, lower 20 bytes.
// 32-64: `from` address, lower 20 bytes.
// 64-96: `is_constructor` flag.
// 96-128: `is_system` flag.
// 128-160: `extra_abi_data_1` the first extra abi param.
// 160-192: `extra_abi_data_2` the second extra abi param.
// 192-224: `extra_abi_data_3` the third extra abi param.
// 224-256: `context_u128_value` for the call, lower 16 bytes.
// 256-288: calldata length.
// 288-`288+calldata length`: calldata.

// TODO: think if success and return data check is needed
// `288+calldata length`-`288+calldata length`: expected return data length
// `288+calldata length`-`288+calldata length+expected return data length`: expected return data

object "CompilerTestsBootloader" {
    code {}
    object "CompilerTestsBootloader_deployed" {
        code {
            let success := mimicCallOnlyResult(
                mload(0),
                mload(32),
                256,
                mload(64),
                mload(96),
                mload(128),
                mload(160),
                mload(192),
            )

            /// @dev Returns an ABI that can be used for low-level
            /// invocations of calls and mimicCalls
            /// @param dataPtr The pointer to the calldata.
            /// @param gasPassed The number of gas to be passed with the call.
            /// @param shardId The shard id of the callee. Currently only `0` (Rollup) is supported.
            /// @param forwardingMode The mode of how the calldata is forwarded
            /// It is possible to either pass a pointer, slice of auxheap or heap. For the
            /// bootloader purposes using heap (0) is enough.
            /// @param isConstructorCall Whether the call should contain the isConstructor flag.
            /// @param isSystemCall Whether the call should contain the isSystemCall flag.
            /// @return ret The ABI
            function getFarCallABI(
                dataPtr,
                gasPassed,
                shardId,
                forwardingMode,
                isConstructorCall,
                isSystemCall
            ) -> ret {
                let dataStart := add(dataPtr, 32)
                let dataLength := mload(dataPtr)

                // Skip dataOffset and memoryPage, because they are always zeros
                ret := or(ret, shl(64, dataStart))
                ret := or(ret, shl(96, dataLength))

                ret := or(ret, shl(192, gasPassed))
                ret := or(ret, shl(224, forwardingMode))
                ret := or(ret, shl(232, shardId))
                ret := or(ret, shl(240, isConstructorCall))
                ret := or(ret, shl(248, isSystemCall))
            }

            /// @dev Does mimicCall without copying the returndata.
            /// @param to Who to call
            /// @param whoToMimic The `msg.sender` of the call
            /// @param data The pointer to the calldata
            /// @param isConstructor Whether the call should contain the isConstructor flag
            /// @param isSystemCall Whether the call should contain the isSystem flag.
            /// @param extraAbi1 The first extraAbiParam
            /// @param extraAbi2 The second extraAbiParam
            /// @param extraAbi3 The third extraAbiParam
            /// @return ret 1 if the call was successful, 0 otherwise.
            function mimicCallOnlyResult(
                to,
                whoToMimic,
                data,
                isConstructor,
                isSystemCall,
                extraAbi1,
                extraAbi2,
                extraAbi3
            ) -> ret {
                let farCallAbi := getFarCallABI(
                    data,
                    gas(),
                    // Only rollup is supported for now
                    0,
                    0,
                    isConstructor,
                    isSystemCall
                )

                ret := verbatim_7i_1o("system_mimic_call", to, whoToMimic, farCallAbi, extraAbi1, extraAbi2, extraAbi3, 0)
            }
        }
    }
}
