// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

library UserOpUtils {
    function getUserOpHash(UserOperation memory op, address entryPoint)
        public
        view
        returns (bytes32)
    {
        bytes32 _userOpHash = keccak256(packUserOp(op, true));
        bytes memory enc = abi.encode(_userOpHash, entryPoint, block.chainid);
        return keccak256(enc);
    }

    function packUserOp(UserOperation memory op, bool forSignature)
        public
        pure
        returns (bytes memory)
    {
        if (forSignature) {
            // lighter signature scheme (must match UserOperation#pack): do encode a zero-length signature, but strip afterwards the appended zero-length value
            bytes memory encoded = abi.encode(
                op.sender,
                op.nonce,
                op.initCode,
                op.callData,
                op.callGasLimit,
                op.verificationGasLimit,
                op.preVerificationGas,
                op.maxFeePerGas,
                op.maxPriorityFeePerGas,
                op.paymasterAndData
            );
            bytes memory signature = abi.encodePacked(bytes32(0));
            bytes memory result = new bytes(encoded.length + signature.length);
            assembly {
                let encodedLength := mload(encoded)
                let signatureLength := mload(signature)
                let resultLength := add(encodedLength, signatureLength)
                mstore(result, resultLength)
                mstore(add(result, 0x20), encodedLength)
                mstore(add(result, add(0x20, encodedLength)), signatureLength)
                mstore(add(add(result, 0x40), encodedLength), encoded)
                mstore(
                    add(add(result, add(0x40, encodedLength)), signatureLength),
                    signature
                )
            }
            return result;
        } else {
            // Full scheme with signature
            bytes memory encoded = abi.encode(
                op.sender,
                op.nonce,
                op.initCode,
                op.callData,
                op.callGasLimit,
                op.verificationGasLimit,
                op.preVerificationGas,
                op.maxFeePerGas,
                op.maxPriorityFeePerGas,
                op.paymasterAndData,
                op.signature
            );
            return abi.encodePacked(keccak256(encoded));
        }
    }
}
