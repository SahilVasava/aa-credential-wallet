// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "./CredentialWalletFactoryState.t.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

abstract contract CredentialWalletState is CredentialWalletFactoryState {
    UserOperation defaultsForUserOp =
        UserOperation({
            sender: address(0),
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            callGasLimit: 0,
            verificationGasLimit: 100000, // default verification gas. will add create2 cost (3200+200*length) if initCode exists
            preVerificationGas: 21000, // should also cover calldata cost.
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 1e9,
            paymasterAndData: hex"",
            signature: hex""
        });

    function setUp() public override virtual {
        super.setUp();
    }
}
