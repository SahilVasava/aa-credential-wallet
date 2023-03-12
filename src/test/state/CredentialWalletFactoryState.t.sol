// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../../CredentialWalletFactory.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

abstract contract CredentialWalletFactoryState is Test {
    address entryPoint;
    CredentialWalletFactory credentialWalletFactory;

    function setUp() public virtual {
        entryPoint = vm.addr(1);
        credentialWalletFactory = new CredentialWalletFactory(
            IEntryPoint(entryPoint)
        );
    }
}
