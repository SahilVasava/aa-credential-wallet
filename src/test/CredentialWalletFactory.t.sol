// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../CredentialWalletFactory.sol";
import "./state/CredentialWalletFactoryState.t.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract CredentialWalletFactoryTest is CredentialWalletFactoryState {

    function setUp() public override {
        super.setUp();
    }

    function testCredWFactory_shouldCreateAccount() public {
        address owner = vm.addr(2);
        uint256 salt = 123;
        address addr = credentialWalletFactory.getAddress(owner, salt);
        CredentialWallet credentialWallet = credentialWalletFactory.createAccount(owner, salt);
        assert(credentialWallet.owner() == owner);
        assert(credentialWallet.entryPoint() == IEntryPoint(entryPoint));
        assert(address(credentialWallet) == addr);
    }

    function testCredWFactory_checkDeployer() public {
        address owner = vm.addr(2);
        uint256 salt = 123;
        address target = credentialWalletFactory.getAddress(owner, salt);
        assert(address(target).code.length <= 2);
        credentialWalletFactory.createAccount(owner, salt);
        assert(address(target).code.length > 2);
    }
}