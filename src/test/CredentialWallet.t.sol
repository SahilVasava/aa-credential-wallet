// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../CredentialWallet.sol";
import "./state/CredentialWalletFactoryState.t.sol";
import "./state/CredentialWalletState.t.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "./utils/UserOpUtils.sol";

contract CredentialWalletTest is CredentialWalletFactoryState {
    function setUp() public override {
        super.setUp();
        // vm.deal(address(credentialWalletFactory), 0.2 ether);
    }

    function testCredWallet_OthersShouldBeAbleToCallTransfer() public {
        address randomOwner = vm.addr(2);
        address dest = vm.addr(3);
        address otherUser = vm.addr(4);
        CredentialWallet _credentialWallet = credentialWalletFactory
            .createAccount(randomOwner, 123);
        vm.prank(otherUser);
        vm.expectRevert(CredentialWallet.NotOwnerOrEntryPoint.selector);
        _credentialWallet.execute(dest, 1 ether, "0x");
    }

    function testCredWallet_OwnerShouldBeAbleToCallTransfer() public {
        address randomOwner = vm.addr(2);
        address dest = vm.addr(3);
        CredentialWallet _credentialWallet = credentialWalletFactory
            .createAccount(randomOwner, 123);
        vm.prank(randomOwner);
        vm.deal(address(_credentialWallet), 2 ether);
        _credentialWallet.execute(dest, 1 ether, "0x");
        assertEq(dest.balance, 1 ether);
    }
}

contract CredentialWalletUserOpTest is CredentialWalletState {
    using ECDSA for bytes32;
    CredentialWallet credentialWallet;
    address accountOwner;
    uint256 accountOwnerKey;
    UserOperation userOp;
    uint256 actualGasPrice = 1e9;
    uint256 preBalance;
    uint256 expectedPay;
    bytes32 userOpHash;

    function setUp() public virtual override {
        super.setUp();
        (accountOwner, accountOwnerKey) = makeAddrAndKey("accountOwner");
        credentialWallet = credentialWalletFactory.createAccount(
            accountOwner,
            123
        );
        vm.deal(address(credentialWallet), 0.2 ether);
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 maxFeePerGas = 3e9;
        userOp.sender = address(credentialWallet);
        userOp = defaultsForUserOp;
        userOp.callGasLimit = callGasLimit;
        userOp.verificationGasLimit = verificationGasLimit;
        userOp.maxFeePerGas = maxFeePerGas;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            accountOwnerKey,
            UserOpUtils
                .getUserOpHash(userOp, entryPoint)
                .toEthSignedMessageHash()
        );
        userOp.signature = abi.encodePacked(r, s, v);
        userOpHash = UserOpUtils.getUserOpHash(userOp, entryPoint);
        expectedPay = actualGasPrice * (callGasLimit + verificationGasLimit);
        preBalance = address(credentialWallet).balance;
        vm.prank(entryPoint);
        credentialWallet.validateUserOp{gas: actualGasPrice}(
            userOp,
            userOpHash,
            expectedPay
        );
    }

    function testCredWalletUserOp_shouldPay() public {
        assertEq(preBalance - address(credentialWallet).balance, expectedPay);
    }

    function testCredWalletUserOp_shouldIncrementNonce() public {
        assertEq(credentialWallet.nonce(), 1);
    }

    function testCredWalletUserOp_shouldRevertSameTxOnNonceError() public {
        vm.prank(entryPoint);
        vm.expectRevert(CredentialWallet.InvalidNonce.selector);
        credentialWallet.validateUserOp(userOp, userOpHash, expectedPay);
    }

    function testCredWalletUserOp_shouldRevertOnWrongSig() public {
        vm.prank(entryPoint);
        userOp.nonce = 1;
        uint256 ret = credentialWallet.validateUserOp(
            userOp,
            bytes32(0),
            expectedPay
        );
        assert(ret == 1);
    }
}

contract CredentialWalletMultiWalletTest is CredentialWalletUserOpTest {
    using ECDSA for bytes32;

    function setUp() public override {
        super.setUp();
    }

    function testCredWalletMultiWallets_nonOwnerCannotAddWallet() public {
        (address randomUser, uint256 randomUserKey) = makeAddrAndKey(
            "randomUser"
        );
        bytes32 hash = keccak256(
            abi.encode(address(credentialWallet), block.chainid)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            randomUserKey,
            hash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.prank(randomUser);
        vm.expectRevert(CredentialWallet.NotOwner.selector);
        credentialWallet.addWallet(randomUser, signature);
    }

    function testCredWalletMultiWallets_addWalletInvalidAccountInSig() public {
        (address unAuthWallet, uint256 unAuthWalletKey) = makeAddrAndKey(
            "unAuthWallet"
        );
        (address unAuthAccount, ) = makeAddrAndKey("unAuthAccount");
        bytes32 hash = keccak256(
            abi.encode(address(unAuthAccount), block.chainid)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            unAuthWalletKey,
            hash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.prank(accountOwner);
        vm.expectRevert(MultiWallets.InvalidSignature.selector);
        credentialWallet.addWallet(unAuthWallet, signature);
    }

    function testCredWalletMultiWallets_addWalletInvalidChainIdInSig() public {
        (address otherWallet, uint256 otherWalletKey) = makeAddrAndKey(
            "otherWallet"
        );
        bytes32 hash = keccak256(
            abi.encode(address(credentialWallet), block.chainid + 1)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            otherWalletKey,
            hash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.prank(accountOwner);
        vm.expectRevert(MultiWallets.InvalidSignature.selector);
        credentialWallet.addWallet(otherWallet, signature);
    }

    function testCredWalletMultiWallets_accountOwnerCanAddWallet() public {
        (address otherWallet, uint256 otherWalletKey) = makeAddrAndKey(
            "otherWallet"
        );
        bytes32 hash = keccak256(
            abi.encode(address(credentialWallet), block.chainid)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            otherWalletKey,
            hash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.prank(accountOwner);
        credentialWallet.addWallet(otherWallet, signature);
        assertEq(credentialWallet.getWallets()[0], otherWallet);
    }

    function testCredWalletMultiWallets_nonOwnerCannotRemoveWallet() public {
        (address otherWallet, uint256 otherWalletKey) = makeAddrAndKey(
            "otherWallet"
        );
        bytes32 hash = keccak256(
            abi.encode(address(credentialWallet), block.chainid)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            otherWalletKey,
            hash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.prank(accountOwner);
        credentialWallet.addWallet(otherWallet, signature);
        (address randomUser, ) = makeAddrAndKey("randomUser");
        vm.prank(randomUser);
        address[] memory walletsToBeRemoved = new address[](1);
        walletsToBeRemoved[0] = otherWallet;
        vm.expectRevert(CredentialWallet.NotOwner.selector);
        credentialWallet.removeWallets(walletsToBeRemoved);
    }

    function testCredWalletMultiWallets_ownerCanRemoveWallets() public {
        (address otherWallet, uint256 otherWalletKey) = makeAddrAndKey(
            "otherWallet"
        );
        bytes32 hash = keccak256(
            abi.encode(address(credentialWallet), block.chainid)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            otherWalletKey,
            hash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.startPrank(accountOwner);
        credentialWallet.addWallet(otherWallet, signature);
        address[] memory walletsToBeRemoved = new address[](1);
        walletsToBeRemoved[0] = otherWallet;
        address[] memory wallets = credentialWallet.getWallets();
        assert(wallets.length == 1);
        credentialWallet.removeWallets(walletsToBeRemoved);
        wallets = credentialWallet.getWallets();
        assert(wallets.length == 0);
        vm.stopPrank();
    }
}
