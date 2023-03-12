// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MultiWallets {
    using ECDSA for bytes32;
    address[] public wallets;
    uint96 private _multiWalletsNonce;
    error InvalidSignature();

    function multiWalletsNonce() public view returns (uint256) {
        return _multiWalletsNonce;
    }

    function _addWallet(address _signer, bytes memory _signature) internal {
        bytes32 hash = keccak256(abi.encode(address(this), block.chainid))
            .toEthSignedMessageHash();
        if (!SignatureChecker.isValidSignatureNow(_signer, hash, _signature)) {
            revert InvalidSignature();
        }
        wallets.push(_signer);
    }

    function _removeWallets(address[] memory _walletsToBeRemoved) internal {
        for (uint256 i = 0; i < _walletsToBeRemoved.length; i++) {
            for (uint256 j = 0; i < wallets.length; i++) {
                if (wallets[j] == _walletsToBeRemoved[i]) {
                    wallets[j] = wallets[wallets.length - 1];
                    wallets.pop();
                    break;
                }
            }
        }
    }

    function getWallets() public view returns (address[] memory) {
        return wallets;
    }
}
