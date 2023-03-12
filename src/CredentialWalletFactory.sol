// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./CredentialWallet.sol";

/**
 * A sample factory contract for CredentialWallet
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract CredentialWalletFactory {
    CredentialWallet public immutable walletImplementation;

    constructor(IEntryPoint _entryPoint) {
        walletImplementation = new CredentialWallet(_entryPoint);
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(address owner, uint256 salt)
        public
        returns (CredentialWallet ret)
    {
        address addr = getAddress(owner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return CredentialWallet(payable(addr));
        }
        ret = CredentialWallet(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(walletImplementation),
                    abi.encodeCall(CredentialWallet.initialize, (owner))
                )
            )
        );
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner, uint256 salt)
        public
        view
        returns (address)
    {
        return
            Create2.computeAddress(
                bytes32(salt),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(walletImplementation),
                            abi.encodeCall(CredentialWallet.initialize, (owner))
                        )
                    )
                )
            );
    }
}
