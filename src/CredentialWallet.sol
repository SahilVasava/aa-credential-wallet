// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@account-abstraction/contracts/core/BaseAccount.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./mixins/MultiWallets.sol";

contract CredentialWallet is
    BaseAccount,
    MultiWallets,
    Initializable,
    UUPSUpgradeable
{
    using ECDSA for bytes32;

    //filler member, to push the nonce and owner to the same slot
    // the "Initializeble" class takes 2 bytes in the first slot
    bytes28 private _filler;

    uint96 private _nonce;
    address public owner;

    IEntryPoint private immutable _entryPoint;

    event SimpleAccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner
    );
    error NotOwner();
    error WrongArrayLengths();
    error NotOwnerOrEntryPoint();
    error InvalidNonce();

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    /// @inheritdoc BaseAccount
    function nonce() public view virtual override returns (uint256) {
        return _nonce;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        if (msg.sender != owner && msg.sender != address(this)) {
            revert NotOwner();
        }
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func)
        external
    {
        _requireFromEntryPointOrOwner();
        if (dest.length != func.length) {
            revert WrongArrayLengths();
        }
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SimpleAccountInitialized(_entryPoint, owner);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != owner) {
            revert NotOwnerOrEntryPoint();
        }
    }

    /// implement template method of BaseAccount
    function _validateAndUpdateNonce(UserOperation calldata userOp)
        internal
        override
    {
        if(_nonce++ != userOp.nonce) {
            revert InvalidNonce();
        }
    }

    /// implement template method of BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (
            owner != hash.recover(userOp.signature) &&
            !_isSignedFromSecondaryWallet(userOp, userOpHash)
        ) return SIG_VALIDATION_FAILED;
        return 0;
    }

    function _isSignedFromSecondaryWallet(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (bool isSecondaryWallet) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);
        for (uint256 i = 0; i < wallets.length; i++) {
            if (wallets[i] == signer) {
                return true;
            }
        }
        return false;
    }

    function _call(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// Multi wallets functions

    function addWallet(
        address _signer,
        bytes memory _signature
    ) external onlyOwner {
        _addWallet(_signer, _signature);
    }

    function removeWallets(address[] memory _walletsToBeRemoved)
        external
        onlyOwner
    {
        _removeWallets(_walletsToBeRemoved);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        view
        override
    {
        (newImplementation);
        _onlyOwner();
    }
}
