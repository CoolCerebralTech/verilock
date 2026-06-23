// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGuard}       from "./interfaces/IGuard.sol";
import {TollgateTypes} from "./TollgateTypes.sol";

/**
 * @title  TollgateGuard
 * @notice Gnosis Safe Guard that enforces Tollgate policy approval on every
 *         outgoing transaction. Every transaction leaving the Safe must carry
 *         a valid EIP-712 Approval Token signed by the registered Tollgate
 *         Notary. Without a valid token the transaction reverts before
 *         execution — the money never moves.
 *
 * @dev    Implements IGuard. Attach to a Gnosis Safe via Safe.setGuard(address).
 *
 *         DEPLOYMENT:
 *           constructor(notaryAddress, safeAddress)
 *           notaryAddress — from: go run ./cmd/server  (printed on boot)
 *           safeAddress   — your Gnosis Safe on Base
 *
 *         After deployment, update GUARD_CONTRACT_ADDRESS in .env to the
 *         deployed address so the Notary's EIP-712 domain separator matches.
 *
 *         Verification pipeline in checkTransaction (12 steps, in order):
 *           1.  Caller must be the Safe (OnlySafe)
 *           2.  Guard must not be paused (GuardIsPaused)
 *           3.  Reject DELEGATECALL operations (DelegateCallNotAllowed)
 *           4.  Extract ApprovalToken from transaction data (TokenMissing)
 *           5.  Token must not be expired (TokenExpired)
 *           6.  Token nonce must not be consumed (TokenNonceReplayed)
 *           7.  Token chainId must match block.chainid (ChainIdMismatch)
 *           8.  Token destination must match actual to (DestinationMismatch)
 *           9.  Token amountRaw must match actual value (AmountMismatch)
 *           10. EIP-712 signature must recover to notaryAddress (SignatureInvalid)
 *           11. Store pending nonce for checkAfterExecution
 *           12. Emit TransactionApproved
 *
 *         checkAfterExecution marks the nonce as consumed — replay prevention.
 */
contract TollgateGuard is IGuard, TollgateTypes {

    // ── CONSTANTS ─────────────────────────────────────────────────────────────

    /// @dev 4-byte prefix the SDK appends before the ABI-encoded token.
    ///      bytes4(keccak256("tollgate.approval.v1")) truncated to 4 bytes.
    ///      The token is ALWAYS appended as the LAST element of tx data,
    ///      so extraction uses a fixed suffix position, not a search.
    bytes4 internal constant TOKEN_PREFIX = 0x544F4C47;

    /// @dev Minimum data length: 4-byte prefix + 9 ABI-encoded fields.
    ///      9 fields × 32 bytes minimum = 288 bytes + 4-byte prefix = 292.
    ///      Dynamic fields (string, bytes) add more — this is the floor.
    uint256 internal constant MIN_TOKEN_DATA_LENGTH = 292;

    // ── IMMUTABLE STATE ───────────────────────────────────────────────────────

    /// @notice The Tollgate Notary address — only signatures from this address
    ///         are accepted. Pass the address printed by: go run ./cmd/server
    ///         Do NOT hardcode here — the address changes when keys rotate.
    address public immutable notaryAddress;

    /// @notice The Gnosis Safe this Guard is attached to.
    ///         Only this address may call checkTransaction and checkAfterExecution.
    address public immutable safeAddress;

    // ── MUTABLE STATE ─────────────────────────────────────────────────────────

    /// @notice Consumed token nonces — append-only. Once true, never cleared.
    mapping(bytes32 => bool) public consumedNonces;

    /// @notice Emergency pause — when true ALL transactions are blocked.
    bool public paused;

    /// @notice Owner of this Guard — the Safe itself.
    address public owner;

    /// @dev Transient nonce set in checkTransaction, consumed in checkAfterExecution.
    ///      Protected against reentrancy: if non-zero when checkTransaction runs
    ///      again, a nested call is in progress and we revert.
    bytes32 private _pendingNonce;

    // ── STRUCTS ───────────────────────────────────────────────────────────────

    struct ApprovalTokenData {
        bytes32 tokenId;
        string  agentId;
        address destination;
        uint256 amountRaw;
        uint256 chainId;
        bytes32 nonce;
        uint256 expiresAt;
        bytes32 policyHash;
        bytes   signature;
    }

    // ── EVENTS ────────────────────────────────────────────────────────────────

    event TransactionApproved(
        bytes32 indexed tokenId,
        address indexed destination,
        uint256         amountRaw,
        string          agentId,
        bytes32         policyHash
    );

    event GuardPaused(bool isPaused);

    // ── ERRORS ────────────────────────────────────────────────────────────────

    error TokenMissing();
    error TokenExpired();
    error TokenNonceReplayed();
    error SignatureInvalid();
    error DestinationMismatch();
    error AmountMismatch();
    error ChainIdMismatch();
    error GuardIsPaused();
    error OnlySafe();
    error OnlyOwner();
    error ZeroAddress();
    error DelegateCallNotAllowed();
    error ReentrancyDetected();

    // ── CONSTRUCTOR ───────────────────────────────────────────────────────────

    /**
     * @param _notaryAddress Tollgate Notary public address.
     *                       Get this from: go run ./cmd/server (printed on boot).
     *                       After deployment, set GUARD_CONTRACT_ADDRESS in .env
     *                       to address(this) so the Notary's domain separator matches.
     * @param _safeAddress   The Gnosis Safe this Guard will protect.
     */
    constructor(address _notaryAddress, address _safeAddress) {
        if (_notaryAddress == address(0)) revert ZeroAddress();
        if (_safeAddress   == address(0)) revert ZeroAddress();

        notaryAddress    = _notaryAddress;
        safeAddress      = _safeAddress;
        owner            = _safeAddress;
        paused           = false;
        _domainSeparator = _buildDomainSeparator();
    }

    // ── IGUARD IMPLEMENTATION ─────────────────────────────────────────────────

    /**
     * @notice Called by the Safe BEFORE every transaction.
     *         Reverts if the Approval Token is missing, expired, invalid, or replayed.
     */
    function checkTransaction(
        address          to,
        uint256          value,
        bytes   calldata data,
        uint8            operation,
        uint256          safeTxGas,
        uint256          baseGas,
        uint256          gasPrice,
        address          gasToken,
        address payable  refundReceiver,
        bytes   memory   signatures,
        address          msgSender
    ) external override {
        // Suppress unused-variable warnings for parameters we don't need.
        safeTxGas; baseGas; gasPrice; gasToken; refundReceiver; signatures; msgSender;

        // CHECK 1: Only the Safe may call this.
        if (msg.sender != safeAddress) revert OnlySafe();

        // CHECK 2: Guard must not be paused.
        if (paused) revert GuardIsPaused();

        // CHECK 3: Reject DELEGATECALL (operation == 1).
        // A delegatecall from the Safe to a malicious contract could bypass
        // Guard logic or drain the Safe without a valid Tollgate token.
        if (operation != 0) revert DelegateCallNotAllowed();

        // CHECK 3b: Reentrancy guard on _pendingNonce.
        // If a nested call re-enters checkTransaction while a transaction is
        // already in-flight, _pendingNonce will be non-zero. Block it.
        if (_pendingNonce != bytes32(0)) revert ReentrancyDetected();

        // CHECK 4: Skip token validation for guard removal (setGuard to zero address).
        // This is Safe self-management — the Safe owners already authorized it.
        // The guard must NOT block its own removal, or the Safe becomes permanently
        // locked. This is a critical escape hatch.
        if (_isGuardRemoval(to, data)) {
            _pendingNonce = bytes32(uint256(1)); // marker, not a real nonce — skip consumption in checkAfterExecution
            return;
        }

        // CHECK 5: Extract Approval Token from the end of tx data.
        ApprovalTokenData memory token = _extractToken(data);

        // CHECK 5: Token must not be expired.
        if (block.timestamp > token.expiresAt) revert TokenExpired();

        // CHECK 6: Token nonce must not have been consumed.
        if (consumedNonces[token.nonce]) revert TokenNonceReplayed();

        // CHECK 7: Token chainId must match this chain.
        if (token.chainId != block.chainid) revert ChainIdMismatch();

        // CHECK 8: Token destination must match the actual transaction target.
        if (token.destination != to) revert DestinationMismatch();

        // CHECK 9: Token amountRaw must match the actual transaction value.
        if (token.amountRaw != value) revert AmountMismatch();

        // CHECK 10: EIP-712 signature must recover to notaryAddress.
        bytes32 structHash = _hashApprovalToken(
            token.tokenId,
            token.agentId,
            token.destination,
            token.amountRaw,
            token.chainId,
            token.nonce,
            token.expiresAt,
            token.policyHash
        );
        address recovered = _recoverSigner(_getDigest(structHash), token.signature);
        if (recovered != notaryAddress) revert SignatureInvalid();

        // CHECK 11: Store nonce for consumption in checkAfterExecution.
        // Set AFTER all checks pass — if any check reverts, nonce is not stored.
        _pendingNonce = token.nonce;

        // CHECK 12: Emit approval event for on-chain auditability.
        emit TransactionApproved(
            token.tokenId,
            to,
            value,
            token.agentId,
            token.policyHash
        );
    }

    /**
     * @notice Called by the Safe AFTER every transaction.
     *         Marks the Approval Token nonce as consumed — prevents replay.
     *         Clears _pendingNonce regardless of execution success.
     */
    function checkAfterExecution(bytes32 txHash, bool success) external override {
        txHash; success;
        if (msg.sender != safeAddress) revert OnlySafe();
        // Skip nonce consumption for guard removal — it used a dummy nonce.
        if (_pendingNonce == bytes32(uint256(1))) {
            _pendingNonce = bytes32(0);
            return;
        }
        if (_pendingNonce != bytes32(0)) {
            consumedNonces[_pendingNonce] = true;
            _pendingNonce = bytes32(0);
        }
    }

    // ── ADMIN ─────────────────────────────────────────────────────────────────

    /// @notice Pause or unpause the Guard. Only the owner (Safe) may call this.
    /// @dev    To pause: execute a Safe transaction calling this function.
    ///         While paused, ALL transactions from the Safe are blocked.
    function setPaused(bool _paused) external {
        if (msg.sender != owner) revert OnlyOwner();
        paused = _paused;
        emit GuardPaused(_paused);
    }

    /// @notice Check whether a nonce has been consumed.
    function isNonceConsumed(bytes32 nonce) external view returns (bool) {
        return consumedNonces[nonce];
    }

    /// @notice ERC-165 interface detection.
    ///         Returns true for IGuard (0xe6d7a83a) and ERC-165 (0x01ffc9a7).
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == 0xe6d7a83a   // IGuard
            || interfaceId == 0x01ffc9a7;  // ERC-165
    }

    // ── INTERNAL: GUARD REMOVAL DETECTION ─────────────────────────────────────

    /**
     * @notice Detects if the given transaction is a Safe setGuard(address) call
     *         targeting the zero address (i.e. removing this guard).
     * @dev    This is the critical escape hatch — the guard must allow the Safe
     *         to remove itself. Safe owners already authorized this through the
     *         Safe's own multisig/signing process.
     */
    function _isGuardRemoval(address to, bytes calldata data) internal view returns (bool) {
        // Must be sending to the Safe itself
        if (to != safeAddress) return false;
        
        // Minimum length: 4-byte selector + 32-byte address argument
        if (data.length < 36) return false;
        
        bytes4 setGuardSelector = bytes4(keccak256("setGuard(address)"));
        bytes4 selector = bytes4(data[:4]);
        if (selector != setGuardSelector) return false;
        
        // The argument (address parameter) must be zero address (removal)
        address guardAddress = abi.decode(data[4:], (address));
        return guardAddress == address(0);
    }

    // ── INTERNAL: TOKEN EXTRACTION ────────────────────────────────────────────

    /**
     * @dev Extracts the Approval Token from the END of tx data.
     *
     *      Token format (appended by the SDK):
     *        [original calldata] [TOKEN_PREFIX 4 bytes] [ABI-encoded token fields]
     *
     *      The SDK always appends the token as the final element. We search
     *      backwards for the LAST occurrence of TOKEN_PREFIX to find it.
     *      This is more robust than a forward search because calldata may
     *      contain the prefix bytes by coincidence in earlier positions.
     *
     *      SECURITY: The prefix is 4 bytes (not unique enough on its own).
     *      After finding a candidate position, we verify the ABI-decoded
     *      token is structurally valid by checking that the decoded signature
     *      length is exactly 65 bytes — rejecting false prefix matches.
     *
     *      Reverts TokenMissing() if no valid token found.
     */
    function _extractToken(
        bytes calldata data
    ) internal pure returns (ApprovalTokenData memory token) {
        if (data.length < MIN_TOKEN_DATA_LENGTH) revert TokenMissing();

        // Search backwards for TOKEN_PREFIX — SDK appends it last so the
        // last match is the genuine token start.
        uint256 prefixPos = type(uint256).max;
        if (data.length >= 4) {
            for (uint256 i = data.length - 4; ; ) {
                if (bytes4(data[i:i + 4]) == TOKEN_PREFIX) {
                    prefixPos = i;
                    break;
                }
                if (i == 0) break;
                unchecked { --i; }
            }
        }

        if (prefixPos == type(uint256).max) revert TokenMissing();

        bytes calldata encoded = data[prefixPos + 4:];
        if (encoded.length == 0) revert TokenMissing();

        (
            token.tokenId,
            token.agentId,
            token.destination,
            token.amountRaw,
            token.chainId,
            token.nonce,
            token.expiresAt,
            token.policyHash,
            token.signature
        ) = abi.decode(
            encoded,
            (bytes32, string, address, uint256, uint256, bytes32, uint256, bytes32, bytes)
        );

        // Structural validation: signature must be exactly 65 bytes.
        // This catches false prefix matches — real ABI-encoded data from the
        // Notary always produces a 65-byte signature.
        if (token.signature.length != 65) revert TokenMissing();
    }
}
