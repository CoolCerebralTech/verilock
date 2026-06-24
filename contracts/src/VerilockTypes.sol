// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VerilockTypes
 * @notice EIP-712 type definitions and cryptographic primitives for Verilock
 *         Approval Token verification.
 *
 * @dev CRITICAL CORRECTNESS REQUIREMENT:
 *      Every hash produced by this contract must be IDENTICAL to the hash
 *      produced by the Go Notary (internal/signing/approval.go).
 *      A single byte difference makes every signature verification fail.
 *
 *      Three things that must match the Go code exactly:
 *        1. The type string (field names, types, ORDER) — copied verbatim
 *        2. The domain separator fields (name, version, chainId, verifyingContract)
 *        3. The ABI encoding order of each field in _hashApprovalToken()
 *
 *      DEPLOYMENT NOTE:
 *      The domain separator includes address(this) as verifyingContract.
 *      After deploying VerilockGuard, you MUST update .env:
 *        GUARD_CONTRACT_ADDRESS=<deployed address>
 *      The Go Notary uses this value in its domain separator. If they differ,
 *      every signature the Notary produces will fail on-chain verification.
 *      Run: go run ./cmd/setup --force  OR  manually update GUARD_CONTRACT_ADDRESS.
 *
 *      V normalization: Go's crypto.Sign() returns V as 0 or 1.
 *      signer.go already adjusts to 27/28 before returning.
 *      _recoverSigner() normalises again as a safety net — do not remove.
 */
abstract contract VerilockTypes {

    // ── APPROVAL TOKEN TYPE HASH ───────────────────────────────────────────
    //
    // keccak256 of the EIP-712 type string.
    // LOCKED — changing a single character breaks all existing Notary deployments.
    //
    // Field order MUST be identical to Go's cachedStructTypeHash in approval.go.
    bytes32 internal constant APPROVAL_TOKEN_TYPEHASH = keccak256(
        "ApprovalToken(bytes32 tokenId,string agentId,address destination,uint256 amountRaw,uint256 chainId,bytes32 nonce,uint256 expiresAt,bytes32 policyHash)"
    );

    // ── EIP-712 DOMAIN TYPE HASH ───────────────────────────────────────────
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    // ── DOMAIN SEPARATOR ──────────────────────────────────────────────────
    //
    // Computed once in the constructor via _buildDomainSeparator().
    // Binds all signatures to this specific contract on this specific chain.
    // A signature valid on Base Sepolia cannot be replayed on Base Mainnet.
    bytes32 internal _domainSeparator;

    // ── DOMAIN SEPARATOR BUILDER ──────────────────────────────────────────
    //
    // Called in VerilockGuard constructor. Uses address(this) — must be
    // called post-deployment, not at compile time.
    //
    // "Verilock" and "1" MUST match the Go Notary's domain separator.
    // See: internal/signing/approval.go — initTypeHashes() and eip712Hash().
    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("Verilock")),  // name    — must match Go: "Verilock"
            keccak256(bytes("1")),          // version — must match Go: "1"
            block.chainid,                  // chainId — set at deployment runtime
            address(this)                   // verifyingContract — this Guard's address
        ));
    }

    // ── STRUCT HASH ───────────────────────────────────────────────────────
    //
    // Encodes one ApprovalToken's fields into a 32-byte hash per EIP-712 §5.1.
    //
    // ENCODING RULES:
    //   static types  (bytes32, address, uint256): encoded directly via abi.encode
    //   dynamic types (string):                    keccak256'd before encoding
    //
    // Field order MUST match the type string and the Go implementation.
    function _hashApprovalToken(
        bytes32 tokenId,
        string  memory agentId,
        address destination,
        uint256 amountRaw,
        uint256 chainId,
        bytes32 nonce,
        uint256 expiresAt,
        bytes32 policyHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            APPROVAL_TOKEN_TYPEHASH,
            tokenId,                       // bytes32 — direct
            keccak256(bytes(agentId)),     // string  — keccak256 first
            destination,                   // address — direct
            amountRaw,                     // uint256 — direct
            chainId,                       // uint256 — direct
            nonce,                         // bytes32 — direct
            expiresAt,                     // uint256 — direct
            policyHash                     // bytes32 — direct
        ));
    }

    // ── DIGEST ────────────────────────────────────────────────────────────
    //
    // Produces the final EIP-712 digest: keccak256("\x19\x01" || domain || struct)
    // The 0x1901 prefix prevents collision with EIP-191 personal_sign messages.
    function _getDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            bytes2(0x1901),
            _domainSeparator,
            structHash
        ));
    }

    // ── SIGNATURE RECOVERY ────────────────────────────────────────────────
    //
    // Recovers the signer from a digest and 65-byte ECDSA signature.
    // Returns address(0) on any malformed input — caller checks and reverts.
    //
    // SECURITY: never reverts — prevents try/catch bypass patterns where a
    // malicious contract could catch the revert and continue execution.
    //
    // EIP-2: rejects high-s signatures to prevent malleability.
    // V normalization: Go signer.go already sets V to 27/28.
    //   This line normalises v < 27 as a safety net for any edge case.
    function _recoverSigner(
        bytes32 digest,
        bytes memory sig
    ) internal pure returns (address) {
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8   v;

        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }

        // Safety net — Go already outputs 27/28 but guard against edge cases.
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        // EIP-2: reject high-s (malleable) signatures.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        return ecrecover(digest, v, r, s);
    }

    // ── VIEW HELPERS ──────────────────────────────────────────────────────

    /// @notice Returns the domain separator. SDK uses this to confirm the Guard
    ///         address in .env matches the deployed contract before submitting.
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparator;
    }

    /// @notice Returns the ApprovalToken type hash for auditor verification.
    function getApprovalTokenTypeHash() external pure returns (bytes32) {
        return APPROVAL_TOKEN_TYPEHASH;
    }
}
