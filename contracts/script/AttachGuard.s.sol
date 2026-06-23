// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {TollgateGuard}   from "../src/TollgateGuard.sol";

/**
 * @title  AttachGuard
 * @notice Attaches a deployed TollgateGuard to a Gnosis Safe.
 *
 * HOW GNOSIS SAFE setGuard WORKS:
 *   setGuard() is a privileged function on the Safe contract. It can ONLY be
 *   called through the Safe's own transaction pipeline — i.e. as a Safe
 *   transaction, signed by the required threshold of Safe owners.
 *   Calling it directly from an EOA will revert with GS031.
 *
 * This script supports two modes controlled by ATTACH_MODE env var:
 *
 *   ATTACH_MODE=direct (default for Anvil / single-owner test Safes)
 *     Calls setGuard directly. Only works when msg.sender IS the Safe
 *     (e.g. Anvil where the deployer address = Safe address for testing).
 *
 *   ATTACH_MODE=multisig (for real Gnosis Safes on testnet/mainnet)
 *     Encodes the setGuard call as a Safe transaction and prints the
 *     calldata you need to submit via the Safe UI or Safe SDK.
 *     You must collect signatures from the required Safe owners and
 *     submit via the Safe Transaction Service or execTransaction directly.
 *
 * Required environment variables:
 *   GUARD_ADDRESS   — deployed TollgateGuard address (from Deploy.s.sol output)
 *   SAFE_ADDRESS    — your Gnosis Safe address
 *   ATTACH_MODE     — "direct" (Anvil/test) or "multisig" (real Safe) [default: direct]
 *
 * Usage — Anvil / single-owner test:
 *   forge script script/AttachGuard.s.sol \
 *     --rpc-url http://127.0.0.1:8545 \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast
 *
 * Usage — real Gnosis Safe (prints calldata, no broadcast needed):
 *   ATTACH_MODE=multisig forge script script/AttachGuard.s.sol \
 *     --rpc-url base_sepolia
 */
contract AttachGuard is Script {

    /// @dev setGuard(address) selector on Gnosis Safe.
    bytes4 constant SET_GUARD_SELECTOR = bytes4(keccak256("setGuard(address)"));

    function run() external {
        address guardAddress = vm.envAddress("GUARD_ADDRESS");
        address safeAddress  = vm.envAddress("SAFE_ADDRESS");
        string memory mode   = vm.envOr("ATTACH_MODE", string("direct"));

        require(guardAddress != address(0), "AttachGuard: GUARD_ADDRESS not set");
        require(safeAddress  != address(0), "AttachGuard: SAFE_ADDRESS not set");

        // ── Cross-check: Guard must be configured for this Safe ───────────────
        // If the Guard was deployed with a different Safe address, attaching it
        // will succeed at the Safe level but every checkTransaction will revert
        // with OnlySafe() because the Safe address won't match.
        TollgateGuard guard = TollgateGuard(guardAddress);
        require(
            guard.safeAddress() == safeAddress,
            "AttachGuard: Guard.safeAddress() does not match SAFE_ADDRESS - deploy a new Guard for this Safe"
        );

        console.log("=== ATTACHING GUARD TO SAFE ===");
        console.log("Safe     :", safeAddress);
        console.log("Guard    :", guardAddress);
        console.log("Mode     :", mode);
        console.log("Chain    :", block.chainid);
        console.log("===============================");

        if (keccak256(bytes(mode)) == keccak256(bytes("direct"))) {
            _attachDirect(safeAddress, guardAddress);
        } else {
            _attachMultisig(safeAddress, guardAddress);
        }
    }

    // ── Mode 1: direct call ───────────────────────────────────────────────────
    // Only works when msg.sender is the Safe (Anvil test setup).
    // On a real Safe this will revert with GS031.

    function _attachDirect(address safeAddress, address guardAddress) internal {
        console.log("Calling setGuard directly (Anvil/test mode)...");

        // Import ISafe inline to avoid a circular dependency with the interface file.
        (bool ok, ) = safeAddress.call(
            abi.encodeWithSelector(SET_GUARD_SELECTOR, guardAddress)
        );
        require(ok, "AttachGuard: direct setGuard call failed - are you running Anvil with msg.sender == Safe?");

        // Verify attachment.
        (bool readOk, bytes memory result) = safeAddress.staticcall(
            abi.encodeWithSignature("getGuard()")
        );
        require(readOk, "AttachGuard: getGuard() call failed");
        address attached = abi.decode(result, (address));
        require(attached == guardAddress, "AttachGuard: verification failed - getGuard() returned wrong address");

        console.log("Guard attached and verified.");
        console.log("getGuard() =");
        console.logAddress(attached);
    }

    // ── Mode 2: multisig — prints calldata for Safe UI submission ─────────────
    // Does NOT broadcast anything. Prints the exact calldata you need to
    // submit as a Safe transaction through the Safe UI or Safe SDK.

    function _attachMultisig(address safeAddress, address guardAddress) internal view {
        bytes memory callData = abi.encodeWithSelector(SET_GUARD_SELECTOR, guardAddress);

        console.log("=== SAFE TRANSACTION REQUIRED ===");
        console.log("");
        console.log("setGuard() can only be called through the Safe's own transaction");
        console.log("pipeline. Submit the following as a Safe transaction:");
        console.log("");
        console.log("To (Safe address):");
        console.logAddress(safeAddress);
        console.log("");
        console.log("Value: 0");
        console.log("");
        console.log("Data (setGuard calldata):");
        console.logBytes(callData);
        console.log("");
        console.log("Options:");
        console.log("  A) Safe UI: app.safe.global -> New transaction -> Contract interaction");
        console.log("     Paste the calldata above into the 'Data' field.");
        console.log("");
        console.log("  B) Safe SDK (Node.js):");
        console.log("     const tx = { to: safeAddress, value: '0', data: calldata }");
        console.log("     const safeTx = await safeSDK.createTransaction({ transactions: [tx] })");
        console.log("     await safeSDK.signTransaction(safeTx)");
        console.log("     await safeSDK.executeTransaction(safeTx)");
        console.log("");
        console.log("  C) Cast (single-owner Safe on testnet):");
        console.log("     cast send $SAFE_ADDRESS \\");
        console.logBytes(callData);
        console.log("     --rpc-url $RPC_URL --private-key $OWNER_PRIVATE_KEY");
        console.log("================================");
        console.log("");
        console.log("After submitting, verify with:");
        console.log("  cast call $SAFE_ADDRESS 'getGuard()(address)' --rpc-url $RPC_URL");
        console.log("  Expected:", guardAddress);
    }
}
