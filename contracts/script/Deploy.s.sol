// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {TollgateGuard}   from "../src/TollgateGuard.sol";

/**
 * @title  Deploy
 * @notice Deploys TollgateGuard to the target network.
 *
 * Required environment variables:
 *   TOLLGATE_NOTARY_ADDRESS  — from: go run ./cmd/server  (printed on boot)
 *   SAFE_ADDRESS             — your Gnosis Safe address on the target chain
 *   DEPLOYER_PRIVATE_KEY     — EOA that pays for deployment gas
 *
 * Optional:
 *   EXPECTED_CHAIN_ID        — safety check; script aborts if chain doesn't match
 *
 * Usage — local Anvil (single-owner Safe or EOA as Safe for testing):
 *   export TOLLGATE_NOTARY_ADDRESS=0x...
 *   export SAFE_ADDRESS=0x...
 *   forge script script/Deploy.s.sol \
 *     --rpc-url http://127.0.0.1:8545 \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast
 *
 * Usage — Base Sepolia:
 *   forge script script/Deploy.s.sol \
 *     --rpc-url base_sepolia \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast --verify \
 *     --etherscan-api-key $BASESCAN_API_KEY
 *
 * After deployment:
 *   1. Copy the Guard address from output.
 *   2. Update core/.env:  GUARD_CONTRACT_ADDRESS=<address>
 *   3. Restart the Notary so it uses the correct domain separator.
 *   4. Run AttachGuard.s.sol to activate the Guard on the Safe.
 */
contract Deploy is Script {
    function run() external {
        // ── Required inputs ───────────────────────────────────────────────────

        address notaryAddress = vm.envAddress("TOLLGATE_NOTARY_ADDRESS");
        require(notaryAddress != address(0), "Deploy: TOLLGATE_NOTARY_ADDRESS not set");

        // SAFE_ADDRESS is required — no silent fallback to msg.sender.
        // On Anvil, deploy a mock Safe or use the Safe SDK to create one first.
        // Falling back to msg.sender creates a Guard where only the deployer
        // EOA is the "Safe" — checkTransaction will revert for any real Safe.
        address safeAddress = vm.envAddress("SAFE_ADDRESS");
        require(safeAddress != address(0), "Deploy: SAFE_ADDRESS not set — set to your Gnosis Safe address");

        // ── Optional chain ID safety check ────────────────────────────────────
        // Set EXPECTED_CHAIN_ID to prevent accidental mainnet deployments.
        // 84532 = Base Sepolia  |  8453 = Base mainnet
        uint256 expectedChainId = vm.envOr("EXPECTED_CHAIN_ID", uint256(0));
        if (expectedChainId != 0) {
            require(
                block.chainid == expectedChainId,
                string(abi.encodePacked(
                    "Deploy: wrong chain. Expected ",
                    vm.toString(expectedChainId),
                    " got ",
                    vm.toString(block.chainid)
                ))
            );
        }

        // Warn loudly if deploying to mainnet without an explicit chain check.
        if (block.chainid == 8453 && expectedChainId == 0) {
            console.log("WARNING: deploying to BASE MAINNET without EXPECTED_CHAIN_ID check");
            console.log("         Set EXPECTED_CHAIN_ID=8453 to confirm this is intentional");
        }

        // ── Pre-deploy summary ────────────────────────────────────────────────

        console.log("=== TOLLGATE GUARD DEPLOYMENT ===");
        console.log("Chain ID  :", block.chainid);
        console.log("Notary    :", notaryAddress);
        console.log("Safe      :", safeAddress);
        console.log("Deployer  :", msg.sender);
        console.log("=================================");

        // ── Deploy ────────────────────────────────────────────────────────────

        vm.startBroadcast();
        TollgateGuard guard = new TollgateGuard(notaryAddress, safeAddress);
        vm.stopBroadcast();

        // ── Post-deploy verification ──────────────────────────────────────────
        // Confirm the constructor stored the correct values.
        // A wrong arg order or constructor bug is caught here, not silently.

        require(
            guard.notaryAddress() == notaryAddress,
            "Deploy: notaryAddress mismatch — constructor stored wrong value"
        );
        require(
            guard.safeAddress() == safeAddress,
            "Deploy: safeAddress mismatch — constructor stored wrong value"
        );

        // ── Output ────────────────────────────────────────────────────────────

        console.log("=== DEPLOYMENT SUCCESSFUL ===");
        console.log("Guard address:");
        console.logAddress(address(guard));
        console.log("Domain separator:");
        console.logBytes32(guard.getDomainSeparator());
        console.log("ApprovalToken type hash:");
        console.logBytes32(guard.getApprovalTokenTypeHash());
        console.log("=============================");
        console.log("");
        console.log("NEXT STEPS:");
        console.log("1. Update core/.env:");
        console.log("   GUARD_CONTRACT_ADDRESS=");
        console.logAddress(address(guard));
        console.log("2. Restart the Notary (go run ./cmd/server)");
        console.log("   The Notary must use the Guard address in its EIP-712 domain separator.");
        console.log("3. Run AttachGuard.s.sol to activate the Guard on the Safe:");
        console.log("   GUARD_ADDRESS=<address above> forge script script/AttachGuard.s.sol ...");
    }
}
