// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {TollgateGuard} from "../src/TollgateGuard.sol";

/**
 * @title  TollgateGuardRemovalTest
 * @notice Tests that the guard's _isGuardRemoval bypass works correctly.
 *         This test MUST pass before deploying to production.
 *
 * Three test cases:
 *   1. setGuard(0x0) from Safe -> PASS (removal escape hatch)
 *   2. setGuard(someOtherGuard) from Safe -> fails with TokenMissing
 *   3. Normal tx without token from Safe -> FAIL with TokenMissing
 */
contract TollgateGuardRemovalTest is Test {
    TollgateGuard public guard;
    address public notary = address(0x1234);  // dummy notary
    address public safe = address(0x5AFE);    // dummy Safe address

    function setUp() public {
        guard = new TollgateGuard(notary, safe);
    }

    // --- Test 1: setGuard(0x0) MUST pass (escape hatch) ---
    function test_setGuardToZero_Passes() public {
        // Build calldata: setGuard(address) with arg x0
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("setGuard(address)")),
            address(0)
        );

        // Simulate Safe calling guard.checkTransaction
        vm.prank(safe);
        guard.checkTransaction(
            safe,    // to = Safe itself
            0,       // value
            data,    // setGuard(0x0) calldata
            0,       // operation = Call (not DelegateCall)
            0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );

        // Simulate Safe calling checkAfterExecution
        vm.prank(safe);
        guard.checkAfterExecution(bytes32(0), true);

        // If we get here, removal succeeded (no revert)
    }

    // --- Test 2: setGuard(otherAddress) -> should fail (no token) ---
    function test_setGuardToOtherAddress_NeedsToken() public {
        address newGuard = address(0x5678);

        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("setGuard(address)")),
            newGuard
        );

        vm.prank(safe);
        // This should FAIL (no token provided)
        vm.expectRevert(TollgateGuard.TokenMissing.selector);
        guard.checkTransaction(
            safe, 0, data, 0,
            0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }

    // --- Test 3: Normal tx without token -> MUST fail ---
    function test_normalTxWithoutToken_Fails() public {
        bytes memory data = hex"12345678"; // random calldata, no token

        vm.prank(safe);
        vm.expectRevert(TollgateGuard.TokenMissing.selector);
        guard.checkTransaction(
            address(0xDEAD), // some destination
            1000,            // some value
            data, 0,
            0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }
}
