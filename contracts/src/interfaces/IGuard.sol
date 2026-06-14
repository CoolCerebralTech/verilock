// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  IGuard
 * @notice Gnosis Safe Guard interface.
 *         Any contract implementing this interface can be attached to a Safe
 *         via Safe.setGuard(address) to intercept every outgoing transaction.
 *
 * @dev    The Safe calls checkTransaction BEFORE execution and
 *         checkAfterExecution AFTER. Both must not revert for the transaction
 *         to proceed.
 *
 *         supportsInterface(0xe6d7a83a) must return true — the Safe checks
 *         this before accepting the guard attachment.
 */
interface IGuard {
    /**
     * @notice Called by the Safe before every transaction executes.
     *         Revert here to block the transaction.
     */
    function checkTransaction(
        address         to,
        uint256         value,
        bytes calldata  data,
        uint8           operation,
        uint256         safeTxGas,
        uint256         baseGas,
        uint256         gasPrice,
        address         gasToken,
        address payable refundReceiver,
        bytes memory    signatures,
        address         msgSender
    ) external;

    /**
     * @notice Called by the Safe after every transaction executes.
     *         Use to finalise state changes that depend on execution outcome.
     */
    function checkAfterExecution(bytes32 txHash, bool success) external;

    /**
     * @notice ERC-165 interface detection.
     *         Must return true for interfaceId == 0xe6d7a83a (IGuard).
     *         Must return true for interfaceId == 0x01ffc9a7 (ERC-165 itself).
     */
    function supportsInterface(bytes4 interfaceId) external pure returns (bool);
}
