// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  ISafe
 * @notice Minimal interface for the Gnosis Safe operations needed by
 *         Tollgate deploy and attach scripts.
 */
interface ISafe {
    function setGuard(address guard) external;
    function getGuard() external view returns (address);
}
