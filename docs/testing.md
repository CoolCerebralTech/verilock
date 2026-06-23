# Testing Guide

## Foundry Tests

### Running Tests

```bash
cd contracts
forge test               # Run all tests
forge test -vvv          # Verbose output
forge test --match-contract TollgateGuardRemovalTest  # Specific test
```

### Test Coverage

| Test | Description | Status |
|------|-------------|--------|
| `test_setGuardToZeroBuffers` | Guard allows removal via zero address |
| `test_setGuardToArbitraryAddress` | Guard blocks setting to random address |
| `test_normalTxWithoutToken` | Guard blocks tx without approval token |
| `test_guardRemovesWithToken` | Guard allows tx with valid token |
| `test_goalRemovedCreation` | Guard can't be added twice |
| `test_withdrawalExecTransaction` | Owner can withdraw funds |

### Writing New Tests

```solidity
function test_something() public {
    // Arrange
    address destination = makeAddr("destination");
    uint256 amount = 0.02 ether;
    
    // Build approval token (mock Notary signature)
    bytes memory token = buildApprovalToken(destination, amount, block.timestamp + 60);
    
    // Encode transaction
    bytes memory data = abi.encodeWithSelector(something.selector, destination, amount);
    data = abi.encodePacked(data, TOKEN_PREFIX, token);
    
    // Act + Assert
    vm.expectRevert(TollgateGuard.TokenMissing.selector);
    guard.checkTransaction(destination, amount, data, ...);
}
```

## Live Testing on Testnet

### Prerequisites

- Base Sepolia Safe
- Base Sepolia ETH (for gas)
- Guard deployed
- Notary running

### Test Scenarios

#### 1. Guard Blocks Without Token

**Setup:** Guard attached to Safe

**Action:** Try sending any amount without approval token

**Expected:** Safe UI shows "Simulation Error: Reverted"

#### 2. Guard Allows With Token

**Setup:** Guard attached, Notary running

**Action:**
1. Get approval token from Notary API
2. Encode token into transaction data
3. Submit to Safe

**Expected:** Transaction succeeds

#### 3. Guard Removal (Escape Hatch)

**Setup:** Guard attached

**Action:** Call `setGuard(address(0))` via Safe Transaction Builder

**Expected:** Transaction succeeds, Guard removed

### Debugging Failed Transactions

```bash
# Check transaction receipt
cast tx <tx-hash> --rpc-url https://sepolia.base.org

# Decode error
# Look for error selector in receipt data
# 0xe0e5afaf -> TokenMissing()
# 0x0c7e229c -> TokenExpired()
# 0x99793a01 -> SignatureInvalid()

# Check Guard state
cast call <guard_address> "owner()(address)" --rpc-url https://sepolia.base.org
cast call <guard_address> "safeAddress()(address)" --rpc-url https://sepolia.base.org
cast call <guard_address> "notaryAddress()(address)" --rpc-url https://sepolia.base.org
```

## Common Errors

| Error Selector | Error Name | Meaning |
|---------------|-----------|---------|
| `0xe0e5afaf` | `TokenMissing()` | No approval token found in tx data |
| `0x0c7e229c` | `TokenExpired()` | Token past expiry timestamp |
| `0x99793a01` | `SignatureInvalid()` | Doesn't recover to Notary address |
| ` 0x61b5ace5 | `TokenNonceReplayed()` | Nonce already consumed |

## Regression Tests

Always run after any Guard contract change:

1. `test_guardCreation` — Guard deploys
2. `test_guardRemoval` — can be removed
3. `test_normalTxDenied` — blocks without token
4. `test_withdrawalExecTransaction` — Safe operations work