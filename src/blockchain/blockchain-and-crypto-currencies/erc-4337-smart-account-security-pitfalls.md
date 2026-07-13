# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction turns wallets into programmable systems. The core flow is **validate-then-execute** across a whole bundle: the `EntryPoint` validates every `UserOperation` before executing any of them. This ordering creates non-obvious attack surface when validation is permissive, stateful, or inconsistent with bundler simulation rules.

## 1) Direct-call bypass of privileged functions
Any externally callable `execute` (or fund-moving) function that is not restricted to `EntryPoint` (or a vetted executor module) can be called directly to drain the account.

```solidity
function execute(address target, uint256 value, bytes calldata data) external {
    (bool ok,) = target.call{value: value}(data);
    require(ok, "exec failed");
}
```

Safe pattern: restrict to `EntryPoint`, and use `msg.sender == address(this)` for admin/self-management flows (module install, validator changes, upgrades).

```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
    require(msg.sender == entryPoint, "not entryPoint");
    (bool ok,) = target.call{value: value}(data);
    require(ok, "exec failed");
}
```

## 2) Unsigned or unchecked gas fields -> fee drain
If signature validation only covers intent (`callData`) but not gas-related fields, a bundler or frontrunner can inflate fees and drain ETH. The signed payload must bind at least:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: use the `EntryPoint`-provided `userOpHash` (which includes gas fields) and/or strictly cap each field.

```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
    external
    returns (uint256)
{
    require(_isApprovedCall(userOpHash, op.signature), "bad sig");
    return 0;
}
```

## 3) Stateful validation clobbering (bundle semantics)
Because all validations run before any execution, storing validation results in contract state is unsafe. Another op in the same bundle can overwrite it, causing your execution to use attacker-influenced state.

Avoid writing storage in `validateUserOp`. If unavoidable, key temporary data by `userOpHash` and delete it deterministically after use (prefer stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` must bind signatures to **this contract** and **this chain**. Recovering over a raw hash lets signatures replay across accounts or chains.

Use EIP-712 typed data (domain includes `verifyingContract` and `chainId`) and return the exact ERC-1271 magic value `0x1626ba7e` on success.

## 5) Reverts do not refund after validation
Once `validateUserOp` succeeds, fees are committed even if execution later reverts. Attackers can repeatedly submit ops that will fail and still collect fees from the account.

For paymasters, paying from a shared pool in `validateUserOp` and charging users in `postOp` is fragile because `postOp` can revert without undoing the payment. Secure funds during validation (per-user escrow/deposit), keep `postOp` minimal and non-reverting, and budget `paymasterPostOpGasLimit` for the worst-case reimbursement path.

## 6) Counterfactual deployment / factory assumptions
The first `UserOperation` often carries `initCode`, which causes the account to be deployed through a **factory** during validation. This path is easy to under-audit because it only runs on first use.

Common failures:

- The factory/initializer trusts `msg.sender == entryPoint`, but the ERC-4337 deployment path does **not** call `initCode` directly from `EntryPoint`.
- The salt, owner, validator, or module configuration is not fully bound to signed intent, so a frontrunner can race the first deployment and burn the counterfactual address with attacker-controlled settings.
- The factory is non-idempotent, so a repeated first-use flow bricks the wallet instead of returning the already-created address.

Safe pattern: recompute the expected sender from signed deployment parameters, make deployment deterministic (typically `CREATE2`), and make initialization one-shot.

```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```

## 7) Validation logic that bundlers reject
Validation code can be correct in local tests and still be unusable in real bundlers. Public bundlers simulate `validateUserOp()` / `validatePaymasterUserOp()` off-chain and commonly run a full `debug_traceCall(handleOps)` before inclusion.

That makes these patterns dangerous inside validation:

- Block-dependent opcodes such as `TIMESTAMP`, `NUMBER`, or `BLOCKHASH`
- State writes such as `SSTORE`
- Unbounded iteration over storage
- Arbitrary external calls or oracle reads that can change between simulation and inclusion

Bad example:

```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
    external
    returns (uint256)
{
    require(block.timestamp < expiry, "expired");
    seen[userOpHash] = true; // SSTORE in validation
    require(oracle.isAllowed(op.sender), "oracle changed");
    return 0;
}
```

Treat validation as a deterministic, bounded preflight function. If you truly need shared state or external lookups, push that complexity into staked/reputation-tracked entities and test the exact bundler simulation path, not just unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 lets an EOA run smart-account code for a single tx. If initialization is externally callable, a frontrunner can set themselves as owner.

Mitigation: allow initialization only on **self-call** and only once.

```solidity
function initialize(address newOwner) external {
    require(msg.sender == address(this), "init: only self");
    require(owner == address(0), "already inited");
    owner = newOwner;
}
```

## Quick pre-merge checks
- Validate signatures using `EntryPoint`'s `userOpHash` (binds gas fields).
- Restrict privileged functions to `EntryPoint` and/or `address(this)` as appropriate.
- Keep `validateUserOp` stateless, deterministic, and compatible with bundler simulation rules.
- Enforce EIP-712 domain separation for ERC-1271 and return `0x1626ba7e` on success.
- Keep `postOp` minimal, bounded, and non-reverting; secure fees during validation.
- Test the first `initCode` path separately: deterministic deployment, idempotent factory behavior, and one-shot initialization.
- Run full bundler simulation (`simulateValidation` plus a traced `handleOps`) before shipping.
- For ERC-7702, allow init only on self-call and only once.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
