# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction turns wallets into programmable systems. The core flow is **validate-then-execute** across a whole bundle: the `EntryPoint` validates every `UserOperation` before executing any of them.<sup>[[5]](#references)</sup> This ordering creates non-obvious attack surface when validation is permissive, stateful, or inconsistent with bundler simulation rules.

## 1) Direct-call bypass of privileged functions
Any externally callable `execute` (or fund-moving) function that is not restricted to `EntryPoint` (or a vetted executor module) can be called directly to drain the account.<sup>[[2]](#references)</sup>

```solidity
function execute(address target, uint256 value, bytes calldata data) external {
    (bool ok,) = target.call{value: value}(data);
    require(ok, "exec failed");
}
```

Safe pattern: restrict to `EntryPoint`, and use `msg.sender == address(this)` for admin/self-management flows (module install, validator changes, upgrades).<sup>[[2]](#references)[[5]](#references)</sup>

```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
    require(msg.sender == entryPoint, "not entryPoint");
    (bool ok,) = target.call{value: value}(data);
    require(ok, "exec failed");
}
```

## 2) Unsigned or unchecked gas fields -> fee drain
If signature validation only covers intent (`callData`) but not gas-related fields, a bundler or frontrunner can inflate fees and drain ETH. The signed payload must bind at least:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: use the `EntryPoint`-provided `userOpHash` (which includes gas fields) and/or strictly cap each field.<sup>[[2]](#references)[[5]](#references)</sup>

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
Because all validations run before any execution, storing validation results in contract state is unsafe. Another op in the same bundle can overwrite it, causing your execution to use attacker-influenced state.<sup>[[2]](#references)</sup>

Avoid writing storage in `validateUserOp`. If unavoidable, key temporary data by `userOpHash` and delete it deterministically after use (prefer stateless validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` must bind signatures to **this contract** and **this chain**. Recovering over a raw hash lets signatures replay across accounts or chains.<sup>[[1]](#references)[[4]](#references)</sup>

Use EIP-712 typed data (domain includes `verifyingContract` and `chainId`) and return the exact ERC-1271 magic value `0x1626ba7e` on success.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
Once `validateUserOp` succeeds, fees are committed even if execution later reverts. Attackers can repeatedly submit ops that will fail and still collect fees from the account.<sup>[[2]](#references)</sup>

For paymasters, paying from a shared pool in `validateUserOp` and charging users in `postOp` is fragile because `postOp` can revert without undoing the payment. Secure funds during validation (per-user escrow/deposit), keep `postOp` minimal and non-reverting, and budget `paymasterPostOpGasLimit` for the worst-case reimbursement path.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
The first `UserOperation` often carries `initCode`, which causes the account to be deployed through a **factory** during validation. This path is easy to under-audit because it only runs on first use.<sup>[[5]](#references)</sup>

Common failures include:<sup>[[5]](#references)</sup>

- The factory/initializer trusts `msg.sender == entryPoint`, but the ERC-4337 deployment path does **not** call `initCode` directly from `EntryPoint`.
- The salt, owner, validator, or module configuration is not fully bound to signed intent, so a frontrunner can race the first deployment and burn the counterfactual address with attacker-controlled settings.
- The factory is non-idempotent, so a repeated first-use flow bricks the wallet instead of returning the already-created address.

Safe pattern: recompute the expected sender from signed deployment parameters, make deployment deterministic (typically `CREATE2`), and make initialization one-shot.<sup>[[5]](#references)</sup>

```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```

## 7) Validation logic that bundlers reject
Validation code can be correct in local tests and still be unusable in real bundlers. Bundlers run validation multiple times and should perform a traced full-bundle validation before submission.<sup>[[6]](#references)</sup>

Under those validation-scope rules, these patterns are dangerous:<sup>[[6]](#references)</sup>

- Block-dependent opcodes such as `TIMESTAMP`, `NUMBER`, or `BLOCKHASH`
- Storage access outside the allowed account/entity scope, or unbounded iteration over storage
- External calls or oracle reads that depend on mutable state outside the allowed validation scope

Bad example:

```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
    external
    returns (uint256)
{
    require(block.timestamp < expiry, "expired");
    seen[userOpHash] = true; // stateful validation can be clobbered by another op
    require(oracle.isAllowed(op.sender), "oracle changed");
    return 0;
}
```

Treat validation as a deterministic, bounded preflight function. If shared state or external lookups are necessary, follow the staked-entity rules and test the same multi-pass bundler simulation path, not just unit tests.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 gives an EOA a persistent delegation to smart-account code; the delegation does not run initialization atomically. If initialization is externally callable, an observer can front-run it and set themselves as owner.<sup>[[7]](#references)</sup>

Mitigation: require initialization calldata to be authorized by the EOA and allow initialization only once. In an ERC-4337 EIP-7702 flow, also restrict the caller to `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>

```solidity
function initialize(address newOwner, bytes calldata initSig) external {
    require(owner == address(0), "already inited");
    // Verify the EOA's signature over the complete initialization calldata.
    require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
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
- Run the bundler's multi-pass validation and a traced full-bundle check before shipping.
- For ERC-7702, bind init to EOA authorization and allow it only once; in ERC-4337 flows, restrict the caller to `EntryPoint.senderCreator()`.

## References

- [1] [ERC1271 Replay - 15+ Teams Affected (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Six mistakes in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standard Signature Validation Method for Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Set Code for EOAs](https://eips.ethereum.org/EIPS/eip-7702)

{{#include ../../banners/hacktricks-training.md}}
