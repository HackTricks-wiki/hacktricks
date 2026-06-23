# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction は、ウォレットをプログラム可能なシステムに変える。中核のフローは、バンドル全体に対する **validate-then-execute** である: `EntryPoint` は、どれかを実行する前にすべての `UserOperation` を検証する。この順序は、validation が permissive だったり、stateful だったり、bundler の simulation rules と不整合だったりすると、明白ではない attack surface を生む。

## 1) Direct-call bypass of privileged functions
`EntryPoint`（または検証済みの executor module）に限定されていない、外部から呼び出し可能な `execute`（または資金移動系の）関数は、直接呼び出されて account を drain されうる。
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全なパターン: `EntryPoint` に制限し、admin/self-management フロー（module install、validator changes、upgrades）では `msg.sender == address(this)` を使用する。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未署名または未チェックの gas フィールド -> fee drain
signature validation が intent（`callData`）のみをカバーし、gas 関連フィールドをカバーしない場合、bundler や frontrunner が fee を膨らませて ETH を drain できます。signed payload には少なくとも以下を bind する必要があります:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御パターン: `EntryPoint` が提供する `userOpHash`（gas フィールドを含む）を使う、または各フィールドを厳密に cap する。
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
すべての validation は any execution の前に実行されるため、validation 結果を contract state に保存するのは unsafe です。同じ bundle 内の別の op がそれを書き換え、execution が attacker-influenced state を使う原因になります。

`validateUserOp` で storage に書き込まないでください。避けられない場合は、一時データを `userOpHash` で key 付けし、使用後に deterministically に削除してください（prefer stateless validation）。

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` は signature を **this contract** と **this chain** に bind しなければなりません。raw hash に対して recover すると、signature が accounts や chains をまたいで replay されます。

EIP-712 typed data を使い（domain に `verifyingContract` と `chainId` を含める）、成功時は exact な ERC-1271 magic value `0x1626ba7e` を返してください。

## 5) Reverts do not refund after validation
一度 `validateUserOp` が成功すると、その後 execution が revert しても fee は確定します。attacker は失敗する op を繰り返し submit しても、account から fee を回収できます。

paymaster では、`validateUserOp` で shared pool から支払い、`postOp` で user に charge する設計は fragile です。`postOp` は payment を元に戻さずに revert する可能性があるためです。validation 中に funds を secure し（per-user escrow/deposit）、`postOp` は minimal かつ non-reverting に保ち、最悪ケースの reimbursement path に対して `paymasterPostOpGasLimit` を budget してください。

## 6) Counterfactual deployment / factory assumptions
最初の `UserOperation` はしばしば `initCode` を含み、validation 中に account が **factory** 経由で deploy されます。この path は first use のときにしか動かないため、under-audit になりやすいです。

よくある failure:

- factory/initializer が `msg.sender == entryPoint` を trust しているが、ERC-4337 の deployment path は `EntryPoint` から `initCode` を直接呼び出しません。
- salt, owner, validator, または module configuration が signed intent に完全に bind されておらず、frontrunner が最初の deployment を race して attacker-controlled settings で counterfactual address を burn できます。
- factory が non-idempotent で、first-use flow が繰り返されると、すでに作成済みの address を返す代わりに wallet が brick されます。

safe pattern: signed deployment parameters から expected sender を再計算し、deployment を deterministic にし（通常は `CREATE2`）、initialization を one-shot にしてください。
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers が拒否する validation logic
validation code はローカルテストでは正しく動いても、実際の bundlers では使えないことがあります。Public bundlers は `validateUserOp()` / `validatePaymasterUserOp()` を off-chain でシミュレートし、通常は inclusion 前に完全な `debug_traceCall(handleOps)` を実行します。

そのため、validation 内では次の pattern が危険です:

- `TIMESTAMP`, `NUMBER`, `BLOCKHASH` のような block-dependent opcodes
- `SSTORE` のような state writes
- storage に対する unbounded iteration
- simulation と inclusion の間で変化しうる arbitrary external calls や oracle reads

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
検証を deterministic な、境界が明確な preflight function として扱ってください。どうしても shared state や external lookups が必要なら、その複雑さは staked/reputation-tracked entities に押し込み、unit tests だけでなく exact bundler simulation path をテストしてください。

## 8) ERC-7702 initialization frontrun
ERC-7702 は EOA が 1 回の tx で smart-account code を実行することを可能にします。initialization が externally callable なら、frontrunner が自分を owner に設定できます。

Mitigation: initialization は **self-call** の場合のみ、かつ 1 回だけ許可してください。
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Quick pre-merge checks
- `EntryPoint` の `userOpHash` を使って署名を検証する（gas フィールドを bind する）。
- 特権関数は、必要に応じて `EntryPoint` および/または `address(this)` のみに制限する。
- `validateUserOp` は stateless で deterministic にし、bundler の simulation rules と互換に保つ。
- ERC-1271 では EIP-712 の domain separation を強制し、成功時は `0x1626ba7e` を返す。
- `postOp` は最小限・bounded・non-reverting に保ち、validation 中に fees を保護する。
- 最初の `initCode` パスは別途テストする: deterministic deployment、idempotent な factory behavior、one-shot initialization。
- リリース前に full bundler simulation（`simulateValidation` に加えて trace 付きの `handleOps`）を実行する。
- ERC-7702 では、init は self-call のみ、かつ 1 回だけ許可する。



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
