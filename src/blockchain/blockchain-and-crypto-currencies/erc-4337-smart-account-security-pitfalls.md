# ERC-4337 Smart AccountのSecurity Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337のaccount abstractionは、walletをprogrammableなsystemに変える。core flowは、bundle全体にわたる **validate-then-execute** である。`EntryPoint`は、いずれかの`UserOperation`をexecuteする前に、すべての`UserOperation`をvalidateする。この順序により、validationがpermissive、stateful、またはbundlerのsimulation rulesと一致していない場合、見落としやすいattack surfaceが生じる。

## 1) privileged functionsのDirect-call bypass
`EntryPoint`（またはvetted executor module）に制限されていない、外部からcall可能な`execute`（またはfund-moving）functionは、accountをdrainするために直接callできる。<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全なパターン: `EntryPoint` に限定し、管理者/自己管理フロー（module install、validator changes、upgrades）では `msg.sender == address(this)` を使用する。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 署名されていない、または検証されていない gas fields -> fee drain
signature validation が intent（`callData`）のみを対象とし、gas-related fields を対象としていない場合、bundler または frontrunner によって fees を引き上げられ、ETH を drain される可能性があります。署名済み payload には、少なくとも以下を紐付ける必要があります:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` が提供する `userOpHash`（gas fields を含む）を使用し、かつ/または各 field に厳格な上限を設定します。<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering（bundle semantics）
すべての validation は execution より前に実行されるため、validation の結果を contract state に保存するのは安全ではありません。同じ bundle 内の別の op がその値を上書きし、execution で attacker-influenced state が使用される可能性があります。<sup>[[1]](#references)</sup>

`validateUserOp` 内で storage に書き込むことは避けてください。避けられない場合は、一時データを `userOpHash` で keying し、使用後に確実に削除してください（stateless validation が望ましい）。<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains（missing domain separation）
`isValidSignature(bytes32 hash, bytes sig)` は、署名を **この contract** と **この chain** に bind する必要があります。raw hash に対して recover すると、署名が複数の account や chain 間で replay される可能性があります。<sup>[[1]](#references)</sup>

EIP-712 typed data を使用し（domain に `verifyingContract` と `chainId` を含める）、成功時には正確な ERC-1271 magic value `0x1626ba7e` を返してください。<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` が成功すると、その後 execution が revert しても fee は確定します。攻撃者は失敗する ops を繰り返し submit し、それでも account から fee を徴収できます。<sup>[[1]](#references)</sup>

paymaster では、`validateUserOp` で shared pool から支払い、`postOp` で users に請求する設計は脆弱です。`postOp` が payment を取り消さずに revert する可能性があるためです。validation 中に資金を確保し（per-user escrow/deposit）、`postOp` は最小限かつ non-reverting にし、最悪時の reimbursement path に備えて `paymasterPostOpGasLimit` を設定してください。<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
最初の `UserOperation` は、多くの場合 `initCode` を含みます。これにより、validation 中に **factory** を通じて account が deploy されます。この path は初回使用時にしか実行されないため、audit が不十分になりやすいものです。<sup>[[2]](#references)</sup>

よくある失敗：

- factory/initializer が `msg.sender == entryPoint` を信頼している。しかし ERC-4337 の deployment path では、`EntryPoint` から直接 `initCode` が call されるわけではありません。
- salt、owner、validator、または module configuration が signed intent に完全には bind されていない。そのため frontrunner が最初の deployment を race し、attacker-controlled settings で counterfactual address を burn できます。
- factory が non-idempotent である。そのため、初回使用フローが繰り返されると、すでに作成済みの address を返す代わりに wallet が brick されます。

安全な pattern：signed deployment parameters から expected sender を再計算し、deployment を deterministic にし（通常は `CREATE2`）、initialization を one-shot にします。<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundler が拒否する validation ロジック
validation コードはローカルテストでは正しく動作していても、実際の bundler では使用できない場合があります。Public bundler は off-chain で `validateUserOp()` / `validatePaymasterUserOp()` をシミュレートし、通常は inclusion 前に完全な `debug_traceCall(handleOps)` を実行します。<sup>[[3]](#references)</sup>

そのため、validation 内では次のパターンが危険です。

- `TIMESTAMP`、`NUMBER`、`BLOCKHASH` などのブロック依存 opcode
- `SSTORE` などの state write
- storage に対する上限のない反復処理
- simulation と inclusion の間で変化する可能性がある、任意の external call や oracle read

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
Validation は、決定論的で bounded な preflight function として扱います。本当に共有 state や外部 lookup が必要な場合は、その複雑性を staked/reputation-tracked entities に移し、unit tests だけでなく、正確な bundler simulation path をテストしてください。

## 8) ERC-7702 initialization frontrun
ERC-7702 により、EOA は単一の tx で smart-account code を実行できます。initialization が externally callable である場合、frontrunner は自分自身を owner に設定できます。<sup>[[1]](#references)</sup>

Mitigation: initialization は **self-call** の場合に限って許可し、かつ一度だけ実行できるようにします。<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## pre-merge 前の簡易チェック
- `EntryPoint` の `userOpHash` を使用して署名を検証する（gas fields をバインドする）。
- 適切に、privileged functions のアクセスを `EntryPoint` および/または `address(this)` に制限する。
- `validateUserOp` は stateless かつ deterministic に保ち、bundler simulation のルールと互換性を持たせる。
- ERC-1271 に対して EIP-712 domain separation を強制し、成功時には `0x1626ba7e` を返す。
- `postOp` は最小限かつ bounded で non-reverting にし、validation 中に fees を secure にする。
- 最初の `initCode` path を個別にテストする：deterministic deployment、idempotent な factory の動作、one-shot initialization。
- リリース前に、完全な bundler simulation（`simulateValidation` と traced `handleOps`）を実行する。
- ERC-7702 では、init を self-call 時にのみ、かつ一度だけ許可する。

## References

- [1] [ERC-4337 smart accounts における6つのミス（Trail of Bits）](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Alt Mempool を使用した Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
