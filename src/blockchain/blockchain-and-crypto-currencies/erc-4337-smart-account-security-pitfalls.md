# ERC-4337 Smart Accountのセキュリティ上の落とし穴

{{#include ../../banners/hacktricks-training.md}}

ERC-4337のaccount abstractionは、walletをprogrammableなシステムへと変える。基本的なフローは、bundle全体にわたる **validate-then-execute** である。`EntryPoint`は、いずれかを実行する前に、すべての`UserOperation`をvalidateする。この順序により、validationが寛容、stateful、またはbundlerのsimulationルールと一貫していない場合、見落としやすいattack surfaceが生じる。

## 1) privileged functionのDirect-call bypass
`EntryPoint`（または検証済みのexecutor module）に制限されていない、外部からcall可能な`execute`（またはfundを移動する）functionは、accountをdrainするために直接callできる。<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全なパターン: `EntryPoint` に限定し、管理者/自己管理フロー（モジュールのインストール、validator の変更、アップグレード）では `msg.sender == address(this)` を使用する。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 署名されていない、またはチェックされていない gas フィールド -> 手数料の流出
signature validation が intent（`callData`）のみを対象とし、gas 関連フィールドを対象としていない場合、bundler または frontrunner は手数料を吊り上げて ETH を流出させる可能性があります。署名済み payload では、少なくとも以下を関連付ける必要があります。<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御パターン: `EntryPoint` が提供する `userOpHash`（gas フィールドを含む）を使用する、または各フィールドに厳格な上限を設定します。<sup>[[1]](#references)</sup>
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
すべての validation は execution の前に実行されるため、validation の結果を contract state に保存するのは安全ではありません。同じ bundle 内の別の op がその値を上書きし、execution で attacker に影響された state が使用される可能性があります。<sup>[[1]](#references)</sup>

`validateUserOp` 内で storage に書き込むのは避けてください。避けられない場合は、一時データを `userOpHash` ごとに key 付けし、使用後に決定論的に削除してください（stateless validation を優先）。<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains（missing domain separation）
`isValidSignature(bytes32 hash, bytes sig)` は、署名を**この contract**および**この chain**に bind する必要があります。raw hash に対して recover すると、署名が複数の account や chain 間で replay される可能性があります。<sup>[[1]](#references)</sup>

EIP-712 typed data を使用し（domain に `verifyingContract` と `chainId` を含める）、成功時には正確な ERC-1271 magic value `0x1626ba7e` を返してください。<sup>[[1]](#references)</sup>

## 5) validation 後の revert では refund されない
`validateUserOp` が成功すると、その後の execution が revert しても fee は確定します。攻撃者は失敗する op を繰り返し submit し、それでも account から fee を徴収できます。<sup>[[1]](#references)</sup>

paymaster については、`validateUserOp` で shared pool から支払い、`postOp` で users に請求する方法は脆弱です。これは `postOp` が payment を取り消さずに revert する可能性があるためです。validation 中に funds を確保し（user ごとの escrow/deposit）、`postOp` は最小限かつ non-reverting に保ち、最悪ケースの reimbursement path に備えて `paymasterPostOpGasLimit` を budget してください。<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
最初の `UserOperation` は、多くの場合 `initCode` を含みます。これにより validation 中に **factory** 経由で account が deploy されます。この path は初回使用時にしか実行されないため、audit が不十分になりやすいものです。<sup>[[2]](#references)</sup>

よくある失敗：

- factory/initializer が `msg.sender == entryPoint` を信頼しているが、ERC-4337 の deployment path では `EntryPoint` から直接 `initCode` を call しません。
- salt、owner、validator、または module configuration が signed intent に完全には bind されていないため、frontrunner が最初の deployment で race を仕掛け、attacker が制御する設定で counterfactual address を先に確保できる。
- factory が non-idempotent であるため、初回使用時の flow が繰り返されると、すでに作成済みの address を返す代わりに wallet が使用不能になる。

安全な pattern：signed deployment parameters から expected sender を再計算し、deployment を deterministic にし（通常は `CREATE2`）、initialization を one-shot にしてください。<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers が拒否する Validation ロジック
Validation code は local tests では正しく動作していても、実際の bundlers では使用できない場合があります。Public bundlers は off-chain で `validateUserOp()` / `validatePaymasterUserOp()` を simulate し、通常は inclusion 前に完全な `debug_traceCall(handleOps)` も実行します。

そのため、Validation 内で次のパターンを使用するのは危険です。

- `TIMESTAMP`、`NUMBER`、`BLOCKHASH` などの block に依存する opcode
- `SSTORE` などの state write
- storage に対する unbounded iteration
- simulation と inclusion の間で変化する可能性がある arbitrary external call や oracle read

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
Validationは、決定論的で上限のあるpreflight関数として扱います。本当に共有stateや外部lookupが必要な場合は、その複雑性をstake済みまたはreputation-trackedなエンティティに移し、unit testsだけでなく、正確なbundler simulation pathをテストしてください。

## 8) ERC-7702 initialization frontrun
ERC-7702では、EOAが単一のtxでsmart-account codeを実行できます。initializationが外部からcall可能な場合、frontrunnerは自分自身をownerに設定できます。<sup>[[1]](#references)</sup>

Mitigation: initializationは**self-call**の場合にのみ、かつ一度だけ許可します。<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## pre-merge のクイックチェック
- `EntryPoint` の `userOpHash` を使用して署名を検証する（gas フィールドをバインドする）。
- 適切に、privileged functions を `EntryPoint` および/または `address(this)` に制限する。
- `validateUserOp` は stateless、deterministic に保ち、bundler の simulation ルールと互換性を持たせる。
- ERC-1271 に EIP-712 domain separation を適用し、成功時には `0x1626ba7e` を返す。
- `postOp` は最小限で、bounded かつ non-reverting に保ち、validation 中に fee を secure にする。
- 最初の `initCode` パスを個別にテストする：deterministic deployment、idempotent な factory の動作、one-shot initialization。
- リリース前に、完全な bundler simulation（`simulateValidation` と trace 付きの `handleOps`）を実行する。
- ERC-7702 では、self-call の場合に限って init を許可し、1 回のみ実行できるようにする。



## References

- [1] [ERC-4337 smart accounts における 6 つの間違い（Trail of Bits）](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337：Alt Mempool を使用した Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
