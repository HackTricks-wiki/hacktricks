# ERC-4337 Smart Account Security Pitfalls

ERC-4337のaccount abstractionは、walletをprogrammableなsystemへと変換します。基本的なflowは、bundle全体にわたる **validate-then-execute** です。`EntryPoint`は、いずれかを実行する前に、すべての`UserOperation`をvalidateします。<sup>[[5]](#references)</sup> この順序により、validationが寛容、stateful、またはbundlerのsimulationルールと一貫していない場合、直感に反するattack surfaceが生じます。

## 1) Direct-call bypass of privileged functions
`EntryPoint`（または検証済みのexecutor module）に制限されていない、外部からcall可能な`execute`（またはfund-moving）functionは、accountをdrainするために直接callできます。<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全なパターン: `EntryPoint` に限定し、管理者/自己管理フロー（module install、validator changes、upgrades）では `msg.sender == address(this)` を使用する。<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 署名されていない、または検証されていない gas フィールド -> fee drain
署名検証が intent (`callData`) のみを対象とし、gas 関連フィールドを対象としていない場合、bundler または frontrunner が手数料を水増しして ETH を drain できる。署名済み payload には、少なくとも以下を紐付ける必要がある:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御パターン: `EntryPoint` が提供する `userOpHash`（gas フィールドを含む）を使用し、かつ各フィールドに厳格な上限を設定する。<sup>[[2]](#references)[[5]](#references)</sup>
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
すべての validation は execution の前に実行されるため、contract state に validation 結果を保存するのは安全ではありません。同じ bundle 内の別の op がその値を上書きし、execution で attacker に影響された state が使用される可能性があります。<sup>[[2]](#references)</sup>

`validateUserOp` で storage に書き込むのは避けてください。避けられない場合は、一時データを `userOpHash` ごとにキー付けし、使用後に決定論的に削除してください（stateless validation を推奨）。<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains（missing domain separation）
`isValidSignature(bytes32 hash, bytes sig)` は、署名を**この contract**および**この chain**にバインドする必要があります。raw hash に対して recover すると、署名が複数の account や chain 間で replay される可能性があります。<sup>[[1]](#references)[[4]](#references)</sup>

EIP-712 typed data を使用し（domain に `verifyingContract` と `chainId` を含める）、成功時には正確な ERC-1271 magic value `0x1626ba7e` を返してください。<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` が成功すると、その後の execution が revert しても fees は確定します。攻撃者は失敗する op を繰り返し submit し、それでも account から fees を徴収できます。<sup>[[2]](#references)</sup>

paymaster については、`validateUserOp` で shared pool から支払い、`postOp` で users に請求する方法は脆弱です。`postOp` が revert しても支払いが取り消されない可能性があるためです。validation 中に資金を確保し（user ごとの escrow/deposit）、`postOp` は最小限かつ non-reverting にし、最悪の reimbursement path に備えて `paymasterPostOpGasLimit` を設定してください。<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
最初の `UserOperation` には `initCode` が含まれることが多く、validation 中に **factory** を介して account が deploy されます。この path は初回使用時にしか実行されないため、audit が不十分になりやすい部分です。<sup>[[5]](#references)</sup>

一般的な失敗には次のようなものがあります。<sup>[[5]](#references)</sup>

- factory/initializer が `msg.sender == entryPoint` を信頼しているが、ERC-4337 の deployment path では `EntryPoint` から `initCode` を直接 call しない。
- salt、owner、validator、または module configuration が signed intent に完全にバインドされていないため、frontrunner が最初の deployment と競合し、attacker が制御する設定で counterfactual address を先に使用できる。
- factory が non-idempotent であるため、初回使用フローが繰り返されると、すでに作成済みの address を返す代わりに wallet が使用不能になる。

Safe pattern: signed deployment parameters から expected sender を再計算し、deployment を deterministic にし（通常は `CREATE2`）、initialization を one-shot にしてください。<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers が拒否するバリデーションロジック
バリデーションコードはローカルテストでは正しく動作しても、実際の bundlers では使用できない場合があります。bundlers はバリデーションを複数回実行するため、送信前に trace された完全な bundle バリデーションを実行する必要があります。<sup>[[6]](#references)</sup>

これらのバリデーションスコープのルールでは、次のパターンは危険です。<sup>[[6]](#references)</sup>

- `TIMESTAMP`、`NUMBER`、`BLOCKHASH` などのブロック依存 opcode
- 許可された account/entity スコープ外への Storage アクセス、または Storage に対する上限のない反復処理
- 許可されたバリデーションスコープ外の mutable state に依存する外部呼び出しまたは oracle 読み取り

悪い例:
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
validationは、決定論的で範囲が限定されたpreflight functionとして扱います。共有stateまたは外部lookupが必要な場合は、staked-entity rulesに従い、unit testsだけでなく、同一のmulti-pass bundler simulation pathをテストします。<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702は、EOAにsmart-account codeへの永続的なdelegationを付与します。このdelegationはinitializationをアトミックには実行しません。initializationが外部からcall可能な場合、observerはそれをfront-runして、自分自身をownerに設定できます。<sup>[[7]](#references)</sup>

Mitigation: initialization calldataがEOAによってauthorizedされていることを要求し、initializationを一度だけ許可します。ERC-4337 EIP-7702 flowでは、callerを`EntryPoint.senderCreator()`にも制限します。<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## マージ前の簡易チェック
- `EntryPoint` の `userOpHash` を使用して署名を検証する（gas フィールドをバインドする）。
- 適切に、特権関数へのアクセスを `EntryPoint` および/または `address(this)` に制限する。
- `validateUserOp` は stateless かつ deterministic にし、bundler のシミュレーションルールに対応させる。
- ERC-1271 に EIP-712 の domain separation を適用し、成功時に `0x1626ba7e` を返す。
- `postOp` は最小限かつ bounded にし、revert しないようにする。validation 中に fees を secure にする。
- 最初の `initCode` パスを個別にテストする：deterministic deployment、idempotent な factory の動作、one-shot initialization。
- リリース前に bundler の multi-pass validation と、trace 付きの full-bundle check を実行する。
- ERC-7702 では init を EOA authorization にバインドし、1 回のみ許可する。ERC-4337 の flows では caller を `EntryPoint.senderCreator()` に制限する。

## References

- [1] [ERC1271 Replay - 15 以上の Teams に影響 (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart accounts における 6 つのミス (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Contracts 向け標準 Signature Validation Method](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data の hashing と signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Alt Mempool を使用した Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: EOAs に Code を設定する](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
