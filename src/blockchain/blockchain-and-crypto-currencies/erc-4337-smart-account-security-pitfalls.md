# ERC-4337 スマートアカウントのセキュリティ上の落とし穴

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 の account abstraction は、ウォレットを programmable system に変える。中核となるフローは、bundle 全体にわたる **validate-then-execute** である。`EntryPoint` は、いずれかを execute する前に、すべての `UserOperation` を validate する。<sup>[[5]](#references)</sup> この順序により、validation が permissive、stateful、または bundler の simulation rules と一貫していない場合、見落としやすい attack surface が生じる。

## 1) privileged functions の direct-call bypass
`EntryPoint`（または審査済みの executor module）に制限されていない、外部から call 可能な `execute`（または資金を移動する）function は、account を drain するために直接 call できる。<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全なパターン: `EntryPoint` に制限し、管理者／self-management フロー（module のインストール、validator の変更、アップグレード）では `msg.sender == address(this)` を使用します。<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 署名されていない、または検証されていない gas フィールド -> fee drain
署名検証が intent（`callData`）のみを対象とし、gas 関連フィールドを対象としていない場合、bundler や frontrunner は手数料を水増しして ETH を drain できます。署名済み payload には、少なくとも以下をバインドする必要があります:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` が提供する `userOpHash`（gas フィールドを含む）を使用し、かつ各フィールドに厳格な上限を設定します。<sup>[[2]](#references)[[5]](#references)</sup>
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
すべての validation は execution より前に実行されるため、validation の結果を contract state に保存するのは安全ではありません。同じ bundle 内の別の op がその値を上書きし、execution が attacker に影響された state を使用する可能性があります。<sup>[[2]](#references)</sup>

`validateUserOp` 内で storage に書き込むことは避けてください。避けられない場合は、一時データを `userOpHash` ごとに key 付けし、使用後に deterministic に削除してください（stateless validation を優先）。<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains（missing domain separation）
`isValidSignature(bytes32 hash, bytes sig)` は、署名を **この contract** および **この chain** に bind する必要があります。raw hash に対して recover すると、署名が複数の account や chain 間で replay されます。<sup>[[1]](#references)[[4]](#references)</sup>

EIP-712 typed data（domain に `verifyingContract` と `chainId` を含める）を使用し、成功時には正確な ERC-1271 magic value `0x1626ba7e` を返してください。<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` が成功すると、その後の execution が revert しても fees は確定します。攻撃者は失敗する op を繰り返し submit し、それでも account から fees を徴収できます。<sup>[[2]](#references)</sup>

paymaster では、`validateUserOp` で shared pool から支払い、`postOp` で users に請求する設計は脆弱です。`postOp` が revert しても支払いは取り消されない可能性があるためです。validation 中に資金を secure し（user ごとの escrow/deposit）、`postOp` は最小限かつ non-reverting に保ち、最悪ケースの reimbursement path に備えて `paymasterPostOpGasLimit` を設定してください。<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
最初の `UserOperation` には `initCode` が含まれることが多く、validation 中に **factory** を通じて account が deploy されます。この path は初回利用時にしか実行されないため、audit が不十分になりやすい箇所です。<sup>[[5]](#references)</sup>

一般的な失敗には次のようなものがあります。<sup>[[5]](#references)</sup>

- factory/initializer が `msg.sender == entryPoint` を信頼している。しかし ERC-4337 の deployment path では、`EntryPoint` から `initCode` を直接 call しません。
- salt、owner、validator、または module configuration が signed intent に完全には bind されていない。そのため、frontrunner が最初の deployment と race し、attacker が制御する設定で counterfactual address を burn できます。
- factory が non-idempotent である。そのため、初回利用フローが繰り返されると、すでに作成された address を返す代わりに wallet が使用不能になります。

安全な pattern は、signed deployment parameters から expected sender を再計算し、deployment を deterministic にし（通常は `CREATE2`）、initialization を one-shot にすることです。<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundler が拒否する Validation ロジック
Validation code はローカルテストでは正しくても、実際の bundler では使用できない場合があります。bundler は validation を複数回実行するため、submission 前に traced full-bundle validation を実行する必要があります。<sup>[[6]](#references)</sup>

これらの validation-scope ルールでは、次のパターンは危険です。<sup>[[6]](#references)</sup>

- `TIMESTAMP`、`NUMBER`、`BLOCKHASH` などの block-dependent opcode
- 許可された account/entity scope 外への Storage access、または Storage に対する unbounded iteration
- 許可された validation scope 外の mutable state に依存する external call や oracle read

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
検証は、決定論的で範囲が限定された preflight function として扱います。共有状態または外部 lookup が必要な場合は、staked-entity のルールに従い、unit tests だけでなく、同じ複数パスの bundler simulation path をテストしてください。<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 は EOA に smart-account code への永続的な delegation を付与しますが、その delegation は initialization を atomic に実行しません。initialization が外部から callable な場合、observer はそれを front-run して、自分自身を owner に設定できます。<sup>[[7]](#references)</sup>

Mitigation: initialization calldata が EOA によって authorized されていることを要求し、initialization を一度だけ許可します。ERC-4337 の EIP-7702 flow では、caller を `EntryPoint.senderCreator()` にも制限してください。<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## pre-merge のクイックチェック
- `EntryPoint` の `userOpHash` を使用して signatures を検証する（gas fields を bind する）。
- 必要に応じて、privileged functions を `EntryPoint` および／または `address(this)` に制限する。
- `validateUserOp` は stateless、deterministic に保ち、bundler の simulation rules と互換性を持たせる。
- ERC-1271 に EIP-712 domain separation を適用し、成功時に `0x1626ba7e` を返す。
- `postOp` は minimal、bounded、non-reverting に保ち、validation 中に fees を secure にする。
- 最初の `initCode` path は個別に test する：deterministic deployment、idempotent な factory behavior、one-shot initialization。
- shipping 前に、bundler の multi-pass validation と traced full-bundle check を実行する。
- ERC-7702 では init を EOA authorization に bind して一度だけ許可し、ERC-4337 flows では caller を `EntryPoint.senderCreator()` に制限する。

## References

- [1] [ERC1271 Replay - 15以上の Teams に影響 (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart accounts における6つの mistakes (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Contracts 向けの Standard Signature Validation Method](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data の hashing と signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Alt Mempool を使用した Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: EOA に対する Set Code](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
