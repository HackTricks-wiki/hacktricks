# ERC-4337 スマートアカウントのセキュリティ上の落とし穴

{{#include ../../banners/hacktricks-training.md}}

ERC-4337のアカウント抽象化により、ウォレットはプログラム可能なシステムになる。コアフローはバンドル全体に渡る**validate-then-execute**であり、`EntryPoint`はどの`UserOperation`も実行する前にそれぞれを検証する。この順序は、検証が緩かったり状態依存的だったりすると、気付きにくい攻撃表面を生む。

## 1) 特権関数の直接呼び出しによるバイパス
`EntryPoint`（または審査済みのexecutor module）に制限されていない外部から呼び出し可能な`execute`（または資金移動を行う）関数は、アカウントから資金を流出させるために直接呼び出され得る。
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全なパターン: `EntryPoint` に限定し、管理者／自己管理フロー（モジュールのインストール、バリデーターの変更、アップグレード）では `msg.sender == address(this)` を使う。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未署名または未検証のガスフィールド -> 手数料の流出
署名検証が意図（`callData`）のみをカバーし、ガス関連フィールドを含まない場合、bundler や frontrunner によって手数料が水増しされ、ETH が流出する可能性があります。署名済みペイロードは少なくとも次を紐付ける必要があります:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御パターン: `EntryPoint` が提供する `userOpHash`（ガスフィールドを含む）を使用する、または各フィールドに厳格な上限を設ける。
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
すべての検証が実行より先に行われるため、検証結果をコントラクトの状態に保存するのは安全ではありません。同じバンドル内の別の op がそれを上書きし、実行が攻撃者に操作された状態を使用してしまう可能性があります。

`validateUserOp` 内でストレージに書き込むのは避けてください。どうしても必要な場合は一時データを `userOpHash` でキー付けし、使用後に決定論的に削除してください（可能ならステートレスな検証を優先）。

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` は署名を **このコントラクト** および **このチェーン** に結びつける必要があります。生のハッシュでリカバーすると、署名がアカウント間やチェーン間でリプレイされる可能性があります。

EIP-712 の typed data を使用し（domain に `verifyingContract` と `chainId` を含める）、成功時には正確な ERC-1271 のマジック値 `0x1626ba7e` を返してください。

## 5) Reverts do not refund after validation
`validateUserOp` が成功すると、その後の実行が revert しても手数料は確定します。攻撃者は失敗する op を何度も送信してアカウントから手数料を巻き上げることができます。

paymasters に関しては、`validateUserOp` で共有プールから支払い、`postOp` でユーザーに請求する方式は脆弱です。`postOp` が revert しても支払いが取り消されない可能性があるためです。検証中に資金を確保する（ユーザーごとのエスクロー／デポジット）ようにし、`postOp` は最小限かつ revert しないようにしてください。

## 6) ERC-7702 initialization frontrun
ERC-7702 は EOA に単一の tx で smart-account コードを実行させることを可能にします。初期化が外部から呼び出し可能だと、frontrunner が自分をオーナーに設定してしまう可能性があります。

Mitigation: 初期化は **self-call** の場合にのみ、かつ一度だけ許可してください。
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## マージ前のクイックチェック
- `EntryPoint`の`userOpHash`を使用して署名を検証する（ガスフィールドを紐付ける）。
- 特権関数を適宜`EntryPoint`および/または`address(this)`に制限する。
- `validateUserOp`をステートレスに保つ。
- ERC-1271に対してEIP-712のドメイン分離を適用し、成功時に`0x1626ba7e`を返す。
- `postOp`は最小限で上限を設け、リバートしないようにし、検証中に手数料を確保する。
- ERC-7702では、initはself-call時のみかつ一度だけ許可する。

## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
