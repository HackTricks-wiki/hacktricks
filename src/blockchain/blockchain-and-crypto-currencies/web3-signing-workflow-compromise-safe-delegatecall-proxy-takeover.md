# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概要

コールドウォレット窃取チェーンでは、Safe{Wallet} web UI の **supply-chain compromise** と、proxy の implementation pointer（**slot 0**）を上書きするオンチェーンの **delegatecall primitive** が組み合わされました。主なポイントは次のとおりです。

- dApp が signing path に code を inject できる場合、signer に攻撃者が指定した fields に対する有効な **EIP-712 signature**<sup>[[4]](#references)</sup>を生成させつつ、他の signer に気付かれないよう元の UI data を復元できます。
- Safe proxy は `masterCopy`（implementation）を **storage slot 0** に保存します。slot 0 に書き込む contract への delegatecall により、実質的に Safe を攻撃者の logic に「upgrade」でき、wallet を完全に制御できます。

## Off-chain: Safe{Wallet} における targeted signing mutation

改ざんされた Safe bundle（`_app-*.js`）は、特定の Safe + signer addresses を選択的に攻撃しました。inject された logic は signing call の直前に実行されました。<sup>[[1]](#references)[[3]](#references)</sup>
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
### 攻撃の特性
- **Context-gated**: 被害者の Safe/signers に対するハードコードされた allowlist により、ノイズを抑え、検知されにくくしていた。<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` の直前にフィールド（`to`、`data`、`operation`、gas）を上書きし、その後元に戻していた。そのため、UI 上の proposal payloads は無害に見えた一方、signatures は attacker payload と一致していた。
- **EIP-712 opacity**: wallets は structured data を表示したが、nested calldata を decode したり、`operation = delegatecall` を強調表示したりしなかったため、mutation された message は実質的に blind-signed されていた。

### Gateway validation relevance
Safe proposals は **Safe Client Gateway** に送信される。<sup>[[5]](#references)</sup> hardened checks が導入される前は、UI が signing 後に値を書き換えた場合、JSON body のフィールドとは異なる `safeTxHash`/signature を持つ proposal を gateway が受け入れる可能性があった。incident 後、gateway は hash/signature が送信された transaction と一致しない proposal を拒否するようになった。同様の server-side hash verification は、あらゆる signing-orchestration API に適用すべきである。

### 2025 Bybit/Safe incident highlights
- 2025 年 2 月 21 日の Bybit cold-wallet drain（約 401k ETH）では、同じパターンが再利用された。compromised Safe S3 bundle は Bybit signers に対してのみ作動し、`operation=0` → `1` に置き換え、`to` を slot 0 に書き込む pre-deployed attacker contract に向けた。<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` には、Bybit の Safe（`0x1db9…cf4`）と signer addresses をキーにして logic を実行し、execution の 2 分後に clean bundle へ即座にロールバックする処理が示されている。これは「mutate → sign → restore」trick と同じである。<sup>[[1]](#references)[[2]](#references)</sup>
- malicious contract（例: `0x9622…c7242`）には、単純な `sweepETH/sweepERC20` functions と、implementation slot に書き込む `transfer(address,uint256)` が含まれていた。`execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` の実行により、proxy implementation が変更され、完全な control が与えられた。<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: slot collision による Delegatecall proxy takeover

Safe proxies は **storage slot 0** に `masterCopy` を保持し、すべての logic をそれに delegate する。Safe は **`operation = 1` (delegatecall)** をサポートしているため、署名済みの任意の transaction から arbitrary contract を指定し、proxy の storage context 内でその code を実行できる。<sup>[[3]](#references)</sup>

attacker contract は ERC-20 の `transfer(address,uint256)` を模倣していたが、代わりに `_to` を slot 0 に書き込んだ。<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. 被害者は `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)` を指定して `execTransaction` に署名する。
2. Safe masterCopy は、これらのパラメータに対する署名を検証する。
3. Proxy は `attackerContract` に delegatecall し、`transfer` の本体が slot 0 に書き込む。
4. slot 0 (`masterCopy`) が攻撃者に制御されたロジックを指すようになり、**wallet の完全な乗っ取りと資金流出**が発生する。

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 では **Guard** をインストールして `delegatecall` を拒否したり、`to`/selectors に ACL を適用したりできる。Bybit は v1.1.1 を実行していたため、Guard hook は存在しなかった。この制御プレーンを利用するには、コントラクトをアップグレードし、owners を再追加する必要がある。

## Detection & hardening checklist

- **UI integrity**: JS assets / SRI を pin し、bundle の差分を監視する。signing UI を trust boundary の一部として扱う。
- **Sign-time validation**: **EIP-712 clear-signing** に対応した hardware wallets を使用し、`operation` を明示的に表示して nested calldata を decode する。ポリシーで許可されていない限り、`operation = 1` の署名を拒否する。
- **Server-side hash checks**: proposal を relay する gateways/services は `safeTxHash` を再計算し、署名が送信された fields と一致することを検証する。
- **Policy/allowlists**: `to`、selectors、asset types に対する preflight ルールを設定し、検証済みの flow を除いて delegatecall を禁止する。完全に署名された transactions を broadcast する前に、internal policy service を必須にする。
- **Contract design**: 厳密に必要な場合を除き、multisig/treasury wallets で arbitrary delegatecall を公開しない。upgrade pointers を slot 0 から離すか、明示的な upgrade logic と access control で保護する。
- **Monitoring**: treasury funds を保有する wallets からの delegatecall executions、および一般的な `call` patterns から `operation` を変更する proposals に対して alert を出す。

## References

- [1] [Bybit Safe exploit に関する AnChain.AI の forensic breakdown](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise に関する Zero Hour Technology の analysis](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack の詳細な technical analysis (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
