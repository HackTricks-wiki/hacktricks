# Web3 Signing Workflow の侵害と Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概要

コールドウォレットの窃取チェーンでは、**Safe{Wallet} web UI の supply-chain compromise**と、**proxy の implementation pointer（slot 0）を上書きする on-chain delegatecall primitive**が組み合わされていました。主なポイントは次のとおりです。

- dApp が signing path に code を inject できる場合、他の signer に気付かれないよう元の UI data を復元しながら、signer に攻撃者が選択した fields に対する有効な **EIP-712 signature**を生成させられます。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies は `masterCopy`（implementation）を **storage slot 0** に保存します。slot 0 に書き込む contract への delegatecall により、実質的に Safe を攻撃者の logic に「upgrade」でき、wallet を完全に制御できます。<sup>[[3]](#references)</sup>

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
### Attack properties
- **Context-gated**: 被害者の Safe/signers に対するハードコードされた allowlist により、ノイズを防ぎ、検知可能性を下げていた。<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: (`to`、`data`、`operation`、gas) フィールドは `signTransaction` の直前に上書きされ、その後元に戻された。そのため UI 上の proposal payload は無害に見えながら、署名は attacker payload と一致していた。<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallet は structured data を表示したが、nested calldata を decode したり、`operation = delegatecall` を強調表示したりしなかったため、変更後の message は実質的に blind-signed された。<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway validation relevance
Safe proposals は **Safe Client Gateway** に送信される。<sup>[[5]](#references)</sup> hardened checks の導入前は、UI が signing 後に値を書き換えた場合、JSON body のフィールドとは異なる `safeTxHash`/signature に対応する proposal を gateway が受け入れる可能性があった。incident 後、gateway は hash/signature が送信された transaction と一致しない proposal を拒否するようになった。<sup>[[3]](#references)</sup> 同様の server-side hash verification を、あらゆる signing-orchestration API に適用すべきである。

### 2025 Bybit/Safe incident highlights
- 2025 年 2 月 21 日の Bybit cold-wallet drain（約 401k ETH）では、同じ pattern が再利用された。compromised Safe S3 bundle は Bybit signers に対してのみ trigger し、`operation=0` → `1` に swap して、slot 0 に書き込む pre-deployed attacker contract を `to` に指定した。<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback に cache された `_app-52c9031bfa03da47.js` には、Bybit の Safe（`0x1db9…cf4`）と signer addresses を key にして logic を実行し、その後 execution の 2 分後に clean bundle へ直ちに rollback する処理が示されており、「mutate → sign → restore」trick を再現している。<sup>[[1]](#references)[[2]](#references)</sup>
- malicious contract（例: `0x9622…c7242`）には、単純な `sweepETH/sweepERC20` functions と、implementation slot に書き込む `transfer(address,uint256)` が含まれていた。`execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` の execution により proxy implementation が変更され、full control が付与された。<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies は **storage slot 0** に `masterCopy` を保持し、すべての logic をそこへ delegate する。Safe は **`operation = 1` (delegatecall)** をサポートしているため、署名済みの任意の transaction で arbitrary contract を指定し、その code を proxy の storage context 内で execute できる。<sup>[[3]](#references)</sup>

attacker contract は ERC-20 の `transfer(address,uint256)` を mimic していたが、代わりに `_to` を slot 0 に書き込んだ。<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
実行経路:<sup>[[1]](#references)[[3]](#references)</sup>
1. 被害者は `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)` を指定した `execTransaction` に署名する。
2. Safe masterCopy は、これらのパラメータに対する署名を検証する。
3. Proxy は `attackerContract` に delegatecall し、`transfer` 本体が slot 0 に書き込む。
4. Slot 0（`masterCopy`）が攻撃者の制御するロジックを指すようになる → **ウォレットの完全な乗っ取りと資金流出**。

### Guard とバージョンに関する注記（インシデント後の hardening）
- Transaction guards は Safe v1.3.0 で導入され、実行前にすべての `execTransaction` パラメータを検査できる。Guard により `delegatecall` を拒否したり、宛先と calldata に対するポリシーを適用したりできる。Bybit は、この hook より前のバージョンである v1.1.1 を使用していた。<sup>[[2]](#references)[[6]](#references)</sup>

## Detection & hardening checklist

- **UI の完全性**: JS assets / SRI を pin し、bundle の差分を監視する。署名 UI を trust boundary の一部として扱う。
- **署名時の検証**: **EIP-712 clear-signing** に対応した hardware wallets を使用し、`operation` を明示的に表示して nested calldata を decode する。ポリシーで許可されていない限り、`operation = 1` の署名を拒否する。<sup>[[3]](#references)</sup>
- **サーバー側の hash チェック**: proposals を relay する gateways/services は `safeTxHash` を再計算し、署名が送信された fields と一致することを検証する。<sup>[[3]](#references)</sup>
- **ポリシー/allowlists**: `to`、selectors、asset types に対する preflight rules を設定し、審査済みの flow 以外では delegatecall を禁止する。完全に署名された transactions を broadcast する前に、internal policy service を必須にする。
- **Contract design**: 厳密に必要でない限り、multisig/treasury wallets で arbitrary delegatecall を公開しない。implementation pointer は upgrade primitive として扱い、明示的な access control と guard によって delegatecall targets/selectors を保護する。pointer を別の slot に移すだけでは完全な防御にならない。<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: treasury funds を保有する wallets からの delegatecall executions、および通常の `call` patterns から `operation` を変更する proposals に対して alert を発する。

## References

- [1] [Bybit Safe exploit に関する AnChain.AI の forensic breakdown](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise に関する Zero Hour Technology の analysis](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack の詳細な technical analysis（NCC Group）](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway（GitHub）](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog（GitHub）](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
