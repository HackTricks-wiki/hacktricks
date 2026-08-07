# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 개요

콜드 월렛 탈취 chain은 **Safe{Wallet} 웹 UI의 supply-chain compromise**와 **on-chain delegatecall primitive를 통한 proxy의 implementation pointer(slot 0) 덮어쓰기**를 결합했습니다. 핵심 내용은 다음과 같습니다.

- dApp이 signing path에 code를 주입할 수 있다면, 다른 signer들이 알아채지 못하도록 원래 UI data를 복원하면서도 signer가 attacker가 선택한 fields에 대한 유효한 **EIP-712 signature**<sup>[[4]](#references)</sup>를 생성하게 만들 수 있습니다.
- Safe proxy는 `masterCopy`(implementation)를 **storage slot 0**에 저장합니다. slot 0에 기록하는 contract로 delegatecall을 수행하면 사실상 Safe가 attacker logic으로 “upgrade”되어 wallet에 대한 full control을 얻을 수 있습니다.

## Off-chain: Safe{Wallet}에서의 targeted signing mutation

변조된 Safe bundle(`_app-*.js`)은 특정 Safe 및 signer addresses를 선택적으로 공격했습니다. 주입된 logic은 signing call 직전에 실행되었습니다:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: 피해자 Safe/서명자에 대한 하드코딩된 allowlist가 불필요한 노이즈를 방지하고 탐지 가능성을 낮췄다.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: 필드(`to`, `data`, `operation`, gas)가 `signTransaction` 직전에 덮어써진 후 되돌려졌기 때문에, UI의 proposal payload는 정상적으로 보이는 반면 signature는 공격자 payload와 일치했다.
- **EIP-712 opacity**: wallet은 structured data를 표시했지만 nested calldata를 decode하거나 `operation = delegatecall`을 강조하지 않았으므로, 변조된 message는 사실상 blind-signed되었다.

### Gateway validation relevance
Safe proposal은 **Safe Client Gateway**로 제출된다.<sup>[[5]](#references)</sup> 강화된 check가 적용되기 전에는 UI가 signing 후 값을 다시 작성한 경우, JSON body의 필드와 다른 `safeTxHash`/signature에 해당하는 proposal도 gateway가 수락할 수 있었다. incident 이후 gateway는 hash/signature가 제출된 transaction과 일치하지 않는 proposal을 거부한다. 유사한 server-side hash verification은 모든 signing-orchestration API에도 적용되어야 한다.

### 2025 Bybit/Safe incident highlights
- 2025년 2월 21일 Bybit cold-wallet drain(약 401k ETH)은 동일한 pattern을 재사용했다. 손상된 Safe S3 bundle은 Bybit signer에 대해서만 실행되었으며 `operation=0`을 `1`로 바꾸고, slot 0에 값을 쓰는 사전 배포된 공격자 contract를 `to`로 지정했다.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback에 cache된 `_app-52c9031bfa03da47.js`는 Bybit의 Safe(`0x1db9…cf4`) 및 signer address를 기준으로 logic을 실행한 뒤, execution 2분 후 즉시 정상 bundle로 되돌린 사실을 보여준다. 이는 “mutate → sign → restore” trick을 그대로 재현한다.<sup>[[1]](#references)[[2]](#references)</sup>
- 악성 contract(예: `0x9622…c7242`)에는 단순한 `sweepETH/sweepERC20` function과 implementation slot에 값을 쓰는 `transfer(address,uint256)`가 포함되어 있었다. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))`을 실행하면 proxy implementation이 변경되고 full control이 부여된다.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: slot collision을 통한 Delegatecall proxy takeover

Safe proxy는 **storage slot 0**에 `masterCopy`를 유지하고 모든 logic을 해당 주소로 delegate한다. Safe는 **`operation = 1` (delegatecall)**을 지원하므로, 서명된 모든 transaction이 임의의 contract를 지정하고 proxy의 storage context에서 해당 contract의 code를 실행할 수 있다.<sup>[[3]](#references)</sup>

공격자 contract는 ERC-20 `transfer(address,uint256)`를 모방했지만, 대신 `_to`를 slot 0에 기록했다:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
실행 경로:<sup>[[1]](#references)[[3]](#references)</sup>
1. 피해자는 `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`인 `execTransaction`에 서명합니다.
2. Safe masterCopy는 이러한 매개변수에 대한 서명을 검증합니다.
3. Proxy는 `attackerContract`로 delegatecall을 수행하고, `transfer` 본문은 slot 0에 값을 씁니다.
4. 이제 slot 0(`masterCopy`)이 attacker가 제어하는 로직을 가리키므로 → **전체 wallet takeover 및 자금 drain**이 발생합니다.

### Guard 및 버전 참고 사항 (사고 후 hardening)
- Safes >= v1.3.0은 **Guard**를 설치하여 `delegatecall`을 거부하거나 `to`/selectors에 ACL을 적용할 수 있습니다. Bybit은 v1.1.1을 실행했으므로 Guard hook이 존재하지 않았습니다. 이 control plane을 확보하려면 contract를 upgrade하고 owners를 다시 추가해야 합니다.

## Detection 및 hardening 체크리스트

- **UI 무결성**: JS asset / SRI를 pin하고, bundle diff를 모니터링하며, signing UI를 trust boundary의 일부로 취급합니다.
- **서명 시 validation**: **EIP-712 clear-signing**을 지원하는 hardware wallet을 사용하고, `operation`을 명시적으로 표시하며 nested calldata를 decode합니다. 정책에서 허용하지 않는 한 `operation = 1`일 때 서명을 거부합니다.
- **Server-side hash checks**: proposal을 relay하는 gateway/service는 `safeTxHash`를 다시 계산하고, 서명이 제출된 field와 일치하는지 검증해야 합니다.
- **정책/allowlist**: `to`, selector, asset type에 대한 preflight rule을 적용하고, 검증된 flow를 제외한 delegatecall을 금지합니다. 완전히 서명된 transaction을 broadcast하기 전에 내부 policy service를 거치도록 요구합니다.
- **Contract design**: 엄격히 필요한 경우가 아니라면 multisig/treasury wallet에서 임의의 delegatecall을 노출하지 않습니다. upgrade pointer를 slot 0에서 떨어진 위치에 배치하거나 명시적인 upgrade logic 및 access control로 보호합니다.
- **Monitoring**: treasury fund를 보유한 wallet에서 delegatecall이 실행되는 경우와, 일반적인 `call` pattern에서 `operation`을 변경하는 proposal에 대해 alert를 발생시킵니다.

## References

- [1] [Bybit Safe exploit에 대한 AnChain.AI forensic 분석](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise에 대한 Zero Hour Technology 분석](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack에 대한 심층 technical 분석 (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
