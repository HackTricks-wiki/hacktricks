# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **스마트 컨트랙트**는 특정 조건이 충족되면 블록체인에서 실행되는 프로그램으로, 중개자 없이 계약 이행을 자동화합니다.
- **탈중앙화 애플리케이션(dApps)**은 스마트 컨트랙트를 기반으로 구축되며, 사용자 친화적인 프런트엔드와 투명하고 감사 가능한 백엔드를 갖춥니다.
- **토큰 및 코인**은 코인이 디지털 화폐로 사용되는 반면, 토큰은 특정 맥락에서 가치나 소유권을 나타낸다는 점에서 구분됩니다.
  - **유틸리티 토큰**은 서비스 이용 권한을 부여하고, **증권형 토큰**은 자산 소유권을 나타냅니다.
- **DeFi**는 탈중앙화 금융(Decentralized Finance)을 뜻하며, 중앙 기관 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAO**는 각각 탈중앙화 거래소 플랫폼(Decentralized Exchange Platforms)과 탈중앙화 자율 조직(Decentralized Autonomous Organizations)을 의미합니다.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 안전하고 합의된 거래 검증을 보장합니다.

- **작업 증명(Proof of Work, PoW)**은 거래 검증에 연산 능력을 사용합니다.
- **지분 증명(Proof of Stake, PoS)**에서는 검증자가 일정량의 토큰을 보유해야 하며, PoW보다 에너지 소비가 적습니다.<sup>[[1]](#references)</sup>

## 비트코인 기본 사항

### 거래

비트코인 거래는 주소 간에 자금을 전송합니다. 거래는 디지털 서명으로 검증되므로 개인 키의 소유자만 전송을 시작할 수 있습니다.<sup>[[2]](#references)</sup>

#### 주요 구성 요소:

- **다중 서명 거래**는 거래를 승인하기 위해 여러 개의 서명이 필요합니다.<sup>[[3]](#references)</sup>
- 거래는 **입력**(자금 출처), **출력**(목적지), **수수료**(채굴자에게 지급), **스크립트**(거래 규칙)로 구성됩니다.

### 라이트닝 네트워크

채널 내에서 여러 거래를 수행하고 최종 상태만 블록체인에 기록함으로써 비트코인의 확장성을 높이는 것을 목표로 합니다.

## 비트코인 프라이버시 문제

**공통 입력 소유권(Common Input Ownership)** 및 **UTXO 변경 주소 탐지(UTXO Change Address Detection)**와 같은 프라이버시 공격은 거래 패턴을 악용합니다. **믹서(Mixers)** 및 **CoinJoin**과 같은 방법은 사용자 간의 거래 연결을 감춰 익명성을 높입니다.

## 익명으로 비트코인 획득하기

방법으로는 현금 거래, 채굴, 믹서 사용 등이 있습니다. **CoinJoin**은 여러 거래를 혼합해 추적을 어렵게 하고, **PayJoin**은 CoinJoin을 일반 거래처럼 위장해 프라이버시를 강화합니다.

# 비트코인 프라이버시 공격 요약

비트코인 세계에서는 거래의 프라이버시와 사용자의 익명성이 흔히 우려의 대상입니다. 공격자가 비트코인 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법을 간략히 살펴보겠습니다.<sup>[[6]](#references)</sup>

## **공통 입력 소유권 가정**

복잡성 때문에 서로 다른 사용자의 입력이 하나의 거래에 결합되는 경우는 일반적으로 드뭅니다. 따라서 **같은 거래에 있는 두 입력 주소는 흔히 동일한 소유자의 주소로 간주됩니다**.

## **UTXO 변경 주소 탐지**

UTXO, 즉 **미사용 거래 출력(Unspent Transaction Output)**은 거래에서 전액 사용되어야 합니다. 일부만 다른 주소로 보내면 나머지는 새 변경 주소로 전송됩니다. 관찰자는 이 새 주소가 송신자의 주소라고 추정할 수 있으며, 이로 인해 프라이버시가 침해될 수 있습니다.

### 예시

이를 완화하려면 믹싱 서비스를 이용하거나 여러 주소를 사용해 소유 관계를 감출 수 있습니다.

## **소셜 네트워크 및 포럼 노출**

사용자는 때때로 온라인에 비트코인 주소를 공유하며, 이로 인해 **주소와 소유자를 쉽게 연결할 수 있습니다**.

## **거래 그래프 분석**

거래를 그래프로 시각화하면 자금 흐름을 바탕으로 사용자 간의 잠재적 연결을 파악할 수 있습니다.

## **불필요한 입력 휴리스틱(최적 변경액 휴리스틱)**

이 휴리스틱은 입력과 출력이 여러 개인 거래를 분석해 어떤 출력이 송신자에게 돌아가는 변경액인지 추측합니다.

### 예시

```bash
2 btc --> 4 btc
3 btc     1 btc
```

입력을 더 추가했을 때 change 출력이 단일 입력보다 커지면 heuristic에 혼란을 줄 수 있습니다.

## **강제 주소 재사용**

공격자는 수신자가 향후 거래에서 이 금액을 다른 입력과 결합하기를 바라며, 이전에 사용된 주소로 소액을 보낼 수 있습니다. 이렇게 하면 주소 간 연결이 드러날 수 있습니다.

### 올바른 Wallet 동작

Wallet은 privacy leak을 방지하기 위해 이미 사용된 빈 주소로 받은 coin을 사용하지 않아야 합니다.

## **기타 Blockchain 분석 기법**

- **정확한 결제 금액:** change가 없는 거래는 같은 사용자가 소유한 두 주소 간 거래일 가능성이 높습니다.
- **반올림된 금액:** 거래 금액이 반올림된 숫자라면 결제일 가능성이 있으며, 반올림되지 않은 출력은 change일 가능성이 높습니다.
- **Wallet 핑거프린팅:** Wallet마다 고유한 거래 생성 패턴이 있어 분석가가 사용된 소프트웨어와 change 주소를 알아낼 수 있습니다.
- **금액 및 시간 상관관계:** 거래 시각이나 금액을 공개하면 거래를 추적할 수 있습니다.

## **트래픽 분석**

네트워크 트래픽을 모니터링하면 공격자가 거래나 블록을 IP 주소와 연결해 사용자의 프라이버시를 침해할 수 있습니다. 한 주체가 다수의 Bitcoin 노드를 운영하는 경우 거래 모니터링 능력이 향상되므로 특히 위험합니다.

## 더 알아보기

프라이버시 공격과 방어에 대한 전체 목록은 [Bitcoin Wiki의 Bitcoin 프라이버시](https://en.bitcoin.it/wiki/Privacy)를 참조하세요.

# 익명 Bitcoin 거래

## 익명으로 Bitcoin을 얻는 방법

- **현금 거래**: 현금으로 bitcoin을 구매합니다.
- **현금 대체 수단**: 기프트 카드를 구매한 뒤 온라인에서 bitcoin으로 교환합니다.
- **Mining**: 특히 혼자 mining하는 것이 bitcoin을 얻는 가장 프라이빗한 방법입니다. Mining pool은 채굴자의 IP 주소를 알 수 있기 때문입니다. [Mining Pools 정보](https://en.bitcoin.it/wiki/Pooled_mining)
- **절도**: 이론적으로 bitcoin을 훔치는 것도 익명으로 획득하는 방법일 수 있지만, 불법이며 권장하지 않습니다.

## Mixing 서비스

Mixing 서비스를 사용하면 사용자가 **bitcoin을 보내고** **다른 bitcoin을 돌려받을 수** 있으므로 원래 소유자를 추적하기 어려워집니다. 하지만 이를 위해서는 서비스가 로그를 보관하지 않고 실제로 bitcoin을 돌려줄 것이라는 신뢰가 필요합니다. Bitcoin 카지노도 대체 mixing 방법에 포함됩니다.

## CoinJoin

**CoinJoin**은 여러 사용자의 거래를 하나로 합쳐 입력과 출력을 연결하려는 사람이 이를 파악하기 어렵게 만듭니다. 효과적이지만, 입력과 출력의 금액이 고유한 거래는 여전히 추적될 수 있습니다.

CoinJoin을 사용했을 수 있는 거래 예시: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하세요. 예치와 이후 출금을 분리하는 Ethereum 스마트 계약 mixer는 [Tornado Cash](https://tornado.cash)를 참조하세요.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 두 당사자(예: 고객과 상인) 간의 거래를 CoinJoin 특유의 동일한 출력 없이 일반 거래처럼 위장합니다. 따라서 이를 탐지하기가 매우 어려우며, 거래 감시 주체가 사용하는 공통 입력 소유권 heuristic을 무효화할 수도 있습니다.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

위와 같은 트랜잭션은 PayJoin일 수 있으며, 일반적인 bitcoin 트랜잭션과 구별되지 않으면서 프라이버시를 강화합니다.

**PayJoin을 활용하면 기존 감시 기법을 크게 무력화할 수 있어**, 트랜잭션 프라이버시를 추구하는 데 유망한 발전입니다.

# 암호화폐 프라이버시를 위한 모범 사례

## **지갑 동기화 기법**

프라이버시와 보안을 유지하려면 지갑을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 특히 유용합니다.

- **Full node**: 전체 블록체인을 다운로드하면 최대한의 프라이버시를 보장할 수 있습니다. 지금까지 발생한 모든 트랜잭션이 로컬에 저장되므로, 공격자는 사용자가 관심을 두는 트랜잭션이나 주소를 알아낼 수 없습니다.
- **클라이언트 측 블록 필터링**: 이 방법은 블록체인의 각 블록에 대한 필터를 만들어 네트워크 관찰자에게 구체적인 관심사를 노출하지 않고도 지갑이 관련 트랜잭션을 식별할 수 있게 합니다. 경량 지갑은 이 필터를 다운로드하고, 사용자의 주소와 일치하는 항목이 있을 때만 전체 블록을 가져옵니다.

## **익명성을 위한 Tor 활용**

Bitcoin은 피어 투 피어 네트워크에서 작동하므로, 네트워크와 상호작용할 때 Tor를 사용해 IP 주소를 숨기고 프라이버시를 강화하는 것이 좋습니다.

## **주소 재사용 방지**

프라이버시를 보호하려면 트랜잭션마다 새 주소를 사용하는 것이 중요합니다. 주소를 재사용하면 트랜잭션이 같은 주체와 연결되어 프라이버시가 침해될 수 있습니다. 최신 지갑은 설계 단계에서 주소 재사용을 방지합니다.

## **트랜잭션 프라이버시 전략**

- **여러 트랜잭션**: 결제를 여러 트랜잭션으로 나누면 트랜잭션 금액을 감춰 프라이버시 공격을 막을 수 있습니다.
- **잔돈 출력 방지**: 잔돈 출력이 필요 없는 트랜잭션을 선택하면 잔돈 탐지 기법을 방해해 프라이버시를 강화할 수 있습니다.
- **여러 잔돈 출력**: 잔돈을 피할 수 없다면 잔돈 출력을 여러 개 생성해 프라이버시를 개선할 수 있습니다.

# **Monero: 익명성의 상징**

Monero는 트랜잭션 프라이버시를 우선시하도록 설계되었습니다.

# **Ethereum: 가스와 트랜잭션**

## **가스 이해하기**

가스는 Ethereum에서 작업을 실행하는 데 필요한 계산량을 측정하며, 가격은 **gwei**로 책정됩니다. 예를 들어, 2,310,000 gwei(또는 0.00231 ETH)가 드는 트랜잭션에는 가스 한도와 기본 수수료가 적용되며, 검증자의 블록 포함을 유도하기 위한 우선순위 수수료도 포함됩니다. 사용자는 최대 수수료를 설정해 과다 지불을 방지할 수 있으며, 초과 금액은 환불됩니다.<sup>[[5]](#references)</sup>

## **트랜잭션 실행**

Ethereum 트랜잭션에는 발신자와 수신자가 있으며, 둘 다 사용자 주소 또는 스마트 컨트랙트 주소일 수 있습니다. 트랜잭션에는 수수료가 필요하며 블록에 포함되어야 합니다. 트랜잭션의 필수 정보에는 수신자, 발신자의 서명, 금액, 선택적 데이터, 가스 한도, 수수료가 포함됩니다. 특히 발신자 주소는 서명에서 도출되므로 트랜잭션 데이터에 포함할 필요가 없습니다.<sup>[[4]](#references)</sup>

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐를 사용하려는 모든 이에게 기본이 됩니다.

## 가치 중심 Web3 레드팀 테스트

- 자금을 이동할 수 있는 주체와 방식을 파악하기 위해 가치가 담긴 구성 요소(서명자, 오라클, 브리지, 자동화)를 목록화합니다.
- 각 구성 요소를 관련 MITRE AADAPT 전술에 대응시켜 권한 상승 경로를 파악합니다.
- 플래시 론/오라클/자격 증명/크로스체인 공격 체인을 리허설하여 영향을 검증하고 악용 가능한 전제 조건을 문서화합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 서명 워크플로 침해

- 지갑 UI의 공급망 변조는 서명 직전에 EIP-712 페이로드를 변경하여 delegatecall 기반 프록시 탈취(예: Safe masterCopy의 슬롯 0 덮어쓰기)에 사용할 유효한 서명을 수집할 수 있습니다.

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## 계정 추상화 (ERC-4337)

- 스마트 계정의 일반적인 실패 유형에는 `EntryPoint` 접근 제어 우회, 서명되지 않은 가스 필드, 상태를 변경하는 검증, ERC-1271 재생 공격, 검증 후 revert를 통한 수수료 탈취가 있습니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## 스마트 컨트랙트 보안

- 테스트 스위트의 사각지대를 찾기 위한 뮤테이션 테스트:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK 증명 / zkVM 게스트 무결성

증명자가 **zkVM** 또는 애플리케이션별 증명 회로를 사용해 주장을 증명할 때, 검증자가 알게 되는 것은 **게스트 프로그램이 작성된 대로 실행되었다는 사실뿐입니다**. 게스트에 **안전하지 않은 역직렬화**, **정의되지 않은 동작**, 또는 **의미적 제약 조건의 누락**이 있으면, 악의적인 증명자는 증명이 유효하게 검증되더라도 **공개 지표나 주장된 불변 조건이 거짓인** 증명을 생성할 수 있습니다.<sup>[[7]](#references)</sup>

### 증명 게스트 내부의 안전하지 않은 역직렬화

- 비공개 witness/회로 바이트는 증명으로 숨겨져 있더라도 **신뢰할 수 없는 공격자 입력**으로 취급합니다.
- 바이트가 이미 별도로 검증된 경우가 아니라면 `rkyv::access_unchecked` 같은 검증되지 않은 헬퍼를 사용해 역직렬화하지 않습니다.
- 신뢰할 수 없는 직렬화 데이터에서 읽어 들이는 열거형 판별자, 상대 포인터, 길이, 인덱스는 제어 흐름이나 메모리 접근에 영향을 주기 전에 검증해야 합니다.

실용적인 감사 패턴:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind`와 같은 필드가 enum이고 공격자가 **범위를 벗어난 판별값**을 주입할 수 있다면, 해당 값을 사용하는 모든 후속 `match`를 의심해야 합니다.

### Jump-table / UB 우회

Rust가 큰 `match`를 **jump table**로 변환하는 경우, 유효하지 않은 enum 판별값으로 인해 **정의되지 않은 제어 흐름**이 발생할 수 있습니다. 위험한 패턴은 다음과 같습니다:<sup>[[7]](#references)[[9]](#references)</sup>

1. 첫 번째 `match`가 **보안상 중요한 카운터/제약 조건**을 갱신합니다.
2. 두 번째 `match`가 **실제 명령어 의미**를 수행합니다.
3. 범위를 벗어난 판별값이 첫 번째 jump table의 범위를 벗어나 인덱싱되어 두 번째 jump table에 연결된 코드로 이동합니다.

결과: 연산은 실행되지만 회계 경로는 건너뜁니다. zkVM에서는 이로 인해 게이트 수, 비용이 큰 연산 수 또는 그 밖의 제한된 리소스가 실제보다 적게 보고되는 불가능한 메트릭을 증명하는 위조 proof가 생성될 수 있습니다.

검토 체크리스트:

- witness/private input에서 역직렬화되는 공격자 제어 enum을 찾습니다.
- 동일한 opcode/kind 필드를 사용하는 반복된 `match` 문을 살펴봅니다.
- `unsafe` + 검증되지 않은 역직렬화 + 대규모 opcode 디스패치가 함께 나타나면 고위험 조합으로 간주합니다.
- 필요하면 생성된 바이너리를 역공학합니다. jump table의 배치가 소스 코드보다 중요할 수 있습니다.

### 가역/특수 인터프리터에서 의미론적 제약 조건 누락

메모리 안전성만 검증하지 말고, proof가 강제해야 하는 **의미론적 규칙**도 검증합니다.

가역/양자 유사 명령어 집합에서는 서로 달라야 하는 피연산자가 실제로 서로 다르도록 제약되는지 확인합니다. 다음과 같이 구현된 Toffoli/CCX 유사 연산은:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

게스트가 다음을 거부하지 않으면 안전하지 않게 됩니다:

```text
op.q_control1 == op.q_control2 == op.q_target
```

이 경우 전환은 다음과 같이 축약됩니다:

```text
q = q ^ (q & q) = 0
```

This는 **결정론적 reset primitive**를 만들어 가역성 가정을 깨뜨리고, 의도하지 않은 연산을 더 저렴하게 수행할 수 있게 합니다. 리소스 사용량을 증명하는 proof system에서는 공격자가 기능 검사를 통과하면서도 verifier가 적용하고 있다고 믿는 비용 모델을 우회할 수 있습니다.

### ZK 시스템에서 테스트할 항목

- 잘못된 witness/private-input 인코딩을 사용해 모든 guest parser를 fuzzing합니다.
- opcode dispatch 전에 enum 범위가 검증되는지 확인합니다.
- operand aliasing 및 기타 유효하지 않은 instruction 형식에 대한 semantic check를 추가합니다.
- 보고된/public counter를 독립적인 reference implementation과 비교합니다.
- guest program에 버그가 있으면 유효한 proof도 **잘못된 statement**를 증명할 수 있다는 점을 기억하세요.

## 상태 종속 권한 부여

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX와 AMM의 실용적인 exploitation(Uniswap v4 hooks, 반올림/정밀도 악용, flash-loan으로 증폭한 임계값 돌파 swap)을 조사한다면 다음을 확인하세요.

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

가상 잔액을 캐시하며 `supply == 0`일 때 오염될 수 있는 다중 자산 가중치 풀은 다음을 살펴보세요.

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [지분 증명 - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [공개 키와 개인 키 설명 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [다중 서명 트랜잭션이란? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [트랜잭션 | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas와 수수료 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [프라이버시 - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google의 양자 암호 분석 zero-knowledge proof를 무력화하다](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [양자 취약점으로부터 타원 곡선 암호화폐 보호: 리소스 추정 및 완화 방안(패치 버전)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept 저장소](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
