# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

이 장에서는 블록체인 개념과 온체인 보안을 다룹니다. 외부에 노출된 Bitcoin peer를 대상으로 할 때는 [Bitcoin P2P service enumeration](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md)을, 브라우저 프런트엔드, 지갑 연결 또는 오프체인 백엔드를 대상으로 할 때는 [DApp 펜테스팅](../../pentesting-web/dapps-DecentralizedApplications.md)을 참고하세요. 암호화폐의 프라이버시 관련 작업과 그 한계는 [암호화폐 프라이버시 장](../../privacy/cryptocurrency-privacy.md)을 참고하세요.

## 기본 개념

- **스마트 컨트랙트**는 특정 조건이 충족될 때 블록체인에서 실행되는 프로그램으로, 중개자 없이 계약 이행을 자동화합니다.
- **탈중앙화 애플리케이션(dApps)**은 스마트 컨트랙트를 기반으로 구축되며, 사용자 친화적인 프런트엔드와 투명하고 감사 가능한 백엔드를 갖춥니다.
- **토큰과 코인**은 용도가 다릅니다. 코인은 디지털 화폐로 사용되는 반면, 토큰은 특정 맥락에서 가치나 소유권을 나타냅니다.
  - **유틸리티 토큰**은 서비스 이용 권한을 부여하고, **증권형 토큰**은 자산 소유권을 나타냅니다.
- **DeFi**는 탈중앙화 금융을 뜻하며, 중앙 기관 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAO**는 각각 탈중앙화 거래소 플랫폼과 탈중앙화 자율 조직을 의미합니다.

암호화폐 시장에서 사용하는 현물 주문, 선물, 레버리지, 옵션 관련 용어는 [투자 용어](investment-terms.md)를 참고하세요. 무기한 프로토콜의 펀딩 비율 악용에 대해서는 [무기한 펀딩 비율 악용](perpetual-funding-rate-exploitation.md)을 참고하세요.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 안전하고 합의된 거래 검증을 보장합니다.

- **작업 증명(PoW)**은 거래 검증에 컴퓨팅 파워를 사용합니다.
- **지분 증명(PoS)**에서는 검증자가 일정량의 토큰을 보유해야 하며, PoW에 비해 에너지 소비가 적습니다.<sup>[[1]](#references)</sup>

## Bitcoin 기본 사항

### 거래

Bitcoin 거래는 주소 간 자금을 전송합니다. 거래는 디지털 서명을 통해 검증되므로 개인 키 소유자만 전송을 시작할 수 있습니다.<sup>[[2]](#references)</sup>

#### 주요 구성 요소:

- **다중 서명 거래**는 거래를 승인하기 위해 여러 개의 서명이 필요합니다.<sup>[[3]](#references)</sup>
- 거래는 **입력**(자금 출처), **출력**(목적지), **수수료**(채굴자에게 지급), **스크립트**(거래 규칙)로 구성됩니다.

### Lightning Network

채널 내에서 여러 거래를 처리하고 최종 상태만 블록체인에 기록하여 Bitcoin의 확장성을 높이는 것을 목표로 합니다.

## Bitcoin 프라이버시 문제

**공통 입력 소유권(Common Input Ownership)** 및 **UTXO 변경 주소 탐지(UTXO Change Address Detection)**와 같은 프라이버시 공격은 거래 패턴을 악용합니다. **믹서(Mixers)**와 **CoinJoin** 같은 전략은 사용자 간 거래 연결을 감춰 익명성을 높입니다.

## 익명으로 Bitcoin 획득하기

현금 거래, 채굴, 믹서 사용 등의 방법이 있습니다. **CoinJoin**은 여러 거래를 섞어 추적을 어렵게 만들고, **PayJoin**은 CoinJoin을 일반 거래처럼 위장해 프라이버시를 강화합니다.

# Bitcoin 프라이버시 공격 요약

Bitcoin에서는 거래 프라이버시와 사용자 익명성이 자주 우려됩니다. 다음은 공격자가 Bitcoin 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법을 간략히 살펴본 내용입니다.<sup>[[6]](#references)</sup>

## **공통 입력 소유권 가정**

여러 사용자의 입력을 하나의 거래에 결합하는 일은 복잡하기 때문에 일반적으로 드뭅니다. 따라서 **같은 거래에 포함된 두 입력 주소는 동일한 소유자의 것이라고 가정하는 경우가 많습니다**.

## **UTXO 변경 주소 탐지**

UTXO, 즉 **미사용 거래 출력(Unspent Transaction Output)**은 거래에서 전액 사용되어야 합니다. 일부만 다른 주소로 보내면 나머지는 새로운 변경 주소로 전송됩니다. 관찰자는 이 새 주소가 송신자의 것이라고 추정할 수 있으며, 이로 인해 프라이버시가 침해될 수 있습니다.

### 예시

이를 완화하려면 믹싱 서비스를 이용하거나 여러 주소를 사용해 소유 관계를 감출 수 있습니다.

## **소셜 네트워크 및 포럼 노출**

사용자는 때때로 자신의 Bitcoin 주소를 온라인에 공유하며, 이로 인해 **주소를 소유자와 쉽게 연결할 수 있습니다**.

## **거래 그래프 분석**

거래를 그래프로 시각화하면 자금 흐름을 바탕으로 사용자 간의 잠재적 연결을 확인할 수 있습니다.

## **불필요한 입력 휴리스틱(최적 변경 휴리스틱)**

이 휴리스틱은 입력과 출력이 여러 개인 거래를 분석해 어떤 출력이 송신자에게 돌아가는 변경분인지 추정합니다.

### 예시

```bash
2 btc --> 4 btc
3 btc     1 btc
```

입력을 더 추가했을 때 변경 출력이 단일 입력보다 커지면 휴리스틱을 혼란스럽게 만들 수 있습니다.

## **강제 주소 재사용**

공격자는 수신자가 향후 트랜잭션에서 이 금액을 다른 입력과 결합하기를 바라며, 이전에 사용된 주소로 소액을 보낼 수 있습니다. 이로 인해 주소 간 연결이 드러날 수 있습니다.

### 올바른 Wallet 동작

Wallet은 이 privacy leak을 방지하기 위해 이미 사용된 빈 주소로 받은 코인을 사용하지 않아야 합니다.

## **기타 Blockchain 분석 기법**

- **정확한 결제 금액:** 잔돈이 없는 트랜잭션은 동일 사용자가 소유한 두 주소 간의 트랜잭션일 가능성이 높습니다.
- **반올림된 금액:** 트랜잭션 금액이 반올림된 숫자라면 결제일 가능성이 있으며, 반올림되지 않은 출력은 잔돈일 가능성이 높습니다.
- **Wallet 핑거프린팅:** Wallet마다 고유한 트랜잭션 생성 패턴이 있어 분석가가 사용된 소프트웨어를 식별하고 잔돈 주소를 알아낼 수 있습니다.
- **금액 및 시간 상관관계:** 트랜잭션 시간이나 금액을 공개하면 트랜잭션을 추적할 수 있습니다.

## **트래픽 분석**

네트워크 트래픽을 모니터링하면 공격자가 트랜잭션이나 블록을 IP 주소와 연결해 사용자의 프라이버시를 침해할 수 있습니다. 특히 한 주체가 다수의 Bitcoin 노드를 운영하면 트랜잭션을 모니터링할 능력이 커지므로 위험이 커집니다.

## 더 알아보기

프라이버시 공격 및 방어에 대한 전체 목록은 [Bitcoin Wiki의 Bitcoin 프라이버시](https://en.bitcoin.it/wiki/Privacy)를 참조하세요.

# 익명 Bitcoin 트랜잭션

## 익명으로 Bitcoins를 얻는 방법

- **현금 거래**: 현금으로 Bitcoin을 구매합니다.
- **현금 대체 수단**: 기프트 카드를 구매한 뒤 온라인에서 Bitcoin으로 교환합니다.
- **Mining**: Bitcoins를 얻는 가장 프라이버시가 보장되는 방법은 mining이며, 특히 혼자 mining하는 경우에 그렇습니다. Mining pool은 miner의 IP 주소를 알 수 있기 때문입니다. [Mining Pool 정보](https://en.bitcoin.it/wiki/Pooled_mining)
- **절도**: 이론적으로는 Bitcoin을 훔치는 것도 익명으로 획득하는 방법일 수 있지만, 불법이며 권장하지 않습니다.

## Mixing 서비스

Mixing 서비스를 사용하면 사용자는 **bitcoins를 보내고** 그 대가로 **다른 bitcoins를 받을 수 있어**, 원래 소유자를 추적하기 어려워집니다. 하지만 이 방법을 사용하려면 서비스가 로그를 보관하지 않고 실제로 bitcoins를 반환할 것이라고 믿어야 합니다. Bitcoin 카지노도 대안적인 mixing 방법입니다.

## CoinJoin

**CoinJoin**은 여러 사용자의 트랜잭션을 하나로 병합해 입력과 출력을 일치시키려는 작업을 어렵게 만듭니다. 효과적이기는 하지만, 입력 및 출력 금액이 고유한 트랜잭션은 여전히 추적될 수 있습니다.

CoinJoin을 사용했을 가능성이 있는 트랜잭션의 예로는 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있습니다.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하세요. 입금과 이후 출금을 분리하는 Ethereum smart contract mixer는 [Tornado Cash](https://tornado.cash)를 참조하세요.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 두 당사자(예: 고객과 판매자) 간의 트랜잭션을 일반적인 트랜잭션처럼 위장합니다. CoinJoin 특유의 동일한 출력 금액을 사용하지 않습니다. 따라서 탐지가 매우 어려우며, 트랜잭션 감시 주체가 사용하는 공통 입력 소유권 휴리스틱을 무력화할 수 있습니다.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

위와 같은 트랜잭션은 PayJoin일 수 있으며, 표준 bitcoin 트랜잭션과 구별되지 않으면서 프라이버시를 강화합니다.

**PayJoin을 활용하면 기존 감시 방식에 큰 지장을 줄 수 있어**, 트랜잭션 프라이버시를 추구하는 데 유망한 발전입니다.

# 암호화폐 프라이버시를 위한 모범 사례

## **Wallet 동기화 기법**

프라이버시와 보안을 유지하려면 blockchain과 wallet을 동기화하는 것이 중요합니다. 두 가지 방법이 특히 두드러집니다.

- **Full node**: blockchain 전체를 다운로드하면 full node가 최대한의 프라이버시를 보장합니다. 지금까지 이루어진 모든 트랜잭션이 로컬에 저장되므로, 공격자가 사용자가 관심 있는 트랜잭션이나 주소를 알아낼 수 없습니다.
- **클라이언트 측 블록 필터링**: 이 방법은 blockchain의 모든 블록에 대한 필터를 만들어, 네트워크 관찰자에게 특정 관심사를 노출하지 않고도 wallet이 관련 트랜잭션을 식별할 수 있게 합니다. 경량 wallet은 이러한 필터를 다운로드하고, 사용자의 주소와 일치하는 항목이 있을 때만 전체 블록을 가져옵니다.

## **익명성을 위한 Tor 활용**

Bitcoin은 P2P 네트워크에서 작동하므로, 네트워크와 상호작용할 때 IP 주소를 숨겨 프라이버시를 강화하려면 Tor 사용을 권장합니다.

## **주소 재사용 방지**

프라이버시를 보호하려면 모든 트랜잭션에 새 주소를 사용하는 것이 중요합니다. 주소를 재사용하면 트랜잭션이 동일한 주체와 연결되어 프라이버시가 침해될 수 있습니다. 최신 wallet은 설계상 주소 재사용을 방지합니다.

## **트랜잭션 프라이버시 전략**

- **여러 트랜잭션 사용**: 결제를 여러 트랜잭션으로 나누면 트랜잭션 금액을 파악하기 어려워져 프라이버시 공격을 막을 수 있습니다.
- **잔돈 출력 방지**: 잔돈 출력이 필요 없는 트랜잭션을 선택하면 잔돈 탐지 기법을 방해해 프라이버시를 강화할 수 있습니다.
- **여러 잔돈 출력 사용**: 잔돈 출력을 피할 수 없다면 여러 잔돈 출력을 생성해 프라이버시를 개선할 수 있습니다.

# **Monero: 익명성의 상징**

Monero는 트랜잭션 프라이버시를 우선시하도록 설계되었습니다.

# **Ethereum: Gas와 트랜잭션**

## **Gas 이해하기**

Gas는 Ethereum에서 작업을 실행하는 데 필요한 연산량을 측정하며, 가격은 **gwei**로 표시됩니다. 예를 들어 2,310,000 gwei(또는 0.00231 ETH)가 드는 트랜잭션에는 gas 한도와 기본 수수료가 있으며, 검증자가 블록에 포함하도록 유도하는 우선순위 수수료도 있습니다. 사용자는 최대 수수료를 설정해 과다 지불을 방지할 수 있으며, 초과분은 환불됩니다.<sup>[[5]](#references)</sup>

## **트랜잭션 실행**

Ethereum 트랜잭션에는 송신자와 수신자가 있으며, 둘 다 사용자 주소 또는 스마트 컨트랙트 주소일 수 있습니다. 트랜잭션에는 수수료가 필요하고 블록에 포함되어야 합니다. 트랜잭션의 필수 정보에는 수신자, 송신자 서명, 값, 선택적 데이터, gas 한도 및 수수료가 포함됩니다. 특히 송신자 주소는 서명에서 추론되므로 트랜잭션 데이터에 포함할 필요가 없습니다.<sup>[[4]](#references)</sup>

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하며 암호화폐를 사용하려는 모든 이에게 기본이 됩니다.

## 가치 중심 Web3 Red Teaming

- 자금의 이동 권한과 방식을 파악할 수 있도록 가치를 보유하거나 이동시키는 구성 요소(signers, oracles, bridges, automation)를 목록화합니다.
- 각 구성 요소를 관련 MITRE AADAPT 전술에 매핑해 권한 상승 경로를 드러냅니다.
- flash-loan/oracle/credential/cross-chain 공격 체인을 리허설해 영향을 검증하고 악용 가능한 사전 조건을 문서화합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 서명 워크플로 손상

- wallet UI의 공급망 변조는 서명 직전에 EIP-712 payload를 변경해 유효한 서명을 탈취하고, delegatecall 기반 proxy 탈취(예: Safe masterCopy의 slot-0 덮어쓰기)에 악용할 수 있습니다.

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 흔한 smart account 오류 유형에는 `EntryPoint` 접근 제어 우회, 서명되지 않은 gas 필드, 상태를 변경하는 검증, ERC-1271 재생 공격, 검증 후 revert를 통한 수수료 탈취가 포함됩니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## 스마트 컨트랙트 보안

- 테스트 스위트의 사각지대를 찾기 위한 mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM 게스트 무결성

prover가 **zkVM** 또는 애플리케이션별 proof circuit을 사용해 주장을 증명할 때, verifier가 알 수 있는 것은 **게스트 프로그램이 작성된 대로 실행되었다는 사실**뿐입니다. 게스트에 **안전하지 않은 역직렬화**, **정의되지 않은 동작** 또는 **의미론적 제약 누락**이 있다면, 악의적인 prover는 검증은 통과하지만 **공개 지표나 주장된 불변 조건은 거짓인 proof**를 생성할 수 있습니다.<sup>[[7]](#references)</sup>

### Proof 게스트 내부의 안전하지 않은 역직렬화

- 비공개 witness/circuit 바이트는 proof로 숨겨져 있더라도 **신뢰할 수 없는 공격자 입력**으로 취급합니다.
- 바이트가 별도의 경로로 이미 검증된 것이 아니라면 `rkyv::access_unchecked`와 같은 검증되지 않은 helper를 사용해 역직렬화하지 않습니다.
- 신뢰할 수 없는 직렬화 데이터에서 불러온 enum 판별자, 상대 포인터, 길이 및 인덱스는 제어 흐름이나 메모리 접근에 영향을 주기 전에 검증해야 합니다.

실무 감사 패턴:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind`와 같은 필드가 enum이고 공격자가 **범위를 벗어난 discriminant**를 주입할 수 있다면, 해당 값을 사용하는 모든 후속 `match`를 의심해야 합니다.

### Jump-table / UB 카운터 우회

Rust가 큰 `match`를 **jump table**로 컴파일하는 경우, 유효하지 않은 enum discriminant가 **정의되지 않은 제어 흐름**을 일으킬 수 있습니다. 위험한 패턴은 다음과 같습니다:<sup>[[7]](#references)[[9]](#references)</sup>

1. 한 `match`가 **보안에 중요한 카운터/제약 조건**을 업데이트합니다.
2. 두 번째 `match`가 **실제 명령어의 의미**를 처리합니다.
3. 범위를 벗어난 discriminant가 첫 번째 jump table의 범위를 벗어나 인덱싱되어 두 번째 jump table에 연결된 코드로 이동합니다.

결과: 연산은 여전히 실행되지만, 계량 경로는 건너뜁니다. zkVM에서는 이로 인해 게이트 수, 고비용 연산 수 또는 기타 제한된 리소스가 실제보다 적다고 보고하는 불가능한 메트릭을 증명하는 위조 증명이 만들어질 수 있습니다.

검토 체크리스트:

- witness/private input에서 역직렬화되는 공격자 제어 enum을 찾습니다.
- 동일한 opcode/kind 필드를 사용하는 반복된 `match` 문을 살펴봅니다.
- `unsafe` + 검증되지 않은 역직렬화 + 대규모 opcode 디스패치가 함께 있으면 위험도가 높은 조합으로 간주합니다.
- 필요한 경우 생성된 바이너리를 리버스 엔지니어링합니다. jump table의 배치가 소스 코드보다 더 중요할 수 있습니다.

### 가역/특수화 인터프리터의 의미론적 제약 조건 누락

메모리 안전성만 검증하지 말고, 증명이 강제해야 하는 **의미론적 규칙**도 검증해야 합니다.

가역/양자 유사 명령어 집합에서는 서로 달라야 하는 피연산자가 실제로 서로 다르도록 제약되는지 확인합니다. Toffoli/CCX 유사 연산이 다음과 같이 구현된 경우:<sup>[[7]](#references)[[8]](#references)</sup>

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

이는 **결정론적 리셋 프리미티브**를 만들어 가역성에 대한 가정을 깨뜨리고, 의도하지 않은 연산을 더 저렴하게 수행할 수 있게 합니다. 리소스 사용량을 증명하는 proof system에서는 공격자가 기능 검사를 통과하면서 검증자가 적용된다고 믿는 비용 모델을 우회할 수 있습니다.

### 제약이 부족한 prover 조언과 모듈러 산술

**advice/witness 스택에서 로드한 값은 prover가 제어합니다.** 미리 계산된 몫, 나머지, 역원 또는 힌트라고 설명하더라도 마찬가지입니다. 증명은 witness가 구현된 제약 조건을 만족한다는 점만 입증할 뿐, 해당 제약 조건에 타입, 범위 또는 정규 형식 검사가 빠져 있다면 의도한 연산이 수행되었음을 입증하지는 않습니다.<sup>[[13]](#references)</sup>

reduction 또는 유클리드 나눗셈 헬퍼를 감사할 때는 마지막 뺄셈이나 곱셈만 보지 말고 완전한 정수 관계를 확인하세요. `q`와 `r`의 모든 limb가 선언된 너비로 제한되어야 하고, 재구성 식 `x = q * m + r`이 의도한 정수 표현에서 성립해야 하며, 정규 범위 `0 <= r < m`이 강제되어야 합니다. 값을 더 좁은 `u32`/`u64` 명령어에 전달하기 **전에** 검증하세요. 좁은 연산을 수행했다고 해서 원래의 필드 원소나 다중 limb 값이 예상한 타입이었다는 사실이 소급해 증명되지는 않습니다.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden의 `mod_12289` 실패는 악용 패턴을 보여 줍니다. 몫은 두 개의 64비트 limb 값으로 검사했지만, advice로 제공된 나머지는 이에 상응하는 검증 없이 `u32overflowing_sub`에 전달되었습니다. 악의적인 prover는 잘못된 몫과 나머지 값을 조합해 구현된 뺄셈 제약은 만족하면서도 프로시저가 수학적으로 올바르지 않은 나머지를 반환하게 할 수 있었습니다. 이 결과가 Falcon 검증에 사용되었으므로, soundness 실패는 단순히 잘못된 산술 결과를 만드는 데 그치지 않고 위조된 권한 부여 서명으로 이어질 수 있었습니다.<sup>[[13]](#references)</sup>

### 암묵적 스택을 사용하는 암호화 VM 감사

스택 언어는 피연산자를 숨기므로, 먼저 각 스택 값의 소비와 생성이 provenance를 가진 표현식으로 나타나는 IR로 명령어를 변환합니다. 그런 다음 보수적인 분석 파이프라인에서 다음을 수행할 수 있습니다.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. 호출 그래프를 구성하고 프로시저의 입력/출력 스택 효과를 추론합니다.
2. 지원되는 명령어를 기호적으로 실행하고 제어 흐름을 SSA/구조화된 표현식으로 변환합니다.
3. `Unknown`, `ProvenU32`, `Bool`, 값의 provenance, 로컬 초기화와 같은 추상적 사실을 고정점에 도달할 때까지 전파합니다.
4. 모든 진입 경로에 sanitizer가 없는 상태로 advice에서 유래한 값이 형식 지정 산술 또는 0이 아닌 값이 필요한 싱크에 도달하는 경우를 표시합니다.
5. 선언된 시그니처와 추론된 시그니처를 비교하고 모든 종료 지점에서 호출자가 소유한 스택 값이 보존되는지 확인합니다.

알 수 없는 시그니처나 지원되지 않는 구문은 분석 결과가 깨끗하다는 뜻이 아니라 **분석 공백**으로 취급합니다. 동적 호출, 스택 중립이 아닌 루프, 스택 효과가 서로 다른 분기는 스택 슬롯을 sound하게 추적하지 못하게 할 수 있습니다. 더 안전한 decompiler는 그럴듯하지만 잘못된 의사 코드를 출력하는 대신 이런 경우를 거부하거나 표시합니다.<sup>[[10]](#references)[[13]](#references)</sup>

제어 흐름이 합쳐지는 지점에서는 모든 선행 블록에서 성립하는 속성만 유지합니다(예: `ProvenU32 join Unknown = Unknown`). 또한 고정점 수렴과 반복 횟수 한도 도달을 구분해야 합니다. 수렴한 sound한 over-approximation만이 진단이 없다는 사실을 근거로 표현된 모든 실행이 해당 속성을 만족한다고 볼 수 있게 해 줍니다.<sup>[[11]](#references)</sup>

### 숨겨진 전제 조건을 드러내는 증명 의무

명령어 집합이 작다면 프로시저를 실행 가능한 형식 VM 모델로 변환하고 결과와 전체 스택 변환을 모두 증명합니다. 정리는 종료, 형식이 지정된 입력, 예상 출력의 접두부, 그리고 변경되지 않은 호출자 스택의 보존을 다뤄야 합니다. 증명만큼 정리문도 꼼꼼히 감사하세요. 커널은 실수로 약화된 주장을 증명한 증명도 검증할 수 있습니다.<sup>[[12]](#references)[[13]](#references)</sup>

예상치 못한 가정은 유용한 발견으로 이어집니다. Miden 검토에서 64비트 오른쪽 회전을 증명하려면 `shift mod 32 != 0`이 필요했으며, 이를 통해 shift가 32의 배수인 큰 입력에서 실패하는 경계 사례가 드러났습니다. 또 다른 증명에서는 256비트 `wrapping_mul`이 호출자가 소유한 스택 값을 버리는 문제가 발견되었습니다. 발견된 경계 사례를 테스트에 추가한 뒤, 추가 가정을 조용히 받아들이기보다는 구현을 수정하거나 공개 전제 조건을 의도적으로 강화하세요.<sup>[[12]](#references)[[13]](#references)</sup>

### ZK 시스템에서 테스트할 항목

- 잘못된 witness/private-input 인코딩을 사용해 모든 guest parser를 fuzz합니다.
- opcode dispatch 전에 enum 범위 검증이 이루어지는지 확인합니다.
- 피연산자 aliasing 및 기타 잘못된 명령어 형식에 대한 의미 검사를 추가합니다.
- 각 advice/witness 소스에서 형식이 지정된 각 산술 싱크까지의 경로를 추적하고, 모든 경로에서 검증이 이루어지는지 확인합니다.<sup>[[11]](#references)[[13]](#references)</sup>
- 산술 헬퍼에 대해 비표준 limb, 범위를 벗어난 나머지, 경계 shift 횟수를 테스트합니다.<sup>[[12]](#references)[[13]](#references)</sup>
- 모든 반환 지점에서 스택 높이와 프로시저의 선언된 인수 아래에 있는 값의 보존을 확인합니다.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- 보고된/공개된 카운터를 독립적인 참조 구현과 비교합니다.
- guest 프로그램에 버그가 있으면 유효한 증명도 여전히 **잘못된 명제**를 증명할 수 있다는 점을 기억하세요.

## 상태 의존적 권한 부여

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX와 AMM의 실용적인 악용(Uniswap v4 hooks, 반올림/정밀도 악용, flash loan으로 임계값을 넘기는 swap)을 조사하는 경우 다음을 참고하세요.

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
- [3] [다중 서명 트랜잭션이란 무엇인가요? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [트랜잭션 | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas와 수수료 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [프라이버시 - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google의 양자 암호분석 zero-knowledge proof를 무력화했습니다](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [양자 취약점으로부터 타원 곡선 암호화폐 보호: 리소스 추정 및 완화 방안(패치 버전)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept 저장소](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler 아키텍처](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM 정적 분석 엔진](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean 모델 및 정확성 증명](https://github.com/trailofbits/masm-lean)
- [13] [충분히 우수한 AI 시대의 감사](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
