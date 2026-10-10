# Blockchain 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **Smart Contracts**는 특정 조건이 충족될 때 blockchain에서 실행되는 프로그램으로 정의되며, 중개자 없이 계약 이행을 자동화합니다.
- **Decentralized Applications (dApps)**는 smart contracts를 기반으로 하며, 사용하기 쉬운 프런트엔드와 투명하고 감사 가능한 백엔드를 갖춥니다.
- **Tokens & Coins**는 사용처가 다릅니다. coin은 디지털 화폐로 기능하고, token은 특정 맥락에서 가치나 소유권을 나타냅니다.
  - **Utility Tokens**는 서비스 이용 권한을 제공하고, **Security Tokens**는 자산 소유권을 나타냅니다.
- **DeFi**는 Decentralized Finance의 약자로, 중앙 기관 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 의미합니다.

## 합의 메커니즘

합의 메커니즘은 blockchain에서 안전하고 합의된 거래 검증을 보장합니다.

- **Proof of Work (PoW)**는 거래 검증에 연산 능력을 사용합니다.
- **Proof of Stake (PoS)**에서는 검증자가 일정량의 token을 보유해야 하며, PoW보다 에너지 소비가 적습니다.<sup>[[1]](#references)</sup>

## Bitcoin 기본 사항

### 거래

Bitcoin 거래는 주소 간에 자금을 전송합니다. 거래는 디지털 서명을 통해 검증되므로, 개인 키 소유자만 전송을 시작할 수 있습니다.<sup>[[2]](#references)</sup>

#### 주요 구성 요소:

- **Multisignature Transactions**는 거래를 승인하기 위해 여러 서명을 요구합니다.<sup>[[3]](#references)</sup>
- 거래는 **inputs**(자금 출처), **outputs**(목적지), **fees**(miner에게 지급), **scripts**(거래 규칙)로 구성됩니다.

### Lightning Network

채널 내에서 여러 거래를 허용하고 최종 상태만 blockchain에 전파하여 Bitcoin의 확장성을 높이는 것을 목표로 합니다.

## Bitcoin의 개인정보 보호 문제

**Common Input Ownership** 및 **UTXO Change Address Detection**과 같은 개인정보 공격은 거래 패턴을 악용합니다. **Mixers**와 **CoinJoin** 같은 전략은 사용자 간 거래 연결을 감춰 익명성을 높입니다.

## 익명으로 Bitcoin 획득하기

방법에는 현금 거래, mining, mixers 사용 등이 있습니다. **CoinJoin**은 추적을 어렵게 만들기 위해 여러 거래를 혼합하고, **PayJoin**은 개인정보 보호를 강화하기 위해 CoinJoin을 일반 거래처럼 위장합니다.

# Bitcoin 개인정보 공격 요약

Bitcoin 세계에서는 거래의 개인정보 보호와 사용자의 익명성이 우려되는 경우가 많습니다. 다음은 공격자가 Bitcoin의 개인정보 보호를 침해할 수 있는 몇 가지 일반적인 방법을 간단히 정리한 것입니다.<sup>[[6]](#references)</sup>

## **공통 입력 소유권 가정**

복잡성 때문에 서로 다른 사용자의 입력을 하나의 거래에 결합하는 경우는 일반적으로 드뭅니다. 따라서 **같은 거래에 포함된 두 입력 주소는 동일한 소유자의 것이라고 여기는 경우가 많습니다**.

## **UTXO 잔돈 주소 탐지**

UTXO, 즉 **미사용 거래 출력(Unspent Transaction Output)**은 거래에서 전액 사용되어야 합니다. 그중 일부만 다른 주소로 보내면 나머지는 새로운 잔돈 주소로 이동합니다. 관찰자는 이 새 주소가 송신자의 소유라고 추정할 수 있으며, 이로 인해 개인정보가 침해될 수 있습니다.

### 예시

이를 완화하려면 mixing 서비스를 이용하거나 여러 주소를 사용해 소유 관계를 감출 수 있습니다.

## **소셜 네트워크 및 포럼 노출**

사용자는 온라인에서 자신의 Bitcoin 주소를 공유하는 경우가 있으며, 이로 인해 **주소와 소유자를 쉽게 연결할 수 있습니다**.

## **거래 그래프 분석**

거래를 그래프로 시각화하면 자금 흐름을 바탕으로 사용자 간의 잠재적 연결 관계를 파악할 수 있습니다.

## **불필요한 입력 휴리스틱(최적 잔돈 휴리스틱)**

이 휴리스틱은 입력과 출력이 여러 개 있는 거래를 분석하여 어떤 출력이 송신자에게 돌아가는 잔돈인지 추측하는 방식입니다.

### 예시

```bash
2 btc --> 4 btc
3 btc     1 btc
```

입력을 더 추가했을 때 change 출력이 단일 입력보다 커지면 휴리스틱이 혼동될 수 있습니다.

## **강제 주소 재사용**

공격자는 수신자가 향후 거래에서 이 금액을 다른 입력과 합쳐 주소 간 연결이 드러나기를 바라며, 이전에 사용된 주소로 소액을 보낼 수 있습니다.

### 올바른 지갑 동작

지갑은 이러한 privacy leak을 방지하기 위해 이미 사용된 빈 주소로 받은 코인을 사용하지 않아야 합니다.

## **기타 블록체인 분석 기법**

- **정확한 결제 금액:** 잔돈이 없는 거래는 동일한 사용자가 소유한 두 주소 간 거래일 가능성이 높습니다.
- **반올림된 금액:** 거래 금액이 반올림된 숫자라면 결제일 가능성이 있으며, 반올림되지 않은 출력은 잔돈일 가능성이 높습니다.
- **지갑 핑거프린팅:** 지갑마다 거래를 생성하는 방식이 고유하므로, 분석가는 사용된 소프트웨어를 식별하고 잔돈 주소를 알아낼 수도 있습니다.
- **금액 및 시간 상관관계:** 거래 시간이나 금액을 공개하면 거래를 추적할 수 있습니다.

## **트래픽 분석**

네트워크 트래픽을 모니터링하면 공격자는 거래나 블록을 IP 주소와 연결해 사용자의 privacy를 침해할 수 있습니다. 한 주체가 다수의 Bitcoin 노드를 운영하는 경우 거래를 모니터링할 능력이 커지므로 특히 그렇습니다.

## 더 알아보기

privacy 공격과 방어에 대한 전체 목록은 [Bitcoin Wiki의 Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy)를 참조하세요.

# 익명 Bitcoin 거래

## 익명으로 Bitcoin을 얻는 방법

- **현금 거래**: 현금으로 bitcoin을 구합니다.
- **현금 대체 수단**: 기프트 카드를 구입한 뒤 온라인에서 bitcoin으로 교환합니다.
- **Mining**: bitcoin을 얻는 가장 privacy가 높은 방법은 mining이며, 특히 혼자 채굴하는 경우 그렇습니다. mining pool은 채굴자의 IP 주소를 알 수 있기 때문입니다. [Mining Pools 정보](https://en.bitcoin.it/wiki/Pooled_mining)
- **절도**: 이론적으로 bitcoin을 훔치는 것도 익명으로 bitcoin을 얻는 방법일 수 있지만, 이는 불법이며 권장되지 않습니다.

## 믹싱 서비스

믹싱 서비스를 이용하면 사용자는 **bitcoin을 보내고** **다른 bitcoin을 돌려받을 수** 있어 원래 소유자를 추적하기 어렵습니다. 그러나 서비스를 신뢰해야 하며, 서비스가 로그를 남기지 않고 실제로 bitcoin을 반환한다는 보장이 필요합니다. Bitcoin 카지노도 대안적인 믹싱 방법입니다.

## CoinJoin

**CoinJoin**은 여러 사용자의 거래를 하나로 병합해 입력과 출력을 서로 대응시키기 어렵게 만듭니다. 효과적인 방법이지만, 입력 및 출력 금액이 고유한 거래는 여전히 추적될 수 있습니다.

CoinJoin을 사용했을 가능성이 있는 거래의 예로는 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`와 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있습니다.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하세요. 예치와 이후 출금을 분리하는 Ethereum smart-contract mixer는 [Tornado Cash](https://tornado.cash)를 참조하세요.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 두 당사자(예: 고객과 판매자) 간 거래를 일반 거래처럼 위장하며, CoinJoin의 특징인 동일한 출력 금액을 사용하지 않습니다. 따라서 이를 탐지하기가 매우 어렵고, 거래 감시 주체가 사용하는 공통 입력 소유권 휴리스틱을 무력화할 수도 있습니다.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

위와 같은 트랜잭션은 PayJoin일 수 있으며, 표준 bitcoin 트랜잭션과 구별되지 않으면서 프라이버시를 강화할 수 있습니다.

**PayJoin을 활용하면 기존 감시 방식에 상당한 차질을 줄 수 있으므로**, 거래 프라이버시를 추구하는 데 유망한 발전입니다.

# 암호화폐 프라이버시를 위한 모범 사례

## **Wallet 동기화 기법**

프라이버시와 보안을 유지하려면 wallet을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 특히 유용합니다.

- **풀 노드**: 전체 블록체인을 다운로드하면 풀 노드가 최대한의 프라이버시를 보장합니다. 지금까지 이루어진 모든 트랜잭션이 로컬에 저장되므로, 공격자가 사용자가 관심을 갖는 트랜잭션이나 주소를 알아내기 어렵습니다.
- **클라이언트 측 블록 필터링**: 이 방식은 블록체인의 각 블록에 대한 필터를 생성하여, 지켜보는 네트워크 참여자에게 특정 관심사를 노출하지 않고도 wallet이 관련 트랜잭션을 식별할 수 있게 합니다. 경량 wallet은 이러한 필터를 다운로드하고, 사용자의 주소와 일치하는 항목을 찾은 경우에만 전체 블록을 가져옵니다.

## **익명성을 위한 Tor 활용**

Bitcoin은 peer-to-peer 네트워크에서 작동하므로, IP 주소를 숨기고 네트워크와 상호작용할 때 프라이버시를 강화하려면 Tor를 사용하는 것이 좋습니다.

## **주소 재사용 방지**

프라이버시를 보호하려면 트랜잭션마다 새 주소를 사용하는 것이 중요합니다. 주소를 재사용하면 트랜잭션이 동일한 주체와 연결되어 프라이버시가 침해될 수 있습니다. 최신 wallet은 설계상 주소 재사용을 방지합니다.

## **트랜잭션 프라이버시 전략**

- **여러 트랜잭션 사용**: 결제를 여러 트랜잭션으로 나누면 트랜잭션 금액을 감출 수 있어 프라이버시 공격을 방해할 수 있습니다.
- **거스름돈 출력 방지**: 거스름돈 출력이 필요하지 않은 트랜잭션을 선택하면 거스름돈을 탐지하는 방식을 교란해 프라이버시를 강화할 수 있습니다.
- **여러 거스름돈 출력 사용**: 거스름돈을 피할 수 없다면 여러 개의 거스름돈 출력을 생성하는 것만으로도 프라이버시를 개선할 수 있습니다.

# **Monero: 익명성의 상징**

Monero는 트랜잭션 프라이버시를 최우선으로 하도록 설계되었습니다.

# **Ethereum: Gas와 트랜잭션**

## **Gas 이해하기**

Gas는 Ethereum에서 작업을 실행하는 데 필요한 연산량을 측정하며, 가격은 **gwei** 단위로 책정됩니다. 예를 들어, 2,310,000 gwei(또는 0.00231 ETH)가 드는 트랜잭션에는 gas limit와 기본 수수료가 필요하며, 검증자가 블록에 포함하도록 유도하는 우선 수수료도 포함됩니다. 사용자는 초과 지불을 방지하기 위해 최대 수수료를 설정할 수 있으며, 남은 금액은 환불됩니다.<sup>[[5]](#references)</sup>

## **트랜잭션 실행**

Ethereum 트랜잭션에는 발신자와 수신자가 있으며, 이들은 사용자 주소 또는 smart contract 주소일 수 있습니다. 트랜잭션에는 수수료가 필요하며 블록에 포함되어야 합니다. 트랜잭션의 필수 정보에는 수신자, 발신자의 서명, 값, 선택적 데이터, gas limit 및 수수료가 포함됩니다. 발신자 주소는 서명으로부터 도출되므로 트랜잭션 데이터에 포함할 필요가 없습니다.<sup>[[4]](#references)</sup>

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐를 이용하려는 모든 사람에게 기본이 됩니다.

## 가치 중심 Web3 Red Teaming

- 자산 이동 권한과 방식을 파악하기 위해 가치를 보유한 구성 요소(signer, oracle, bridge, automation)를 목록화합니다.
- 각 구성 요소를 관련 MITRE AADAPT 전술에 매핑해 권한 상승 경로를 드러냅니다.
- flash-loan/oracle/credential/cross-chain 공격 체인을 리허설해 영향을 검증하고 악용 가능한 전제 조건을 문서화합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 서명 워크플로 침해

- Wallet UI의 공급망 변조는 서명 직전에 EIP-712 payload를 변경하여 delegatecall 기반 proxy 탈취에 사용할 수 있는 유효한 서명을 수집할 수 있습니다(예: Safe masterCopy의 slot-0 덮어쓰기).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## 계정 추상화 (ERC-4337)

- 일반적인 smart account 오류 유형에는 `EntryPoint` 접근 제어 우회, 서명되지 않은 gas 필드, 상태를 변경하는 검증, ERC-1271 재생 공격, 검증 후 revert를 이용한 수수료 탈취가 포함됩니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract 보안

- 테스트 스위트의 사각지대를 찾기 위한 mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest 무결성

prover가 **zkVM** 또는 애플리케이션별 proof circuit을 사용해 주장을 증명할 때, verifier가 알 수 있는 것은 **guest program이 작성된 대로 실행되었다는 사실**뿐입니다. guest에 **안전하지 않은 역직렬화**, **정의되지 않은 동작** 또는 **의미 제약의 누락**이 있으면, 악의적인 prover가 proof는 검증되지만 **공개 지표나 주장된 불변 조건은 거짓인** proof를 생성할 수 있습니다.<sup>[[7]](#references)</sup>

### proof guest 내부의 안전하지 않은 역직렬화

- private witness/circuit 바이트는 proof로 숨겨져 있더라도 **신뢰할 수 없는 공격자 입력**으로 취급합니다.
- 바이트가 이미 별도로 검증되지 않았다면 `rkyv::access_unchecked`와 같은 검증되지 않은 헬퍼를 사용해 역직렬화하지 않습니다.
- 신뢰할 수 없는 직렬화 데이터에서 불러온 enum 판별자, 상대 포인터, 길이 및 인덱스는 제어 흐름이나 메모리 접근에 영향을 주기 전에 검증해야 합니다.

실용적인 감사 패턴:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind`와 같은 필드가 enum이고 공격자가 **범위를 벗어난 판별값**을 주입할 수 있다면, 해당 값을 사용하는 모든 하위 `match`를 의심해야 합니다.

### 점프 테이블 / UB 검사 우회

Rust가 큰 `match`를 **점프 테이블**로 컴파일하는 경우, 잘못된 enum 판별값으로 인해 **정의되지 않은 제어 흐름**이 발생할 수 있습니다. 위험한 패턴은 다음과 같습니다.<sup>[[7]](#references)[[9]](#references)</sup>

1. 첫 번째 `match`가 **보안에 중요한 카운터/제약 조건**을 업데이트합니다.
2. 두 번째 `match`가 **실제 명령어 의미론**을 수행합니다.
3. 범위를 벗어난 판별값이 첫 번째 점프 테이블의 범위를 벗어나 인덱싱하여 두 번째 점프 테이블에 해당하는 코드로 이동합니다.

결과: 연산은 실행되지만 회계 처리 경로는 건너뜁니다. zkVM에서는 게이트 수, 비용이 큰 연산 수 또는 제한된 기타 리소스가 실제보다 적다고 보고하는 불가능한 메트릭을 증명하는 위조 proof를 만들 수 있습니다.

검토 체크리스트:

- witness/private input에서 역직렬화되는 공격자 제어 enum을 찾습니다.
- 동일한 opcode/kind 필드를 사용하는 반복된 `match`문을 살펴봅니다.
- `unsafe` + 검증되지 않은 역직렬화 + 대규모 opcode 디스패치가 함께 있으면 고위험 조합으로 간주합니다.
- 필요한 경우 생성된 바이너리를 리버스 엔지니어링합니다. 점프 테이블의 배치가 소스 코드보다 중요할 수 있습니다.

### 가역/특수 목적 인터프리터에서 누락된 의미론적 제약 조건

메모리 안전성만 검증하지 말고, proof가 적용해야 하는 **의미론적 규칙**도 검증합니다.

가역/양자 유사 명령어 집합의 경우, 서로 달라야 하는 피연산자가 실제로 서로 다르도록 제약되는지 확인합니다. Toffoli/CCX 유사 연산이 다음과 같이 구현된 경우:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

게스트가 거부하지 않으면 안전하지 않게 됩니다:

```text
op.q_control1 == op.q_control2 == op.q_target
```

이 경우 전이는 다음과 같이 축약됩니다:

```text
q = q ^ (q & q) = 0
```

이는 **결정론적 초기화 프리미티브**를 만들어 가역성에 대한 가정을 깨뜨리고, 의도하지 않은 계산을 더 저렴하게 수행할 수 있게 합니다. 리소스 사용량을 입증하는 증명 시스템에서는 공격자가 검증자가 적용된다고 믿는 비용 모델을 우회하면서 기능 검사를 통과할 수 있습니다.

### ZK 시스템에서 테스트할 사항

- 잘못된 witness/private-input 인코딩으로 모든 guest parser를 퍼징합니다.
- opcode 디스패치 전에 enum 범위가 검증되는지 확인합니다.
- 피연산자 aliasing 및 기타 잘못된 명령 형식에 대한 의미 검사를 추가합니다.
- 보고된/공개 카운터를 독립적인 참조 구현과 비교합니다.
- guest 프로그램에 버그가 있으면 유효한 증명도 **잘못된 명제**를 증명할 수 있다는 점을 기억합니다.

## 상태 종속 권한 부여

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM 악용

DEX와 AMM의 실전 악용(Uniswap v4 hooks, 반올림/정밀도 악용, flash loan으로 증폭된 임계값 돌파 스왑)을 조사하는 경우 다음을 참고하세요.

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

가상 잔액을 캐시하며 `supply == 0`일 때 오염될 수 있는 멀티에셋 가중 풀은 다음을 살펴보세요.

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [지분 증명 - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [공개 키 및 개인 키 설명 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [멀티시그 트랜잭션이란? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [트랜잭션 | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas 및 수수료 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [프라이버시 - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google의 양자 암호분석 영지식 증명을 무력화하다](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [양자 취약점으로부터 타원 곡선 암호화폐 보호: 리소스 추정 및 완화책(패치 버전)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept 저장소](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
