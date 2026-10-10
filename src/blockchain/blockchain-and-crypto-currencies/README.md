# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **스마트 컨트랙트(Smart Contracts)**는 특정 조건이 충족되면 블록체인에서 실행되는 프로그램으로, 중개자 없이 계약 이행을 자동화합니다.
- **탈중앙화 애플리케이션(dApps)**은 스마트 컨트랙트를 기반으로 하며, 사용자 친화적인 프런트엔드와 투명하고 감사 가능한 백엔드를 갖춥니다.
- **토큰 및 코인**은 용도가 다릅니다. 코인은 디지털 화폐로 쓰이고, 토큰은 특정 맥락에서 가치나 소유권을 나타냅니다.
  - **유틸리티 토큰(Utility Tokens)**은 서비스 이용 권한을 제공하고, **증권형 토큰(Security Tokens)**은 자산 소유권을 나타냅니다.
- **DeFi**는 탈중앙화 금융(Decentralized Finance)을 의미하며, 중앙 기관 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAO**는 각각 탈중앙화 거래소(Decentralized Exchange Platforms)와 탈중앙화 자율 조직(Decentralized Autonomous Organizations)을 의미합니다.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 트랜잭션을 안전하게 검증하고 이에 합의하도록 합니다.

- **작업 증명(Proof of Work, PoW)**은 트랜잭션 검증에 연산 능력을 사용합니다.
- **지분 증명(Proof of Stake, PoS)**은 검증자가 일정량의 토큰을 보유하도록 요구하며, PoW보다 에너지 소비를 줄입니다.<sup>[[1]](#references)</sup>

## Bitcoin 기본 사항

### 트랜잭션

Bitcoin 트랜잭션은 주소 간에 자금을 전송합니다. 트랜잭션은 디지털 서명을 통해 검증되므로, 개인 키 소유자만 전송을 시작할 수 있습니다.<sup>[[2]](#references)</sup>

#### 주요 구성 요소:

- **다중 서명 트랜잭션(Multisignature Transactions)**은 트랜잭션을 승인하기 위해 여러 개의 서명이 필요합니다.<sup>[[3]](#references)</sup>
- 트랜잭션은 **입력**(자금 출처), **출력**(목적지), **수수료**(채굴자에게 지급), **스크립트**(트랜잭션 규칙)로 구성됩니다.

### Lightning Network

채널 내에서 여러 트랜잭션을 처리하고 최종 상태만 블록체인에 기록하여 Bitcoin의 확장성을 높이는 것을 목표로 합니다.

## Bitcoin 프라이버시 문제

**공통 입력 소유권(Common Input Ownership)** 및 **UTXO 잔돈 주소 탐지(UTXO Change Address Detection)**와 같은 프라이버시 공격은 트랜잭션 패턴을 악용합니다. **믹서(Mixers)**와 **CoinJoin** 같은 방식은 사용자 간 트랜잭션 연결을 감춰 익명성을 높입니다.

## 익명으로 Bitcoin 획득하기

현금 거래, 채굴, 믹서 사용 등의 방법이 있습니다. **CoinJoin**은 여러 트랜잭션을 섞어 추적을 어렵게 만들고, **PayJoin**은 CoinJoin을 일반 트랜잭션처럼 위장해 프라이버시를 강화합니다.

# Bitcoin 프라이버시 공격 요약

Bitcoin 세계에서는 트랜잭션의 프라이버시와 사용자의 익명성이 자주 우려됩니다. 공격자가 Bitcoin 프라이버시를 침해하는 데 사용하는 몇 가지 일반적인 방법을 간략히 살펴보겠습니다.<sup>[[6]](#references)</sup>

## **공통 입력 소유권 가정**

복잡성 때문에 서로 다른 사용자의 입력을 하나의 트랜잭션에 결합하는 경우는 드뭅니다. 따라서 **같은 트랜잭션에 있는 두 입력 주소는 대개 동일한 소유자의 것으로 간주됩니다**.

## **UTXO 잔돈 주소 탐지**

UTXO, 즉 **미사용 트랜잭션 출력(Unspent Transaction Output)**은 트랜잭션에서 전액 사용해야 합니다. 일부만 다른 주소로 보내면 나머지는 새 잔돈 주소로 전송됩니다. 관찰자는 이 새 주소가 송신자의 소유라고 추정할 수 있으며, 이로 인해 프라이버시가 침해될 수 있습니다.

### 예시

이를 완화하려면 믹싱 서비스를 사용하거나 여러 주소를 이용해 소유 관계를 감출 수 있습니다.

## **소셜 네트워크 및 포럼 노출**

사용자는 때때로 온라인에 Bitcoin 주소를 공유하므로, **주소와 소유자를 쉽게 연결할 수 있습니다**.

## **트랜잭션 그래프 분석**

트랜잭션을 그래프로 시각화하면 자금 흐름을 바탕으로 사용자 간의 잠재적 연결을 파악할 수 있습니다.

## **불필요한 입력 휴리스틱(최적 잔돈 휴리스틱)**

이 휴리스틱은 입력과 출력이 여러 개인 트랜잭션을 분석해 어떤 출력이 송신자에게 돌아가는 잔돈인지 추정합니다.

### 예시

```bash
2 btc --> 4 btc
3 btc     1 btc
```

입력을 추가해 change output이 단일 입력보다 커지면 휴리스틱을 혼란스럽게 할 수 있습니다.

## **강제 주소 재사용**

공격자는 수신자가 향후 트랜잭션에서 이 금액을 다른 입력과 합쳐 주소 간의 연관성이 드러나기를 바라며, 이전에 사용된 주소로 소액을 보낼 수 있습니다.

### 올바른 Wallet 동작

Wallet은 이 프라이버시 leak을 방지하기 위해 이미 사용되었고 잔액이 없는 주소로 받은 코인을 사용하지 않아야 합니다.

## **기타 블록체인 분석 기법**

- **정확한 결제 금액:** 잔돈이 없는 트랜잭션은 같은 사용자가 소유한 두 주소 간의 거래일 가능성이 높습니다.
- **반올림된 금액:** 트랜잭션의 금액이 반올림된 숫자라면 결제일 가능성이 있으며, 반올림되지 않은 출력은 잔돈일 가능성이 높습니다.
- **Wallet 핑거프린팅:** Wallet마다 고유한 트랜잭션 생성 패턴이 있어 분석가가 사용된 소프트웨어와 잔돈 주소를 파악할 수 있습니다.
- **금액 및 시간 상관관계:** 트랜잭션 시간이나 금액을 공개하면 트랜잭션을 추적할 수 있습니다.

## **트래픽 분석**

네트워크 트래픽을 모니터링하면 공격자가 트랜잭션이나 블록을 IP 주소와 연결해 사용자의 프라이버시를 침해할 수 있습니다. 여러 Bitcoin 노드를 운영하는 주체라면 트랜잭션 모니터링 능력이 강화되므로 특히 주의해야 합니다.

## 기타 정보

프라이버시 공격과 방어 기법의 전체 목록은 [Bitcoin Wiki의 Bitcoin 프라이버시 항목](https://en.bitcoin.it/wiki/Privacy)을 참조하세요.

# 익명 Bitcoin 트랜잭션

## 익명으로 Bitcoins를 얻는 방법

- **현금 거래**: 현금을 사용해 bitcoin을 얻습니다.
- **현금 대체 수단**: 기프트 카드를 구매한 뒤 온라인에서 bitcoin으로 교환합니다.
- **Mining**: Bitcoins를 얻는 가장 프라이빗한 방법은 mining입니다. 특히 혼자 mining하면 더욱 그렇습니다. Mining pool은 miner의 IP 주소를 알 수 있기 때문입니다. [Mining pool 정보](https://en.bitcoin.it/wiki/Pooled_mining)
- **절도**: 이론적으로 bitcoin을 훔치는 것도 익명으로 얻는 방법이 될 수 있지만, 이는 불법이며 권장하지 않습니다.

## Mixing 서비스

Mixing 서비스를 이용하면 사용자가 **bitcoins를 보내고** 그 대가로 **다른 bitcoins를 받을 수 있어**, 원래 소유자를 추적하기 어려워집니다. 하지만 서비스가 로그를 보관하지 않고 실제로 bitcoins를 반환할 것이라는 신뢰가 필요합니다. 대안적인 mixing 방법으로는 Bitcoin casino가 있습니다.

## CoinJoin

**CoinJoin**은 여러 사용자의 트랜잭션을 하나로 합쳐 입력과 출력을 연결하려는 과정을 복잡하게 만듭니다. 효과적인 방법이지만, 입력 및 출력 금액이 독특한 트랜잭션은 여전히 추적될 수 있습니다.

CoinJoin을 사용했을 가능성이 있는 트랜잭션의 예로 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`와 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있습니다.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하세요. 입금과 이후 출금을 분리하는 Ethereum smart-contract mixer는 [Tornado Cash](https://tornado.cash)를 참조하세요.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 두 당사자(예: 고객과 판매자) 간의 트랜잭션을 CoinJoin의 특징인 동일한 출력 없이 일반 트랜잭션처럼 위장합니다. 따라서 이를 탐지하기가 매우 어려우며, 트랜잭션 감시 주체가 사용하는 공통 입력 소유권 휴리스틱을 무효화할 수 있습니다.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

위와 같은 트랜잭션은 PayJoin일 수 있으며, 표준 bitcoin 트랜잭션과 구별되지 않으면서 프라이버시를 강화할 수 있습니다.

**PayJoin을 활용하면 기존 감시 방식을 크게 방해할 수 있으므로**, 트랜잭션 프라이버시를 추구하는 데 있어 유망한 발전입니다.

# 암호화폐 프라이버시를 위한 모범 사례

## **지갑 동기화 기법**

프라이버시와 보안을 유지하려면 지갑을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 특히 유용합니다.

- **Full node**: 전체 블록체인을 다운로드하면 프라이버시를 최대한 보장할 수 있습니다. 지금까지 이루어진 모든 트랜잭션이 로컬에 저장되므로, 공격자가 사용자가 관심을 두는 트랜잭션이나 주소를 알아낼 수 없습니다.
- **클라이언트 측 블록 필터링**: 블록체인의 모든 블록에 대한 필터를 만들어 네트워크 관찰자에게 구체적인 관심사를 노출하지 않고도 지갑이 관련 트랜잭션을 식별할 수 있게 하는 방법입니다. 경량 지갑은 이 필터를 다운로드하고, 사용자의 주소와 일치하는 항목이 있을 때만 전체 블록을 가져옵니다.

## **익명성을 위한 Tor 활용**

Bitcoin은 피어 투 피어 네트워크에서 작동하므로, 네트워크와 상호 작용할 때 IP 주소를 숨겨 프라이버시를 강화하려면 Tor를 사용하는 것이 좋습니다.

## **주소 재사용 방지**

프라이버시를 보호하려면 트랜잭션마다 새 주소를 사용하는 것이 중요합니다. 주소를 재사용하면 트랜잭션이 동일한 주체와 연결되어 프라이버시가 침해될 수 있습니다. 최신 지갑은 설계상 주소 재사용을 지양하도록 되어 있습니다.

## **트랜잭션 프라이버시 전략**

- **여러 트랜잭션 사용**: 결제를 여러 트랜잭션으로 나누면 트랜잭션 금액을 파악하기 어려워져 프라이버시 공격을 방해할 수 있습니다.
- **잔돈 출력 회피**: 잔돈 출력을 만들지 않는 트랜잭션을 선택하면 잔돈 탐지 기법을 무력화해 프라이버시를 강화할 수 있습니다.
- **여러 잔돈 출력 사용**: 잔돈 출력을 피할 수 없다면 잔돈 출력을 여러 개 생성해 프라이버시를 높일 수 있습니다.

# **Monero: 익명성의 상징**

Monero는 트랜잭션 프라이버시를 우선시하도록 설계되었습니다.

# **Ethereum: Gas와 트랜잭션**

## **Gas 이해하기**

Gas는 Ethereum에서 연산을 실행하는 데 필요한 계산 작업량을 측정하며, 비용은 **gwei**로 책정됩니다. 예를 들어, 2,310,000 gwei(또는 0.00231 ETH)가 드는 트랜잭션에는 gas 한도와 기본 수수료가 있으며, 검증자가 해당 트랜잭션을 포함하도록 유도하는 우선순위 수수료도 있습니다. 사용자는 최대 수수료를 설정해 과도하게 지불하지 않도록 할 수 있으며, 초과분은 환불됩니다.<sup>[[5]](#references)</sup>

## **트랜잭션 실행**

Ethereum의 트랜잭션에는 발신자와 수신자가 있으며, 둘 다 사용자 주소 또는 스마트 컨트랙트 주소일 수 있습니다. 트랜잭션에는 수수료가 필요하며 블록에 포함되어야 합니다. 트랜잭션의 필수 정보에는 수신자, 발신자의 서명, 값, 선택적 데이터, gas 한도 및 수수료가 포함됩니다. 특히 발신자 주소는 서명에서 도출되므로 트랜잭션 데이터에 포함할 필요가 없습니다.<sup>[[4]](#references)</sup>

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐를 이용하려는 모든 사람에게 기본이 됩니다.

## 가치 중심 Web3 Red Teaming

- 가치가 있는 구성 요소(signer, oracle, bridge, automation)를 목록화해 누가 자금을 이동할 수 있으며 어떤 방식으로 가능한지 파악합니다.
- 각 구성 요소를 관련 MITRE AADAPT 전술에 대응시켜 권한 상승 경로를 파악합니다.
- flash loan/oracle/credential/cross-chain 공격 체인을 예행 연습해 영향을 검증하고 악용 가능한 전제 조건을 문서화합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 서명 워크플로 침해

- 지갑 UI의 공급망 변조를 통해 서명 직전에 EIP-712 페이로드를 변경하면 유효한 서명을 탈취해 delegatecall 기반 프록시 탈취를 수행할 수 있습니다(예: Safe masterCopy의 slot-0 덮어쓰기).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## 계정 추상화 (ERC-4337)

- 일반적인 스마트 계정 장애 유형에는 `EntryPoint` 접근 제어 우회, 서명되지 않은 gas 필드, 상태를 변경하는 검증, ERC-1271 재생 공격, 검증 후 revert를 통한 수수료 탈취가 포함됩니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## 스마트 컨트랙트 보안

- 테스트 스위트의 사각지대를 찾기 위한 Mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest 무결성

Prover가 **zkVM** 또는 애플리케이션 전용 증명 회로를 사용해 어떤 주장을 증명할 때, verifier가 알 수 있는 것은 **guest 프로그램이 작성된 대로 실행되었다는 사실뿐입니다**. Guest에 **안전하지 않은 역직렬화**, **정의되지 않은 동작** 또는 **누락된 의미적 제약 조건**이 있으면 악의적인 prover가 검증은 통과하지만 **공개 지표나 주장된 불변 조건은 거짓인 증명**을 생성할 수 있습니다.<sup>[[7]](#references)</sup>

### 증명 guest 내부의 안전하지 않은 역직렬화

- 비공개 witness/circuit 바이트는 증명으로 숨겨져 있더라도 **신뢰할 수 없는 공격자 입력**으로 취급합니다.
- 바이트를 별도의 경로로 이미 검증한 경우가 아니라면 `rkyv::access_unchecked`와 같은 검증되지 않은 helper를 사용해 역직렬화하지 않습니다.
- 신뢰할 수 없는 직렬화 데이터에서 불러온 enum 판별자, 상대 포인터, 길이 및 인덱스는 제어 흐름이나 메모리 접근에 영향을 주기 전에 검증해야 합니다.

실용적인 감사 패턴:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

If `op.kind` 같은 필드가 enum이고 공격자가 **범위를 벗어난 판별값**을 주입할 수 있다면, 해당 값을 대상으로 하는 모든 후속 `match`를 의심해야 합니다.

### Jump-table / UB 카운터 우회

Rust가 큰 `match`를 **jump table**로 컴파일하는 경우, 유효하지 않은 enum 판별값으로 인해 **정의되지 않은 제어 흐름**이 발생할 수 있습니다. 위험한 패턴은 다음과 같습니다:<sup>[[7]](#references)[[9]](#references)</sup>

1. 첫 번째 `match`가 **보안에 중요한 카운터/제약 조건**을 갱신합니다.
2. 두 번째 `match`가 **실제 명령어 의미론**을 수행합니다.
3. 범위를 벗어난 판별값이 첫 번째 jump table의 범위를 넘어 인덱싱되어 두 번째 jump table에 연결된 코드로 이동합니다.

결과: 연산은 계속 실행되지만, 계량 경로는 건너뛰게 됩니다. zkVM에서는 이로 인해 게이트 수 감소, 고비용 연산 감소 또는 기타 제한된 리소스가 위조된 것처럼 보고되는 불가능한 지표를 포함한 증명을 위조할 수 있습니다.

검토 체크리스트:

- witness/private input에서 역직렬화되는 공격자 제어 enum을 찾습니다.
- 같은 opcode/kind 필드를 대상으로 반복되는 `match` 문을 살펴봅니다.
- `unsafe` + 검증되지 않은 역직렬화 + 대규모 opcode 디스패치는 위험도가 높은 조합으로 간주합니다.
- 필요한 경우 생성된 바이너리를 리버스 엔지니어링합니다. jump table 레이아웃이 소스 코드보다 더 중요할 수 있습니다.

### 가역/특수 인터프리터에서 의미론적 제약 조건 누락

메모리 안전성만 검증하지 마세요. 증명이 적용해야 하는 **의미론적 규칙**도 검증해야 합니다.

가역/양자 유사 명령어 집합에서는 서로 달라야 하는 피연산자들이 실제로 서로 다르도록 제약되어 있는지 확인합니다. Toffoli/CCX 유사 연산이 다음과 같이 구현된 경우:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

게스트가 다음을 거부하지 않으면 안전하지 않게 됩니다:

```text
op.q_control1 == op.q_control2 == op.q_target
```

이 경우 전이는 다음과 같이 축약됩니다:

```text
q = q ^ (q & q) = 0
```

이는 **결정론적 reset primitive**를 만들어 가역성에 대한 가정을 깨뜨리고, 의도하지 않은 연산을 더 저렴하게 수행할 수 있게 합니다. 리소스 사용량을 증명하는 시스템에서는 공격자가 기능 검사를 통과하면서도 검증자가 적용된다고 믿는 비용 모델을 우회할 수 있습니다.

### ZK 시스템에서 테스트할 항목

- 모든 guest parser에 잘못된 witness/private-input 인코딩을 넣어 fuzzing합니다.
- opcode dispatch 전에 enum 범위 검증을 수행하는지 확인합니다.
- operand aliasing 및 기타 잘못된 명령 형식에 대한 semantic check를 추가합니다.
- 공개된 카운터를 독립적인 reference implementation과 비교합니다.
- guest program에 버그가 있으면 유효한 증명도 **잘못된 명제**를 증명할 수 있다는 점을 기억합니다.

## 상태에 따른 권한 부여

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM 익스플로잇

DEX와 AMM의 실질적인 익스플로잇(Uniswap v4 hooks, 반올림/정밀도 악용, flash-loan으로 임계값 돌파를 증폭하는 swap)을 조사하는 경우 다음을 확인하세요.

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

가상 잔액을 캐시하고 `supply == 0`일 때 오염될 수 있는 다중 자산 가중치 풀은 다음을 참고하세요.

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [지분 증명 - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [공개 키와 개인 키 설명 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [다중 서명 트랜잭션이란? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [트랜잭션 | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas와 수수료 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [개인정보 보호 - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google의 양자 암호분석 zero-knowledge proof를 꺾다](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [양자 취약점으로부터 타원 곡선 암호화폐 보호: 리소스 추정 및 완화 방안 (패치 버전)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept 저장소](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
