# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **Smart Contracts**는 특정 조건이 충족될 때 블록체인에서 실행되는 프로그램으로 정의되며, 중개자 없이 계약 이행을 자동화합니다.
- **dApps**는 스마트 계약을 기반으로 하며, 사용자 친화적인 프론트엔드와 투명하고 감사 가능한 백엔드를 갖춘 애플리케이션입니다.
- **Tokens & Coins**는 구분되며, coins는 디지털 화폐로 사용되는 반면 tokens는 특정 맥락에서 가치나 소유권을 나타냅니다.
- **Utility Tokens**는 서비스 접근 권한을 부여하고, **Security Tokens**는 자산 소유를 의미합니다.
- **DeFi**는 중앙 권한 없이 금융 서비스를 제공하는 Decentralized Finance를 의미합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 의미합니다.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 안전하고 합의된 거래 검증을 보장합니다:

- **Proof of Work (PoW)**는 거래 검증을 위해 계산 능력에 의존합니다.
- **Proof of Stake (PoS)**는 검증자가 일정량의 토큰을 보유하도록 요구하며, PoW에 비해 에너지 소비를 줄입니다.

## Bitcoin 핵심 개념

### 트랜잭션

Bitcoin 트랜잭션은 주소 간 자금 이전을 포함합니다. 트랜잭션은 디지털 서명을 통해 검증되어, 개인 키의 소유자만이 전송을 시작할 수 있도록 보장합니다.

#### 주요 구성 요소:

- **Multisignature Transactions**는 트랜잭션을 승인하기 위해 여러 서명이 필요합니다.
- 트랜잭션은 **inputs**(자금 출처), **outputs**(목적지), **fees**(miners에게 지급), 및 **scripts**(트랜잭션 규칙)로 구성됩니다.

### Lightning Network

여러 트랜잭션을 채널 내에서 처리하고 최종 상태만 블록체인에 브로드캐스트함으로써 Bitcoin의 확장성을 향상시키는 것을 목표로 합니다.

## Bitcoin 프라이버시 우려

Common Input Ownership 및 UTXO Change Address Detection과 같은 프라이버시 공격은 트랜잭션 패턴을 악용합니다. Mixers 및 CoinJoin과 같은 전략은 사용자 간 트랜잭션 연계를 흐리게 하여 익명성을 향상시킵니다.

## 익명으로 Bitcoin 획득하기

방법에는 현금 거래, 채굴, mixers 사용 등이 포함됩니다. CoinJoin은 추적을 복잡하게 만들기 위해 여러 트랜잭션을 혼합하고, PayJoin은 일반 트랜잭션으로 CoinJoin을 위장하여 프라이버시를 강화합니다.

# Bitcoin Privacy Atacks

# Bitcoin 프라이버시 공격 요약

Bitcoin 세계에서 트랜잭션의 프라이버시와 사용자의 익명성은 종종 우려의 대상입니다. 다음은 공격자가 Bitcoin 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법에 대한 단순화된 개요입니다.

## **Common Input Ownership Assumption**

서로 다른 사용자의 inputs가 하나의 트랜잭션에서 결합되는 것은 복잡성 때문에 일반적으로 드뭅니다. 따라서 **같은 트랜잭션의 두 입력 주소는 종종 동일한 소유자에게 속한다고 가정됩니다**.

## **UTXO Change Address Detection**

UTXO, 또는 **미사용 트랜잭션 출력(Unspent Transaction Output)**는 트랜잭션에서 전체가 사용되어야 합니다. 그 일부만 다른 주소로 전송되면 잔액은 새로운 change address로 돌아갑니다. 관찰자는 이 새로운 주소가 송신자에 속한다고 가정할 수 있어 프라이버시가 손상됩니다.

### 예시

이를 완화하기 위해 mixing 서비스나 여러 주소 사용이 소유권을 숨기는 데 도움이 될 수 있습니다.

## **Social Networks & Forums 노출**

사용자가 때때로 온라인에 자신의 Bitcoin 주소를 공유하여 **주소를 소유자와 연결하기 쉽습니다**.

## **트랜잭션 그래프 분석**

트랜잭션은 그래프로 시각화될 수 있으며, 자금 흐름을 기반으로 사용자 간의 잠재적 연결을 드러냅니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 휴리스틱은 여러 inputs와 outputs를 가진 트랜잭션을 분석하여 어떤 output이 송신자에게 반환되는 change인지 추측하는 데 기반합니다.

### 예시
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

공격자들은 수신자가 이후 트랜잭션에서 이러한 금액을 다른 inputs와 합치길 바라며, 이전에 사용된 addresses로 소액을 보낼 수 있다. 이렇게 하면 주소들이 연결될 가능성이 생긴다.

### Correct Wallet Behavior

Wallets는 이미 사용된, 비어 있는 addresses에서 받은 coins를 사용하지 않음으로써 이러한 privacy leak를 방지해야 한다.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change가 없는 Transactions는 동일 사용자가 소유한 두 addresses 간의 거래일 가능성이 높다.
- **Round Numbers:** 트랜잭션의 반올림된 금액은 지불임을 시사하며, 반올림되지 않은 output이 change일 가능성이 높다.
- **Wallet Fingerprinting:** 서로 다른 wallets는 고유한 transaction 생성 패턴을 가지며, 이는 분석가가 사용된 소프트웨어를 식별하고 잠재적으로 change address를 찾아낼 수 있게 한다.
- **Amount & Timing Correlations:** 거래 시간이나 금액을 공개하면 Transactions를 추적 가능하게 만들 수 있다.

## **Traffic Analysis**

네트워크 트래픽을 모니터링함으로써 공격자들은 Transactions나 blocks를 IP addresses와 연결할 수 있어 사용자 프라이버시를 침해할 수 있다. 특히 한 기관이 많은 Bitcoin nodes를 운영하면 Transactions를 모니터링할 수 있는 능력이 향상되어 이 문제가 심각해진다.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# 익명 Bitcoin Transactions

## Bitcoin을 익명으로 얻는 방법

- **Cash Transactions**: 현금으로 bitcoin을 취득.
- **Cash Alternatives**: 기프트 카드를 구입하여 온라인에서 bitcoin으로 교환.
- **Mining**: 혼자 채굴할 때가 가장 프라이빗하게 bitcoin을 얻는 방법이다. 채굴 풀은 채굴자의 IP address를 알 수 있기 때문에 풀 채굴은 프라이버시가 낮을 수 있다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 이론적으로는 bitcoin을 훔치는 것이 익명으로 획득하는 또 다른 방법이 될 수 있지만, 불법이며 권장되지 않는다.

## Mixing Services

mixing service를 사용하면 사용자는 **bitcoins를 보낸 뒤** **다른 bitcoins를 받음으로써** 원래 소유자를 추적하기 어렵게 만들 수 있다. 그러나 이는 서비스가 로그를 보관하지 않고 실제로 bitcoins를 반환할 것이라는 신뢰를 필요로 한다. 대안으로 Bitcoin 카지노 같은 mixing 옵션이 있다.

## CoinJoin

CoinJoin는 서로 다른 사용자들의 여러 트랜잭션을 하나로 합쳐 inputs와 outputs를 매칭하려는 사람들을 혼란스럽게 만든다. 그럼에도 불구하고 고유한 input 및 output 크기를 가진 트랜잭션은 여전히 추적될 수 있다.

예시로 CoinJoin을 사용했을 가능성이 있는 트랜잭션에는 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있다.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 두 당사자(예: 고객과 상인) 사이의 트랜잭션을 CoinJoin 특유의 동일한 outputs 없이 일반적인 트랜잭션으로 위장한다. 이는 탐지를 매우 어렵게 만들며 transaction surveillance에서 사용하는 common-input-ownership heuristic을 무효화할 수도 있다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
위와 같은 거래는 PayJoin일 수 있으며, 표준 bitcoin 거래와 구별되지 않으면서 프라이버시를 향상시킨다.

**PayJoin의 활용은 기존의 감시 기법을 상당히 혼란시킬 수 있다**, 이는 거래 프라이버시를 추구하는 데 있어 유망한 발전이다.

# 암호화폐 프라이버시 모범 사례

## **Wallet Synchronization Techniques**

프라이버시와 보안을 유지하려면 블록체인과 지갑을 동기화하는 것이 중요하다. 다음 두 가지 방법이 특히 유용하다:

- **Full node**: 전체 블록체인을 다운로드함으로써 full node는 최대한의 프라이버시를 보장한다. 지금까지 발생한 모든 거래가 로컬에 저장되어, 공격자가 사용자가 관심 있는 거래나 주소를 식별할 수 없게 한다.
- **Client-side block filtering**: 이 방법은 블록체인의 각 블록에 대한 필터를 생성해 지갑이 네트워크 관측자에게 특정 관심사항을 노출하지 않고 관련 거래를 식별할 수 있게 한다. 라이트급 지갑은 이 필터들만 다운로드하고, 사용자의 주소와 일치하는 경우에만 전체 블록을 가져온다.

## **Utilizing Tor for Anonymity**

Bitcoin이 peer-to-peer 네트워크에서 작동하므로, 네트워크와 상호작용할 때 IP 주소를 감추기 위해 Tor 사용을 권장한다.

## **Preventing Address Reuse**

프라이버시를 보호하려면 거래마다 새로운 주소를 사용하는 것이 중요하다. 주소를 재사용하면 거래들이 동일한 주체와 연결되어 프라이버시가 침해될 수 있다. 최신 지갑은 설계상 주소 재사용을 권장하지 않는다.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 결제를 여러 거래로 나누면 거래 금액을 흐리게 하여 프라이버시 공격을 방해할 수 있다.
- **Change avoidance**: 잔돈 출력(change outputs)이 필요 없는 거래를 선택하면 change detection 기법을 방해해 프라이버시를 높일 수 있다.
- **Multiple change outputs**: 잔돈 회피가 불가능할 경우, 여러 개의 change outputs를 생성하는 것도 프라이버시를 개선할 수 있다.

# **Monero: 익명성의 상징**

Monero는 디지털 거래에서 절대적 익명성의 요구를 충족시키며 프라이버시에 대해 높은 기준을 세운다.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas는 Ethereum에서 연산을 실행하는 데 필요한 계산 작업량을 측정하며, 가격 단위는 **gwei**다. 예를 들어 2,310,000 gwei(또는 0.00231 ETH) 비용이 드는 거래는 gas limit과 base fee가 포함되며, 마이너(또는 검증자)를 유인하기 위한 tip이 추가된다. 사용자는 초과 지불을 방지하기 위해 max fee를 설정할 수 있으며, 초과분은 환불된다.

## **Executing Transactions**

Ethereum의 거래는 sender와 recipient가 참여하며, 이들은 사용자 주소이거나 smart contract 주소일 수 있다. 거래는 수수료가 필요하고 채굴(또는 검증)되어야 한다. 거래에 포함되는 주요 정보는 recipient, sender의 서명, value, 선택적 data, gas limit 및 수수료 등이다. 특이하게도 sender의 주소는 서명으로부터 유도되므로 거래 데이터에 명시적으로 포함될 필요가 없다.

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐를 다루고자 하는 사람들에게 기본이 된다.

## Smart Contract Security

- Mutation testing을 통해 테스트 스위트의 사각지대를 찾기:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

DEXes와 AMMs(Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps)의 실제 익스플로잇을 연구하고 있다면, 다음을 확인하세요:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
