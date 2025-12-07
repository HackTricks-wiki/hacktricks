# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **Smart Contracts**은 특정 조건이 충족되면 블록체인에서 실행되는 프로그램으로, 중개자 없이 합의 실행을 자동화합니다.
- **Decentralized Applications (dApps)**은 스마트 계약 위에 구축되며, 사용자 친화적인 프론트엔드와 투명하고 감사 가능한 백엔드를 갖춥니다.
- **Tokens & Coins**는 구분되어 사용되며, 코인은 디지털 화폐로 기능하고 토큰은 특정 맥락에서 가치나 소유권을 나타냅니다.
- **Utility Tokens**는 서비스 접근을 제공하고, **Security Tokens**는 자산 소유권을 의미합니다.
- **DeFi**는 탈중앙화 금융을 의미하며 중앙 권한 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 가리킵니다.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 거래 검증의 보안성과 합의를 보장합니다:

- **Proof of Work (PoW)**는 거래 검증을 위해 계산 능력에 의존합니다.
- **Proof of Stake (PoS)**는 검증자가 일정량의 토큰을 보유하도록 요구하며, PoW에 비해 에너지 소비를 줄입니다.

## 비트코인 필수 개념

### Transactions

비트코인 거래는 주소 간 자금 전송을 포함합니다. 거래는 디지털 서명을 통해 검증되며, 개인 키의 소유자만 전송을 시작할 수 있음을 보장합니다.

#### 주요 구성요소:

- **Multisignature Transactions**는 거래를 승인하려면 여러 서명이 필요합니다.
- 거래는 **inputs** (자금 출처), **outputs** (목적지), **fees** (채굴자에게 지급), 및 **scripts** (거래 규칙)로 구성됩니다.

### Lightning Network

여러 거래를 채널 내에서 처리하고 최종 상태만 블록체인에 브로드캐스트하여 비트코인의 확장성을 향상시키는 것을 목표로 합니다.

## 비트코인 프라이버시 문제

Common Input Ownership, **UTXO Change Address Detection** 등과 같은 프라이버시 공격은 거래 패턴을 악용합니다. **Mixers**와 **CoinJoin** 같은 전략은 사용자 간 거래 연결을 흐리게 하여 익명성을 개선합니다.

## 익명으로 비트코인 획득하기

현금 거래, 채굴, 믹서 사용 등이 방법에 포함됩니다. **CoinJoin**은 추적을 복잡하게 만들기 위해 여러 거래를 혼합하고, **PayJoin**은 더 높은 프라이버시를 위해 CoinJoin을 일반 거래처럼 위장합니다.

# Bitcoin Privacy Atacks

# 비트코인 프라이버시 공격 요약

비트코인 세계에서 거래의 프라이버시와 사용자 익명성은 종종 우려의 대상입니다. 다음은 공격자가 비트코인 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법에 대한 간단한 개요입니다.

## **Common Input Ownership Assumption**

여러 사용자의 inputs가 하나의 거래에 결합되는 경우는 드물기 때문에, **같은 거래에 있는 두 개의 input 주소는 종종 동일한 소유자에게 속한다고 가정**됩니다.

## **UTXO Change Address Detection**

UTXO(미사용 거래 출력)는 거래에서 완전히 사용되어야 합니다. 일부만 다른 주소로 전송되면 나머지 금액은 새로운 change address로 돌아갑니다. 관찰자는 이 새로운 주소가 송금자에게 속한다고 가정할 수 있어 프라이버시가 침해됩니다.

### 예시

이를 완화하려면 믹싱 서비스 사용이나 여러 주소 사용으로 소유권을 흐리게 만드는 것이 도움이 될 수 있습니다.

## **Social Networks & Forums Exposure**

사용자들이 때때로 온라인에 비트코인 주소를 공유하여 그 주소를 소유자와 연결하기가 **쉽게** 됩니다.

## **Transaction Graph Analysis**

거래는 그래프로 시각화될 수 있으며, 자금의 흐름을 기반으로 사용자의 잠재적 연결을 드러낼 수 있습니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 휴리스틱은 여러 입력과 출력을 가진 거래를 분석하여 어떤 출력이 송금자에게 돌아가는 change인지 추측하는 데 기반합니다.

### 예시
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **강제 주소 재사용 (Forced Address Reuse)**

공격자는 수령인이 향후 트랜잭션에서 이러한 소액을 다른 입력과 합쳐 주소들을 연결시키기를 기대하며, 이전에 사용된 주소로 소액을 보낼 수 있다.

### 올바른 지갑 동작

지갑은 이미 사용된, 비어 있는 주소로 수신된 코인을 사용하지 않음으로써 이 프라이버시 leak을 방지해야 한다.

## **기타 블록체인 분석 기법**

- **Exact Payment Amounts:** change가 없는 트랜잭션은 동일 사용자가 소유한 두 주소 간의 거래일 가능성이 높다.
- **Round Numbers:** 트랜잭션에 둥근 숫자가 있으면 지불일 가능성이 있으며, 비둥근 출력이 거스름돈일 가능성이 높다.
- **Wallet Fingerprinting:** 서로 다른 지갑은 고유한 트랜잭션 생성 패턴을 가지므로, 분석가는 사용된 소프트웨어와 잠재적으로 change address를 식별할 수 있다.
- **Amount & Timing Correlations:** 트랜잭션 시간이나 금액을 노출하면 트랜잭션을 추적할 수 있게 된다.

## **트래픽 분석**

네트워크 트래픽을 모니터링함으로써 공격자는 트랜잭션이나 블록을 IP 주소와 연결하여 사용자 프라이버시를 침해할 수 있다. 특히 많은 Bitcoin 노드를 운영하는 주체는 트랜잭션을 감시할 능력이 향상된다.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# 익명 Bitcoin 거래

## 익명으로 Bitcoins를 얻는 방법

- **Cash Transactions**: 현금을 통해 bitcoin을 획득.
- **Cash Alternatives**: 기프트 카드를 구매하고 온라인에서 이를 bitcoin으로 교환.
- **Mining**: 비트코인을 획득하는 가장 프라이빗한 방법은 채굴이며, 특히 단독 채굴 시 프라이버시가 높다. 채굴 풀은 채굴자의 IP 주소를 알 수 있다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 이론적으로 비트코인을 도용하는 것도 익명으로 획득하는 방법일 수 있으나 불법이며 권장되지 않는다.

## 믹싱 서비스 (Mixing Services)

믹싱 서비스를 사용하면 사용자는 **비트코인을 보내고** **다른 비트코인을 돌려받아** 원래 소유자를 추적하기 어렵게 만들 수 있다. 그러나 이는 서비스가 로그를 남기지 않고 실제로 비트코인을 반환할 것이라는 신뢰를 필요로 한다. 대안적 믹싱 옵션으로는 Bitcoin 카지노가 있다.

## CoinJoin

**CoinJoin**은 여러 사용자의 여러 트랜잭션을 하나로 합쳐 입력과 출력을 매칭하려는 사람을 어렵게 만든다. 그럼에도 불구하고 입력과 출력 크기가 독특한 트랜잭션은 여전히 추적될 수 있다.

예시로 CoinJoin을 사용했을 가능성이 있는 트랜잭션은 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 와 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` 이 있다.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 거래를 두 당사자(예: 고객과 상인) 사이의 일반 거래로 위장하여 CoinJoin의 동등한 출력과 같은 특징을 제거한다. 이는 감지하기 매우 어렵게 만들며 트랜잭션 감시 기관들이 사용하는 common-input-ownership 휴리스틱을 무효화할 수 있다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin의 활용은 전통적인 감시 기법에 큰 타격을 줄 수 있으며**, 거래 프라이버시를 향한 유망한 발전으로 볼 수 있습니다.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

프라이버시와 보안을 유지하려면 지갑을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 특히 유용합니다:

- **Full node**: 전체 블록체인을 다운로드함으로써 Full node는 최대의 프라이버시를 보장합니다. 지금까지 수행된 모든 트랜잭션이 로컬에 저장되므로 공격자가 사용자가 관심 있는 트랜잭션이나 주소를 식별할 수 없습니다.
- **Client-side block filtering**: 이 방법은 블록체인의 각 블록에 대한 필터를 생성하여, 지갑이 네트워크 관찰자에게 특정 관심을 노출하지 않고 관련 트랜잭션을 식별할 수 있게 합니다. 라이트급 지갑은 이러한 필터만 다운로드하고, 사용자의 주소와 매치될 때에만 전체 블록을 가져옵니다.

## **Utilizing Tor for Anonymity**

Bitcoin이 피어투피어 네트워크에서 동작한다는 점을 고려할 때, Tor를 사용하여 IP 주소를 숨기는 것이 권장되며, 네트워크와 상호작용할 때 프라이버시를 향상시킵니다.

## **Preventing Address Reuse**

프라이버시를 보호하려면 각 트랜잭션마다 새로운 주소를 사용하는 것이 중요합니다. 주소 재사용은 트랜잭션들을 동일한 주체에 연결시켜 프라이버시를 손상시킬 수 있습니다. 최신 지갑들은 설계상 주소 재사용을 방지하도록 권장합니다.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 결제를 여러 트랜잭션으로 분할하면 금액을 흐리게 하여 프라이버시 공격을 방해할 수 있습니다.
- **Change avoidance**: 체인지 출력이 필요하지 않은 트랜잭션을 선택하면 체인지 탐지 기법을 무력화하여 프라이버시를 향상시킬 수 있습니다.
- **Multiple change outputs**: 체인지 회피가 불가능한 경우, 여러 체인지 출력을 생성하는 것이 여전히 프라이버시를 개선할 수 있습니다.

# **Monero: A Beacon of Anonymity**

Monero는 디지털 거래에서 절대적인 익명성에 대한 요구를 다루며, 프라이버시에 높은 기준을 설정합니다.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas는 Ethereum에서 연산을 실행하는 데 필요한 계산 자원을 측정하는 단위이며, 가격은 **gwei**로 표시됩니다. 예를 들어, 2,310,000 gwei(또는 0.00231 ETH) 비용이 드는 트랜잭션은 가스 한도와 기본 수수료(base fee)를 포함하며, 마이너 인센티브로 팁이 추가됩니다. 사용자는 과다 지불을 방지하기 위해 최대 수수료(max fee)를 설정할 수 있고, 초과분은 환불됩니다.

## **Executing Transactions**

Ethereum의 트랜잭션은 송신자와 수신자를 포함하며, 수신자는 사용자 주소이거나 스마트 컨트랙트 주소일 수 있습니다. 트랜잭션은 수수료가 필요하고 채굴되어야 합니다. 트랜잭션의 핵심 정보에는 수신자, 송신자 서명, 값(value), 선택적 데이터, 가스 한도, 수수료가 포함됩니다. 특히, 송신자 주소는 서명으로부터 유추되므로 트랜잭션 데이터에 별도로 포함될 필요가 없습니다.

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하며 암호화폐를 다루려는 누구에게나 기본이 됩니다.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## 참고자료

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
