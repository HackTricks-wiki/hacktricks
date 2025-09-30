# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **스마트 계약(Smart Contracts)** 는 특정 조건이 충족되면 블록체인 상에서 실행되는 프로그램으로, 중개자 없이 합의 이행을 자동화합니다.
- **분산형 애플리케이션(dApps)** 는 스마트 계약을 기반으로 하며, 사용자 친화적인 프런트엔드와 투명하고 감사 가능한 백엔드를 갖춥니다.
- **토큰 & 코인** 은 코인이 디지털 화폐로 사용되는 반면, 토큰은 특정 맥락에서 가치나 소유권을 나타낸다는 점에서 구분됩니다.
- **유틸리티 토큰(Utility Tokens)** 은 서비스 접근 권한을 부여하고, **증권형 토큰(Security Tokens)** 은 자산 소유를 의미합니다.
- **DeFi** 는 중앙 권한 없이 금융 서비스를 제공하는 탈중앙화 금융을 의미합니다.
- **DEX** 와 **DAOs** 는 각각 분산형 거래소(Decentralized Exchange)와 분산형 자율 조직(Decentralized Autonomous Organization)을 가리킵니다.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 거래 검증을 안전하고 합의된 방식으로 보장합니다:

- **Proof of Work (PoW)** 는 거래 검증을 위해 계산 능력에 의존합니다.
- **Proof of Stake (PoS)** 는 검증자가 일정량의 토큰을 보유하도록 요구하여 PoW에 비해 에너지 소비를 줄입니다.

## 비트코인 필수 지식

### 거래

비트코인 거래는 주소 간 자금 이동을 포함합니다. 거래는 디지털 서명을 통해 검증되어 개인 키 소유자만 전송을 시작할 수 있음을 보장합니다.

#### 핵심 요소:

- **다중 서명 거래(Multisignature Transactions)** 는 거래를 승인하기 위해 여러 서명이 필요합니다.
- 거래는 **입력(inputs)**(자금의 출처), **출력(outputs)**(목적지), **수수료(fees)**(채굴자에게 지급), 및 **스크립트(scripts)**(거래 규칙)로 구성됩니다.

### 라이트닝 네트워크

라이트닝 네트워크는 채널 내에서 여러 거래를 허용하고 최종 상태만 블록체인에 브로드캐스트하여 비트코인의 확장성을 향상시키는 것을 목표로 합니다.

## 비트코인 프라이버시 문제

Common Input Ownership, UTXO Change Address Detection과 같은 프라이버시 공격은 거래 패턴을 악용합니다. Mixers와 CoinJoin 같은 전략은 사용자 간 거래 연결을 난독화하여 익명성을 개선합니다.

## 익명으로 비트코인 획득하기

방법으로는 현금 거래, 채굴 및 믹서 사용 등이 있습니다. **CoinJoin** 은 여러 거래를 섞어 추적을 복잡하게 만들고, **PayJoin** 은 CoinJoin을 일반 거래로 위장하여 더 높은 프라이버시를 제공합니다.

# Bitcoin Privacy Atacks

# 비트코인 프라이버시 공격 요약

비트코인 세계에서 거래의 프라이버시와 사용자의 익명성은 자주 우려되는 주제입니다. 다음은 공격자가 비트코인 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법에 대한 간단한 개요입니다.

## **Common Input Ownership Assumption (공통 입력 소유 가정)**

서로 다른 사용자의 입력이 단일 거래에서 결합되는 경우는 복잡성 때문에 일반적으로 드뭅니다. 따라서 **같은 거래의 두 입력 주소는 종종 동일한 소유자에게 속한다고 가정됩니다**.

## **UTXO Change Address Detection (UTXO 잔액 주소 탐지)**

UTXO, 즉 미사용 거래 출력(Unspent Transaction Output)은 거래에서 전체가 소비되어야 합니다. 그 중 일부만 다른 주소로 전송될 경우, 나머지 금액은 새로운 잔액 주소(change address)로 돌아갑니다. 관찰자는 이 새 주소가 송금자에게 속한다고 추정할 수 있어 프라이버시가 침해됩니다.

### 예시

이를 완화하기 위해 믹싱 서비스나 여러 주소를 사용하는 것이 소유권을 혼동시키는 데 도움이 됩니다.

## **소셜 네트워크 및 포럼 노출**

사용자들이 종종 자신의 비트코인 주소를 온라인에 공유하여 **주소와 소유자를 연결하기 쉽도록** 만듭니다.

## **거래 그래프 분석**

거래는 그래프로 시각화할 수 있으며, 자금 흐름을 기반으로 사용자 간의 잠재적 연결을 드러낼 수 있습니다.

## **불필요한 입력 휴리스틱(Optimal Change Heuristic)**

이 휴리스틱은 여러 입력과 출력을 가진 거래를 분석하여 어떤 출력이 송금자에게 돌아가는 잔액(change)인지 추측하는 데 기반합니다.

### 예시
```bash
2 btc --> 4 btc
3 btc     1 btc
```
입력이 더 추가되어 잔돈 출력이 어느 단일 입력보다 커지면, 그 휴리스틱을 혼란스럽게 만들 수 있다.

## **강제 주소 재사용**

공격자는 이전에 사용된 주소로 소량을 전송해, 수신자가 이후 거래에서 이를 다른 입력과 결합하도록 유도함으로써 주소들을 서로 연결하려 할 수 있다.

### 올바른 지갑 동작

지갑은 이미 사용된 빈 주소로 수신된 코인을 사용하지 않아야 하며, 이로써 개인정보 leak을 방지해야 한다.

## **기타 블록체인 분석 기법**

- **정확한 결제 금액:** 잔돈이 없는 거래는 동일 사용자가 소유한 두 주소 간의 거래일 가능성이 높다.
- **반올림된 숫자:** 거래의 반올림된 금액은 결제임을 시사하며, 반올림되지 않은 출력이 잔돈일 가능성이 높다.
- **지갑 지문화:** 지갑마다 고유한 거래 생성 패턴이 있어 분석가가 사용된 소프트웨어를 식별하고 잠재적으로 잔돈 주소를 알아낼 수 있다.
- **금액 및 시간 상관관계:** 거래 시간이나 금액을 공개하면 거래를 추적 가능하게 만들 수 있다.

## **트래픽 분석**

네트워크 트래픽을 모니터링함으로써 공격자는 거래나 블록을 IP 주소와 연결할 수 있어 사용자 개인정보를 침해할 수 있다. 특히 어떤 단체가 다수의 Bitcoin 노드를 운영하면 거래를 모니터링할 수 있는 능력이 향상된다.

## 추가 자료

개인정보 공격 및 방어에 대한 포괄적 목록은 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)을 참조하라.

# 익명 비트코인 거래

## 비트코인을 익명으로 얻는 방법

- **현금 거래**: 현금으로 비트코인을 획득한다.
- **현금 대안**: 기프트 카드를 구매해 온라인에서 비트코인으로 교환한다.
- **채굴**: 비트코인을 얻는 가장 프라이빗한 방법은 채굴이며, 특히 단독 채굴일 때 그렇다. 채굴 풀은 채굴자의 IP 주소를 알 수 있다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **도둑질**: 이론적으로는 비트코인을 훔치는 것이 익명으로 획득하는 방법이 될 수 있지만 불법이며 권장되지 않는다.

## 믹싱 서비스

믹싱 서비스를 사용하면 사용자는 **비트코인을 보낼 수** 있고 **다른 비트코인을 되돌려받을 수** 있어 원소유자를 추적하기 어렵게 만든다. 그러나 서비스가 로그를 보관하지 않고 실제로 비트코인을 반환할 것이라는 신뢰가 필요하다. 대안 믹싱 옵션으로는 Bitcoin 카지노가 있다.

## CoinJoin

CoinJoin은 서로 다른 사용자의 여러 거래를 하나로 합쳐 입력과 출력을 매칭하려는 시도를 어렵게 만든다. 그럼에도 불구하고 입력과 출력 크기가 고유한 거래는 여전히 추적될 수 있다.

CoinJoin을 사용했을 수 있는 예시 거래에는 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`와 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있다.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하라. Ethereum에서 유사한 서비스로는 채굴자의 자금으로 거래를 익명화하는 [Tornado Cash](https://tornado.cash)가 있다.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 고객과 상인 등 두 당사자 간의 거래를 일반 거래로 위장하여 CoinJoin 특유의 동일한 출력을 드러나지 않게 만든다. 이는 탐지를 매우 어렵게 하며, 트랜잭션 감시 기관이 사용하는 common-input-ownership 휴리스틱을 무효화할 수 있다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

프라이버시와 보안을 유지하려면 지갑을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 특히 유용합니다:

- **Full node**: 전체 블록체인을 다운로드함으로써 Full node는 최대한의 프라이버시를 보장합니다. 지금까지 발생한 모든 거래가 로컬에 저장되어 있어 공격자가 사용자가 어떤 거래나 주소에 관심이 있는지 식별하기 어렵습니다.
- **Client-side block filtering**: 이 방법은 블록체인의 각 블록에 대한 필터를 생성하여 지갑이 네트워크 관찰자에게 특정 관심사를 노출하지 않고 관련 거래를 식별할 수 있게 합니다. 라이트급 지갑은 이러한 필터만 다운로드하며, 사용자의 주소와 일치할 때만 전체 블록을 가져옵니다.

## **Utilizing Tor for Anonymity**

Bitcoin이 P2P 네트워크에서 동작하기 때문에, Tor를 사용해 IP 주소를 은폐하는 것이 권장되며 네트워크와 상호작용할 때 프라이버시를 향상시킵니다.

## **Preventing Address Reuse**

프라이버시를 보호하려면 거래마다 새 주소를 사용하는 것이 중요합니다. 주소를 재사용하면 동일한 실체에 거래들이 연결되어 프라이버시가 손상될 수 있습니다. 최신 지갑은 설계상 주소 재사용을 권장하지 않습니다.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 결제를 여러 거래로 분할하면 거래 금액을 불분명하게 만들어 프라이버시 공격을 방해할 수 있습니다.
- **Change avoidance**: change outputs가 필요 없는 거래를 선택하면 change 탐지 기법을 교란시켜 프라이버시를 향상시킵니다.
- **Multiple change outputs**: change 회피가 불가능한 경우 여러 개의 change outputs를 생성하는 것만으로도 프라이버시를 개선할 수 있습니다.

# **Monero: A Beacon of Anonymity**

Monero는 디지털 거래에서 절대적인 익명성 요구를 해결하며 높은 수준의 프라이버시 기준을 제시합니다.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas는 Ethereum에서 연산을 실행하는 데 필요한 계산량을 측정하며, 가격 단위는 **gwei**입니다. 예를 들어 2,310,000 gwei(또는 0.00231 ETH) 비용이 드는 거래는 gas limit과 base fee를 포함하며, 채굴자 인센티브로 tip이 추가됩니다. 사용자는 초과 지불을 피하기 위해 max fee를 설정할 수 있으며, 남는 금액은 환불됩니다.

## **Executing Transactions**

Ethereum의 거래는 송신자와 수신자를 포함하며, 수신자는 사용자 주소이거나 스마트 컨트랙트 주소일 수 있습니다. 거래는 수수료가 필요하고 채굴되어야 합니다. 거래에 포함되는 필수 정보로는 수신자, 송신자의 서명, 값(value), 선택적 데이터, gas limit, 그리고 수수료가 있습니다. 특히 송신자의 주소는 서명으로부터 유추되므로 거래 데이터에 별도로 포함될 필요가 없습니다.

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐를 다루려는 누구에게나 기초가 됩니다.

## References

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

{{#include ../../banners/hacktricks-training.md}}
