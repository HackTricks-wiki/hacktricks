# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts**는 특정 조건이 충족될 때 블록체인에서 실행되는 프로그램으로, 중개인 없이 계약 실행을 자동화합니다.
- **Decentralized Applications (dApps)**는 스마트 컨트랙트를 기반으로 하며, 사용자 친화적 프론트엔드와 투명하고 감사가 가능한 백엔드를 가집니다.
- **Tokens & Coins**는 코인이 디지털 통화 역할을 하는 반면, 토큰은 특정 맥락에서 가치나 소유권을 나타낸다는 차이가 있습니다.
- **Utility Tokens**는 서비스 접근 권한을 제공하고, **Security Tokens**는 자산 소유권을 나타냅니다.
- **DeFi**는 중앙 기관 없이 금융 서비스를 제공하는 Decentralized Finance를 의미합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 가리킵니다.

## Consensus Mechanisms

Consensus 메커니즘은 블록체인에서 거래 검증의 보안성과 합의를 보장합니다:

- **Proof of Work (PoW)**는 트랜잭션 검증을 위해 계산 능력에 의존합니다.
- **Proof of Stake (PoS)**는 검증자가 일정량의 토큰을 보유하도록 요구하여 PoW에 비해 에너지 소비를 줄입니다.

## Bitcoin Essentials

### Transactions

Bitcoin 트랜잭션은 주소 간 자금 이체를 포함합니다. 트랜잭션은 디지털 서명을 통해 검증되며, 개인 키 소유자만 전송을 시작할 수 있도록 보장합니다.

#### Key Components:

- **Multisignature Transactions**는 트랜잭션 인가에 여러 서명을 요구합니다.
- 트랜잭션은 **inputs**(자금의 출처), **outputs**(목적지), **fees**(miners에게 지급되는 수수료), 및 **scripts**(트랜잭션 규칙)로 구성됩니다.

### Lightning Network

Lightning Network는 채널 내에서 여러 트랜잭션을 허용하고 최종 상태만 블록체인에 브로드캐스트함으로써 Bitcoin의 확장성을 향상시키는 것을 목표로 합니다.

## Bitcoin Privacy Concerns

프라이버시 공격은 **Common Input Ownership** 및 **UTXO Change Address Detection** 등 트랜잭션 패턴을 악용합니다. **Mixers**와 **CoinJoin**과 같은 전략은 사용자 간 트랜잭션 연결을 모호하게 하여 익명성을 향상합니다.

## Acquiring Bitcoins Anonymously

방법에는 현금 거래, 채굴, 믹서 사용 등이 포함됩니다. **CoinJoin**은 추적 가능성을 복잡하게 만들기 위해 여러 트랜잭션을 혼합하고, **PayJoin**은 CoinJoin을 일반 트랜잭션처럼 위장하여 더 높은 프라이버시를 제공합니다.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin 세계에서 트랜잭션의 프라이버시와 사용자의 익명성은 자주 문제가 됩니다. 다음은 공격자가 Bitcoin 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법의 간단한 개요입니다.

## **Common Input Ownership Assumption**

다른 사용자들의 inputs가 하나의 트랜잭션에 결합되는 것은 복잡성 때문에 일반적으로 드뭅니다. 따라서 **같은 트랜잭션의 두 입력 주소는 종종 동일한 소유자에 속한다고 가정됩니다**.

## **UTXO Change Address Detection**

UTXO, 또는 **Unspent Transaction Output**,는 트랜잭션에서 전부 소비되어야 합니다. 그 일부만 다른 주소로 보내는 경우 남은 금액은 새로운 change address로 갑니다. 관찰자는 이 새로운 주소가 송신자에게 속한다고 추정할 수 있어 프라이버시를 침해합니다.

### Example

이를 완화하기 위해 mixing services나 여러 주소 사용이 소유권을 흐리게 하는 데 도움이 될 수 있습니다.

## **Social Networks & Forums Exposure**

사용자들이 때때로 온라인에 자신의 Bitcoin 주소를 공유하여 **주소와 소유자를 연결하기 쉽게** 만듭니다.

## **Transaction Graph Analysis**

트랜잭션은 그래프로 시각화될 수 있으며, 자금 흐름을 기반으로 사용자 간의 잠재적 연결을 드러냅니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 휴리스틱은 여러 inputs와 outputs를 가진 트랜잭션을 분석하여 어떤 output이 송신자에게 반환되는 change인지 추측하는 데 기반합니다.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

공격자는 이전에 사용된 주소로 소량을 전송해 수취인이 향후 거래에서 이를 다른 입력과 결합하도록 유도함으로써 주소들을 서로 연결하려 할 수 있다.

### Correct Wallet Behavior

지갑은 이 privacy leak을 방지하기 위해 이미 사용된, 비어 있는 주소에서 받은 코인을 사용하지 않아야 한다.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 거스름돈(change)이 없는 거래는 두 주소가 동일한 사용자의 소유일 가능성이 높다.
- **Round Numbers:** 거래에서 반올림된 숫자는 결제일 가능성이 있으며, 비반올림 출력이 거스름돈일 가능성이 높다.
- **Wallet Fingerprinting:** 서로 다른 wallets는 고유한 트랜잭션 생성 패턴을 가지므로 분석가는 사용된 소프트웨어를 식별하고 잠재적으로 change 주소를 찾아낼 수 있다.
- **Amount & Timing Correlations:** 거래 시간이나 금액을 공개하면 거래를 추적할 수 있다.

## Traffic Analysis

네트워크 트래픽을 모니터링함으로써 공격자는 거래나 블록을 IP 주소와 연결해 사용자 프라이버시를 침해할 수 있다. 한 엔터티가 많은 Bitcoin 노드를 운영하면 거래를 감시할 능력이 향상되어 특히 그러하다.

## More

자세한 프라이버시 공격 및 방어 목록은 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)를 참조하라.

# 익명의 Bitcoin 거래

## 비트코인을 익명으로 얻는 방법

- **Cash Transactions**: 현금으로 비트코인을 획득.
- **Cash Alternatives**: 기프트 카드를 구매해 온라인에서 비트코인으로 교환.
- **Mining**: 비트코인을 획득하는 가장 프라이빗한 방법은 채굴이며, 특히 단독 채굴 시 더욱 그러하다. 채굴 풀은 채굴자의 IP 주소를 알 수 있다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 이론적으로 비트코인을 훔치는 것이 익명으로 획득하는 또 다른 방법일 수 있으나 불법이며 권장되지 않는다.

## Mixing Services

혼합 서비스를 사용하면 사용자가 **비트코인을 보낸 후** **다른 비트코인을 받음으로써** 원래 소유자를 추적하기 어렵게 만들 수 있다. 다만 이는 서비스가 로그를 남기지 않고 실제로 비트코인을 반환할 것이라는 신뢰가 필요하다. 대안으로 Bitcoin 카지노 등이 있다.

## CoinJoin

CoinJoin은 여러 사용자의 여러 트랜잭션을 하나로 합쳐 입력과 출력을 매칭하기 어렵게 만든다. 그럼에도 불구하고 입력 및 출력 크기가 독특한 거래는 여전히 추적될 수 있다.

예시 거래(아마도 CoinJoin을 사용했을 수 있음): `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)를 참조하라. Ethereum상의 유사 서비스로는 채굴자 자금으로 거래를 익명화하는 [Tornado Cash](https://tornado.cash)가 있다.

## PayJoin

CoinJoin의 변형인 PayJoin(또는 P2EP)은 두 당사자(예: 고객과 상인) 간의 거래를 CoinJoin 특유의 동일한 출력이 있는 거래처럼 보이지 않게 일반 거래로 위장한다. 이것은 탐지하기 매우 어렵게 만들며, 거래 감시 기관이 사용하는 common-input-ownership heuristic을 무효화할 수 있다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin의 활용은 전통적인 감시 기법을 크게 혼란시킬 수 있으며**, 거래 프라이버시 확보를 위한 유망한 발전입니다.

# 암호화폐 프라이버시를 위한 모범 사례

## **Wallet Synchronization Techniques**

프라이버시와 보안을 유지하려면 지갑을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 두드러집니다:

- **Full node**: 전체 블록체인을 다운로드함으로써 최대의 프라이버시를 보장합니다. 사용자가 관심 있는 트랜잭션이나 주소를 식별하는 것이 불가능하도록 모든 거래 기록이 로컬에 저장됩니다.
- **Client-side block filtering**: 이 방법은 블록체인의 모든 블록에 대한 필터를 생성하여, 지갑이 네트워크 관찰자에게 특정 관심사를 노출하지 않고 관련 트랜잭션을 식별할 수 있게 합니다. 라이트웨이트 지갑은 이러한 필터만 다운로드하고, 사용자의 주소와 일치할 때만 전체 블록을 가져옵니다.

## **Utilizing Tor for Anonymity**

Bitcoin이 P2P 네트워크에서 작동하므로, Tor 사용을 권장합니다. Tor는 네트워크와 상호작용할 때 IP 주소를 숨겨 프라이버시를 향상시킵니다.

## **Preventing Address Reuse**

프라이버시를 보호하려면 각 거래마다 새로운 주소를 사용하는 것이 필수적입니다. 주소를 재사용하면 동일한 실체에 거래들이 연결되어 프라이버시가 손상될 수 있습니다. 최신 지갑들은 디자인적으로 주소 재사용을 권장하지 않습니다.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: 결제를 여러 거래로 분할하면 금액을 은폐하여 프라이버시 공격을 방해할 수 있습니다.
- **Change avoidance**: 체인지 출력이 필요 없는 거래를 선택하면 체인지 탐지 기법을 무력화해 프라이버시를 강화합니다.
- **Multiple change outputs**: 체인지를 피할 수 없다면, 여러 개의 체인지 출력을 생성하는 것도 프라이버시를 개선할 수 있습니다.

# **Monero: A Beacon of Anonymity**

Monero는 디지털 거래에서 절대적인 익명성을 해결하며 프라이버시에 대한 높은 기준을 설정합니다.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas는 Ethereum에서 연산을 실행하는 데 필요한 계산 노력을 측정하며, 가격 단위는 **gwei**입니다. 예를 들어, 2,310,000 gwei(또는 0.00231 ETH) 비용의 거래는 gas limit과 base fee가 포함되며, 채굴자 인센티브로 tip이 추가됩니다. 사용자는 과다 지불을 방지하기 위해 max fee를 설정할 수 있고, 초과분은 환불됩니다.

## **Executing Transactions**

Ethereum의 거래는 발신자와 수신자를 포함하며, 수신자는 사용자 주소 또는 smart contract 주소일 수 있습니다. 거래는 수수료가 필요하고 채굴되어야 합니다. 거래의 필수 정보에는 수신자, 발신자의 서명, 값(value), 선택적 데이터, gas limit 및 수수료가 포함됩니다. 주목할 점은 발신자 주소가 서명으로부터 유추되므로 거래 데이터에 별도로 포함할 필요가 없다는 것입니다.

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐와 상호작용하려는 모든 사람에게 기본이 됩니다.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
