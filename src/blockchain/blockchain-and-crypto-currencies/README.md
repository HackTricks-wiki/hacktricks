# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **Smart Contracts**는 특정 조건이 충족되면 블록체인에서 실행되는 프로그램으로, 중개자 없이 계약 실행을 자동화합니다.
- **Decentralized Applications (dApps)**는 **Smart Contracts**를 기반으로 하며 사용자 친화적인 프런트엔드와 투명하고 감사 가능한 백엔드를 갖습니다.
- **Tokens & Coins**은 코인이 디지털 화폐 역할을 하는 반면, 토큰은 특정 맥락에서 가치나 소유권을 나타냅니다.
- **Utility Tokens**는 서비스 접근을 부여하고, **Security Tokens**는 자산 소유권을 나타냅니다.
- **DeFi**는 분산형 금융을 의미하며 중앙 권한 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 가리킵니다.

## 합의 메커니즘

합의 메커니즘은 블록체인에서 안전하고 합의된 트랜잭션 검증을 보장합니다:

- **Proof of Work (PoW)**는 트랜잭션 검증을 위해 계산 능력에 의존합니다.
- **Proof of Stake (PoS)**는 검증자가 일정 수량의 토큰을 보유하도록 요구하여 PoW에 비해 에너지 소비를 줄입니다.

## Bitcoin 필수 개념

### Transactions

Bitcoin 거래는 주소 간 자금 이전을 포함합니다. 거래는 디지털 서명을 통해 검증되며, 오직 개인 키 소유자만 전송을 시작할 수 있도록 보장합니다.

#### 핵심 구성 요소:

- **Multisignature Transactions**는 거래를 승인하기 위해 여러 서명을 필요로 합니다.
- 거래는 **inputs** (자금의 출처), **outputs** (목적지), **fees** (채굴자에게 지불되는 수수료), 및 **scripts** (거래 규칙)으로 구성됩니다.

### Lightning Network

Lightning Network는 채널 내에서 여러 거래를 허용하여 Bitcoin의 확장성을 향상시키고, 최종 상태만 블록체인에 브로드캐스트하도록 설계되었습니다.

## Bitcoin 프라이버시 우려

프라이버시 공격은 **Common Input Ownership** 및 **UTXO Change Address Detection**과 같은 트랜잭션 패턴을 악용합니다. **Mixers**와 **CoinJoin** 같은 전략은 사용자 간 트랜잭션 연결을 숨겨 익명성을 향상합니다.

## 익명으로 Bitcoin 획득하기

방법으로는 현금 거래, 채굴, 믹서 사용 등이 있습니다. **CoinJoin**은 여러 거래를 섞어 추적을 어렵게 만들고, **PayJoin**은 CoinJoin을 일반 거래로 위장하여 프라이버시를 강화합니다.

# Bitcoin 프라이버시 공격

# Bitcoin 프라이버시 공격 요약

Bitcoin 세계에서 거래의 프라이버시와 사용자의 익명성은 자주 우려되는 주제입니다. 다음은 공격자가 Bitcoin 프라이버시를 침해할 수 있는 몇 가지 일반적인 방법에 대한 간단한 개요입니다.

## **Common Input Ownership Assumption**

서로 다른 사용자의 inputs가 하나의 거래에 결합되는 경우는 일반적으로 드물기 때문에, 동일 거래의 두 input 주소는 종종 동일한 소유자에 속한다고 가정됩니다.

## **UTXO Change Address Detection**

UTXO, 즉 **Unspent Transaction Output**은 거래에서 전부 사용되어야 합니다. 그 일부만 다른 주소로 전송될 경우, 남은 금액은 새로운 change 주소로 가게 됩니다. 관찰자는 이 새 주소가 송금자에 속한다고 가정할 수 있어 프라이버시가 침해됩니다.

### 예시

이를 완화하기 위해 믹싱 서비스 사용이나 여러 주소 사용은 소유권을 흐리게 하는 데 도움이 될 수 있습니다.

## **Social Networks & Forums Exposure**

사용자들이 때때로 자신의 Bitcoin 주소를 온라인에 공유하여 **주소를 소유자와 연결하기 쉬움**을 초래합니다.

## **Transaction Graph Analysis**

거래는 그래프로 시각화될 수 있으며, 자금 흐름에 기반해 사용자들 간의 잠재적 연결을 드러낼 수 있습니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 휴리스틱은 여러 입력과 출력을 가진 거래를 분석하여 어떤 출력이 발신자에게 돌아가는 change인지 추측하는 데 기반합니다.

### 예시
```bash
2 btc --> 4 btc
3 btc     1 btc
```
입력을 더 추가하여 잔돈 출력이 어떤 단일 입력보다 커지면 휴리스틱을 혼동시킬 수 있다.

## **Forced Address Reuse**

공격자는 이전에 사용된 주소들에 소액을 보내 수신자가 이후 트랜잭션에서 이를 다른 입력과 결합하도록 유도하여 주소들을 연결하려고 할 수 있다.

### Correct Wallet Behavior

지갑은 이미 사용된 빈 주소에서 받은 코인을 사용하지 않아 이러한 privacy leak을 방지해야 한다.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 잔돈이 없는 트랜잭션은 동일 사용자가 소유한 두 주소 간의 거래일 가능성이 높다.
- **Round Numbers:** 트랜잭션의 라운드 숫자는 결제임을 시사하며, 라운드가 아닌 출력이 잔돈일 가능성이 높다.
- **Wallet Fingerprinting:** 서로 다른 지갑은 고유한 트랜잭션 생성 패턴을 가지므로 분석가는 사용된 소프트웨어를 식별하고 잠재적으로 change 주소를 찾아낼 수 있다.
- **Amount & Timing Correlations:** 트랜잭션의 시간이나 금액을 공개하면 트랜잭션을 추적할 수 있게 된다.

## **Traffic Analysis**

네트워크 트래픽을 모니터링함으로써 공격자는 트랜잭션이나 블록을 IP 주소와 연결하여 사용자 프라이버시를 침해할 수 있다. 특히 한 주체가 많은 Bitcoin 노드를 운영하면 트랜잭션을 감시할 수 있는 능력이 향상된다.

## More

프라이버시 공격과 방어에 대한 포괄적인 목록은 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)를 참조하라.

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 현금으로 Bitcoin을 획득.
- **Cash Alternatives**: 기프트 카드를 구매해 온라인에서 Bitcoin으로 교환.
- **Mining**: 비트코인을 획득하는 가장 프라이빗한 방법은 채굴이며, 특히 단독 채굴 시 더 익명성이 높다. 채굴 풀은 채굴자의 IP 주소를 알 수 있다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 이론적으로 비트코인을 훔치는 것이 익명으로 획득하는 방법이 될 수 있으나 불법이며 권장하지 않는다.

## Mixing Services

믹싱 서비스를 사용하면 사용자는 비트코인을 보내고 다른 비트코인을 받음으로써 원래 소유자를 추적하기 어렵게 만들 수 있다. 하지만 이는 서비스가 로그를 남기지 않고 실제로 비트코인을 반환할 것이라는 신뢰를 필요로 한다. 대안적인 믹싱 옵션으로는 Bitcoin 카지노가 있다.

## CoinJoin

CoinJoin은 여러 사용자의 트랜잭션을 하나로 합쳐 입력과 출력을 매칭하려는 사람을 복잡하게 만든다. 그럼에도 불구하고 입력 및 출력 크기가 고유한 트랜잭션은 여전히 추적될 수 있다.

예시 트랜잭션: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

자세한 정보는 [CoinJoin](https://coinjoin.io/en)를 참조하라. Ethereum에서 유사한 서비스로는 [Tornado Cash](https://tornado.cash)가 있는데, 이는 채굴자 자금을 이용해 트랜잭션을 익명화한다.

## PayJoin

CoinJoin의 변형인 PayJoin(또는 P2EP)은 두 당사자(예: 고객과 상인) 간의 거래를 CoinJoin 특유의 동일한 출력이 없는 일반 거래로 위장한다. 이는 탐지를 극히 어렵게 만들며, 트랜잭션 감시 기관들이 사용하는 common-input-ownership heuristic을 무효화할 수 있다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin의 활용은 전통적 감시 기법을 크게 혼란시킬 수 있으며**, 거래 프라이버시 확보에 있어 유망한 발전입니다.

# 암호화폐 프라이버시 모범 사례

## **지갑 동기화 기법**

프라이버시와 보안을 유지하려면 지갑을 블록체인과 동기화하는 것이 중요합니다. 두 가지 방법이 주목됩니다:

- **풀 노드**: 전체 블록체인을 다운로드함으로써 풀 노드는 최대의 프라이버시를 보장합니다. 사용자가 관심 있는 거래나 주소를 식별할 수 없게 모든 거래가 로컬에 저장됩니다.
- **클라이언트 측 블록 필터링**: 이 방법은 블록체인의 각 블록에 대한 필터를 생성하여, 지갑이 관련 거래를 네트워크 관찰자에게 노출하지 않고 식별할 수 있게 합니다. 경량 지갑은 이러한 필터만 다운로드하고, 사용자의 주소와 일치하는 경우에만 전체 블록을 가져옵니다.

## **익명성을 위한 Tor 활용**

Bitcoin이 P2P 네트워크에서 동작하기 때문에, 네트워크와 상호작용할 때 IP 주소를 숨기기 위해 Tor 사용을 권장합니다.

## **주소 재사용 방지**

프라이버시를 보호하려면 거래마다 새로운 주소를 사용하는 것이 중요합니다. 주소 재사용은 동일한 주체로 거래를 연결할 수 있어 프라이버시를 침해할 수 있습니다. 최신 지갑은 설계상 주소 재사용을 권장하지 않습니다.

## **거래 프라이버시 전략**

- **여러 거래**: 결제를 여러 거래로 분할하면 거래 금액을 은폐하여 프라이버시 공격을 방해할 수 있습니다.
- **체인지 회피**: 체인지 출력이 필요 없는 거래를 선택하면 체인지 탐지 방법을 무력화하여 프라이버시를 향상시킵니다.
- **여러 체인지 출력**: 체인지 회피가 불가능한 경우에도 여러 체인지 출력을 생성하면 프라이버시를 개선할 수 있습니다.

# **Monero: 익명성의 이정표**

Monero는 디지털 거래에서 절대적인 익명성 필요를 해결하며, 프라이버시에 대한 높은 기준을 설정합니다.

# **Ethereum: Gas와 거래**

## **Gas 이해하기**

Gas는 Ethereum에서 연산을 실행하는 데 필요한 계산 노력을 측정하며, 단위는 **gwei**입니다. 예를 들어 2,310,000 gwei(또는 0.00231 ETH)가 드는 거래는 gas limit과 base fee를 포함하며, 채굴자 인센티브를 위한 tip이 추가됩니다. 사용자는 초과 지불을 방지하기 위해 max fee를 설정할 수 있으며, 초과분은 환불됩니다.

## **거래 실행**

Ethereum의 거래는 발신자와 수신자를 포함하며, 수신자는 사용자 주소이거나 스마트 계약 주소일 수 있습니다. 거래에는 수수료가 필요하고 채굴되어야 합니다. 거래의 필수 정보에는 수신자, 발신자의 서명, 가치(value), 선택적 데이터, gas limit 및 수수료가 포함됩니다. 특히, 발신자의 주소는 서명으로부터 유추되므로 거래 데이터에 주소를 별도로 포함할 필요가 없습니다.

이러한 관행과 메커니즘은 프라이버시와 보안을 우선시하면서 암호화폐를 다루려는 모든 이에게 기초가 됩니다.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
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
