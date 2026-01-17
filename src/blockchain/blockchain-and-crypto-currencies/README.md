# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** are defined as programs that execute on a blockchain when certain conditions are met, automating agreement executions without intermediaries.
- **Decentralized Applications (dApps)** build upon smart contracts, featuring a user-friendly front-end and a transparent, auditable back-end.
- **Tokens & Coins** differentiate where coins serve as digital money, while tokens represent value or ownership in specific contexts.
- **Utility Tokens** grant access to services, and **Security Tokens** signify asset ownership.
- **DeFi** stands for Decentralized Finance, offering financial services without central authorities.
- **DEX** and **DAOs** refer to Decentralized Exchange Platforms and Decentralized Autonomous Organizations, respectively.

## Consensus Mechanisms

Consensus mechanisms ensure secure and agreed transaction validations on the blockchain:

- **Proof of Work (PoW)** relies on computational power for transaction verification.
- **Proof of Stake (PoS)** demands validators to hold a certain amount of tokens, reducing energy consumption compared to PoW.

## Bitcoin Essentials

### Transactions

Bitcoin transactions involve transferring funds between addresses. Transactions are validated through digital signatures, ensuring only the owner of the private key can initiate transfers.

#### Key Components:

- **Multisignature Transactions** require multiple signatures to authorize a transaction.
- Transactions consist of **inputs** (source of funds), **outputs** (destination), **fees** (paid to miners), and **scripts** (transaction rules).

### Lightning Network

Aims to enhance Bitcoin's scalability by allowing multiple transactions within a channel, only broadcasting the final state to the blockchain.

## Bitcoin Privacy Concerns

Privacy attacks, such as **Common Input Ownership** and **UTXO Change Address Detection**, exploit transaction patterns. Strategies like **Mixers** and **CoinJoin** improve anonymity by obscuring transaction links between users.

## Acquiring Bitcoins Anonymously

Methods include cash trades, mining, and using mixers. **CoinJoin** mixes multiple transactions to complicate traceability, while **PayJoin** disguises CoinJoins as regular transactions for heightened privacy.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

In the world of Bitcoin, the privacy of transactions and the anonymity of users are often subjects of concern. Here's a simplified overview of several common methods through which attackers can compromise Bitcoin privacy.

## **Common Input Ownership Assumption**

It is generally rare for inputs from different users to be combined in a single transaction due to the complexity involved. Thus, **two input addresses in the same transaction are often assumed to belong to the same owner**.

## **UTXO Change Address Detection**

A UTXO, or **Unspent Transaction Output**, must be entirely spent in a transaction. If only a part of it is sent to another address, the remainder goes to a new change address. Observers can assume this new address belongs to the sender, compromising privacy.

### Example

To mitigate this, mixing services or using multiple addresses can help obscure ownership.

## **Social Networks & Forums Exposure**

Users sometimes share their Bitcoin addresses online, making it **easy to link the address to its owner**.

## **Transaction Graph Analysis**

Transactions can be visualized as graphs, revealing potential connections between users based on the flow of funds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

This heuristic is based on analyzing transactions with multiple inputs and outputs to guess which output is the change returning to the sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
입력(입력 UTXO)을 더 추가해 거스름돈 출력이 어떤 단일 입력보다 커지면, 휴리스틱을 혼동시킬 수 있다.

## **강제된 주소 재사용**

공격자는 소액을 이전에 사용된 주소로 보내 수신자가 이후 트랜잭션에서 이를 다른 입력들과 결합하도록 유도할 수 있으며, 이로써 주소들을 서로 연결시키려 한다.

### 올바른 지갑 동작

지갑은 이미 사용된 빈 주소로 받은 코인을 사용하지 않아야 하며, 이는 프라이버시 leak를 방지하기 위함이다.

## **기타 블록체인 분석 기법**

- **정확한 결제 금액:** 거스름돈이 없는 트랜잭션은 동일 사용자가 소유한 두 주소 간의 거래일 가능성이 높다.
- **반올림된 금액:** 거래에서 반올림된 금액은 결제일 가능성이 높고, 반올림되지 않은 출력이 거스름돈일 가능성이 높다.
- **지갑 지문화:** 서로 다른 지갑은 고유한 트랜잭션 생성 패턴을 가지며, 분석가는 이를 통해 사용된 소프트웨어 및 잠재적인 change 주소를 식별할 수 있다.
- **금액 및 시간 상관관계:** 거래 시간이나 금액을 공개하면 거래 추적이 쉬워진다.

## **트래픽 분석**

네트워크 트래픽을 모니터링함으로써 공격자는 트랜잭션이나 블록을 IP 주소와 연결시켜 사용자 프라이버시를 손상시킬 수 있다. 특히 많은 수의 Bitcoin 노드를 운영하는 주체는 트랜잭션을 감시할 능력이 향상된다.

## More

포괄적인 프라이버시 공격 및 방어 목록은 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)를 참조하라.

# 익명 Bitcoin 거래

## 익명으로 Bitcoin을 얻는 방법

- **Cash Transactions**: 현금을 통해 bitcoin을 취득.
- **Cash Alternatives**: 기프트 카드를 구매해 온라인에서 bitcoin으로 교환.
- **채굴**: 혼자 채굴할 때가 가장 프라이빗하게 bitcoin을 얻는 방법이다. 마이닝 풀은 채굴자의 IP 주소를 알 수 있다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 이론적으로는 비트코인을 훔치는 것이 또 다른 익명 획득 방법이 될 수 있으나, 불법이며 권장되지 않는다.

## 믹싱 서비스

믹싱 서비스를 이용하면 사용자는 비트코인을 보내고 다른 비트코인을 받아 원래 소유자를 추적하기 어렵게 만들 수 있다. 다만 서비스가 로그를 보관하지 않고 실제로 비트코인을 반환할 것이라는 신뢰가 필요하다. 대안으로 Bitcoin 카지노 등이 있다.

## CoinJoin

CoinJoin는 여러 사용자의 트랜잭션을 하나로 합쳐 입력과 출력을 매칭하려는 시도를 복잡하게 만든다. 그럼에도 불구하고 입력 및 출력 크기가 고유한 트랜잭션은 여전히 추적될 가능성이 있다.

예시 트랜잭션(사용됐을 가능성 있음): `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

자세한 정보는 [CoinJoin](https://coinjoin.io/en)을 참고하라. Ethereum 상의 유사 서비스는 [Tornado Cash](https://tornado.cash)로, 채굴자들로부터의 자금으로 트랜잭션을 익명화한다.

## PayJoin

CoinJoin의 변형인 PayJoin(또는 P2EP)은 두 당사자(예: 고객과 상인) 사이의 트랜잭션을 일반 트랜잭션처럼 위장하여 CoinJoin의 동등한 출력 특징을 보이지 않게 한다. 이는 탐지가 극도로 어렵게 만들며, 거래 감시 주체들이 사용하는 common-input-ownership heuristic을 무력화할 수도 있다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

To maintain privacy and security, synchronizing wallets with the blockchain is crucial. Two methods stand out:

- **Full node**: By downloading the entire blockchain, a full node ensures maximum privacy. All transactions ever made are stored locally, making it impossible for adversaries to identify which transactions or addresses the user is interested in.
- **Client-side block filtering**: This method involves creating filters for every block in the blockchain, allowing wallets to identify relevant transactions without exposing specific interests to network observers. Lightweight wallets download these filters, only fetching full blocks when a match with the user's addresses is found.

## **Utilizing Tor for Anonymity**

Given that Bitcoin operates on a peer-to-peer network, using Tor is recommended to mask your IP address, enhancing privacy when interacting with the network.

## **Preventing Address Reuse**

To safeguard privacy, it's vital to use a new address for every transaction. Reusing addresses can compromise privacy by linking transactions to the same entity. Modern wallets discourage address reuse through their design.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Splitting a payment into several transactions can obscure the transaction amount, thwarting privacy attacks.
- **Change avoidance**: Opting for transactions that don't require change outputs enhances privacy by disrupting change detection methods.
- **Multiple change outputs**: If avoiding change isn't feasible, generating multiple change outputs can still improve privacy.

# **Monero: A Beacon of Anonymity**

Monero addresses the need for absolute anonymity in digital transactions, setting a high standard for privacy.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas measures the computational effort needed to execute operations on Ethereum, priced in **gwei**. For example, a transaction costing 2,310,000 gwei (or 0.00231 ETH) involves a gas limit and a base fee, with a tip to incentivize miners. Users can set a max fee to ensure they don't overpay, with the excess refunded.

## **Executing Transactions**

Transactions in Ethereum involve a sender and a recipient, which can be either user or smart contract addresses. They require a fee and must be mined. Essential information in a transaction includes the recipient, sender's signature, value, optional data, gas limit, and fees. Notably, the sender's address is deduced from the signature, eliminating the need for it in the transaction data.

These practices and mechanisms are foundational for anyone looking to engage with cryptocurrencies while prioritizing privacy and security.

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
