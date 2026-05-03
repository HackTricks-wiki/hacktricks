# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts**는 특정 조건이 충족될 때 blockchain에서 실행되는 프로그램으로 정의되며, 중개자 없이 agreement 실행을 자동화합니다.
- **Decentralized Applications (dApps)**은 Smart Contracts 위에 구축되며, 사용자 친화적인 front-end와 투명하고 감사 가능한 back-end를 갖습니다.
- **Tokens & Coins**는 coins가 디지털 money로 사용되는 반면, tokens는 특정 맥락에서 value 또는 ownership을 나타낸다는 점을 구분합니다.
- **Utility Tokens**는 서비스 접근 권한을 부여하고, **Security Tokens**는 asset ownership을 의미합니다.
- **DeFi**는 Decentralized Finance의 약자로, 중앙 권한 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 의미합니다.

## Consensus Mechanisms

Consensus mechanisms는 blockchain에서 안전하고 합의된 transaction validation을 보장합니다:

- **Proof of Work (PoW)**는 transaction verification을 위해 computational power에 의존합니다.
- **Proof of Stake (PoS)**는 validators가 일정량의 tokens를 보유해야 하며, PoW에 비해 energy consumption을 줄입니다.

## Bitcoin Essentials

### Transactions

Bitcoin transactions는 주소 간에 funds를 전송하는 것을 포함합니다. Transactions는 digital signatures를 통해 검증되며, private key의 소유자만 transfer를 시작할 수 있습니다.

#### Key Components:

- **Multisignature Transactions**는 transaction을 승인하기 위해 여러 signatures를 요구합니다.
- Transactions는 **inputs**(자금의 출처), **outputs**(도착지), **fees**(miners에게 지불), 그리고 **scripts**(transaction 규칙)로 구성됩니다.

### Lightning Network

채널 내에서 여러 transactions를 허용하고, 최종 상태만 blockchain에 broadcast함으로써 Bitcoin의 scalability를 향상시키는 것을 목표로 합니다.

## Bitcoin Privacy Concerns

**Common Input Ownership** 및 **UTXO Change Address Detection** 같은 privacy attacks는 transaction 패턴을 악용합니다. **Mixers**와 **CoinJoin** 같은 전략은 사용자 간 transaction link를 흐리게 하여 anonymity를 향상시킵니다.

## Acquiring Bitcoins Anonymously

방법에는 현금 거래, mining, 그리고 mixers 사용이 포함됩니다. **CoinJoin**은 여러 transactions를 섞어 추적 가능성을 복잡하게 만들고, **PayJoin**은 더 높은 privacy를 위해 CoinJoins를 일반 transactions처럼 위장합니다.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin 세계에서 transaction의 privacy와 사용자의 anonymity는 종종 우려의 대상입니다. 아래는 attackers가 Bitcoin privacy를 침해할 수 있는 몇 가지 일반적인 방법에 대한 간단한 개요입니다.

## **Common Input Ownership Assumption**

복잡성 때문에 서로 다른 users의 inputs가 하나의 transaction에 결합되는 경우는 일반적으로 드뭅니다. 따라서 **같은 transaction의 두 input addresses는 종종 같은 owner의 것이라고 가정됩니다**.

## **UTXO Change Address Detection**

UTXO, 즉 **Unspent Transaction Output**는 transaction에서 전부 사용되어야 합니다. 만약 그 일부만 다른 address로 보내지면, 나머지는 새로운 change address로 갑니다. 관찰자는 이 새로운 address가 sender의 것이라고 추정할 수 있어 privacy가 침해됩니다.

### Example

이를 완화하려면 mixing services를 사용하거나 여러 addresses를 사용해 ownership을 흐리게 할 수 있습니다.

## **Social Networks & Forums Exposure**

users가 때때로 온라인에 자신의 Bitcoin addresses를 공유하여, **address를 그 owner와 연결하기 쉽게** 만듭니다.

## **Transaction Graph Analysis**

Transactions는 graph로 시각화할 수 있으며, funds의 흐름을 바탕으로 users 간의 잠재적 연결을 드러낼 수 있습니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 heuristic은 여러 inputs와 outputs가 있는 transactions를 분석하여 어떤 output이 sender에게 돌아가는 change인지 추측하는 데 기반합니다.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
더 많은 입력을 추가하면 change output이 어떤 단일 input보다 커질 수 있어, heuristic을 혼란스럽게 만들 수 있습니다.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions without change are likely between two addresses owned by the same user.
- **Round Numbers:** A round number in a transaction suggests it's a payment, with the non-round output likely being the change.
- **Wallet Fingerprinting:** Different wallets have unique transaction creation patterns, allowing analysts to identify the software used and potentially the change address.
- **Amount & Timing Correlations:** Disclosing transaction times or amounts can make transactions traceable.

## **Traffic Analysis**

By monitoring network traffic, attackers can potentially link transactions or blocks to IP addresses, compromising user privacy. This is especially true if an entity operates many Bitcoin nodes, enhancing their ability to monitor transactions.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** merges multiple transactions from different users into one, complicating the process for anyone trying to match inputs with outputs. Despite its effectiveness, transactions with unique input and output sizes can still potentially be traced.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
위와 같은 거래는 PayJoin일 수 있으며, 표준 bitcoin 거래와 구별되지 않으면서도 프라이버시를 향상시킬 수 있습니다.

**PayJoin의 활용은 전통적인 감시 방법을 크게 교란할 수 있어**, 거래 프라이버시를 추구하는 데 유망한 발전입니다.

# 암호화폐에서 프라이버시를 위한 모범 사례

## **Wallet 동기화 기법**

프라이버시와 보안을 유지하려면 Wallet을 blockchain과 동기화하는 것이 중요합니다. 두 가지 방법이 두드러집니다.

- **Full node**: 전체 blockchain을 다운로드함으로써 Full node는 최대의 프라이버시를 보장합니다. 지금까지 발생한 모든 거래가 로컬에 저장되므로, 공격자가 사용자가 어떤 거래나 주소에 관심이 있는지 식별하는 것이 불가능합니다.
- **Client-side block filtering**: 이 방법은 blockchain의 각 block에 대한 filter를 생성하여, Wallet이 네트워크 관찰자에게 특정 관심사를 노출하지 않고도 관련 거래를 식별할 수 있게 합니다. Lightweight Wallet은 이러한 filter를 다운로드하고, 사용자의 주소와 일치하는 경우에만 전체 block을 가져옵니다.

## **익명성을 위한 Tor 활용**

Bitcoin은 peer-to-peer network에서 동작하므로, 네트워크와 상호작용할 때 IP 주소를 숨겨 프라이버시를 높이기 위해 Tor 사용이 권장됩니다.

## **주소 재사용 방지**

프라이버시를 보호하려면 모든 거래마다 새 주소를 사용하는 것이 중요합니다. 주소를 재사용하면 거래가 동일한 개체와 연결되어 프라이버시가 손상될 수 있습니다. 현대적인 Wallet은 설계상 주소 재사용을 억제합니다.

## **거래 프라이버시 전략**

- **여러 거래**: 결제를 여러 거래로 나누면 거래 금액을 숨길 수 있어 프라이버시 공격을 방해합니다.
- **Change 회피**: Change output이 필요 없는 거래를 선택하면 Change 탐지 방법을 방해해 프라이버시가 향상됩니다.
- **여러 Change output**: Change를 피할 수 없다면, 여러 Change output을 생성하는 것만으로도 프라이버시를 개선할 수 있습니다.

# **Monero: 익명성의 등대**

Monero는 디지털 거래에서 절대적 익명성의 필요성을 해결하며, 프라이버시의 높은 기준을 제시합니다.

# **Ethereum: Gas와 거래**

## **Gas 이해하기**

Gas는 Ethereum에서 작업을 실행하는 데 필요한 계산 비용을 측정하며, **gwei**로 가격이 매겨집니다. 예를 들어 2,310,000 gwei(또는 0.00231 ETH)가 드는 거래는 gas limit와 base fee를 포함하며, miners를 유인하기 위한 tip도 있습니다. 사용자는 과지불을 막기 위해 max fee를 설정할 수 있고, 초과분은 환불됩니다.

## **거래 실행하기**

Ethereum의 거래는 sender와 recipient를 포함하며, 둘 다 user 또는 smart contract 주소일 수 있습니다. 거래에는 fee가 필요하고 mined되어야 합니다. 거래의 필수 정보에는 recipient, sender의 signature, value, optional data, gas limit, fees가 포함됩니다. 특히 sender의 주소는 signature로부터 추론되므로, 거래 데이터에 이를 따로 넣을 필요가 없습니다.

이러한 관행과 메커니즘은 privacy와 security를 우선시하면서 암호화폐를 다루려는 모든 사람에게 기초가 됩니다.

## Value-Centric Web3 Red Teaming

- 가치가 있는 구성 요소(signers, oracles, bridges, automation)를 목록화하여 누가 어떻게 자금을 이동할 수 있는지 파악합니다.
- 각 구성 요소를 관련 MITRE AADAPT tactics에 매핑하여 권한 상승 경로를 드러냅니다.
- flash-loan/oracle/credential/cross-chain attack chain을 리허설하여 영향을 검증하고 악용 가능한 전제 조건을 문서화합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI의 supply-chain tampering은 서명 직전에 EIP-712 payload를 변조하여, delegatecall 기반 proxy takeover를 위한 유효한 signature를 수집할 수 있습니다(예: Safe masterCopy의 slot-0 overwrite).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 일반적인 smart-account failure mode에는 `EntryPoint` access control 우회, unsigned gas fields, stateful validation, ERC-1271 replay, revert-after-validation을 통한 fee-drain이 포함됩니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- test suite의 blind spot을 찾기 위한 mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

prover가 **zkVM** 또는 애플리케이션 전용 proof circuit을 사용해 어떤 주장을 증명할 때, verifier가 알게 되는 것은 **guest program이 작성된 대로 실행되었다**는 사실뿐입니다. guest에 **unsafe deserialization**, **undefined behavior**, 또는 **semantic constraint 누락**이 있으면, 악의적인 prover는 **public metrics 또는 주장된 invariant가 거짓인데도** 검증되는 proof를 생성할 수 있습니다.

### proof guest 내부의 unsafe deserialization

- proof로 숨겨져 있더라도 private witness/circuit bytes를 **신뢰할 수 없는 attacker input**으로 취급합니다.
- 바이트가 이미 외부에서 검증되지 않았다면 `rkyv::access_unchecked` 같은 unchecked helper로 역직렬화하지 마십시오.
- 신뢰할 수 없는 serialized data에서 읽어온 enum discriminant, relative pointer, length, index는 control flow나 memory access에 영향을 주기 전에 검증해야 합니다.

실용적인 audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
If a field such as `op.kind` is an enum and an attacker can inject an **out-of-range discriminant**, every downstream `match` on that value becomes suspicious.

### Jump-table / UB counter bypass

If Rust lowers a large `match` into a **jump table**, an invalid enum discriminant may produce **undefined control flow**. A dangerous pattern is:

1. One `match` updates **security-critical counters/constraints**.
2. A second `match` performs the **real instruction semantics**.
3. An out-of-range discriminant indexes past the first jump table and lands in code associated with the second one.

Result: the operation still executes, but the accounting path is skipped. In a zkVM this can forge proofs that report impossible metrics such as fewer gates, fewer expensive operations, or other falsified bounded resources.

Review checklist:

- Look for attacker-controlled enums deserialized from witness/private input.
- Inspect repeated `match` statements over the same opcode/kind field.
- Treat `unsafe` + unchecked deserialization + large opcode dispatch as a high-risk combination.
- Reverse engineer the emitted binary when needed; jump-table layout can matter more than the source.

### Missing semantic constraints in reversible/specialized interpreters

Do not just validate memory safety; also validate the **semantic rules** that the proof is meant to enforce.

For reversible/quantum-like instruction sets, ensure operands that must be distinct are actually constrained to be distinct. A Toffoli/CCX-like operation implemented as:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
게스트가 거부하지 않으면 안전하지 않게 됩니다:
```text
op.q_control1 == op.q_control2 == op.q_target
```
그 경우 전환은 다음으로 축약됩니다:
```text
q = q ^ (q & q) = 0
```
이것은 **deterministic reset primitive**를 만들어 reversibility 가정를 깨뜨리고, 더 저렴한 의도되지 않은 계산을 가능하게 합니다. 자원 사용을 증명하는 proof systems에서는, 공격자가 기능적 검사는 통과하면서 verifier가 강제되고 있다고 믿는 cost model은 우회하게 만들 수 있습니다.

### ZK systems에서 테스트할 것

- malformed witness/private-input encodings로 모든 guest parser를 fuzz하세요.
- opcode dispatch 전에 enum 범위 검증을 assert하세요.
- operand aliasing 및 기타 잘못된 instruction form에 대한 semantic checks를 추가하세요.
- 보고된/public counter를 독립적인 reference implementation과 비교하세요.
- 유효한 proof라도 guest program이 buggy하면 **잘못된 statement**를 증명할 수 있다는 점을 기억하세요.

## DeFi/AMM Exploitation

DEXes와 AMMs의 실전 exploitation을 연구 중이라면(Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), 다음을 확인하세요:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

`supply == 0`일 때 cache된 virtual balances가 poison될 수 있는 multi-asset weighted pools에 대해서는 다음을 공부하세요:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
