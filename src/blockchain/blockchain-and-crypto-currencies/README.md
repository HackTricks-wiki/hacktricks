# Blockchain 및 Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **Smart Contracts**는 특정 조건이 충족되면 blockchain에서 실행되는 프로그램으로 정의되며, 중개자 없이 계약 실행을 자동화합니다.
- **Decentralized Applications (dApps)**는 smart contracts를 기반으로 하며, 사용자 친화적인 front-end와 투명하고 감사 가능한 back-end를 제공합니다.
- **Tokens & Coins**는 서로 다른 개념으로, coins는 digital money로 사용되는 반면 tokens는 특정 맥락에서 가치 또는 소유권을 나타냅니다.
- **Utility Tokens**는 서비스에 대한 액세스 권한을 부여하고, **Security Tokens**는 자산 소유권을 나타냅니다.
- **DeFi**는 Decentralized Finance를 의미하며, 중앙 기관 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 의미합니다.

## Consensus Mechanisms

Consensus mechanisms는 blockchain에서 안전하고 합의된 transaction 검증을 보장합니다:

- **Proof of Work (PoW)**는 transaction verification에 computational power를 사용합니다.
- **Proof of Stake (PoS)**는 validators가 일정량의 tokens를 보유하도록 요구하며, PoW에 비해 energy consumption을 줄입니다.<sup>[[1]](#references)</sup>

## Bitcoin 기본 사항

### Transactions

Bitcoin transactions는 addresses 간에 funds를 전송합니다. Transactions는 digital signatures를 통해 검증되므로 private key의 소유자만 transfers를 시작할 수 있습니다.<sup>[[2]](#references)</sup>

#### 주요 구성 요소:

- **Multisignature Transactions**는 transaction을 승인하기 위해 여러 signatures를 요구합니다.<sup>[[3]](#references)</sup>
- Transactions는 **inputs** (funds의 source), **outputs** (destination), **fees** (miners에게 지급), **scripts** (transaction rules)로 구성됩니다.

### Lightning Network

여러 transactions를 하나의 channel 내에서 처리하고 최종 state만 blockchain에 broadcast하여 Bitcoin의 scalability를 향상하는 것을 목표로 합니다.

## Bitcoin Privacy 우려 사항

**Common Input Ownership** 및 **UTXO Change Address Detection**과 같은 privacy attacks는 transaction patterns를 악용합니다. **Mixers** 및 **CoinJoin**과 같은 strategies는 users 간 transaction links를 가려 anonymity를 향상합니다.

## Bitcoin을 익명으로 획득하기

방법으로는 cash trades, mining, mixers 사용 등이 있습니다. **CoinJoin**은 여러 transactions를 섞어 traceability를 어렵게 만들며, **PayJoin**은 CoinJoins를 일반 transactions처럼 위장하여 privacy를 더욱 강화합니다.

# Bitcoin Privacy Attacks 요약

Bitcoin의 세계에서 transactions의 privacy와 users의 anonymity는 자주 우려되는 대상입니다. 다음은 attackers가 Bitcoin privacy를 침해할 수 있는 몇 가지 일반적인 방법을 간단히 정리한 것입니다.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

복잡성 때문에 서로 다른 users의 inputs가 하나의 transaction에 결합되는 경우는 일반적으로 드뭅니다. 따라서 **동일한 transaction 내의 두 input addresses는 동일한 owner에게 속한다고 간주되는 경우가 많습니다**.

## **UTXO Change Address Detection**

UTXO 또는 **Unspent Transaction Output**은 transaction에서 전부 사용되어야 합니다. 그중 일부만 다른 address로 전송되면 나머지는 새로운 change address로 전송됩니다. Observers는 이 새로운 address가 sender에게 속한다고 추정할 수 있으며, 이로 인해 privacy가 침해됩니다.

### 예시

이를 완화하려면 mixing services를 사용하거나 여러 addresses를 사용하여 ownership을 감출 수 있습니다.

## **Social Networks & Forums Exposure**

Users는 때때로 자신의 Bitcoin addresses를 online에 공유하며, 이로 인해 **address를 owner와 쉽게 연결할 수 있습니다**.

## **Transaction Graph Analysis**

Transactions는 graph로 시각화할 수 있으며, funds의 flow를 기반으로 users 간의 잠재적인 connections를 드러낼 수 있습니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 heuristic는 여러 inputs와 outputs가 있는 transactions를 분석하여 어떤 output이 sender에게 반환되는 change인지 추측하는 방식입니다.

### 예시
```bash
2 btc --> 4 btc
3 btc     1 btc
```
입력을 더 추가하면 change output이 단일 input보다 커질 수 있으며, 이는 heuristic을 혼란스럽게 만들 수 있습니다.

## **강제 주소 재사용**

공격자는 이전에 사용된 주소로 소액을 보내고, 수신자가 향후 거래에서 이를 다른 input과 결합하여 주소들이 서로 연결되기를 기대할 수 있습니다.

### 올바른 Wallet 동작

Wallet은 privacy leak을 방지하기 위해 이미 사용된 빈 주소로 받은 coin을 사용하지 않아야 합니다.

## **기타 Blockchain 분석 기법**

- **정확한 결제 금액:** change가 없는 거래는 동일한 사용자가 소유한 두 주소 간에 이루어진 거래일 가능성이 높습니다.
- **반올림된 숫자:** 거래의 반올림된 숫자는 결제임을 나타내며, 반올림되지 않은 output은 change일 가능성이 높습니다.
- **Wallet Fingerprinting:** 서로 다른 wallet은 고유한 거래 생성 패턴을 가지므로, 분석가는 사용된 software를 식별하고 change address를 알아낼 수 있습니다.
- **금액 및 시간 상관관계:** 거래 시간이나 금액을 공개하면 거래를 추적할 수 있습니다.

## **Traffic Analysis**

Network traffic을 모니터링하면 공격자가 거래 또는 block을 IP address와 잠재적으로 연결할 수 있어 사용자의 privacy가 침해될 수 있습니다. 하나의 entity가 여러 Bitcoin node를 운영하면 거래 모니터링 능력이 향상되므로 이러한 위험은 특히 커집니다.

## 더 보기

privacy 공격 및 방어의 전체 목록은 [Bitcoin Wiki의 Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy)를 참조하세요.

# 익명 Bitcoin 거래

## Bitcoin을 익명으로 얻는 방법

- **현금 거래:** 현금을 통해 bitcoin을 획득합니다.
- **현금 대체 수단:** gift card를 구매한 다음 online에서 bitcoin으로 교환합니다.
- **Mining:** bitcoin을 얻는 가장 private한 방법은 mining을 이용하는 것입니다. 특히 혼자 mining하는 경우가 그렇습니다. mining pool은 miner의 IP address를 알 수 있기 때문입니다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **절도:** 이론적으로 bitcoin을 훔치는 것도 익명으로 획득하는 또 다른 방법일 수 있지만, 이는 불법이며 권장되지 않습니다.

## Mixing Services

mixing service를 사용하면 사용자는 **bitcoin을 전송하고** **서로 다른 bitcoin을 돌려받을 수 있으며**, 이를 통해 원래 소유자를 추적하기 어려워집니다. 그러나 이를 위해서는 해당 service가 log를 보관하지 않고 실제로 bitcoin을 반환할 것이라는 신뢰가 필요합니다. 다른 mixing 옵션으로는 Bitcoin casino가 있습니다.

## CoinJoin

**CoinJoin**은 서로 다른 사용자의 여러 거래를 하나로 병합하여 input과 output을 대응시키려는 사람의 작업을 복잡하게 만듭니다. 효과적이지만, input과 output의 크기가 고유한 거래는 여전히 추적될 가능성이 있습니다.

CoinJoin을 사용했을 가능성이 있는 거래의 예로는 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있습니다.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하세요. deposit과 이후 withdrawal을 분리하는 Ethereum smart-contract mixer는 [Tornado Cash](https://tornado.cash)를 참조하세요.

## PayJoin

CoinJoin의 변형인 **PayJoin**(또는 P2EP)은 두 당사자(예: 고객과 merchant) 간의 거래를 CoinJoin의 특징적인 동일 output 없이 일반적인 거래처럼 위장합니다. 따라서 이를 탐지하기가 매우 어려우며, 거래 감시 entity가 사용하는 common-input-ownership heuristic을 무효화할 수 있습니다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
위와 같은 Transactions는 PayJoin일 수 있으며, 표준 bitcoin Transactions와 구별되지 않으면서 privacy를 향상시킬 수 있습니다.

**PayJoin의 활용은 기존 surveillance methods를 크게 방해할 수 있으므로**, transactional privacy를 추구하는 데 있어 유망한 발전입니다.

# Cryptocurrencies에서 Privacy를 위한 Best Practices

## **Wallet Synchronization Techniques**

privacy와 security를 유지하려면 blockchain과 wallets를 synchronization하는 것이 중요합니다. 두 가지 methods가 특히 두드러집니다.

- **Full node**: 전체 blockchain을 다운로드하면 full node가 maximum privacy를 보장합니다. 지금까지 수행된 모든 transactions가 로컬에 저장되므로, adversary가 사용자가 관심을 갖는 transactions 또는 addresses를 식별할 수 없습니다.
- **Client-side block filtering**: 이 method는 blockchain의 모든 block에 대한 filters를 생성하여, wallets가 특정 관심사를 network observers에게 노출하지 않고 관련 transactions를 식별할 수 있도록 합니다. Lightweight wallets는 이러한 filters를 다운로드하고, 사용자의 addresses와 일치하는 항목이 발견된 경우에만 full blocks를 가져옵니다.

## **Anonymity를 위한 Tor 활용**

Bitcoin은 peer-to-peer network에서 작동하므로, IP address를 숨기고 network와 상호작용할 때 privacy를 향상시키기 위해 Tor를 사용하는 것이 권장됩니다.

## **Address Reuse 방지**

privacy를 보호하려면 모든 transaction에 새로운 address를 사용하는 것이 중요합니다. Addresses를 재사용하면 transactions가 동일한 entity와 연결되어 privacy가 침해될 수 있습니다. Modern wallets는 설계를 통해 address reuse를 방지합니다.

## **Transaction Privacy를 위한 Strategies**

- **Multiple transactions**: payment를 여러 transactions로 분할하면 transaction amount를 모호하게 만들어 privacy attacks를 방해할 수 있습니다.
- **Change avoidance**: change outputs가 필요하지 않은 transactions를 선택하면 change detection methods를 방해하여 privacy를 향상시킬 수 있습니다.
- **Multiple change outputs**: change를 피할 수 없는 경우에도 여러 change outputs를 생성하면 privacy를 향상시킬 수 있습니다.

# **Monero: Anonymity의 Beacon**

Monero는 transaction privacy를 우선시하도록 설계되었습니다.

# **Ethereum: Gas와 Transactions**

## **Gas 이해하기**

Gas는 Ethereum에서 operations를 실행하는 데 필요한 computational effort를 측정하며, **gwei** 단위로 가격이 책정됩니다. 예를 들어, 2,310,000 gwei(또는 0.00231 ETH)가 드는 transaction에는 gas limit와 base fee가 포함되며, validator가 transaction을 포함하도록 유도하기 위한 priority fee도 포함됩니다. 사용자는 max fee를 설정하여 초과 지불을 방지할 수 있으며, 초과분은 환불됩니다.<sup>[[5]](#references)</sup>

## **Transactions 실행**

Ethereum의 transactions에는 sender와 recipient가 포함되며, 이들은 user address 또는 smart contract address일 수 있습니다. Transactions에는 fee가 필요하고 block에 포함되어야 합니다. Transaction의 필수 정보에는 recipient, sender's signature, value, optional data, gas limit 및 fees가 포함됩니다. 특히 sender's address는 signature에서 추론되므로 transaction data에 포함할 필요가 없습니다.<sup>[[4]](#references)</sup>

이러한 practices와 mechanisms는 privacy와 security를 우선시하면서 cryptocurrencies에 참여하려는 모든 사람에게 기본이 됩니다.

## Value-Centric Web3 Red Teaming

- Value-bearing components(signers, oracles, bridges, automation)의 inventory를 작성하여 누가 funds를 이동할 수 있고 어떤 방식으로 가능한지 파악합니다.
- 각 component를 관련 MITRE AADAPT tactics에 매핑하여 privilege escalation paths를 노출합니다.
- Flash-loan/oracle/credential/cross-chain attack chains를 rehearse하여 impact를 검증하고 exploitable preconditions를 문서화합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UIs에 대한 supply-chain tampering은 signing 직전에 EIP-712 payloads를 변경하여, delegatecall-based proxy takeovers에 사용할 수 있는 유효한 signatures를 수집할 수 있습니다(예: Safe masterCopy의 slot-0 overwrite).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 일반적인 smart-account failure modes에는 `EntryPoint` access control 우회, unsigned gas fields, stateful validation, ERC-1271 replay 및 revert-after-validation을 통한 fee-drain이 포함됩니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suites의 blind spots를 찾기 위한 mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Prover가 **zkVM** 또는 application-specific proof circuit을 사용하여 claim을 증명할 때, verifier가 확인하는 것은 **guest program이 작성된 대로 실행되었다는 사실**뿐입니다. Guest에 **unsafe deserialization**, **undefined behavior** 또는 **missing semantic constraints**가 포함되어 있다면, malicious prover는 verification을 통과하지만 **public metrics 또는 claimed invariant가 false인** proof를 생성할 수 있습니다.<sup>[[7]](#references)</sup>

### Proof guests 내부의 Unsafe deserialization

- Private witness/circuit bytes는 proof에 의해 숨겨져 있더라도 **untrusted attacker input**으로 취급합니다.
- Bytes가 이미 out-of-band로 검증된 경우가 아니라면 `rkyv::access_unchecked`와 같은 unchecked helpers를 사용하여 deserializing하지 않습니다.
- Untrusted serialized data에서 로드되는 enum discriminants, relative pointers, lengths 및 indexes는 control flow 또는 memory access에 영향을 주기 전에 검증해야 합니다.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
필드(예: `op.kind`)가 enum이고 공격자가 **범위를 벗어난 discriminant**를 주입할 수 있다면, 해당 값을 대상으로 하는 모든 downstream `match`는 의심해야 합니다.

### Jump-table / UB counter bypass

Rust가 큰 `match`를 **jump table**로 변환하는 경우, 유효하지 않은 enum discriminant가 **undefined control flow**를 일으킬 수 있습니다. 위험한 패턴은 다음과 같습니다:<sup>[[7]](#references)[[9]](#references)</sup>

1. 하나의 `match`가 **security-critical counters/constraints**를 업데이트합니다.
2. 두 번째 `match`가 **실제 instruction semantics**를 수행합니다.
3. 범위를 벗어난 discriminant가 첫 번째 jump table을 지나 인덱싱하고, 두 번째 jump table과 연결된 코드에 도달합니다.

결과적으로 operation은 계속 실행되지만 accounting 경로가 건너뛰어집니다. zkVM에서는 이로 인해 더 적은 gate, 더 적은 expensive operation 또는 기타 위조된 bounded resource와 같이, 불가능한 metrics를 보고하는 proof를 위조할 수 있습니다.

검토 체크리스트:

- witness/private input에서 deserialize되는 attacker-controlled enum을 찾습니다.
- 동일한 opcode/kind 필드에 대한 반복적인 `match` 문을 검사합니다.
- `unsafe` + unchecked deserialization + large opcode dispatch 조합을 high-risk로 간주합니다.
- 필요한 경우 emitted binary를 reverse engineer합니다. jump-table layout이 source보다 더 중요할 수 있습니다.

### reversible/specialized interpreters의 누락된 semantic constraints

memory safety만 검증하지 말고, proof가 enforce해야 하는 **semantic rules**도 검증합니다.

reversible/quantum-like instruction set의 경우, 서로 달라야 하는 operand가 실제로 distinct하도록 constraint가 적용되었는지 확인합니다. 다음과 같이 구현된 Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
게스트가 거부하지 않으면 안전하지 않게 됩니다:
```text
op.q_control1 == op.q_control2 == op.q_target
```
그 경우 전환은 다음과 같이 축약됩니다:
```text
q = q ^ (q & q) = 0
```
이는 **결정론적 reset primitive**를 생성하여 가역성 가정을 깨뜨리고, 의도되지 않은 계산을 더 저렴하게 수행할 수 있게 합니다. 리소스 사용량을 입증하는 proof system에서는 공격자가 기능 검사를 충족하면서도 verifier가 적용한다고 믿는 cost model을 우회할 수 있습니다.

### ZK systems에서 테스트할 항목

- 잘못된 witness/private-input encoding을 사용하여 모든 guest parser를 fuzz합니다.
- opcode dispatch 전에 enum 범위 검증이 수행되는지 확인합니다.
- operand aliasing 및 기타 유효하지 않은 instruction form에 대한 semantic check를 추가합니다.
- 보고된/public counter를 독립적인 reference implementation과 비교합니다.
- guest program에 버그가 있으면 유효한 proof라도 **잘못된 statement**를 증명할 수 있다는 점을 기억합니다.

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX와 AMM의 실용적인 exploitation(Uniswap v4 hooks, rounding/precision abuse, flash-loan으로 증폭된 threshold-crossing swap)을 연구하는 경우 다음을 확인하세요.

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balance를 cache하고 `supply == 0`일 때 오염될 수 있는 multi-asset weighted pool에 대해서는 다음을 학습하세요.

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [지분 증명 - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key와 Private Key 설명 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [multi-signature transaction이란 무엇인가? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas 및 fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google의 quantum cryptanalysis zero-knowledge proof를 무력화했습니다](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities로부터 Elliptic Curve Cryptocurrency 보호: Resource Estimates 및 Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
