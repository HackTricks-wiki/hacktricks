# 블록체인 및 암호화폐

{{#include ../../banners/hacktricks-training.md}}

## 기본 개념

- **Smart Contracts**는 특정 조건이 충족되면 blockchain에서 실행되는 프로그램으로 정의되며, 중개자 없이 계약 이행을 자동화합니다.
- **Decentralized Applications (dApps)**는 smart contracts를 기반으로 구축되며, 사용자 친화적인 front-end와 투명하고 감사 가능한 back-end를 제공합니다.
- **Tokens & Coins**는 서로 구분됩니다. coins는 디지털 화폐로 사용되는 반면, tokens는 특정 맥락에서 가치 또는 소유권을 나타냅니다.
- **Utility Tokens**는 서비스에 대한 액세스 권한을 부여하고, **Security Tokens**는 자산 소유권을 나타냅니다.
- **DeFi**는 Decentralized Finance의 약자로, 중앙 기관 없이 금융 서비스를 제공합니다.
- **DEX**와 **DAOs**는 각각 Decentralized Exchange Platforms와 Decentralized Autonomous Organizations를 의미합니다.

## 합의 메커니즘

합의 메커니즘은 blockchain에서 안전하고 합의된 transaction 검증을 보장합니다.

- **Proof of Work (PoW)**는 transaction 검증을 위해 연산 능력에 의존합니다.
- **Proof of Stake (PoS)**는 validator가 일정량의 token을 보유하도록 요구하며, PoW에 비해 energy consumption을 줄입니다.<sup>[[1]](#references)</sup>

## Bitcoin 필수 개념

### Transactions

Bitcoin transactions는 address 간에 자금을 전송합니다. Transactions는 digital signatures를 통해 검증되므로 private key의 소유자만 transfer를 시작할 수 있습니다.<sup>[[2]](#references)</sup>

#### 주요 구성 요소:

- **Multisignature Transactions**는 transaction을 승인하기 위해 여러 개의 signature를 요구합니다.<sup>[[3]](#references)</sup>
- Transactions는 **inputs**(자금 출처), **outputs**(목적지), **fees**(miner에게 지급되는 수수료), **scripts**(transaction 규칙)로 구성됩니다.

### Lightning Network

여러 transaction을 하나의 channel 내에서 처리하고 최종 상태만 blockchain에 broadcast하여 Bitcoin의 scalability를 향상하는 것을 목표로 합니다.

## Bitcoin Privacy 우려 사항

**Common Input Ownership** 및 **UTXO Change Address Detection**과 같은 privacy attacks는 transaction patterns를 악용합니다. **Mixers** 및 **CoinJoin**과 같은 strategies는 사용자 간의 transaction links를 숨겨 anonymity를 향상합니다.

## 익명으로 Bitcoins 획득하기

방법에는 현금 거래, mining, mixers 사용 등이 있습니다. **CoinJoin**은 traceability를 복잡하게 만들기 위해 여러 transactions를 혼합하며, **PayJoin**은 privacy를 강화하기 위해 CoinJoins를 일반 transactions처럼 위장합니다.

# Bitcoin Privacy Attacks

# Bitcoin Privacy Attacks 요약

Bitcoin의 세계에서 transactions의 privacy와 사용자의 anonymity는 자주 우려되는 주제입니다. 다음은 attackers가 Bitcoin privacy를 침해할 수 있는 몇 가지 일반적인 방법을 간략히 정리한 것입니다.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

복잡성 때문에 서로 다른 사용자의 inputs가 하나의 transaction에 결합되는 경우는 일반적으로 드뭅니다. 따라서 **동일한 transaction에 있는 두 input addresses는 동일한 owner에 속한다고 추정되는 경우가 많습니다**.

## **UTXO Change Address Detection**

UTXO 또는 **Unspent Transaction Output**은 transaction에서 전부 사용되어야 합니다. UTXO의 일부만 다른 address로 전송되면 나머지는 새로운 change address로 이동합니다. Observers는 이 새로운 address가 sender에게 속한다고 추정할 수 있으며, 이는 privacy를 침해합니다.

### 예시

이를 완화하려면 mixing services를 사용하거나 여러 addresses를 사용하여 ownership을 숨길 수 있습니다.

## **Social Networks & Forums Exposure**

사용자는 때때로 자신의 Bitcoin addresses를 온라인에 공유하므로, **해당 address를 owner와 연결하기 쉬워집니다**.

## **Transaction Graph Analysis**

Transactions는 graph로 시각화할 수 있으며, 자금 흐름을 기반으로 사용자 간의 잠재적인 connections를 드러낼 수 있습니다.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

이 heuristic는 여러 inputs와 outputs가 있는 transactions를 분석하여 어떤 output이 sender에게 반환되는 change인지 추측하는 방식입니다.

### 예시
```bash
2 btc --> 4 btc
3 btc     1 btc
```
입력을 추가했을 때 change output이 단일 입력보다 커지면 heuristic을 혼란스럽게 할 수 있습니다.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### 올바른 Wallet 동작

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **기타 Blockchain Analysis Techniques**

- **정확한 Payment Amounts:** change가 없는 transactions은 동일한 사용자가 소유한 두 addresses 간의 거래일 가능성이 높습니다.
- **반올림된 숫자:** transaction의 금액이 반올림된 숫자라면 payment임을 의미하며, 반올림되지 않은 output이 change일 가능성이 높습니다.
- **Wallet Fingerprinting:** 서로 다른 wallets은 고유한 transaction 생성 패턴을 가지므로, analysts가 사용된 software를 식별하고 change address를 추정할 수 있습니다.
- **금액 및 Timing Correlations:** transaction 시간이나 금액을 공개하면 transactions을 추적할 수 있습니다.

## **Traffic Analysis**

Network traffic을 모니터링하면 attackers가 transactions 또는 blocks를 IP addresses와 잠재적으로 연결할 수 있어 user privacy가 침해될 수 있습니다. 특히 한 entity가 많은 Bitcoin nodes를 운영하는 경우 transactions을 모니터링하는 능력이 향상되므로 더욱 그렇습니다.

## 더 보기

privacy attacks 및 defenses의 전체 목록은 [Bitcoin Wiki의 Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy)를 참조하세요.

# Anonymous Bitcoin Transactions

## Bitcoins를 익명으로 얻는 방법

- **Cash Transactions**: cash를 통해 bitcoin을 획득합니다.
- **Cash Alternatives**: gift cards를 구매한 뒤 online에서 bitcoin으로 교환합니다.
- **Mining**: bitcoins를 얻는 가장 privacy-preserving한 방법은 mining이며, 특히 혼자 수행할 때 그렇습니다. mining pools는 miner의 IP address를 알 수 있기 때문입니다. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 이론적으로 bitcoin을 훔치는 것도 익명으로 획득하는 또 다른 방법일 수 있지만, 불법이며 권장되지 않습니다.

## Mixing Services

mixing service를 사용하면 user가 **bitcoins를 전송하고** 그 대가로 **서로 다른 bitcoins를 받을 수 있어**, original owner를 추적하기 어려워집니다. 그러나 이를 위해서는 service가 logs를 보관하지 않고 실제로 bitcoins를 반환할 것이라는 신뢰가 필요합니다. Alternative mixing options에는 Bitcoin casinos도 포함됩니다.

## CoinJoin

**CoinJoin**은 서로 다른 users의 여러 transactions을 하나로 병합하여, inputs와 outputs를 매칭하려는 사람의 작업을 복잡하게 만듭니다. 효과적이지만, input 및 output 크기가 고유한 transactions은 여전히 추적될 가능성이 있습니다.

CoinJoin을 사용했을 가능성이 있는 example transactions에는 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 및 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`가 있습니다.

자세한 내용은 [CoinJoin](https://coinjoin.io/en)을 참조하세요. Ethereum에서 유사한 service를 사용하려면 [Tornado Cash](https://tornado.cash)를 확인하세요. 이 service는 miners의 funds를 사용하여 transactions을 anonymize합니다.

## PayJoin

CoinJoin의 variant인 **PayJoin**(또는 P2EP)은 두 parties(예: customer와 merchant) 간의 transaction을 일반적인 transaction처럼 위장하며, CoinJoin의 특징인 동일한 outputs를 사용하지 않습니다. 따라서 이를 detect하기가 매우 어려우며, transaction surveillance entities가 사용하는 common-input-ownership heuristic을 무효화할 수 있습니다.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
위와 같은 Transactions는 PayJoin일 수 있으며, 표준 bitcoin Transactions와 구별되지 않으면서 privacy를 향상시킬 수 있습니다.

**PayJoin의 활용은 기존 surveillance methods를 크게 무력화할 수 있으므로**, transactional privacy를 추구하는 데 있어 유망한 발전으로 평가됩니다.

# Cryptocurrencies에서 Privacy를 위한 Best Practices

## **Wallet Synchronization Techniques**

privacy와 security를 유지하려면 blockchain과 wallet을 동기화하는 것이 중요합니다. 두 가지 방법이 특히 주목됩니다.

- **Full node**: 전체 blockchain을 다운로드하면 full node가 최대한의 privacy를 보장합니다. 지금까지 발생한 모든 Transactions가 로컬에 저장되므로, adversary가 사용자가 어떤 Transactions 또는 addresses에 관심이 있는지 식별할 수 없습니다.
- **Client-side block filtering**: 이 방법은 blockchain의 모든 block에 대해 filters를 생성하여, network observers에게 구체적인 관심사를 노출하지 않고 wallet이 관련 Transactions를 식별할 수 있도록 합니다. Lightweight wallet은 이러한 filters를 다운로드하고, 사용자의 addresses와 일치하는 항목이 발견된 경우에만 전체 blocks를 가져옵니다.

## **Anonymity를 위한 Tor 활용**

Bitcoin은 peer-to-peer network에서 작동하므로, IP address를 숨기고 network와 상호 작용할 때 privacy를 향상하려면 Tor를 사용하는 것이 좋습니다.

## **Address Reuse 방지**

privacy를 보호하려면 모든 transaction에 새로운 address를 사용하는 것이 중요합니다. Address를 재사용하면 Transactions를 동일한 entity와 연결하여 privacy가 침해될 수 있습니다. Modern wallet은 설계를 통해 address 재사용을 방지합니다.

## **Transaction Privacy를 위한 Strategies**

- **Multiple transactions**: Payment을 여러 Transactions로 분할하면 transaction amount를 모호하게 만들어 privacy attacks를 방해할 수 있습니다.
- **Change avoidance**: Change outputs가 필요하지 않은 Transactions를 선택하면 change detection methods를 방해하여 privacy가 향상됩니다.
- **Multiple change outputs**: Change를 피할 수 없다면 여러 change outputs를 생성하는 것만으로도 privacy를 개선할 수 있습니다.

# **Monero: Anonymity의 Beacon**

Monero는 digital transactions에서 완전한 anonymity에 대한 요구를 해결하며, privacy에 대한 높은 기준을 제시합니다.

# **Ethereum: Gas와 Transactions**

## **Gas 이해하기**

Gas는 Ethereum에서 operations를 실행하는 데 필요한 computational effort를 측정하며, **gwei** 단위로 가격이 책정됩니다. 예를 들어 2,310,000 gwei(또는 0.00231 ETH)의 비용이 드는 transaction에는 gas limit과 base fee가 포함되며, miners에게 incentive를 제공하기 위한 tip도 포함됩니다. 사용자는 초과 지불을 방지하기 위해 max fee를 설정할 수 있으며, 초과분은 환불됩니다.<sup>[[5]](#references)</sup>

## **Transactions 실행**

Ethereum의 Transactions에는 sender와 recipient가 포함되며, 이들은 user address 또는 smart contract address일 수 있습니다. Transactions에는 fee가 필요하고 mining되어야 합니다. Transaction의 필수 정보에는 recipient, sender의 signature, value, optional data, gas limit 및 fees가 포함됩니다. 특히 sender의 address는 signature에서 추론되므로 transaction data에 포함할 필요가 없습니다.<sup>[[4]](#references)</sup>

이러한 practices와 mechanisms는 privacy와 security를 우선시하면서 cryptocurrencies를 사용하려는 모든 사람에게 기본이 됩니다.

## Value-Centric Web3 Red Teaming

- 자금을 이동할 수 있는 주체와 방법을 이해하기 위해 value-bearing components(signers, oracles, bridges, automation)의 inventory를 작성합니다.
- privilege escalation paths를 노출하기 위해 각 component를 관련 MITRE AADAPT tactics에 매핑합니다.
- impact를 검증하고 악용 가능한 preconditions를 문서화하기 위해 flash-loan/oracle/credential/cross-chain attack chains를 rehearse합니다.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI의 supply-chain tampering은 signing 직전에 EIP-712 payloads를 변조하여, delegatecall-based proxy takeovers에 사용할 수 있는 유효한 signatures를 수집할 수 있습니다(예: Safe masterCopy의 slot-0 overwrite).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 일반적인 smart-account failure modes에는 `EntryPoint` access control 우회, unsigned gas fields, stateful validation, ERC-1271 replay, 그리고 revert-after-validation을 통한 fee-drain이 포함됩니다.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suites의 blind spots를 찾기 위한 mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Prover가 **zkVM** 또는 application-specific proof circuit을 사용해 claim을 증명할 때, verifier가 알게 되는 것은 **guest program이 작성된 그대로 실행되었다는 사실**뿐입니다. Guest에 **unsafe deserialization**, **undefined behavior** 또는 **missing semantic constraints**가 포함되어 있으면, malicious prover는 검증을 통과하지만 **public metrics 또는 claimed invariant가 거짓인 proof**를 생성할 수 있습니다.<sup>[[7]](#references)</sup>

### Proof guest 내부의 Unsafe deserialization

- Private witness/circuit bytes는 proof에 의해 숨겨져 있더라도 **신뢰할 수 없는 attacker input**으로 취급합니다.
- 해당 bytes가 이미 out-of-band로 검증된 경우가 아니라면 `rkyv::access_unchecked`와 같은 unchecked helpers를 사용한 deserialization을 피합니다.
- 신뢰할 수 없는 serialized data에서 로드된 enum discriminants, relative pointers, lengths 및 indexes는 control flow 또는 memory access에 영향을 주기 전에 검증해야 합니다.

실용적인 audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
`op.kind`와 같은 필드가 enum이고 공격자가 **범위를 벗어난 discriminant**를 주입할 수 있다면, 해당 값을 사용하는 모든 후속 `match`는 의심 대상으로 삼아야 합니다.

### Jump-table / UB counter bypass

Rust가 큰 `match`를 **jump table**로 낮추는 경우, 잘못된 enum discriminant가 **undefined control flow**를 일으킬 수 있습니다. 위험한 패턴은 다음과 같습니다.<sup>[[7]](#references)[[9]](#references)</sup>

1. 하나의 `match`가 **보안에 중요한 카운터/제약 조건**을 업데이트합니다.
2. 두 번째 `match`가 **실제 명령어 semantics**를 수행합니다.
3. 범위를 벗어난 discriminant가 첫 번째 jump table을 넘어 인덱싱하고, 두 번째 jump table과 관련된 코드로 이동합니다.

결과적으로 연산은 계속 실행되지만 accounting 경로가 건너뛰어집니다. zkVM에서는 더 적은 gate, 더 적은 expensive operation 또는 기타 위조된 bounded resource와 같이 불가능한 metric을 보고하는 proof를 위조할 수 있습니다.

Review checklist:

- witness/private input에서 역직렬화되는 공격자 제어 enum을 찾습니다.
- 동일한 opcode/kind 필드에 대한 반복적인 `match` 문을 검사합니다.
- `unsafe` + 검사되지 않은 역직렬화 + 큰 opcode dispatch 조합을 high-risk로 간주합니다.
- 필요한 경우 생성된 binary를 reverse engineer합니다. jump-table 레이아웃이 source보다 더 중요할 수 있습니다.

### reversible/specialized interpreter의 누락된 semantic constraints

memory safety만 검증하지 말고, proof가 enforcement해야 하는 **semantic rules**도 검증해야 합니다.

reversible/quantum-like instruction set의 경우 서로 달라야 하는 operand가 실제로 서로 다르도록 constraint가 적용되었는지 확인합니다. 다음과 같이 구현된 Toffoli/CCX-like operation은:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
게스트가 다음을 거부하지 않으면 안전하지 않게 됩니다:
```text
op.q_control1 == op.q_control2 == op.q_target
```
그 경우 전이는 다음과 같이 축약됩니다:
```text
q = q ^ (q & q) = 0
```
This는 **결정론적 reset primitive**를 생성하여, reversibility 가정을 깨뜨리고 더 저렴한 비의도적 연산을 가능하게 합니다. 리소스 사용량을 증명하는 proof systems에서는 공격자가 기능 검사를 충족하면서도 verifier가 적용되고 있다고 믿는 cost model을 우회할 수 있습니다.

### ZK systems에서 테스트할 항목

- 모든 guest parser에 대해 잘못된 witness/private-input 인코딩을 사용하여 fuzzing합니다.
- opcode dispatch 전에 enum 범위 검증을 수행하는지 확인합니다.
- operand aliasing 및 기타 유효하지 않은 instruction form에 대한 semantic checks를 추가합니다.
- 보고된/public counter를 독립적인 reference implementation과 비교합니다.
- 유효한 proof라도 guest program에 버그가 있으면 **잘못된 statement**를 증명할 수 있다는 점을 기억합니다.

## DeFi/AMM Exploitation

DEX와 AMM의 실용적인 exploitation(Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps)을 연구하는 경우 다음을 확인하세요.

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

virtual balances를 캐시하며 `supply == 0`일 때 poisoning될 수 있는 multi-asset weighted pools에 대해서는 다음을 학습하세요.

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
