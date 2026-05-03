# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** 是指在 blockchain 上在满足某些条件时执行的程序，通过自动化执行协议而无需中介。
- **Decentralized Applications (dApps)** 基于 smart contracts 构建，具有用户友好的前端和透明、可审计的后端。
- **Tokens & Coins** 区分了 coin 作为数字货币，而 token 在特定场景中代表价值或所有权。
- **Utility Tokens** 授予对服务的访问权限，而 **Security Tokens** 表示资产所有权。
- **DeFi** 代表 Decentralized Finance，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指 Decentralized Exchange Platforms 和 Decentralized Autonomous Organizations。

## Consensus Mechanisms

Consensus mechanisms ensure secure and agreed transaction validations on the blockchain:

- **Proof of Work (PoW)** 依赖计算能力进行交易验证。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的 token，与 PoW 相比可降低能耗。

## Bitcoin Essentials

### Transactions

Bitcoin transactions involve transferring funds between addresses. Transactions are validated through digital signatures, ensuring only the owner of the private key can initiate transfers.

#### Key Components:

- **Multisignature Transactions** require multiple signatures to authorize a transaction.
- Transactions consist of **inputs** (资金来源), **outputs** (destination), **fees** (paid to miners), and **scripts** (transaction rules).

### Lightning Network

旨在通过允许在一个 channel 内进行多笔 transactions 来增强 Bitcoin 的可扩展性，只将最终状态广播到 blockchain。

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
如果添加更多 inputs 会使 change output 大于任何单个 input，那么它可能会让 heuristic 产生混淆。

## **Forced Address Reuse**

Attackers 可能会向之前使用过的 addresses 发送少量资金，希望接收方在未来的交易中将这些资金与其他 inputs 合并，从而把 addresses 关联在一起。

### Correct Wallet Behavior

Wallets 应避免在已使用过的空 addresses 上使用收到的 coins，以防止这种 privacy leak。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 没有 change 的 transactions 很可能发生在由同一用户拥有的两个 addresses 之间。
- **Round Numbers:** transaction 中的整数金额表明它是 payment，而非整数的 output 很可能是 change。
- **Wallet Fingerprinting:** 不同 wallets 有独特的 transaction 创建模式，分析人员可以识别所用的软件，并可能推断出 change address。
- **Amount & Timing Correlations:** 公开 transaction times 或 amounts 会让 transactions 更容易被追踪。

## **Traffic Analysis**

通过监控 network traffic，attackers 可以潜在地将 transactions 或 blocks 关联到 IP addresses，从而危及 user privacy。尤其当某个实体运营大量 Bitcoin nodes 时，这种情况更明显，因为这会增强其监控 transactions 的能力。

## More

有关 privacy attacks 和 defenses 的完整列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 通过现金获取 bitcoin。
- **Cash Alternatives**: 购买 gift cards 并在线兑换为 bitcoin。
- **Mining**: 赚取 bitcoins 最私密的方法是 mining，尤其是单独进行时，因为 mining pools 可能知道 miner 的 IP address。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 从理论上说，stealing bitcoin 也可能是匿名获取它的另一种方式，不过这是非法的，也不推荐。

## Mixing Services

通过使用 mixing service，用户可以 **send bitcoins** 并收到 **different bitcoins in return**，这会让追踪原始 owner 变得困难。不过，这要求信任该 service 不会保留 logs，并且会实际返还 bitcoins。其他 mixing 方式还包括 Bitcoin casinos。

## CoinJoin

**CoinJoin** 将来自不同 users 的多个 transactions 合并为一个，使任何试图匹配 inputs 与 outputs 的人都更难处理。尽管它很有效，但具有独特 input 和 output sizes 的 transactions 仍然可能被追踪。

可能使用过 CoinJoin 的 example transactions 包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

更多信息请访问 [CoinJoin](https://coinjoin.io/en)。类似的 Ethereum service 可参考 [Tornado Cash](https://tornado.cash)，它使用来自 miners 的 funds 来 anonymizes transactions。

## PayJoin

作为 CoinJoin 的一个变体，**PayJoin**（或 P2EP）会把两个 parties 之间的 transaction（例如 customer 和 merchant）伪装成一笔普通 transaction，而不会出现 CoinJoin 典型的相同 outputs 特征。这使其极难被检测，并且可能使 transaction surveillance entities 使用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
像上面的交易可能是 PayJoin，在保持与标准 bitcoin 交易无法区分的同时增强隐私。

**PayJoin 的使用可能会显著扰乱传统监控方法**，这使其成为推进交易隐私的一个很有前景的发展。

# Cryptocurrencies 中的隐私最佳实践

## **Wallet 同步技术**

为了保持隐私和安全，与 blockchain 同步 wallets 至关重要。有两种方法尤为突出：

- **Full node**：通过下载整个 blockchain，full node 可确保最大的隐私。所有曾经发生的交易都存储在本地，这使得对手无法识别用户对哪些交易或地址感兴趣。
- **Client-side block filtering**：这种方法为 blockchain 中的每个 block 创建 filters，使 wallets 能够在不向网络观察者暴露具体兴趣的情况下识别相关交易。轻量级 wallets 会下载这些 filters，只有在与用户地址匹配时才获取完整 blocks。

## **利用 Tor 实现匿名性**

鉴于 Bitcoin 运行在 peer-to-peer 网络上，建议使用 Tor 来隐藏你的 IP 地址，从而在与网络交互时增强隐私。

## **防止地址重用**

为了保护隐私，每笔交易都必须使用一个新地址。重用地址会通过将交易关联到同一实体而损害隐私。现代 wallets 通过其设计来抑制地址重用。

## **交易隐私策略**

- **多笔交易**：将一笔支付拆分为多笔交易可以掩盖交易金额，挫败隐私攻击。
- **避免找零**：选择不需要 change outputs 的交易可通过破坏 change detection 方法来增强隐私。
- **多个找零输出**：如果无法避免找零，生成多个 change outputs 仍然可以改善隐私。

# **Monero：匿名性的灯塔**

Monero 满足了数字交易中对绝对匿名性的需求，为隐私设立了很高的标准。

# **Ethereum：Gas 和交易**

## **理解 Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算工作量，以 **gwei** 定价。例如，一笔花费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas limit 和 base fee，并通过 tip 来激励 miners。用户可以设置 max fee 以确保不会支付过多，多余部分会被退还。

## **执行交易**

Ethereum 中的交易涉及发送方和接收方，二者可以是用户地址或 smart contract 地址。它们需要 fee，并且必须被 mined。交易中的关键信息包括接收方、发送方签名、value、可选 data、gas limit 和 fees。值得注意的是，发送方地址可由签名推导出来，因此无需写入交易数据中。

这些实践和机制是任何希望在优先考虑隐私和安全的同时使用 cryptocurrencies 的人的基础。

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

## ZK Proof / zkVM Guest Integrity

When a prover uses a **zkVM** or an application-specific proof circuit to attest a claim, the verifier is only learning that the **guest program executed as written**. If the guest contains **unsafe deserialization**, **undefined behavior**, or **missing semantic constraints**, a malicious prover may generate a proof that verifies while the **public metrics or claimed invariant are false**.

### Unsafe deserialization inside proof guests

- Treat private witness/circuit bytes as **untrusted attacker input** even if they are hidden by the proof.
- Avoid deserializing them with unchecked helpers such as `rkyv::access_unchecked` unless the bytes were already validated out-of-band.
- Enum discriminants, relative pointers, lengths, and indexes loaded from untrusted serialized data must be validated before they influence control flow or memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
如果像 `op.kind` 这样的字段是一个 enum，而攻击者可以注入一个 **超出范围的 discriminant**，那么对这个值的每一次下游 `match` 都会变得可疑。

### jump-table / UB bypass

如果 Rust 将一个较大的 `match` 降低为 **jump table**，一个无效的 enum discriminant 可能导致 **undefined control flow**。一种危险模式是：

1. 第一个 `match` 更新 **security-critical counters/constraints**。
2. 第二个 `match` 执行 **真实的指令语义**。
3. 一个超出范围的 discriminant 会索引越过第一个 jump table，并落到与第二个 jump table 相关的代码中。

结果：操作仍然执行，但计账路径被跳过。在 zkVM 中，这可能伪造证明，报告不可能的指标，例如更少的 gates、更少的 expensive operations，或其他被篡改的 bounded resources。

Review checklist:

- 查找从 witness/private input 反序列化而来的、由攻击者控制的 enums。
- 检查针对同一个 opcode/kind 字段重复出现的 `match` 语句。
- 将 `unsafe` + unchecked deserialization + 大型 opcode dispatch 视为高风险组合。
- 在需要时对生成的二进制进行 reverse engineer；jump-table 布局可能比源码更重要。

### reversible/specialized interpreters 中缺失语义约束

不要只验证内存安全；还要验证证明需要强制执行的 **语义规则**。

对于 reversible/quantum-like instruction sets，确保必须不同的操作数实际上被约束为不同。一个类似 Toffoli/CCX 的操作如果按如下方式实现：
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
如果 guest 不拒绝，就会变得不安全：
```text
op.q_control1 == op.q_control2 == op.q_target
```
在这种情况下，转换会简化为：
```text
q = q ^ (q & q) = 0
```
这会创建一个**deterministic reset primitive**，破坏可逆性假设，并使非预期计算变得更便宜。在证明资源使用量的 proof systems 中，这会让攻击者在绕过 verifier 认为正在强制执行的 cost model 的同时，通过 functional checks。

### 在 ZK systems 中测试什么

- 使用畸形的 witness/private-input 编码 fuzz 所有 guest parsers。
- 在 opcode dispatch 之前断言 enum 范围验证。
- 为 operand aliasing 和其他无效 instruction forms 添加语义检查。
- 将报告的/public counters 与独立的 reference implementation 进行对比。
- 记住，即使 proof 有效，如果 guest program 有 bug，仍然可能证明**错误的 statement**。

## DeFi/AMM Exploitation

如果你在研究 DEXes 和 AMMs 的实际 exploitation（Uniswap v4 hooks、rounding/precision abuse、flash-loan amplified threshold-crossing swaps），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于缓存 virtual balances 且在 `supply == 0` 时可能被 poison 的多资产加权池，请研究：

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
