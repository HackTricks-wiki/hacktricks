# 区块链与加密货币

## 基本概念

- **Smart Contracts** 被定义为在满足特定条件时于区块链上执行的程序，可在无需中介的情况下自动执行协议。
- **Decentralized Applications (dApps)** 建立在 smart contracts 之上，具有用户友好的前端以及透明、可审计的后端。
- **Tokens & Coins** 的区别在于，coins 充当数字货币，而 tokens 则代表特定场景中的价值或所有权。
- **Utility Tokens** 授予服务访问权限，而 **Security Tokens** 表示资产所有权。
- **DeFi** 代表 Decentralized Finance，在没有中央机构的情况下提供金融服务。
- **DEX** 和 **DAOs** 分别指 Decentralized Exchange Platforms 和 Decentralized Autonomous Organizations。

## 共识机制

共识机制确保区块链上的交易验证安全且达成一致：

- **Proof of Work (PoW)** 依靠计算能力验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的 tokens，与 PoW 相比可降低能源消耗。<sup>[[1]](#references)</sup>

## Bitcoin 基础知识

### 交易

Bitcoin 交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥所有者才能发起转账。<sup>[[2]](#references)</sup>

#### 关键组件：

- **Multisignature Transactions** 需要多个签名才能授权交易。<sup>[[3]](#references)</sup>
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给 miners 的费用）以及 **scripts**（交易规则）组成。

### Lightning Network

通过允许在通道内执行多笔交易，并仅将最终状态广播到区块链上，旨在增强 Bitcoin 的可扩展性。

## Bitcoin 隐私问题

**Common Input Ownership** 和 **UTXO Change Address Detection** 等隐私攻击会利用交易模式。**Mixers** 和 **CoinJoin** 等策略通过隐藏用户之间的交易关联来提高匿名性。

## 匿名获取 Bitcoins

相关方法包括现金交易、挖矿和使用 mixers。**CoinJoin** 将多笔交易混合在一起，以增加追踪难度；而 **PayJoin** 将 CoinJoins 伪装成普通交易，以提升隐私性。

# Bitcoin 隐私攻击总结

在 Bitcoin 的世界中，交易隐私和用户匿名性经常受到关注。以下是攻击者可能破坏 Bitcoin 隐私的几种常见方法的简要概述。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

由于涉及的复杂性，将不同用户的 inputs 合并到一笔交易中通常并不常见。因此，**同一笔交易中的两个 input 地址通常被认为属于同一所有者**。

## **UTXO Change Address Detection**

UTXO，即 **Unspent Transaction Output**，必须在一笔交易中被全部花费。如果只有其中一部分被发送到另一个地址，剩余部分就会转入一个新的找零地址。观察者可以推断该新地址属于发送者，从而破坏隐私。

### 示例

为缓解这一问题，可以使用 mixing services 或多个地址来隐藏所有权。

## **Social Networks & Forums Exposure**

用户有时会在网上分享自己的 Bitcoin 地址，使得**将地址与其所有者关联起来变得容易**。

## **Transaction Graph Analysis**

交易可以被可视化为图，根据资金流动揭示用户之间潜在的关联。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

该启发式方法通过分析具有多个 inputs 和 outputs 的交易，猜测哪个 output 是返回给发送者的找零。

### 示例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果添加更多输入使交易的找零输出大于任何单个输入，这可能会混淆启发式分析。

## **Forced Address Reuse**

攻击者可能会向之前使用过的地址发送少量资金，希望收款方在未来的交易中将这些资金与其他输入合并，从而将多个地址关联起来。

### 正确的钱包行为

钱包应避免使用已在使用且余额为空的地址上收到的 coins，以防止这种隐私 leak。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 没有找零的交易很可能发生在同一用户拥有的两个地址之间。
- **Round Numbers:** 交易中的整数金额表明这可能是一笔付款，而非整数的输出很可能是找零。
- **Wallet Fingerprinting:** 不同钱包具有独特的交易创建模式，使分析人员能够识别所使用的软件，并可能确定找零地址。
- **Amount & Timing Correlations:** 泄露交易时间或金额可能使交易变得可追踪。

## **Traffic Analysis**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联起来，从而危及用户隐私。如果某个实体运营大量 Bitcoin 节点，这一点尤其明显，因为这会增强其监控交易的能力。

## More

如需隐私攻击与防御的完整列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**：通过现金获取 bitcoin。
- **Cash Alternatives**：购买礼品卡，然后在线将其兑换为 bitcoin。
- **Mining**：通过 mining 赚取 bitcoins 是最私密的方法，尤其是在单独进行时，因为 mining pools 可能知道 miner 的 IP 地址。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**：从理论上讲，窃取 bitcoin 可能是另一种匿名获取 bitcoin 的方法，但这是违法行为，不推荐这样做。

## Mixing Services

通过使用 mixing service，用户可以**发送 bitcoins**并获得**不同的 bitcoins 作为回报**，这会使追踪原始所有者变得困难。不过，这需要信任该服务不会保留日志，并且确实会返还 bitcoins。其他 mixing 选项包括 Bitcoin casinos。

## CoinJoin

**CoinJoin** 将不同用户的多笔交易合并为一笔，使任何试图匹配输入与输出的人都更加难以进行分析。尽管这种方法有效，但具有独特输入和输出数量的交易仍可能被追踪。

可能使用过 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

如需更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。如需了解一种将存款与后续提款分离的 Ethereum smart-contract mixer，请参阅 [Tornado Cash](https://tornado.cash)。

## PayJoin

作为 CoinJoin 的一种变体，**PayJoin**（或 P2EP）将两方之间的交易（例如客户与商户之间的交易）伪装成普通交易，不具有 CoinJoin 特有的等额输出特征。这使其极难被检测，并可能使交易监控实体使用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
类似上述的交易可能是 PayJoin，在保持与标准 bitcoin 交易无法区分的同时增强隐私性。

**PayJoin 的使用可能会显著扰乱传统的 surveillance 方法**，使其成为追求交易隐私过程中一个前景可观的发展方向。

# 加密货币隐私最佳实践

## **Wallet Synchronization Techniques**

为了维护隐私和安全，将 wallets 与 blockchain 同步至关重要。其中有两种方法尤为突出：

- **Full node**：通过下载完整的 blockchain，full node 可确保最大程度的隐私。所有曾经发生过的交易都会存储在本地，使 adversary 无法识别用户感兴趣的交易或地址。
- **Client-side block filtering**：该方法为 blockchain 中的每个 block 创建 filters，使 wallets 能够识别相关交易，而不会向 network observer 暴露具体兴趣。轻量级 wallets 会下载这些 filters，仅在发现与用户地址匹配的内容时获取完整 block。

## **使用 Tor 实现匿名性**

鉴于 Bitcoin 运行在 peer-to-peer network 上，建议使用 Tor 来隐藏 IP address，从而增强与 network 交互时的隐私性。

## **防止地址重用**

为了保护隐私，务必为每笔交易使用新地址。重复使用地址可能会通过将多笔交易关联到同一实体而损害隐私。现代 wallets 通过设计来避免地址重用。

## **交易隐私策略**

- **Multiple transactions**：将一笔付款拆分为多笔交易，可以隐藏交易金额，阻止隐私攻击。
- **Change avoidance**：选择不需要找零输出的交易，可以通过干扰找零检测方法来增强隐私。
- **Multiple change outputs**：如果无法避免找零，生成多个找零输出仍然可以改善隐私。

# **Monero：匿名性的灯塔**

Monero 的设计优先考虑交易隐私。

# **Ethereum：Gas 与交易**

## **理解 Gas**

Gas 用于衡量在 Ethereum 上执行操作所需的计算工作量，并以 **gwei** 定价。例如，一笔成本为 2,310,000 gwei（或 0.00231 ETH）的交易包含 gas limit 和 base fee，并通过 priority fee 激励 validator 将其纳入 block。用户可以设置 max fee，以确保不会支付过高费用，超出的部分会退还。<sup>[[5]](#references)</sup>

## **执行交易**

Ethereum 中的交易涉及 sender 和 recipient，两者可以是 user address，也可以是 smart contract address。交易需要支付 fee，并且必须被纳入 block。交易中的关键信息包括 recipient、sender 的 signature、value、可选的 data、gas limit 和 fees。值得注意的是，sender address 可从 signature 中推导出来，因此无需将其包含在交易 data 中。<sup>[[4]](#references)</sup>

对于任何希望在优先考虑隐私和安全的同时参与 cryptocurrency 的人而言，这些实践和机制都是基础。

## 以价值为中心的 Web3 Red Teaming

- 清点承载价值的组件（signers、oracles、bridges、automation），了解谁能够移动资金以及如何移动。
- 将每个组件映射到相关的 MITRE AADAPT tactics，以暴露 privilege escalation 路径。
- 演练 flash-loan/oracle/credential/cross-chain attack chains，以验证影响并记录可利用的前置条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI 的 supply-chain tampering 可能会在 signing 前立即修改 EIP-712 payload，从而窃取有效 signatures，用于基于 delegatecall 的 proxy takeover（例如覆盖 slot-0 中的 Safe masterCopy）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 常见的 smart-account failure modes 包括绕过 `EntryPoint` access control、未签名的 gas fields、有状态 validation、ERC-1271 replay，以及 validation 后通过 revert 实现的 fee-drain。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- 通过 mutation testing 查找 test suites 中的 blind spots：

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

当 prover 使用 **zkVM** 或特定于 application 的 proof circuit 来证明某项声明时，verifier 只能获知 **guest program 按照编写的方式执行了**。如果 guest 包含 **unsafe deserialization**、**undefined behavior** 或 **missing semantic constraints**，恶意 prover 可能生成一个能够通过 verification 的 proof，但其 **public metrics 或 claimed invariant 是错误的**。<sup>[[7]](#references)</sup>

### Proof guest 内的 Unsafe deserialization

- 将 private witness/circuit bytes 视为**不受信任的 attacker input**，即使它们被 proof 隐藏。
- 除非这些 bytes 已通过 out-of-band 方式验证，否则应避免使用诸如 `rkyv::access_unchecked` 之类的 unchecked helpers 对其进行 deserialization。
- 从不受信任的 serialized data 中加载的 enum discriminants、relative pointers、lengths 和 indexes，必须在影响 control flow 或 memory access 之前进行验证。

实用的 audit 模式：
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
如果某个字段（例如 `op.kind`）是 enum，并且攻击者可以注入**超出范围的 discriminant**，那么下游对该值执行的每个 `match` 都值得怀疑。

### Jump-table / UB counter bypass

如果 Rust 将一个较大的 `match` 降级为 **jump table**，无效的 enum discriminant 可能导致**未定义的控制流**。一种危险模式是：<sup>[[7]](#references)[[9]](#references)</sup>

1. 一个 `match` 更新**安全关键的计数器/约束**。
2. 第二个 `match` 执行**实际的指令语义**。
3. 超出范围的 discriminant 索引越过第一个 jump table，并跳转到与第二个 jump table 关联的代码。

结果：该操作仍然执行，但 accounting 路径被跳过。在 zkVM 中，这可能伪造证明，使其报告不可能的指标，例如更少的 gates、更少的 expensive operations，或其他被伪造的有界资源。

Review checklist:

- 查找从 witness/private input 反序列化、且由攻击者控制的 enum。
- 检查是否对同一个 opcode/kind 字段重复执行 `match`。
- 将 `unsafe` + unchecked deserialization + large opcode dispatch 视为高风险组合。
- 必要时对生成的 binary 进行 reverse engineer；jump-table 布局的重要性可能高于 source。

### Missing semantic constraints in reversible/specialized interpreters

不要只验证 memory safety；还要验证 proof 预期强制执行的**语义规则**。

对于 reversible/quantum-like instruction sets，必须确保那些必须不同的 operands 确实受到 distinct 约束。一个类似 Toffoli/CCX 的操作实现为：<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
如果 guest 不拒绝，就会变得不安全：
```text
op.q_control1 == op.q_control2 == op.q_target
```
在这种情况下，该转换可简化为：
```text
q = q ^ (q & q) = 0
```
这会创建一个**确定性重置原语**，破坏可逆性假设，并支持成本更低的非预期计算。在证明资源使用情况的证明系统中，这可能让攻击者满足功能检查，同时绕过验证器认为正在强制执行的成本模型。

### ZK systems 中的测试内容

- 使用格式错误的 witness/private-input 编码对所有 guest parser 进行模糊测试。
- 在 opcode dispatch 之前断言 enum 范围验证。
- 添加 operand aliasing 及其他无效指令形式的语义检查。
- 将报告的/公开的计数器与独立的 reference implementation 进行比较。
- 请记住，如果 guest program 存在 bug，有效证明仍可能证明**错误的陈述**。

## DeFi/AMM Exploitation

如果你正在研究 DEX 和 AMM 的实际 exploitation（Uniswap v4 hooks、舍入/精度滥用、由 flash loan 放大的跨阈值 swaps），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于会缓存虚拟余额、并且在 `supply == 0` 时可能被污染的多资产加权池，请研究：

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [权益证明 - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公钥与私钥详解 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [什么是多重签名交易？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [交易 | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas 与费用 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [隐私 - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - 我们攻破了 Google 的量子密码分析零知识证明](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [保护椭圆曲线加密货币免受量子漏洞影响：资源估算与缓解措施（修订版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
