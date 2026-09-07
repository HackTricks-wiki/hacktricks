# Blockchain 和 Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** 被定义为在满足特定条件时于 blockchain 上执行的程序，可在没有中间人的情况下自动执行协议。
- **Decentralized Applications (dApps)** 构建于 smart contracts 之上，具有用户友好的前端以及透明、可审计的后端。
- **Tokens & Coins** 用于区分不同概念：coins 充当数字货币，而 tokens 表示特定场景中的价值或所有权。
- **Utility Tokens** 授予服务访问权限，而 **Security Tokens** 表示资产所有权。
- **DeFi** 代表 Decentralized Finance，即无需中心机构即可提供金融服务。
- **DEX** 和 **DAOs** 分别指 Decentralized Exchange Platforms 和 Decentralized Autonomous Organizations。

## 共识机制

共识机制确保在 blockchain 上安全并达成共识地验证交易：

- **Proof of Work (PoW)** 依靠计算能力验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的 tokens，与 PoW 相比可降低能源消耗。<sup>[[1]](#references)</sup>

## Bitcoin 基础知识

### 交易

Bitcoin 交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有 private key 的所有者才能发起转账。<sup>[[2]](#references)</sup>

#### 关键组件：

- **Multisignature Transactions** 需要多个签名才能授权交易。<sup>[[3]](#references)</sup>
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给 miners 的费用）和 **scripts**（交易规则）组成。

### Lightning Network

其目标是通过允许在一个 channel 内进行多笔交易来提升 Bitcoin 的可扩展性，并仅将最终状态广播到 blockchain。

## Bitcoin 隐私问题

**Common Input Ownership** 和 **UTXO Change Address Detection** 等隐私攻击会利用交易模式。**Mixers** 和 **CoinJoin** 等策略通过隐藏用户之间的交易关联来提升匿名性。

## 匿名获取 Bitcoins

方法包括现金交易、mining 以及使用 mixers。**CoinJoin** 将多笔交易混合，以增加追踪难度；而 **PayJoin** 将 CoinJoins 伪装成普通交易，从而增强隐私性。

# Bitcoin 隐私攻击总结

在 Bitcoin 世界中，交易隐私和用户匿名性经常受到关注。以下是攻击者可能破坏 Bitcoin 隐私的几种常见方法的简要概述。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

由于复杂性较高，不同用户的 inputs 通常很少会被合并到同一笔交易中。因此，**同一笔交易中的两个 input 地址通常被假设属于同一所有者**。

## **UTXO Change Address Detection**

UTXO，即 **Unspent Transaction Output**，必须在一笔交易中被全部花费。如果只有其中一部分被发送到另一个地址，剩余部分就会发送到新的找零地址。观察者可以假设这个新地址属于发送方，从而破坏隐私。

### 示例

为缓解这一问题，可以使用 mixing services 或多个地址来隐藏所有权。

## **Social Networks & Forums Exposure**

用户有时会在网上分享其 Bitcoin 地址，使得**将地址与其所有者关联起来变得容易**。

## **Transaction Graph Analysis**

交易可以被可视化为图，从资金流向中揭示用户之间潜在的关联。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

该启发式方法基于分析具有多个 inputs 和 outputs 的交易，来推测哪个 output 是返回给发送方的找零。

### 示例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果添加更多输入使找零输出大于任何单个输入，这可能会混淆启发式分析。

## **Forced Address Reuse**

攻击者可能会向之前使用过的地址发送少量资金，希望收款方在未来的交易中将这些资金与其他输入合并，从而将地址关联起来。

### 正确的钱包行为

钱包应避免使用已使用过的空地址上收到的币，以防止这种隐私 leak。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 没有找零的交易可能发生在同一用户拥有的两个地址之间。
- **Round Numbers:** 交易中的整数金额表明这可能是一笔支付，而非整数金额的输出可能是找零。
- **Wallet Fingerprinting:** 不同钱包具有独特的交易创建模式，使分析人员能够识别所使用的软件，并可能确定找零地址。
- **Amount & Timing Correlations:** 泄露交易时间或金额可能使交易变得可追踪。

## **Traffic Analysis**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联起来，从而危及用户隐私。如果某个实体运行大量 Bitcoin 节点，这一点尤其明显，因为这会增强其监控交易的能力。

## More

如需隐私攻击和防御措施的完整列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: 通过现金获取 bitcoin。
- **Cash Alternatives**: 购买礼品卡，然后在线将其兑换为 bitcoin。
- **Mining**: 通过 mining 获取 bitcoins 是最具隐私性的方式，尤其是在单独进行时，因为 mining pools 可能知道矿工的 IP 地址。[Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 从理论上讲，窃取 bitcoin 可能是匿名获取 bitcoin 的另一种方式，但这是违法行为，不建议这样做。

## Mixing Services

通过使用 mixing service，用户可以 **send bitcoins**，并接收 **different bitcoins in return**，这会增加追踪原始所有者的难度。不过，这要求信任该服务不会保留日志，并且确实会返还 bitcoins。其他 mixing 选项包括 Bitcoin casinos。

## CoinJoin

**CoinJoin** 将来自不同用户的多笔交易合并为一笔交易，使任何试图匹配输入与输出的人都更加困难。尽管其效果显著，但具有独特输入和输出规模的交易仍可能被追踪。

可能使用过 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

如需更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。如需了解一种将存款与之后的取款分离的 Ethereum smart-contract mixer，请参阅 [Tornado Cash](https://tornado.cash)。

## PayJoin

作为 CoinJoin 的一种变体，**PayJoin**（或 P2EP）将两方之间的交易（例如客户与商户之间的交易）伪装成普通交易，不具备 CoinJoin 特有的等额输出特征。这使其极难被检测，并且可能使交易监控实体使用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
像上面的交易可能是 PayJoin，在保持与标准 bitcoin 交易无法区分的同时增强隐私。

**PayJoin 的使用可能会显著扰乱传统的监控方法**，使其成为追求交易隐私过程中极具前景的发展方向。

# 加密货币隐私最佳实践

## **Wallet Synchronization Techniques**

为了维护隐私和安全，将 wallets 与 blockchain 同步至关重要。有两种方法尤为突出：

- **Full node**：通过下载完整的 blockchain，full node 可确保最高级别的隐私。所有曾经发生的交易都会存储在本地，使 adversaries 无法识别用户关注的是哪些交易或地址。
- **Client-side block filtering**：该方法为 blockchain 中的每个区块创建 filters，使 wallets 能够识别相关交易，而不会向 network observers 暴露具体关注点。轻量级 wallets 会下载这些 filters，仅在发现与用户地址匹配的内容时获取完整区块。

## **Utilizing Tor for Anonymity**

鉴于 Bitcoin 运行在 peer-to-peer network 上，建议使用 Tor 来隐藏 IP 地址，从而增强与该 network 交互时的隐私。

## **Preventing Address Reuse**

为了保护隐私，每笔交易都使用新地址至关重要。重复使用地址可能会将交易关联到同一实体，从而损害隐私。现代 wallets 通过其设计来阻止地址重复使用。

## **Strategies for Transaction Privacy**

- **Multiple transactions**：将一笔付款拆分为多笔交易可以隐藏交易金额，阻碍 privacy attacks。
- **Change avoidance**：选择不需要 change outputs 的交易，可以通过干扰 change detection methods 来增强隐私。
- **Multiple change outputs**：如果无法避免 change，生成多个 change outputs 仍可改善隐私。

# **Monero：匿名性的灯塔**

Monero 的设计重点是交易隐私。

# **Ethereum：Gas 和交易**

## **Understanding Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算工作量，并以 **gwei** 定价。例如，一笔成本为 2,310,000 gwei（或 0.00231 ETH）的交易包含 gas limit 和 base fee，并通过 priority fee 激励 validator 将其纳入区块。用户可以设置 max fee，以确保不会支付过高费用，超出的部分会被退还。<sup>[[5]](#references)</sup>

## **Executing Transactions**

Ethereum 中的交易涉及 sender 和 recipient，二者可以是 user 或 smart contract addresses。交易需要支付费用，并且必须被纳入区块。交易中的必要信息包括 recipient、sender's signature、value、可选的 data、gas limit 和 fees。值得注意的是，sender's address 可从 signature 中推导出来，因此无需包含在交易数据中。<sup>[[4]](#references)</sup>

对于任何希望在优先考虑隐私和安全的同时参与加密货币活动的人来说，这些实践和机制都是基础。

## 以价值为中心的 Web3 Red Teaming

- 清点承载价值的组件（signers、oracles、bridges、automation），以了解谁能够转移资金以及如何转移。
- 将每个组件映射到相关的 MITRE AADAPT tactics，以暴露 privilege escalation paths。
- 演练 flash-loan/oracle/credential/cross-chain attack chains，以验证影响并记录可利用的前置条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- 对 wallet UIs 进行 supply-chain tampering，可能会在 signing 之前修改 EIP-712 payloads，从而窃取有效 signatures，用于基于 delegatecall 的 proxy takeovers（例如覆盖 slot-0 中的 Safe masterCopy）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 常见的 smart-account failure modes 包括绕过 `EntryPoint` access control、未签名的 gas fields、有状态 validation、ERC-1271 replay，以及通过 revert-after-validation 进行 fee-drain。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- 使用 mutation testing 查找 test suites 中的盲点：

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

当 prover 使用 **zkVM** 或特定于应用的 proof circuit 来证明某项声明时，verifier 只能得知 **guest program 按照编写内容执行了**。如果 guest 包含 **unsafe deserialization**、**undefined behavior** 或 **missing semantic constraints**，恶意 prover 可能生成一个能够通过验证的 proof，但其 **public metrics 或 claimed invariant 是错误的**。<sup>[[7]](#references)</sup>

### proof guests 内的 Unsafe deserialization

- 将 private witness/circuit bytes 视为 **untrusted attacker input**，即使它们被 proof 隐藏。
- 除非这些 bytes 已通过 out-of-band 方式验证，否则应避免使用 `rkyv::access_unchecked` 等 unchecked helpers 对其进行 deserializing。
- 必须先验证从 untrusted serialized data 中加载的 enum discriminants、relative pointers、lengths 和 indexes，然后才能让它们影响 control flow 或 memory access。

实用的 audit pattern：
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
如果某个字段（例如 `op.kind`）是 enum，并且攻击者可以注入**超出范围的 discriminant**，那么对该值执行的每个下游 `match` 都值得怀疑。

### Jump-table / UB counter bypass

如果 Rust 将大型 `match` 降级为 **jump table**，无效的 enum discriminant 可能导致**未定义的控制流**。一种危险模式如下：<sup>[[7]](#references)[[9]](#references)</sup>

1. 第一个 `match` 更新**安全关键的计数器/约束**。
2. 第二个 `match` 执行**实际的指令语义**。
3. 超出范围的 discriminant 索引越过第一个 jump table，并跳转到与第二个 jump table 相关的代码。

结果：该操作仍会执行，但 accounting 路径被跳过。在 zkVM 中，这可能伪造证明，使其报告不可能的指标，例如更少的 gates、更少的 expensive operations，或其他被伪造的有界资源。

Review checklist：

- 查找从 witness/private input 反序列化、且由攻击者控制的 enums。
- 检查是否对同一个 opcode/kind 字段重复执行 `match`。
- 将 `unsafe` + unchecked deserialization + large opcode dispatch 视为高风险组合。
- 必要时对生成的 binary 进行 reverse engineer；jump-table 布局的重要性可能高于源代码。

### reversible/specialized interpreters 中缺失的 semantic constraints

不要只验证 memory safety；还要验证 proof 旨在强制执行的**语义规则**。

对于 reversible/quantum-like instruction sets，应确保必须彼此不同的 operands 确实受到 distinct 约束。一个类似 Toffoli/CCX 的操作实现如下：<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
如果 guest 不拒绝，就会变得不安全：
```text
op.q_control1 == op.q_control2 == op.q_target
```
在这种情况下，该跃迁塌缩为：
```text
q = q ^ (q & q) = 0
```
这会创建一个**确定性的重置原语**，打破可逆性假设，并允许执行成本更低的非预期计算。在证明资源使用情况的证明系统中，这可能使攻击者满足功能检查，同时绕过验证器认为正在强制执行的成本模型。

### ZK 系统中应测试的内容

- 使用格式错误的 witness/private-input 编码，对所有 guest parser 进行模糊测试。
- 在 opcode dispatch 之前断言 enum 范围验证。
- 对 operand aliasing 及其他无效指令形式添加语义检查。
- 将报告的/公开的计数器与独立的 reference implementation 进行比较。
- 请记住，如果 guest program 存在错误，即使是有效的 proof，也可能证明**错误的 statement**。

## 依赖状态的授权

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM 利用

如果你正在研究 DEX 和 AMM 的实际利用方式（Uniswap v4 hooks、舍入/精度滥用、由 flash loan 放大的跨阈值 swaps），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于会缓存虚拟余额、且在 `supply == 0` 时可能遭到投毒的多资产加权池，请研究：

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
