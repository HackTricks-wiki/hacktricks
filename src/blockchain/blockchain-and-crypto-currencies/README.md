# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts**（智能合约）是指在满足特定条件时于区块链上执行的程序，可自动执行协议，而无需中介。
- **Decentralized Applications (dApps)**（去中心化应用）基于智能合约构建，具有用户友好的前端和透明、可审计的后端。
- **Tokens & Coins**（代币与币）有所区别：币作为数字货币使用，而代币则代表特定场景中的价值或所有权。
  - **Utility Tokens**（实用型代币）提供服务访问权限，**Security Tokens**（证券型代币）代表资产所有权。
- **DeFi** 是 Decentralized Finance（去中心化金融）的简称，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指 Decentralized Exchange Platforms（去中心化交易平台）和 Decentralized Autonomous Organizations（去中心化自治组织）。

## 共识机制

共识机制可确保区块链上的交易得到安全且一致的验证：

- **Proof of Work (PoW)** 依靠计算能力验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的代币，与 PoW 相比可降低能源消耗。<sup>[[1]](#references)</sup>

## Bitcoin 基础知识

### 交易

Bitcoin 交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥所有者才能发起转账。<sup>[[2]](#references)</sup>

#### 关键组成部分：

- **Multisignature Transactions**（多重签名交易）需要多个签名才能授权交易。<sup>[[3]](#references)</sup>
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给矿工的费用）和 **scripts**（交易规则）组成。

### Lightning Network

Lightning Network 旨在提升 Bitcoin 的可扩展性：允许在一个通道内进行多笔交易，只将最终状态广播到区块链。

## Bitcoin 隐私问题

**Common Input Ownership**（共同输入所有权）和 **UTXO Change Address Detection**（UTXO 找零地址检测）等隐私攻击会利用交易模式。**Mixers**（混币器）和 **CoinJoin** 等策略则通过隐藏用户间的交易关联来提升匿名性。

## 匿名获取 Bitcoin

方法包括现金交易、挖矿和使用混币器。**CoinJoin** 将多笔交易混合，使追踪更加困难；而 **PayJoin** 将 CoinJoin 伪装成常规交易，以提升隐私性。

# Bitcoin 隐私攻击概要

在 Bitcoin 世界中，交易隐私和用户匿名性经常受到关注。以下简要介绍攻击者可能用来破坏 Bitcoin 隐私的几种常见方法。<sup>[[6]](#references)</sup>

## **共同输入所有权假设**

由于操作复杂，将不同用户的输入合并到一笔交易中的情况通常很少见。因此，**同一笔交易中的两个输入地址通常被认为属于同一所有者**。

## **UTXO 找零地址检测**

UTXO，即 **Unspent Transaction Output**（未花费交易输出），必须在一笔交易中全部花费。如果只将其中一部分发送到另一个地址，剩余部分就会转到一个新的找零地址。观察者可以推断这个新地址属于发送者，从而损害其隐私。

### 示例

为降低这种风险，可以使用混币服务或多个地址来隐藏所有权关系。

## **社交网络与论坛信息暴露**

用户有时会在网上分享自己的 Bitcoin 地址，因此**很容易将地址与其所有者关联起来**。

## **交易图分析**

可以将交易可视化为图，根据资金流向揭示用户之间可能存在的关联。

## **不必要输入启发式（最佳找零启发式）**

此启发式通过分析包含多个输入和输出的交易，推测哪个输出是返回给发送者的找零。

### 示例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

如果添加更多输入会使找零输出金额大于任何单个输入金额，就可能误导启发式判断。

## **强制地址复用**

攻击者可能会向先前使用过的地址发送小额款项，希望收款方在未来的交易中将这些款项与其他输入合并，从而将地址关联起来。

### 正确的钱包行为

钱包应避免使用曾经收款且余额已清空的地址中的币，以防止这种隐私 leak。

## **其他区块链分析技术**

- **精确付款金额：** 没有找零的交易很可能发生在同一用户拥有的两个地址之间。
- **整数金额：** 交易中的整数金额暗示这是一笔付款，而非整数金额的输出很可能是找零。
- **钱包指纹识别：** 不同钱包创建交易的模式各不相同，分析人员可以据此识别所用软件，并有可能找出找零地址。
- **金额与时间关联：** 泄露交易时间或金额可能会使交易变得可追踪。

## **流量分析**

攻击者通过监控网络流量，可能将交易或区块与 IP 地址关联起来，从而损害用户隐私。如果某个实体运营许多 Bitcoin 节点，这种情况尤为明显，因为这会增强其监控交易的能力。

## 更多信息

如需查看隐私攻击与防御措施的完整列表，请访问 [Bitcoin Wiki 上的 Bitcoin 隐私页面](https://en.bitcoin.it/wiki/Privacy)。

# 匿名 Bitcoin 交易

## 匿名获取 Bitcoin 的方式

- **现金交易**：通过现金获取 Bitcoin。
- **现金替代方式**：购买礼品卡，然后在线兑换 Bitcoin。
- **挖矿**：通过挖矿赚取 Bitcoin 是最私密的方式，尤其是独自挖矿，因为矿池可能知道矿工的 IP 地址。[矿池信息](https://en.bitcoin.it/wiki/Pooled_mining)
- **盗窃**：理论上，盗取 Bitcoin 也是匿名获取 Bitcoin 的另一种方式，但这是违法行为，不建议这么做。

## 混币服务

使用混币服务时，用户可以**发送 Bitcoin**，并收到**不同的 Bitcoin 作为回报**，这会使追踪原始所有者变得困难。但这要求用户信任该服务不会保留日志，并且会实际返还 Bitcoin。其他混币选项包括 Bitcoin 赌场。

## CoinJoin

**CoinJoin** 将不同用户的多笔交易合并为一笔，使尝试匹配输入与输出的过程更加复杂。尽管这种方法有效，但输入和输出金额独特的交易仍可能被追踪。

可能使用过 CoinJoin 的交易示例包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

如需了解更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。如需了解一种将存款与之后的提款分离的 Ethereum 智能合约混币器，请参阅 [Tornado Cash](https://tornado.cash)。

## PayJoin

**PayJoin**（或 P2EP）是 CoinJoin 的一种变体，它将双方（例如客户与商家）之间的交易伪装成普通交易，不具备 CoinJoin 特有的等额输出。这使其极难被检测到，并可能使交易监控实体使用的共同输入所有权启发式失效。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

像上述交易这样的交易可能是 PayJoin，在增强隐私的同时，仍与标准 bitcoin 交易无法区分。

**使用 PayJoin 可能会显著扰乱传统监控方法**，使其成为追求交易隐私的一项很有前景的发展。

# 加密货币隐私最佳实践

## **钱包同步技术**

为了维护隐私和安全，与区块链同步钱包至关重要。以下两种方法尤为突出：

- **Full node**：通过下载整个区块链，full node 可确保最大程度的隐私。所有曾经发生的交易都存储在本地，因此攻击者无法识别用户关注哪些交易或地址。
- **客户端区块过滤**：此方法为区块链中的每个区块创建过滤器，让钱包能够识别相关交易，而不会向网络观察者暴露具体关注内容。轻量级钱包会下载这些过滤器，仅在发现与用户地址匹配的内容时才获取完整区块。

## **使用 Tor 实现匿名性**

鉴于 Bitcoin 运行在点对点网络上，建议使用 Tor 隐藏 IP 地址，从而在与网络交互时增强隐私。

## **避免重复使用地址**

为了保护隐私，每笔交易都使用新地址至关重要。重复使用地址可能会将多笔交易关联到同一实体，从而损害隐私。现代钱包的设计会避免地址重复使用。

## **交易隐私策略**

- **多笔交易**：将一笔付款拆分成多笔交易，可以隐藏交易金额，阻止隐私攻击。
- **避免找零**：选择无需找零输出的交易，可通过破坏找零检测方法来增强隐私。
- **多个找零输出**：如果无法避免找零，生成多个找零输出仍可改善隐私。

# **Monero：匿名性的灯塔**

Monero 的设计优先考虑交易隐私。

# **Ethereum：Gas 与交易**

## **了解 Gas**

Gas 用于衡量在 Ethereum 上执行操作所需的计算工作量，以 **gwei** 计价。例如，一笔费用为 2,310,000 gwei（或 0.00231 ETH）的交易包含 Gas limit 和基础费用，并附有用于激励验证者纳入交易的优先费用。用户可以设置最高费用，以确保不会多付，超出部分将退还。<sup>[[5]](#references)</sup>

## **执行交易**

Ethereum 交易涉及发送方和接收方，两者可以是用户地址或智能合约地址。交易需要支付费用，并且必须纳入区块。交易中的必要信息包括接收方、发送方签名、数值、可选数据、Gas limit 和费用。值得注意的是，发送方地址可从签名中推导出来，因此无需将其包含在交易数据中。<sup>[[4]](#references)</sup>

对于任何希望在优先考虑隐私和安全的同时参与加密货币活动的人来说，这些实践和机制都是基础。

## 以价值为中心的 Web3 红队测试

- 清点承载价值的组件（签名者、预言机、桥、自动化组件），以了解谁能转移资金以及如何转移。
- 将每个组件映射到相关的 MITRE AADAPT 策略，以暴露权限提升路径。
- 演练 flash loan/预言机/凭据/跨链攻击链，以验证影响并记录可利用的前置条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 签名工作流失陷

- 对钱包 UI 进行供应链篡改，可能会在签名前修改 EIP-712 payload，从而窃取有效签名，用于基于 delegatecall 的代理接管（例如覆盖 Safe masterCopy 的 slot-0）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## 账户抽象（ERC-4337）

- 常见的智能账户故障模式包括绕过 `EntryPoint` 访问控制、Gas 字段未签名、有状态验证、ERC-1271 重放，以及验证后回滚导致的费用耗尽。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## 智能合约安全

- 使用 mutation testing 查找测试套件中的盲点：

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK 证明 / zkVM Guest 完整性

当 prover 使用 **zkVM** 或特定于应用的证明电路来证明某项声明时，verifier 只能得知 **guest 程序按编写内容执行了**。如果 guest 包含 **不安全的反序列化**、**未定义行为**或**缺失的语义约束**，恶意 prover 可能生成能够通过验证、但 **公开指标或所声称的不变量并不成立** 的证明。<sup>[[7]](#references)</sup>

### 证明 guest 中的不安全反序列化

- 将私有 witness/电路字节视为**不可信的攻击者输入**，即使它们被证明隐藏也应如此处理。
- 避免使用 `rkyv::access_unchecked` 等未经检查的辅助函数对其进行反序列化，除非这些字节已在带外验证。
- 必须先验证从不可信序列化数据中载入的枚举判别值、相对指针、长度和索引，然后才能让它们影响控制流或内存访问。

实用审计模式：

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

如果 `op.kind` 这类字段是 enum，且攻击者可以注入**超出范围的判别值**，那么所有下游针对该值的 `match` 都值得怀疑。

### 跳转表 / UB 绕过计数器

如果 Rust 将大型 `match` 编译为**跳转表**，无效的 enum 判别值可能导致**未定义的控制流**。一种危险模式如下：<sup>[[7]](#references)[[9]](#references)</sup>

1. 一个 `match` 更新**安全关键计数器/约束**。
2. 第二个 `match` 执行**实际指令语义**。
3. 超出范围的判别值越过第一个跳转表的边界，跳转到与第二个跳转表相关联的代码。

结果：操作仍会执行，但计数路径被跳过。在 zkVM 中，这可能伪造证明，报告不可能的指标，例如更少的 gates、更少的高成本操作，或其他被篡改的有界资源。

审查清单：

- 查找从 witness/private input 反序列化、且由攻击者控制的 enum。
- 检查是否有针对同一 opcode/kind 字段的重复 `match` 语句。
- 将 `unsafe` + 未经检查的反序列化 + 大型 opcode 分派视为高风险组合。
- 必要时对生成的二进制文件进行逆向工程；跳转表布局可能比源代码更重要。

### 可逆/专用解释器中缺失的语义约束

不要只验证内存安全；还要验证证明要强制执行的**语义规则**。

对于可逆/类量子指令集，确保必须互不相同的操作数确实受到互异性约束。以如下方式实现的 Toffoli/CCX 类操作：<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

如果客户机未拒绝，则会变得不安全：

```text
op.q_control1 == op.q_control2 == op.q_target
```

在这种情况下，转换会简化为：

```text
q = q ^ (q & q) = 0
```

这会创建一个**确定性重置原语**，破坏可逆性假设，并使成本更低的非预期计算成为可能。在用于证明资源使用情况的证明系统中，攻击者可能借此满足功能检查，同时绕过验证者认为正在执行的成本模型。

### ZK 系统中需要测试的内容

- 使用格式错误的 witness/private-input 编码对所有 guest 解析器进行 fuzz 测试。
- 在 opcode 分发前断言已进行枚举范围验证。
- 添加语义检查，验证操作数别名及其他无效指令形式。
- 将报告的/公开的计数器与独立的参考实现进行比较。
- 请记住，如果 guest 程序存在 bug，有效证明仍可能证明**错误的陈述**。

## 状态依赖型授权

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM 利用

如果你正在研究 DEX 和 AMM 的实际利用方式（Uniswap v4 hooks、舍入/精度滥用、由 flash loan 放大的阈值跨越型 swap），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于会缓存虚拟余额，且可能在 `supply == 0` 时遭到投毒的多资产加权池，请研究：

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [权益证明 - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [公钥与私钥详解 - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [什么是多重签名交易？ - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [交易 | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas 和费用 | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [隐私 - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - 我们击败了 Google 的量子密码分析零知识证明](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [保护椭圆曲线加密货币免受量子漏洞影响：资源估算与缓解措施（修补版本）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits 概念验证代码仓库](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
