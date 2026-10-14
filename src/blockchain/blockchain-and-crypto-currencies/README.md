# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **智能合约**是指在满足特定条件时于区块链上执行的程序，可自动执行协议，无需中间方参与。
- **去中心化应用（dApps）**基于智能合约构建，具有易于使用的前端，以及透明、可审计的后端。
- **Token 与 Coin**的区别在于：Coin 作为数字货币，而 Token 则代表特定场景中的价值或所有权。
  - **Utility Token** 可用于访问服务，**Security Token** 则代表资产所有权。
- **DeFi** 是去中心化金融（Decentralized Finance）的缩写，提供无需中央机构参与的金融服务。
- **DEX** 和 **DAO** 分别指去中心化交易平台（Decentralized Exchange Platforms）和去中心化自治组织（Decentralized Autonomous Organizations）。

如需了解加密市场中的现货订单、期货、杠杆和期权术语，请参阅[投资术语](investment-terms.md)。

## 共识机制

共识机制可确保区块链上的交易验证安全且达成一致：

- **工作量证明（PoW）**依靠计算能力验证交易。
- **权益证明（PoS）**要求验证者持有一定数量的 Token，与 PoW 相比可降低能耗。<sup>[[1]](#references)</sup>

## Bitcoin 基础知识

### 交易

Bitcoin 交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥所有者才能发起转账。<sup>[[2]](#references)</sup>

#### 关键组成部分：

- **多重签名交易**需要多个签名才能授权交易。<sup>[[3]](#references)</sup>
- 交易由**输入**（资金来源）、**输出**（资金去向）、**手续费**（支付给矿工）和**脚本**（交易规则）组成。

### Lightning Network

Lightning Network 旨在提高 Bitcoin 的可扩展性：允许在通道内进行多笔交易，只将最终状态广播到区块链。

## Bitcoin 隐私问题

**Common Input Ownership** 和 **UTXO Change Address Detection** 等隐私攻击会利用交易模式。**Mixers** 和 **CoinJoin** 等策略通过隐藏用户之间的交易关联来提高匿名性。

## 匿名获取 Bitcoin

方法包括现金交易、挖矿和使用 Mixers。**CoinJoin** 将多笔交易混合，使追踪更加困难；**PayJoin** 则将 CoinJoin 伪装成普通交易，以增强隐私性。

# Bitcoin 隐私攻击总结

在 Bitcoin 世界中，交易隐私和用户匿名性一直备受关注。以下简要介绍攻击者可能破坏 Bitcoin 隐私的几种常见方式。<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

由于流程复杂，不同用户的输入通常很少会合并到同一笔交易中。因此，**同一笔交易中的两个输入地址通常被认为属于同一所有者**。

## **UTXO Change Address Detection**

UTXO，即**未花费交易输出**，必须在一笔交易中全部花费。如果只将其中一部分发送到另一个地址，剩余部分就会转到新的找零地址。观察者可能会推断这个新地址属于发送方，从而损害其隐私。

### 示例

为缓解这一问题，可以使用混币服务或多个地址来隐藏所有权关系。

## **社交网络与论坛泄露**

用户有时会在网上分享自己的 Bitcoin 地址，使他人**很容易将地址与其所有者关联起来**。

## **交易图分析**

可以将交易表示为图，根据资金流向揭示用户之间可能存在的关联。

## **不必要输入启发式（最优找零启发式）**

这种启发式通过分析包含多个输入和输出的交易，推测哪个输出是返回给发送方的找零。

### 示例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

如果添加更多输入导致找零金额大于任何单个输入，可能会迷惑启发式分析。

## **强制地址重用**

攻击者可能会向之前使用过的地址发送少量资金，希望收款方在未来交易中将这些资金与其他输入合并，从而将地址关联起来。

### 钱包的正确行为

钱包应避免使用曾经收过款、现已清空的地址中的币，以防止这种隐私泄露。

## **其他区块链分析技术**

- **精确付款金额：** 没有找零的交易很可能发生在同一用户拥有的两个地址之间。
- **整数金额：** 交易中的整数金额暗示这可能是一笔付款，而非整数金额的输出很可能是找零。
- **钱包指纹识别：** 不同钱包具有独特的交易创建模式，分析人员可以据此识别所用软件，并可能推断出找零地址。
- **金额与时间关联：** 泄露交易时间或金额可能会使交易变得可追踪。

## **流量分析**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联起来，从而损害用户隐私。如果某个实体运营大量 Bitcoin 节点，这一点尤其值得关注，因为这会增强其监控交易的能力。

## 更多信息

有关隐私攻击和防御措施的完整列表，请访问 [Bitcoin Wiki 上的 Bitcoin 隐私页面](https://en.bitcoin.it/wiki/Privacy)。

# 匿名 Bitcoin 交易

## 匿名获取比特币的方式

- **现金交易**：通过现金获取比特币。
- **现金替代方式**：购买礼品卡，然后在线兑换比特币。
- **挖矿**：挖矿是获取比特币最注重隐私的方式，尤其是独自挖矿，因为矿池可能知道矿工的 IP 地址。[矿池信息](https://en.bitcoin.it/wiki/Pooled_mining)
- **盗窃**：理论上，盗取比特币也可能是匿名获取比特币的一种方式，但这是违法行为，不建议这样做。

## 混币服务

用户可以通过混币服务**发送比特币**，并**收取不同的比特币**，从而增加追踪原所有者的难度。但这需要信任该服务不会保留日志，并且会实际返还比特币。其他混币方式包括 Bitcoin 赌场。

## CoinJoin

**CoinJoin** 会将不同用户的多笔交易合并为一笔，使试图匹配输入与输出的过程更加复杂。尽管这种方法有效，但输入和输出金额独特的交易仍有可能被追踪。

可能使用过 CoinJoin 的交易示例包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

如需了解更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。有关一种将存款与之后的取款分离的 Ethereum 智能合约混币器，请参阅 [Tornado Cash](https://tornado.cash)。

## PayJoin

**PayJoin**（或 P2EP）是 CoinJoin 的一种变体，它会将双方（例如客户和商家）之间的交易伪装成普通交易，不具备 CoinJoin 特有的等额输出。这使其极难被检测到，并可能使交易监控实体使用的共同输入所有权启发式分析失效。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

像上面这样的交易可能是 PayJoin，在增强隐私的同时，仍与标准 bitcoin 交易无法区分。

**使用 PayJoin 可能会显著扰乱传统监控方法**，因此它是追求交易隐私的一项值得期待的发展。

# 加密货币隐私最佳实践

## **钱包同步技术**

为维护隐私和安全，与区块链同步钱包至关重要。以下两种方法尤为突出：

- **Full node**：通过下载整个区块链，full node 可确保最大程度的隐私。所有已发生的交易都存储在本地，攻击者因此无法识别用户感兴趣的交易或地址。
- **客户端区块过滤**：此方法为区块链中的每个区块创建过滤器，让钱包能够识别相关交易，而不向网络观察者暴露具体关注点。轻量级钱包会下载这些过滤器，仅在发现与用户地址匹配的内容时才获取完整区块。

## **使用 Tor 实现匿名**

鉴于 Bitcoin 运行在点对点网络上，建议使用 Tor 隐藏 IP 地址，以增强与网络交互时的隐私。

## **避免地址重用**

为保护隐私，每笔交易都应使用新地址。重复使用地址可能会将多笔交易关联到同一实体，从而损害隐私。现代钱包在设计上会避免地址重用。

## **交易隐私策略**

- **多笔交易**：将一笔付款拆分为多笔交易，可以掩盖交易金额，阻碍针对隐私的攻击。
- **避免找零**：选择无需找零输出的交易，可通过干扰找零检测方法来增强隐私。
- **多个找零输出**：如果无法避免找零，生成多个找零输出仍能提升隐私。

# **Monero：匿名性的灯塔**

Monero 的设计优先考虑交易隐私。

# **Ethereum：Gas 与交易**

## **了解 Gas**

Gas 用于衡量在 Ethereum 上执行操作所需的计算量，并以 **gwei** 计价。例如，一笔耗费 2,310,000 gwei（或 0.00231 ETH）的交易包含 gas limit 和 base fee，并通过 priority fee 激励验证者将其纳入区块。用户可以设置 max fee，以确保不会多付费用；超出部分会退还。<sup>[[5]](#references)</sup>

## **执行交易**

Ethereum 交易涉及发送方和接收方，两者可以是用户地址，也可以是智能合约地址。交易需要支付费用，并且必须纳入区块。交易中的必要信息包括接收方、发送方签名、金额、可选数据、gas limit 和费用。值得注意的是，发送方地址可从签名中推导得出，因此无需将其包含在交易数据中。<sup>[[4]](#references)</sup>

对于希望在参与加密货币活动时优先保障隐私和安全的任何人来说，这些实践和机制都是基础。

## 以价值为中心的 Web3 Red Teaming

- 清点持有或处理价值的组件（签名者、预言机、桥、自动化系统），了解哪些组件能够转移资金以及如何转移。
- 将每个组件映射到相关的 MITRE AADAPT 战术，以揭示权限提升路径。
- 演练 flash-loan/预言机/凭证/跨链攻击链，以验证影响并记录可被利用的前提条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 签名工作流失陷

- 对钱包 UI 进行供应链篡改，可在签名前修改 EIP-712 payload，从而窃取有效签名，用于基于 delegatecall 的代理接管（例如，覆盖 Safe masterCopy 的 slot-0）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## 账户抽象（ERC-4337）

- 智能账户常见的失效模式包括绕过 `EntryPoint` 访问控制、未签名的 gas 字段、有状态验证、ERC-1271 重放，以及验证后回滚导致的费用耗尽。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## 智能合约安全

- 使用变异测试发现测试套件中的盲点：

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest 完整性

当 prover 使用 **zkVM** 或特定于应用的证明电路来证明某项声明时，verifier 只能得知 **guest program 按照编写的方式执行了**。如果 guest 存在 **不安全反序列化**、**未定义行为**或**缺少语义约束**，恶意 prover 可能生成可通过验证的证明，尽管 **公开指标或所声称的不变量是错误的**。<sup>[[7]](#references)</sup>

### Proof guest 中的不安全反序列化

- 即使私有 witness/circuit 字节被证明隐藏，也应将其视为**不可信的攻击者输入**。
- 避免使用 `rkyv::access_unchecked` 等未经检查的辅助函数对其进行反序列化，除非这些字节已通过带外方式验证。
- 必须先验证从不可信序列化数据加载的枚举判别值、相对指针、长度和索引，再让它们影响控制流或内存访问。

实用审计模式：

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

如果像 `op.kind` 这样的字段是 enum，且攻击者可以注入**超出范围的判别值**，那么所有下游对该值执行的 `match` 都值得警惕。

### 跳转表 / UB 绕过计数器

如果 Rust 将大型 `match` 降低为**跳转表**，无效的 enum 判别值可能导致**未定义的控制流**。一种危险模式是：<sup>[[7]](#references)[[9]](#references)</sup>

1. 第一个 `match` 更新**安全关键计数器/约束**。
2. 第二个 `match` 执行**实际指令语义**。
3. 超出范围的判别值越过第一个跳转表的边界，跳转到与第二个跳转表关联的代码。

结果：操作仍会执行，但计数路径被跳过。在 zkVM 中，这可能伪造证明，报告不可能的指标，例如更少的门、更少的高开销操作，或其他被篡改的有界资源数据。

审查清单：

- 查找从 witness/私有输入反序列化、且由攻击者控制的 enum。
- 检查是否对同一个 opcode/kind 字段重复执行 `match`。
- 将 `unsafe` + 未经检查的反序列化 + 大型 opcode 分派视为高风险组合。
- 必要时对生成的二进制文件进行逆向工程；跳转表布局可能比源代码更重要。

### 可逆/专用解释器中缺失的语义约束

不要只验证内存安全；还要验证证明本应强制执行的**语义规则**。

对于可逆/类量子指令集，请确保必须互不相同的操作数确实受到约束，保证彼此不同。类似 Toffoli/CCX 的操作如果实现为：<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

如果 guest 不拒绝，则会变得不安全：

```text
op.q_control1 == op.q_control2 == op.q_target
```

在这种情况下，转换会简化为：

```text
q = q ^ (q & q) = 0
```

这会创建一个**确定性重置原语**，打破可逆性假设，并使成本更低的非预期计算成为可能。在证明系统对资源使用情况进行证明时，攻击者可能借此通过功能检查，同时绕过验证者认为正在强制执行的成本模型。

### 约束不足的 prover advice 与模运算

从 **advice/witness stack** 加载的值由 prover 控制，即使它们被描述为预先计算的商、余数、逆元或提示。证明只能证明 witness 满足已实现的约束；如果这些约束遗漏了类型、范围或规范形式检查，就无法证明预期的计算确实发生。<sup>[[13]](#references)</sup>

对于归约或欧几里得除法辅助函数，应审计完整的整数关系，而不只是最终的减法或乘法。`q` 和 `r` 的每个 limb 都必须受其声明位宽约束；重构关系 `x = q * m + r` 必须在预期的整数表示中成立；并且必须强制执行规范边界 `0 <= r < m`。将值传递给更窄的 `u32`/`u64` 指令之前，先验证该值；窄位宽运算无法追溯证明原始字段元素或多 limb 值具有预期类型。<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden 中的 `mod_12289` 故障体现了这种 exploit 模式：商值经过了双 limb 64 位检查，但 advice 提供的余数却未经同等验证，便传入 `u32overflowing_sub`。恶意 prover 可以协调无效的商值和余数，使已实现的减法约束仍然成立，同时让过程返回非数学意义上的余数。由于该结果会用于 Falcon 验证，这一 soundness 失效可能进一步导致伪造授权签名，而不只是产生错误的算术结果。<sup>[[13]](#references)</sup>

### 审计隐式栈式密码学 VM

栈语言会隐藏操作数，因此应先将指令转换为 IR，让每个被消耗和产生的栈值都成为带有来源信息的表达式。随后可采用保守的分析流程：<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. 构建调用图，并推断过程的输入/输出栈效果。
2. 符号执行受支持的指令，并将控制流转换为 SSA/结构化表达式。
3. 传播 `Unknown`、`ProvenU32`、`Bool`、值来源和局部初始化状态等抽象事实，直到达到不动点。
4. 标记流向类型化算术或非零值接收点的 advice 派生值，前提是并非**所有**入边路径上都有 sanitizer。
5. 比较声明的签名与推断出的签名，并验证每个退出点都保留了调用方拥有的栈值。

将未知签名或不支持的构造视为**分析缺口**，而非通过分析。动态调用、非栈中性的循环，以及栈效果不同的分支，都可能导致无法可靠跟踪栈槽；更安全的反编译器应拒绝或标记这些情况，而不是生成看似合理却错误的伪代码。<sup>[[10]](#references)[[13]](#references)</sup>

在控制流汇合点，仅当某个属性对每个前驱都成立时才保留它（例如，`ProvenU32 join Unknown = Unknown`）。还应区分不动点收敛与达到迭代上限：只有收敛且可靠的过近似，才能让人据此将没有诊断结果视为所有已表示执行都满足该属性的证据。<sup>[[11]](#references)</sup>

### 用证明义务揭示隐藏的前置条件

对于小型指令集，可将过程转换为可执行的形式化 VM 模型，并证明结果以及完整的栈变换。定理应涵盖终止性、类型化输入、预期输出前缀，以及对未修改调用方栈的保留。应像审查证明一样仔细审查定理陈述：内核可以验证一个意外弱化的命题之证明。<sup>[[12]](#references)[[13]](#references)</sup>

意外出现的假设是有价值的发现。在 Miden 审查中，64 位右旋转的证明要求 `shift mod 32 != 0`，这揭示了一个失败边界情况：当大输入的 shift 是 32 的倍数时会出错；另一项证明发现，256 位 `wrapping_mul` 会丢弃调用方拥有的栈值。将发现的边界情况加入测试，然后修复实现，或有意强化公开前置条件，而不是默默接受额外假设。<sup>[[12]](#references)[[13]](#references)</sup>

### ZK 系统中的测试要点

- 使用格式错误的 witness/private-input 编码，对所有 guest parser 进行 fuzz 测试。
- 确保在 opcode 分发前进行 enum 范围验证。
- 添加语义检查，验证操作数别名及其他无效指令形式。
- 跟踪每个 advice/witness 来源到各个类型化算术接收点的路径，并要求每条路径都经过验证。<sup>[[11]](#references)[[13]](#references)</sup>
- 使用非规范 limb、越界余数和边界 shift 计数测试算术辅助函数。<sup>[[12]](#references)[[13]](#references)</sup>
- 确保每个返回点的栈高度正确，并保留过程声明参数以下的值。<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- 将报告的/公开的计数器与独立的参考实现进行比较。
- 请记住，如果 guest 程序有 bug，有效证明仍可能证明**错误的命题**。

## 依赖状态的授权

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM 利用

如果你正在研究 DEX 和 AMM 的实际利用方式（Uniswap v4 hooks、舍入/精度滥用、由 flash loan 放大的阈值跨越 swap），请参阅：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于缓存虚拟余额且可能在 `supply == 0` 时遭到投毒的多资产加权池，请参阅：

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
- [7] [Trail of Bits - 我们破解了 Google 的量子密码分析零知识证明](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [保护椭圆曲线加密货币免受量子漏洞影响：资源估算与缓解措施（修订版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits 概念验证仓库](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM 反编译器架构](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM 静态分析引擎](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean 模型与正确性证明](https://github.com/trailofbits/masm-lean)
- [13] [（足够好）AI 时代的审计](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
