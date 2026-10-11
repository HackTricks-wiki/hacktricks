# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **智能合约**是指在满足特定条件时于区块链上执行的程序，可在没有中介的情况下自动执行协议。
- **去中心化应用（dApps）**基于智能合约构建，具有用户友好的前端，以及透明、可审计的后端。
- **Token 与 Coin**的区别在于：Coin 用作数字货币，而 Token 则代表特定情境中的价值或所有权。
  - **Utility Token**可授予服务访问权限，而 **Security Token**则表示资产所有权。
- **DeFi**是去中心化金融（Decentralized Finance）的简称，提供不依赖中心化机构的金融服务。
- **DEX** 和 **DAO** 分别指去中心化交易平台（Decentralized Exchange Platforms）和去中心化自治组织（Decentralized Autonomous Organizations）。

## 共识机制

共识机制确保区块链上的交易验证安全且达成共识：

- **工作量证明（PoW）**依靠计算能力验证交易。
- **权益证明（PoS）**要求验证者持有一定数量的 Token，与 PoW 相比可降低能耗。<sup>[[1]](#references)</sup>

## Bitcoin 基础知识

### 交易

Bitcoin 交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥持有者才能发起转账。<sup>[[2]](#references)</sup>

#### 关键组成部分：

- **多重签名交易**需要多个签名才能授权交易。<sup>[[3]](#references)</sup>
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给矿工的费用）和 **scripts**（交易规则）组成。

### Lightning Network

旨在通过允许在一个通道内进行多笔交易来提升 Bitcoin 的可扩展性，并且只将最终状态广播到区块链。

## Bitcoin 隐私问题

**共同输入所有权**和 **UTXO 找零地址检测**等隐私攻击会利用交易模式。**Mixers** 和 **CoinJoin** 等策略通过隐藏用户之间的交易关联来提高匿名性。

## 匿名获取 Bitcoin

方法包括现金交易、挖矿和使用 Mixers。**CoinJoin** 会混合多笔交易以增加追踪难度，而 **PayJoin** 则将 CoinJoin 伪装成普通交易，以进一步增强隐私。

# Bitcoin 隐私攻击概要

在 Bitcoin 的世界中，交易隐私和用户匿名性往往备受关注。以下简要介绍攻击者可能利用的几种常见方法，从而损害 Bitcoin 隐私。<sup>[[6]](#references)</sup>

## **共同输入所有权假设**

由于操作复杂，将不同用户的输入合并到同一笔交易中通常并不常见。因此，**同一笔交易中的两个输入地址通常被认为属于同一所有者**。

## **UTXO 找零地址检测**

UTXO（即 **未花费交易输出**）必须在一笔交易中全部花费。如果只将其中一部分发送到另一个地址，剩余部分就会进入一个新的找零地址。观察者可以推断这个新地址属于发送方，从而损害其隐私。

### 示例

为缓解这一问题，可以使用混币服务或多个地址来隐藏所有权。

## **社交网络与论坛信息暴露**

用户有时会在网上分享自己的 Bitcoin 地址，因此**很容易将地址与其所有者关联起来**。

## **交易图分析**

可以将交易可视化为图，从资金流向中揭示用户之间可能存在的关联。

## **非必要输入启发式（最优找零启发式）**

这种启发式方法通过分析具有多个输入和输出的交易，猜测哪个输出是返回给发送方的找零。

### 示例

```bash
2 btc --> 4 btc
3 btc     1 btc
```

如果添加更多输入后，找零输出大于任何单个输入，就可能使启发式分析产生混淆。

## **强制地址重用**

攻击者可能会向以前用过的地址发送少量资金，希望收款人在未来的交易中将这些资金与其他输入合并，从而将地址关联起来。

### 正确的钱包行为

钱包应避免使用已收款且余额已空的地址，以防止这种 privacy leak。

## **其他区块链分析技术**

- **精确付款金额：**没有找零的交易很可能发生在同一用户拥有的两个地址之间。
- **整数金额：**交易中的整数金额可能表明这是一笔付款，而非整数金额的输出则可能是找零。
- **钱包指纹识别：**不同钱包有各自独特的交易创建模式，分析人员可以据此识别所用软件，并可能找出找零地址。
- **金额与时间关联：**披露交易时间或金额可能使交易变得可追踪。

## **流量分析**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联起来，损害用户隐私。如果某个实体运营许多 Bitcoin 节点，这种风险尤其突出，因为它能更有效地监控交易。

## 更多信息

如需查看隐私攻击与防御措施的完整列表，请访问 [Bitcoin Wiki 上的 Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy)。

# 匿名 Bitcoin 交易

## 匿名获取 Bitcoin 的方式

- **现金交易**：通过现金获取 bitcoin。
- **现金替代方式**：购买礼品卡，再在线兑换 bitcoin。
- **挖矿**：赚取 bitcoins 最隐私的方式是挖矿，尤其是独立挖矿，因为矿池可能会知道矿工的 IP 地址。[矿池信息](https://en.bitcoin.it/wiki/Pooled_mining)
- **盗窃**：理论上，盗取 bitcoin 也可能是匿名获取 bitcoin 的另一种方式，但这是违法行为，不建议这样做。

## 混币服务

用户可以通过混币服务**发送 bitcoins**，并收到**不同的 bitcoins 作为回报**，从而增加追踪原始所有者的难度。不过，这需要信任该服务不会保留日志，并且确实会返还 bitcoins。其他混币方式还包括 Bitcoin 博彩网站。

## CoinJoin

**CoinJoin** 将不同用户的多笔交易合并为一笔，使试图匹配输入与输出的过程更加复杂。尽管这种方式有效，但输入和输出金额大小独特的交易仍可能被追踪。

以下交易示例可能使用了 CoinJoin：`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

如需了解更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。如需了解一种将存款与之后的取款分离的 Ethereum 智能合约混币器，请参阅 [Tornado Cash](https://tornado.cash)。

## PayJoin

**PayJoin**（或 P2EP）是 CoinJoin 的一种变体，它会将双方（例如客户和商家）之间的交易伪装成普通交易，不具备 CoinJoin 标志性的等额输出。这使其极难被检测到，并可能使交易监控实体使用的共同输入所有权启发式分析失效。

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

像上面的交易可能是 PayJoin，在提升隐私性的同时，仍与标准 Bitcoin 交易无法区分。

**使用 PayJoin 可能会显著扰乱传统的监控方法**，因此它是实现交易隐私的一项很有前景的发展。

# 加密货币隐私最佳实践

## **钱包同步技术**

为维护隐私和安全，与区块链同步钱包至关重要。以下两种方法尤为突出：

- **Full node**：通过下载整个区块链，full node 可确保最大程度的隐私。所有历史交易都存储在本地，攻击者无法识别用户感兴趣的交易或地址。
- **客户端区块过滤**：此方法会为区块链中的每个区块创建过滤器，让钱包能够识别相关交易，而不会向网络观察者暴露具体的查询目标。轻量级钱包会下载这些过滤器，仅在发现与用户地址匹配的内容时才获取完整区块。

## **使用 Tor 实现匿名性**

鉴于 Bitcoin 运行在点对点网络上，建议使用 Tor 隐藏 IP 地址，从而在与网络交互时增强隐私性。

## **防止地址重复使用**

为保护隐私，每笔交易都应使用新地址。重复使用地址可能会将多笔交易关联到同一实体，从而损害隐私。现代钱包在设计上会避免地址重复使用。

## **交易隐私策略**

- **多笔交易**：将一笔付款拆分为多笔交易，可以掩盖交易金额，阻止针对隐私的攻击。
- **避免找零**：选择无需找零输出的交易，可以通过干扰找零检测方法来增强隐私。
- **多个找零输出**：如果无法避免找零，生成多个找零输出仍可改善隐私。

# **Monero：匿名性的灯塔**

Monero 的设计优先考虑交易隐私。

# **Ethereum：Gas 与交易**

## **了解 Gas**

Gas 用于衡量在 Ethereum 上执行操作所需的计算量，并以 **gwei** 计价。例如，一笔耗费 2,310,000 gwei（即 0.00231 ETH）的交易包含 gas limit 和 base fee，还会设置 priority fee 以激励验证者将其纳入区块。用户可以设置 max fee，确保不会支付过高费用，超出的部分会退还。<sup>[[5]](#references)</sup>

## **执行交易**

Ethereum 交易涉及发送方和接收方，二者可以是用户地址，也可以是智能合约地址。交易需要支付费用，并且必须被纳入区块。交易中的必要信息包括接收方、发送方签名、金额、可选数据、gas limit 和费用。值得注意的是，发送方地址可从签名中推导出来，因此无需将其包含在交易数据中。<sup>[[4]](#references)</sup>

对于希望在优先考虑隐私和安全的同时参与加密货币活动的人来说，这些实践和机制是基础。

## Web3 价值导向 Red Teaming

- 梳理持有价值的组件（签名者、预言机、桥、自动化系统），了解谁能够转移资金以及如何转移。
- 将每个组件映射到相关的 MITRE AADAPT tactics，以揭示权限提升路径。
- 演练 flash-loan/oracle/credential/cross-chain 攻击链，以验证影响并记录可被利用的前置条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 签名工作流失陷

- 对钱包 UI 进行供应链篡改，可在签名前篡改 EIP-712 payload，从而窃取有效签名，用于基于 delegatecall 的代理接管（例如覆盖 slot-0 中的 Safe masterCopy）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## 账户抽象（ERC-4337）

- 常见的智能账户故障模式包括绕过 `EntryPoint` 访问控制、gas 字段未签名、验证过程具有状态性、ERC-1271 重放，以及验证后回滚导致的费用耗尽。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## 智能合约安全

- 使用 mutation testing 查找测试套件中的盲点：

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK 证明 / zkVM Guest 完整性

当 prover 使用 **zkVM** 或特定于应用的证明电路来证明某项声明时，verifier 只能确认 **guest program 按照所编写的方式执行了**。如果 guest 中包含 **不安全的反序列化**、**未定义行为**或**缺失的语义约束**，恶意 prover 可能生成可通过验证的证明，但 **公开指标或所声明的不变量却是错误的**。<sup>[[7]](#references)</sup>

### Proof guest 中的不安全反序列化

- 即使私有 witness/circuit 字节被证明隐藏，也应将其视为**不可信的攻击者输入**。
- 除非这些字节已通过带外方式验证，否则应避免使用 `rkyv::access_unchecked` 等未经检查的辅助函数对其进行反序列化。
- 从不可信的序列化数据中加载的枚举判别值、相对指针、长度和索引，必须经过验证后才能影响控制流或内存访问。

实用审计模式：

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

如果像 `op.kind` 这样的字段是 enum，且攻击者可以注入**超出范围的判别值**，那么所有下游对该值执行的 `match` 都值得怀疑。

### Jump-table / UB 绕过计数检查

如果 Rust 将较大的 `match` 编译为**跳转表**，无效的 enum 判别值可能导致**未定义的控制流**。一种危险模式是：<sup>[[7]](#references)[[9]](#references)</sup>

1. 一个 `match` 更新**安全关键计数器/约束**。
2. 第二个 `match` 执行**实际指令语义**。
3. 超出范围的判别值越过第一个跳转表的边界，跳转到与第二个跳转表关联的代码。

结果：操作仍会执行，但计数路径被跳过。在 zkVM 中，这可能伪造证明，报告不可能的指标，例如更少的门、更少的高开销操作，或其他被篡改的有界资源。

审查清单：

- 查找从 witness/private input 反序列化、且由攻击者控制的 enum。
- 检查是否对同一个 opcode/kind 字段执行了重复的 `match`。
- 将 `unsafe` + 未经检查的反序列化 + 大型 opcode 分发视为高风险组合。
- 必要时对生成的二进制进行逆向工程；跳转表布局可能比源代码更重要。

### 可逆/专用解释器中缺失的语义约束

不要只验证内存安全；还要验证证明旨在强制执行的**语义规则**。

对于可逆/类量子指令集，请确保必须互不相同的操作数确实受到约束，保证它们互不相同。一个类似 Toffoli/CCX 的操作实现为：<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

如果 guest 不拒绝以下内容，就会变得不安全：

```text
op.q_control1 == op.q_control2 == op.q_target
```

在这种情况下，转换会简化为：

```text
q = q ^ (q & q) = 0
```

这会创建一个**确定性重置原语**，打破可逆性假设，并使非预期计算的成本更低。在用于证明资源使用情况的证明系统中，攻击者可以借此通过功能检查，同时绕过验证者认为正在执行的成本模型。

### 约束不足的 prover advice 与模运算

从 **advice/witness stack** 加载的值由 prover 控制，即使它们被描述为预先计算的商、余数、逆元或提示也是如此。证明只能证明 witness 满足已实现的约束；如果这些约束缺少类型、范围或规范形式检查，就不能证明预期的计算确实发生了。<sup>[[13]](#references)</sup>

对于 reduction 或欧几里得除法辅助函数，应审计完整的整数关系，而不只是最终的减法或乘法。`q` 和 `r` 的每个 limb 都必须受其声明位宽的约束，重构关系 `x = q * m + r` 必须在预期的整数表示中成立，并且必须强制执行规范界限 `0 <= r < m`。在将值传递给较窄的 `u32`/`u64` 指令**之前**验证该值；窄位宽运算无法追溯证明原始域元素或多 limb 值具有预期类型。<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

`mod_12289` 在 Miden 中的故障体现了这种 exploit 模式：商被检查为一个双 limb 的 64 位值，但由 advice 提供的余数在进入 `u32overflowing_sub` 前没有经过同等验证。恶意 prover 可以协调无效的商和余数，使已实现的减法约束仍然成立，同时让过程返回一个不符合数学定义的余数。由于该结果会用于 Falcon 验证，这一 soundness 故障可能进一步升级为伪造授权签名，而不只是产生错误的算术结果。<sup>[[13]](#references)</sup>

### 审计隐式栈密码学 VM

栈语言会隐藏操作数，因此首先要将指令提升到 IR 中，其中每个被消费和产生的栈值都是带有来源信息的表达式。随后可以使用保守的分析流水线：<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. 构建调用图，并推断过程的输入/输出栈效果。
2. 对受支持的指令进行符号执行，并将控制流提升为 SSA/结构化表达式。
3. 传播 `Unknown`、`ProvenU32`、`Bool`、值来源和局部初始化等抽象事实，直到达到不动点。
4. 标记流向类型化算术或非零 sink、且在**每条**入边路径上都未经过 sanitizer 的 advice 派生值。
5. 比较声明的签名与推断的签名，并验证每个出口是否保留了调用方拥有的栈值。

将未知签名或不受支持的结构视为**分析缺口**，而不是安全结果。动态调用、非栈中性的循环，以及栈效果不同的分支，都可能导致无法可靠地跟踪栈槽；更安全的反编译器会拒绝或标记这些情况，而不是输出看似合理但实际错误的伪代码。<sup>[[10]](#references)[[13]](#references)</sup>

在控制流汇合点，只有当前驱路径上都成立时才保留某个属性（例如，`ProvenU32 join Unknown = Unknown`）。还要区分达到不动点与触及迭代次数上限：只有收敛且可靠的过近似，才能支持这样的判断：没有诊断结果，说明所有已表示的执行都满足该属性。<sup>[[11]](#references)</sup>

### 使用证明义务揭示隐藏的前置条件

对于较小的指令集，将过程转换为可执行的形式化 VM 模型，并证明结果和完整的栈变换。定理应涵盖终止性、类型化输入、预期输出前缀，以及未修改调用方栈的保留。应像检查证明本身一样仔细审查定理陈述：内核可以验证针对意外弱化后主张的证明。<sup>[[12]](#references)[[13]](#references)</sup>

意外出现的假设是有价值的发现。在 Miden 审查中，64 位右旋转的一个证明要求 `shift mod 32 != 0`，这揭示了一个边界情况：当大输入的移位量是 32 的倍数时会失败；另一个证明则发现 256 位的 `wrapping_mul` 丢弃了调用方拥有的栈值。将发现的边界情况加入测试，然后修复实现，或有意收紧公开前置条件，而不是悄悄接受额外假设。<sup>[[12]](#references)[[13]](#references)</sup>

### ZK 系统中的测试要点

- 使用格式错误的 witness/私有输入编码，对所有 guest parser 进行 fuzz。
- 在 opcode 分派前断言 enum 范围验证已完成。
- 针对操作数别名及其他无效指令形式添加语义检查。
- 跟踪每个 advice/witness 来源到各个类型化算术 sink 的路径，并要求每条路径都经过验证。<sup>[[11]](#references)[[13]](#references)</sup>
- 使用非规范 limb、超出范围的余数和边界移位计数测试算术辅助函数。<sup>[[12]](#references)[[13]](#references)</sup>
- 在每次返回时，断言栈高度正确，并且过程声明参数以下的值都得到保留。<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- 将报告的/公开的计数器与独立的参考实现进行比较。
- 请记住，如果 guest program 有 bug，有效的 proof 仍可能证明了**错误的陈述**。

## 状态依赖型授权

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

如果你正在研究 DEX 和 AMM 的实际 exploitation（Uniswap v4 hooks、舍入/精度滥用、由 flash loan 放大的跨阈值 swap），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于会缓存虚拟余额、且可能在 `supply == 0` 时遭到投毒的多资产加权池，请研究：

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
- [8] [保护椭圆曲线加密货币免受量子漏洞影响：资源估算与缓解措施（修订版）](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept 仓库](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM 反编译器架构](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM 静态分析引擎](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean 模型与正确性证明](https://github.com/trailofbits/masm-lean)
- [13] [（足够好）AI 时代的审计](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
