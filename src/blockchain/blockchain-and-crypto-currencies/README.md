# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** 指在满足特定条件时在区块链上执行的程序，能够在无需中介的情况下自动履行协议。
- **Decentralized Applications (dApps)** 基于智能合约构建，具有用户友好的前端和透明、可审计的后端。
- **Tokens & Coins** 区分代币与币：coins 用作数字货币，而 tokens 在特定语境中表示价值或所有权。
- **Utility Tokens** 授予对服务的访问权，**Security Tokens** 则表示资产所有权。
- **DeFi** 代表 Decentralized Finance，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指去中心化交易平台和去中心化自治组织。

## 共识机制

共识机制确保区块链上交易验证的安全性和一致性：

- **Proof of Work (PoW)** 依赖计算能力来验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的代币，与 PoW 相比降低了能耗。

## 比特币基础

### 交易

比特币交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥的拥有者可以发起转账。

#### 关键组成部分：

- **Multisignature Transactions** 需要多个签名来授权交易。
- 交易由 **inputs**（资金来源）、**outputs**（目标地址）、**fees**（支付给矿工的费用）和 **scripts**（交易规则）组成。

### Lightning Network

旨在通过允许在通道内进行多次交易，仅将最终状态广播到区块链，从而提升比特币的可扩展性。

## 比特币隐私问题

隐私攻击如 **Common Input Ownership** 和 **UTXO Change Address Detection** 利用交易模式进行分析。使用 **Mixers** 和 **CoinJoin** 等策略可以通过混淆用户之间的交易关联来提升匿名性。

## 匿名获取比特币

方法包括现金交易、挖矿和使用混合服务。**CoinJoin** 将多笔交易混合以增加可追踪性的难度，而 **PayJoin** 则将 CoinJoin 伪装成普通交易以获得更高隐私性。

# Bitcoin Privacy Atacks

# 比特币隐私攻击概述

在比特币世界中，交易隐私和用户匿名性常常受到关注。下面是几种常见的攻击方法的简要概述，说明攻击者如何破坏比特币隐私。

## **Common Input Ownership Assumption**

由于将来自不同用户的 inputs 合并到单笔交易中通常较少见且复杂，因此 **同一交易中的两个输入地址通常被假定属于同一所有者**。

## **UTXO Change Address Detection**

UTXO，即 **Unspent Transaction Output（未花费交易输出）**，在交易中必须全部被消费。如果只把它的一部分发送到另一个地址，剩余部分会发送到新的 change 地址。观察者可以假定这个新地址属于发送方，从而导致隐私泄露。

### 示例

为减轻此问题，可以使用混合服务或使用多个地址来帮助模糊所有权。

## **社交网络与论坛暴露**

用户有时会在网上分享他们的比特币地址，使得**很容易将地址与其所有者关联**。

## **交易图分析**

交易可以被可视化为图，从资金流向中揭示用户之间的潜在关联。

## **不必要输入启发式（Optimal Change Heuristic）**

该启发式基于分析含有多个 inputs 和 outputs 的交易来猜测哪个 output 是返回给发送者的找零地址。

### 示例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果添加更多的输入使得找零输出比任何单个输入都大，会让该启发式算法产生混淆。

## **强制地址重用**

攻击者可能会向以前使用过的地址发送少量比特币，希望收款人在未来的交易中将这些与其他输入合并，从而将地址关联起来。

### 正确的钱包行为

钱包应避免使用在已使用且为空的地址上接收到的币，以防止这种隐私 leak。

## **其他区块链分析技术**

- **Exact Payment Amounts:** 没有找零的交易很可能是两个属于同一用户的地址之间的交易。
- **Round Numbers:** 交易中的整数金额表明这是一次付款，非整数的输出很可能是找零。
- **Wallet Fingerprinting:** 不同钱包有独特的交易创建模式，分析人员可以据此识别所使用的软件并可能找出找零地址。
- **Amount & Timing Correlations:** 披露交易时间或金额可以使交易可被追踪。

## **Traffic Analysis**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联，进而破坏用户隐私。如果某个实体运行大量 Bitcoin 节点，他们监视交易的能力会增强。

## More

要查看全面的隐私攻击和防御列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# 匿名 Bitcoin 交易

## 以匿名方式获取比特币的方式

- **Cash Transactions**: 通过现金获取比特币。
- **Cash Alternatives**: 购买礼品卡并在线兑换为比特币。
- **Mining**: 获得比特币最私密的方式是通过挖矿，尤其是独自挖矿，因为矿池可能会知道矿工的 IP 地址。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理论上，偷窃比特币也可能是另一种匿名获取方式，但这是非法且不推荐的。

## 混币服务

通过使用混币服务，用户可以发送比特币并收到不同的比特币作为回报，从而使追踪原始所有者变得困难。然而，这需要信任该服务不会保留日志并且确实会返还比特币。替代的混币选项包括比特币赌场。

## CoinJoin

CoinJoin 将来自不同用户的多个交易合并为一个，这使得试图将输入与输出匹配的工作变得复杂。尽管它有效，但具有独特输入和输出大小的交易仍可能被追踪。

示例交易（可能使用了 CoinJoin）包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

欲了解更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。对于以太坊上的类似服务，请查看 [Tornado Cash](https://tornado.cash)，它使用来自矿工的资金来匿名化交易。

## PayJoin

作为 CoinJoin 的一种变体，PayJoin（或 P2EP）将两方（例如客户和商家）之间的交易伪装成普通交易，而不具有 CoinJoin 那种特征性的相等输出。这使得它极难被检测，可能使交易监控机构使用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
像上面这样的交易可能是 PayJoin，它在增强隐私的同时仍与标准 bitcoin 交易无法区分。

**使用 PayJoin 可能会显著破坏传统的监控方法**，因此在追求交易隐私方面它是一项很有前途的发展。

# 加密货币隐私最佳实践

## **钱包同步技术**

为了维护隐私和安全，将钱包与区块链同步至关重要。有两种突出的同步方法：

- **完整节点 (Full node)**：通过下载整个区块链，完整节点能确保最大的隐私。所有历史交易都保存在本地，这使得对手无法识别用户感兴趣的是哪些交易或地址。
- **客户端区块过滤 (Client-side block filtering)**：该方法为区块链中的每个区块创建过滤器，允许钱包识别相关交易而不会向网络观察者暴露特定兴趣。轻量级钱包下载这些过滤器，只有在与用户地址匹配时才获取完整区块。

## **使用 Tor 以实现匿名性**

鉴于 Bitcoin 在点对点网络上运行，建议使用 Tor 来掩盖你的 IP 地址，从而在与网络交互时增强隐私。

## **防止地址重用**

为了保护隐私，每笔交易使用新的地址至关重要。重用地址会通过将交易链接到同一实体而危及隐私。现代钱包通过设计来不鼓励地址重用。

## **交易隐私策略**

- **多笔交易 (Multiple transactions)**：将一笔支付拆分为多笔交易可以混淆交易金额，从而阻止隐私攻击。
- **避免找零 (Change avoidance)**：选择不需要找零输出的交易可以通过打乱找零检测方法来增强隐私。
- **多个找零输出 (Multiple change outputs)**：如果无法避免找零，生成多个找零输出仍然可以提高隐私。

# **Monero：匿名的灯塔**

Monero 解决了数字交易中对绝对匿名性的需求，为隐私设定了高标准。

# **Ethereum：Gas 与交易**

## **理解 Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算量，价格以 **gwei** 计。例如，耗费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas 限额和基础费，并可附加小费以激励矿工。用户可以设置最高费用以确保不会多付，超额部分会被退还。

## **执行交易**

在 Ethereum 中，交易涉及发送方和接收方，两者都可以是用户地址或 smart contract 地址。交易需要支付费用并且必须被挖矿。交易中的关键信息包括接收方、发送方的签名、金额、可选数据、gas 限额和费用。值得注意的是，发送方的地址是从签名中推导出来的，因此无需在交易数据中显式包含发送方地址。

这些做法和机制是任何在优先考虑隐私与安全的前提下参与加密货币的人必须掌握的基础。

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM 利用

如果你在研究对 DEXes 和 AMMs 的实际利用（Uniswap v4 hooks、rounding/precision abuse、flash‑loan amplified threshold‑crossing swaps），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
