# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **智能合约** 被定义为在区块链上在满足特定条件时执行的程序，自动化执行协议而无需中介。
- **去中心化应用 (dApps)** 基于智能合约构建，具有用户友好的前端和透明、可审计的后端。
- **代币 & 币** 的区别在于，coins 用作数字货币，而 tokens 则代表特定场景下的价值或所有权。
- **实用型代币 (Utility Tokens)** 授予对服务的访问权限，**证券型代币 (Security Tokens)** 表示资产所有权。
- **DeFi** 指去中心化金融，提供无需中央权威的金融服务。
- **DEX** 和 **DAOs** 分别指去中心化交易平台和去中心化自治组织。

## 共识机制

共识机制确保区块链上交易验证的安全性和一致性：

- **Proof of Work (PoW)** 依赖计算能力来验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的代币，与 PoW 相比减少了能耗。

## 比特币要点

### 交易

比特币交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥的所有者才能发起转账。

#### 关键组成部分：

- **多重签名交易** 需要多个签名来授权交易。
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给矿工）和 **scripts**（交易规则）组成。

### Lightning Network

旨在通过在通道内允许多笔交易、只将最终状态广播到区块链，从而提升比特币的扩展性。

## 比特币隐私问题

隐私攻击，如 **Common Input Ownership** 和 **UTXO Change Address Detection**，利用交易模式。像 **Mixers** 和 **CoinJoin** 这样的策略通过模糊用户之间的交易关联来提高匿名性。

## 匿名获取比特币

方法包括现金交易、挖矿和使用 mixers。**CoinJoin** 将多笔交易混合以增加可追踪性的难度，而 **PayJoin** 将 CoinJoins 伪装成常规交易以提高隐私性。

# Bitcoin Privacy Atacks

# 比特币隐私攻击摘要

在比特币世界中，交易隐私和用户匿名性常常是关注焦点。下面是几种攻击者可能破坏比特币隐私的常见方法的简要概述。

## **Common Input Ownership Assumption**

由于操作复杂，来自不同用户的 inputs 很少被合并到同一笔交易中。因此，**同一笔交易中的两个输入地址通常被假定属于同一所有者**。

## **UTXO Change Address Detection**

UTXO，即 **Unspent Transaction Output**，在交易中必须被全部消费。如果仅将其中一部分发送到另一个地址，剩余部分会发送到一个新的 change address。观察者可以假定这个新地址属于发送者，从而破坏隐私。

### 示例

为缓解此问题，使用混币服务或使用多个地址可以帮助模糊所有权。

## **社交网络与论坛暴露**

用户有时会在网上分享他们的比特币地址，使得**很容易将地址与其所有者关联起来**。

## **交易图分析**

交易可以可视化为图，从资金流动中揭示用户之间的潜在关联。

## **不必要输入启发式（最佳找零启发式）**

该启发式基于分析具有多个输入和输出的交易，以猜测哪个输出是返回给发送者的找零地址。

### 示例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果添加更多的输入导致找零输出大于任何单个输入，它可能会混淆启发式方法。

## **强制地址重用**

攻击者可能向之前使用过的地址发送少量资金，希望收款方在未来的交易中将这些与其他输入合并，从而将地址关联在一起。

### 钱包的正确行为

钱包应避免使用在已被使用且为空的地址上收到的币，以防止此隐私 leak。

## **其他区块链分析技术**

- **Exact Payment Amounts:** 没有找零的交易很可能发生在同一用户拥有的两个地址之间。
- **Round Numbers:** 交易中的整数金额通常表明这是一次付款，非整数输出很可能是找零。
- **Wallet Fingerprinting:** 不同钱包在创建交易时有独特的模式，分析人员可以据此识别所用软件并可能找到找零地址。
- **Amount & Timing Correlations:** 公开交易时间或金额会使交易更容易被追踪。

## **流量分析**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联，从而破坏用户隐私。如果某个实体运行大量 Bitcoin 节点，则其监控交易的能力会增强，这一点尤其明显。

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# 匿名 Bitcoin 交易

## 获得 Bitcoins 匿名方式

- **现金交易**：通过现金获取 bitcoin。
- **现金替代品**：购买礼品卡并在线兑换为 bitcoin。
- **Mining**：最私密的赚取 bitcoins 的方式是挖矿，尤其是单独挖矿，因为矿池可能知道矿工的 IP 地址。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**：理论上，偷窃 bitcoin 也可能是另一种匿名获取方式，但这是非法且不建议的。

## 混币服务

通过使用混币服务，用户可以**发送 bitcoins**并收到**不同的 bitcoins 作为回报**，这使得追踪原始所有者变得困难。不过，这需要信任该服务不会保留日志并且会实际返还比特币。替代的混币选项包括 Bitcoin 赌场。

## CoinJoin

**CoinJoin** 将来自不同用户的多个交易合并为一个交易，增加了将输入与输出匹配的难度。尽管它有效，但具有独特输入和输出大小的交易仍然可能被追踪。

可能使用了 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

作为 CoinJoin 的一种变体，**PayJoin**（或 P2EP）将两方（例如客户和商家）之间的交易伪装为普通交易，不具有 CoinJoin 那种相等输出的明显特征。这使其极难被检测，并可能使交易监视实体使用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# 隐私相关的加密货币最佳实践

## **钱包与区块链同步技术**

为了维护隐私和安全，将钱包与区块链同步至关重要。两种方法尤其值得注意：

- **Full node**：通过下载整个区块链，full node 可确保最大程度的隐私。所有历史交易都存储在本地，使对手无法确定用户关心的是哪些交易或地址。
- **Client-side block filtering**：该方法为区块链中的每个区块创建过滤器，使钱包能够在不向网络观察者暴露具体兴趣点的情况下识别相关交易。轻量级钱包下载这些过滤器，只有在与用户地址匹配时才会获取完整区块。

## **使用 Tor 以增强匿名性**

鉴于 Bitcoin 在点对点网络上运行，建议使用 Tor 来掩盖你的 IP 地址，从而在与网络交互时增强隐私。

## **防止地址复用**

为保护隐私，每笔交易使用一个新地址非常重要。地址复用会通过将交易链接到同一实体而削弱隐私。现代钱包通过设计来劝阻地址复用。

## **交易隐私策略**

- **Multiple transactions**：将付款拆分为多笔交易可以混淆交易金额，从而挫败隐私攻击。
- **Change avoidance**：选择不需要找零输出的交易可以增强隐私，破坏找零检测方法。
- **Multiple change outputs**：如果无法避免找零，生成多个找零输出仍然可以改善隐私。

# **Monero: A Beacon of Anonymity**

Monero 解决了数字交易中绝对匿名的需求，为隐私设定了高标准。

# **Ethereum: Gas and Transactions**

## **理解 Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算工作量，以 **gwei** 定价。例如，花费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas limit 和 base fee，并包含奖励矿工的 tip。用户可以设置一个 max fee 以确保不会过度支付，多余部分会被退还。

## **执行交易**

Ethereum 中的交易涉及发送方和接收方，它们可以是用户地址或 smart contract 地址。交易需要支付费用并必须被挖矿。交易中的重要信息包括接收方、发送方的签名、value、可选数据、gas limit 和费用。值得注意的是，发送方的地址可由签名推导出来，因此不需要在交易数据中包含发送方地址。

这些实践和机制是任何希望在优先考虑隐私和安全的前提下参与加密货币的人都应掌握的基础。

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
