# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **智能合约 (Smart Contracts)** 被定义为在区块链上在满足特定条件时执行的程序，自动化协议执行而无需中介。
- **去中心化应用 (dApps)** 基于智能合约构建，具有用户友好的前端和透明、可审计的后端。
- **代币 & 币 (Tokens & Coins)** 区分了币作为数字货币，而代币在特定语境中代表价值或所有权。
- **实用型代币 (Utility Tokens)** 授予对服务的访问权限，**证券型代币 (Security Tokens)** 则表示资产所有权。
- **DeFi** 代表去中心化金融，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指去中心化交易平台和去中心化自治组织。

## 共识机制

共识机制确保区块链上交易验证的安全性和一致性：

- **工作量证明 (Proof of Work, PoW)** 依赖计算能力来验证交易。
- **权益证明 (Proof of Stake, PoS)** 要求验证者持有一定数量的代币，相较于 PoW 降低能耗。

## 比特币要点

### 交易

比特币交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥持有者可以发起转账。

#### 关键组成部分：

- **多重签名交易 (Multisignature Transactions)** 需要多个签名来授权一笔交易。
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给矿工的费用）和 **scripts**（交易规则）组成。

### Lightning Network（闪电网络）

旨在通过允许在通道内进行多次交易并仅将最终状态广播到区块链上来提升比特币的可扩展性。

## 比特币隐私问题

隐私攻击，如 **Common Input Ownership** 和 **UTXO Change Address Detection**，利用交易模式进行分析。使用 **Mixers** 和 **CoinJoin** 等策略可以通过模糊用户之间的交易关联来提高匿名性。

## 匿名获取比特币的方法

方法包括现金交易、挖矿和使用 mixers。**CoinJoin** 将多笔交易混合以增加可追踪性的难度，而 **PayJoin** 则将 CoinJoin 伪装成普通交易以进一步提高隐私。

# 比特币隐私攻击

# 比特币隐私攻击摘要

在比特币世界中，交易的隐私和用户的匿名性常常成为关注点。下面是一些攻击者可能用来破坏比特币隐私的常见方法的简要概述。

## **常见输入所有权假设 (Common Input Ownership Assumption)**

由于将来自不同用户的 inputs 合并到单笔交易中通常较为少见且复杂，因此通常假定**同一笔交易中的两个输入地址属于同一所有者**。

## **UTXO 找零地址检测 (UTXO Change Address Detection)**

UTXO（未花费交易输出，UTXO）必须在一笔交易中被完全花费。如果只将其中一部分发送到另一个地址，剩余部分会转入一个新的找零地址。观察者可以假定该新地址属于发送者，从而暴露隐私。

### 示例

为缓解这一点，可以使用混合服务或使用多个地址来模糊所有权。

## **社交网络与论坛泄露**

用户有时会在网上分享他们的比特币地址，这使得**将地址与其所有者关联变得容易**。

## **交易图分析**

交易可以被可视化为图，揭示基于资金流动的潜在用户间联系。

## **不必要输入启发式（最优找零启发式） (Unnecessary Input Heuristic / Optimal Change Heuristic)**

该启发式基于分析具有多个 inputs 和 outputs 的交易来猜测哪个 output 是返回给发送者的找零。

### 示例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果增加更多的输入使找零输出大于任何单个输入，可能会让启发式规则混淆。

## **Forced Address Reuse**

攻击者可能向先前使用过的地址发送少量资金，希望收款人在未来交易中将这些与其他输入合并，从而将地址关联起来。

### Correct Wallet Behavior

钱包应避免使用发送到已使用且为空的地址上的币，以防止这种隐私 leak。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 没有找零的交易很可能是在同一用户拥有的两个地址之间进行的。
- **Round Numbers:** 交易中的整数金额通常表明这是一次支付，而非整数的输出很可能是找零。
- **Wallet Fingerprinting:** 不同钱包有各自独特的交易创建模式，分析人员可以据此识别所用软件并可能找到找零地址。
- **Amount & Timing Correlations:** 披露交易时间或金额会使交易可被追踪。

## **Traffic Analysis**

通过监视网络流量，攻击者可能将交易或区块关联到 IP 地址，从而危及用户隐私。如果某实体运行大量 Bitcoin 节点，这种监视能力会增强，尤其如此。

## 更多

如需隐私攻击与防护的完整列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# 匿名 Bitcoin 交易

## 以匿名方式获取 Bitcoin 的方法

- **Cash Transactions**: 通过现金获取 Bitcoin。
- **Cash Alternatives**: 购买礼品卡并在线兑换为 Bitcoin。
- **Mining**: 通过挖矿是获得 Bitcoin 最私密的方法，尤其是独自挖矿，因为矿池可能会知道矿工的 IP 地址。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理论上，窃取 Bitcoin 也可能是另一种匿名获取方式，但这是非法且不建议的。

## Mixing Services

使用混合服务时，用户可以 **send bitcoins** 并收到 **different bitcoins in return**，这使得追踪原持有者变得困难。但这需要信任该服务不会保留日志并且会实际归还比特币。替代的混合选项包括 Bitcoin 赌场。

## CoinJoin

**CoinJoin** 将来自不同用户的多个交易合并为一个，使试图匹配输入与输出的行为变得复杂。尽管有效，但输入和输出大小独特的交易仍可能被追踪。

可能使用 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

更多信息请参见 [CoinJoin](https://coinjoin.io/en)。对于 Ethereum 上的类似服务，请查看 [Tornado Cash](https://tornado.cash)，它用矿工的资金来匿名化交易。

## PayJoin

作为 CoinJoin 的变体，**PayJoin**（或 P2EP）将两方（例如顾客和商家）之间的交易伪装成普通交易，而没有 CoinJoin 那种相同输出的典型特征。这使其极难被检测，并可能使交易监控实体使用的 common-input-ownership 启发式失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**采用 PayJoin 可能会显著扰乱传统的监控方法**，使其成为实现交易隐私的有前景的发展。

# 加密货币隐私最佳实践

## **钱包同步技术**

为了保持隐私和安全，将钱包与区块链同步至关重要。有两种突出的方法：

- **Full node**: 通过下载整个区块链，Full node 可确保最大的隐私。所有历史交易都保存在本地，使对手无法识别用户感兴趣的是哪些交易或地址。
- **Client-side block filtering**: 该方法为区块链中的每个区块创建过滤器，使钱包能够识别相关交易而不会向网络观察者暴露具体兴趣。轻量钱包下载这些过滤器，只有在与用户地址匹配时才获取完整区块。

## **使用 Tor 实现匿名**

鉴于 Bitcoin 在点对点网络上运行，建议使用 Tor 来掩盖你的 IP 地址，从而在与网络交互时增强隐私。

## **防止地址重用**

为了保护隐私，每笔交易使用一个新地址至关重要。地址重用会通过将交易关联到同一实体而破坏隐私。现代钱包通过设计鼓励避免地址重用。

## **交易隐私策略**

- **多个交易**: 将一笔支付拆分为多笔交易可以混淆交易金额，从而挫败隐私攻击。
- **避免找零**: 选择不需要找零输出的交易，通过破坏找零检测方法来增强隐私。
- **多个找零输出**: 如果无法避免找零，生成多个找零输出仍能改善隐私。

# **Monero: A Beacon of Anonymity**

Monero 解决了数字交易中对绝对匿名的需求，为隐私设立了高标准。

# **Ethereum: Gas and Transactions**

## **理解 Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算工作量，价格以 **gwei** 计价。例如，耗费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas limit 和 base fee，以及为激励矿工支付的 tip。用户可以设置 max fee 以确保不会支付过多，超出部分会被退还。

## **执行交易**

在 Ethereum 中，交易包含发送者和接收者，它们可以是用户地址或 smart contract 地址。交易需要支付费用并必须被挖矿。交易中的关键信息包括接收者、发送者的签名、value、可选 data、gas limit 和 fees。值得注意的是，发送者地址可从签名推导出，因此不需要在交易数据中显式包含它。

这些实践和机制是任何在优先考虑隐私和安全的前提下参与加密货币活动的人都应掌握的基础。

## 以价值为中心的 Web3 Red Teaming

- 清点承载价值的组件（signers、oracles、bridges、automation），以了解谁可以移动资金以及如何移动。
- 将每个组件映射到相关的 MITRE AADAPT tactics，以揭示特权升级路径。
- 排练 flash-loan/oracle/credential/cross-chain 攻击链以验证影响并记录可被利用的先决条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## 智能合约安全

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## 参考资料

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

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
