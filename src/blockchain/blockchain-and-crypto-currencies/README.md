# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** 被定义为在区块链上当满足特定条件时执行的程序，自动化协议执行而无需中介。
- **Decentralized Applications (dApps)** 建立在 smart contracts 之上，拥有用户友好的前端和透明、可审计的后端。
- **Tokens & Coins** 区分了币作为数字货币的角色，而 token 则表示在特定语境下的价值或所有权。
- **Utility Tokens** 授予对服务的访问权限，**Security Tokens** 则表示资产所有权。
- **DeFi** 代表 Decentralized Finance，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指 Decentralized Exchange Platforms 和 Decentralized Autonomous Organizations。

## Consensus Mechanisms

共识机制确保区块链上安全且达成一致的交易验证：

- **Proof of Work (PoW)** 依赖计算能力来验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的 token，相较于 PoW 降低能耗。

## Bitcoin Essentials

### Transactions

Bitcoin 交易涉及在地址间转移资金。交易通过数字签名进行验证，确保只有私钥的所有者可以发起转账。

#### Key Components:

- **Multisignature Transactions** 需要多个签名来授权交易。
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给 miners 的费用）和 **scripts**（交易规则）组成。

### Lightning Network

旨在通过允许在通道内进行多次交易、仅将最终状态广播到区块链来提升 Bitcoin 的可扩展性。

## Bitcoin Privacy Concerns

隐私攻击，例如 **Common Input Ownership** 和 **UTXO Change Address Detection**，利用交易模式。像 **Mixers** 和 **CoinJoin** 这样的策略通过模糊用户之间的交易关联来提升匿名性。

## Acquiring Bitcoins Anonymously

方法包括现金交易、挖矿和使用 mixers。**CoinJoin** 将多笔交易混合以增加追踪难度，而 **PayJoin** 则将 CoinJoin 伪装成常规交易以提高隐私。

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

在 Bitcoin 的世界中，交易隐私和用户匿名性常常令人担忧。下面是几种常见攻击方法的简要概述，这些方法可以用来破坏 Bitcoin 的隐私。

## **Common Input Ownership Assumption**

由于操作复杂，来自不同用户的 inputs 很少会在同一交易中被合并。因此，**同一交易中的两个输入地址通常被假设属于同一所有者**。

## **UTXO Change Address Detection**

UTXO（Unspent Transaction Output，未花费交易输出）在交易中必须被全部消费。如果只将其中一部分发送到另一个地址，剩余部分会发送到一个新的找零地址。观察者可以假设该新地址属于发送者，从而破坏隐私。

### Example

为减轻这一点，使用 mixing 服务或使用多个地址可以帮助混淆所有权。

## **Social Networks & Forums Exposure**

用户有时会在网上分享他们的 Bitcoin 地址，从而使得**将地址与其所有者关联变得容易**。

## **Transaction Graph Analysis**

交易可以被可视化为图，从资金流动中揭示用户之间的潜在关联。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

该启发式基于分析具有多个 inputs 和 outputs 的交易来猜测哪个 output 是返回给发送者的找零。

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果增加更多 inputs 导致 change output 大于任何单个 input，会让该启发式规则产生混淆。

## **Forced Address Reuse**

攻击者可能会向先前使用过的地址发送少量资金，希望接收方在将来的交易中将这些资金与其他 inputs 合并，从而将地址关联在一起。

### Correct Wallet Behavior

钱包应避免在已使用且为空的地址上使用收到的币，以防止这种隐私 leak。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 没有找零的交易很可能是在同一用户控制的两个地址之间发生的。
- **Round Numbers:** 交易中的圆整数额通常表明这是一次支付，而非圆整的输出很可能是找零。
- **Wallet Fingerprinting:** 不同的钱包有独特的交易创建模式，分析者可以据此识别所用的软件，并可能确定找零地址。
- **Amount & Timing Correlations:** 披露交易时间或金额可能使交易可被追踪。

## Traffic Analysis

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联，从而危及用户隐私。若某实体运行大量 Bitcoin 节点，其监控交易的能力会增强，尤其如此。

## More

有关隐私攻击和防御的完整列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# 匿名 Bitcoin 交易

## 匿名获取 Bitcoins 的方式

- **Cash Transactions**: 通过现金获取 Bitcoin。
- **Cash Alternatives**: 购买礼品卡并在网上将其兑换为 Bitcoin。
- **Mining**: 最私密的获得 Bitcoin 的方法是通过挖矿，尤其是单独挖矿，因为矿池可能知道矿工的 IP 地址。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理论上，偷窃 Bitcoin 也可能是另一种匿名获取方式，但这是违法且不建议的。

## 混币服务

通过使用混币服务，用户可以 **send bitcoins** 并以 **different bitcoins in return** 收到回款，这使追踪原始所有者变得困难。然而，这需要信任该服务不会保留日志并且确实会返还比特币。替代的混币选项包括比特币赌场。

## CoinJoin

CoinJoin 将来自不同用户的多个交易合并为一个交易，增加了将 inputs 与 outputs 匹配的难度。尽管有效，但具有独特输入和输出大小的交易仍可能被追踪。

可能使用 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

有关更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。在 Ethereum 上的类似服务参见 [Tornado Cash](https://tornado.cash)，它使用来自矿工的资金来匿名化交易。

## PayJoin

作为 CoinJoin 的一个变体，**PayJoin** (或 P2EP) 将两个方（例如客户和商家）之间的交易伪装成普通交易，而不具有 CoinJoin 那种等额输出的明显特征。这使其极难被检测，并可能使交易监控实体常用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
像上面的交易可能是 PayJoin，它在保持与标准 bitcoin 交易无法区分的同时增强了隐私。

**使用 PayJoin 可能会显著扰乱传统监控方法**，使其成为追求交易隐私的有前景的发展。

# 加密货币隐私最佳实践

## **钱包同步技术**

为了维护隐私和安全，将钱包与区块链同步至关重要。两种方法尤其突出：

- **Full node**：通过下载整个区块链，full node 可确保最大的隐私。所有历史交易都本地存储，使对手无法识别用户关注的是哪些交易或地址。
- **Client-side block filtering**：该方法为区块链中的每个区块创建过滤器，允许钱包在不向网络观察者暴露具体关注点的情况下识别相关交易。轻量级钱包下载这些过滤器，仅在与用户地址匹配时才获取完整区块。

## **使用 Tor 实现匿名**

鉴于 Bitcoin 在点对点网络上运行，建议使用 Tor 来隐藏你的 IP 地址，从而在与网络交互时增强隐私。

## **防止地址重用**

为保护隐私，每笔交易使用新地址至关重要。重复使用地址会通过将交易关联到同一实体而损害隐私。现代钱包通过设计来避免地址重用。

## **交易隐私策略**

- **Multiple transactions**：将一笔支付拆分为多笔交易可以模糊交易金额，从而挫败隐私攻击。
- **Change avoidance**：选择不产生找零输出的交易可以通过破坏找零检测方法来增强隐私。
- **Multiple change outputs**：如果无法避免找零，生成多个找零输出仍可提高隐私。

# **Monero：匿名性的灯塔**

Monero 满足了数字交易中对绝对匿名的需求，为隐私设定了高标准。

# **Ethereum：Gas 与交易**

## **理解 Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算量，以 **gwei** 定价。例如，花费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas limit 和 base fee，并包含用于激励矿工的小费。用户可以设置 max fee 以确保不会过付，多余部分会被退还。

## **执行交易**

Ethereum 的交易涉及发送方和接收方，二者可以是用户地址或智能合约地址。交易需要支付费用并必须被矿工打包。交易中的关键信息包括接收方、发送方签名、数额、可选数据、gas limit 和费用。值得注意的是，发送方地址可从签名推导出来，因此无需在交易数据中显式包含。

这些实践和机制是任何希望在优先考虑隐私和安全的前提下参与加密货币的人士的基础。

## Value-Centric Web3 Red Teaming

- 对 value-bearing 组件（signers、oracles、bridges、automation）进行清单化，以了解谁可以移动资金以及如何移动。
- 将每个组件映射到相关的 MITRE AADAPT 策略，以揭示权限提升路径。
- 演练 flash-loan/oracle/credential/cross-chain 攻击链以验证影响并记录可被利用的先决条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- 对钱包 UI 的 supply-chain 篡改可以在签名前修改 EIP-712 payload，从而收集有效签名以用于基于 delegatecall 的代理接管（例如覆盖 Safe masterCopy 的 slot-0）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- 使用 mutation testing 在测试套件中发现盲点：

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

## DeFi/AMM 利用

如果你正在研究对 DEXes 和 AMMs 的实际利用（Uniswap v4 hooks、rounding/precision abuse、flash‑loan amplified threshold‑crossing swaps），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于缓存虚拟余额且在 `supply == 0` 时可能被污染的多资产加权池，请研究：

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
