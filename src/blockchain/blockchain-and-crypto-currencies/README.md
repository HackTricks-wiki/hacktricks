# 区块链与加密货币

{{#include ../../banners/hacktricks-training.md}}

## 基本概念

- **Smart Contracts** 被定义为在满足特定条件时在区块链上执行的程序，自动化协议的执行而无需中介。
- **Decentralized Applications (dApps)** 建立在 smart contracts 之上，具有用户友好的前端和透明、可审计的后端。
- **Tokens & Coins** 的区别在于 coins 用作数字货币，而 tokens 则表示特定语境下的价值或所有权。
- **Utility Tokens** 授予对服务的访问权限，**Security Tokens** 则表示资产所有权。
- **DeFi** 指 Decentralized Finance，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指 Decentralized Exchange Platforms 和 Decentralized Autonomous Organizations。

## 共识机制

共识机制确保区块链上交易验证的安全性和一致性：

- **Proof of Work (PoW)** 依赖计算能力来验证交易。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的 tokens，相比 PoW 降低能耗。

## 比特币要点

### Transactions

比特币交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥的所有者才能发起转账。

#### 关键组件：

- **Multisignature Transactions** 需要多个签名来授权交易。
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给矿工）和 **scripts**（交易规则）组成。

### Lightning Network

旨在通过允许在通道内进行多次交易并仅将最终状态广播到区块链来提高比特币的可扩展性。

## 比特币隐私问题

隐私攻击，例如 **Common Input Ownership** 和 **UTXO Change Address Detection**，利用交易模式。像 **Mixers** 和 **CoinJoin** 这样的策略通过混淆用户之间的交易链接来提高匿名性。

## 匿名获取比特币的方法

方法包括现金交易、挖矿和使用 mixers。**CoinJoin** 将多笔交易混合以增加可追踪性的难度，而 **PayJoin** 将 CoinJoins 伪装成普通交易以提高隐私。

# Bitcoin Privacy Atacks

# 比特币隐私攻击概述

在比特币的世界中，交易的隐私和用户的匿名性常常是关注点。以下是几种攻击者可能用来破坏比特币隐私的常见方法的简要概述。

## **Common Input Ownership Assumption**

由于将不同用户的 inputs 组合到单笔交易中通常很少见且复杂，因此 **同一交易中的两个输入地址通常被假定属于同一所有者**。

## **UTXO Change Address Detection**

UTXO（Unspent Transaction Output，未花费交易输出）在交易中必须全部被花费。如果只将其中一部分发送到另一个地址，剩余部分会发送到一个新的 change address。观察者可以假定该新地址属于发送者，从而暴露隐私。

### 示例

为缓解这一点，使用 mixing 服务或使用多个地址可以帮助混淆所有权。

## **社交网络与论坛暴露**

用户有时会在网上分享他们的比特币地址，这使得**将地址与其所有者关联变得容易**。

## **交易图分析**

交易可以可视化为图表，基于资金流动揭示用户之间的潜在联系。

## **不必要输入启发式（Optimal Change Heuristic）**

该启发式基于分析具有多个 inputs 和 outputs 的交易，以猜测哪个 output 是返回给发送者的 change。

### 示例
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果增加更多输入导致找零输出大于任何单个输入，这会使启发式判断混淆。

## **Forced Address Reuse**

攻击者可能向先前使用过的地址发送少量资金，希望接收者在未来交易中将这些与其他输入合并，从而将地址连接在一起。

### 正确的钱包行为

钱包应避免使用在已使用且为空的地址上收到的币，以防止这种隐私 leak。

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** 没有找零的交易很可能是两个属于同一用户的地址之间的支付。
- **Round Numbers:** 交易中的整数金额通常表明这是一次支付，非整数的输出很可能是找零。
- **Wallet Fingerprinting:** 不同钱包有独特的交易创建模式，使分析者可以识别所使用的软件并可能推断出找零地址。
- **Amount & Timing Correlations:** 披露交易时间或金额可能使交易可被追踪。

## **Traffic Analysis**

通过监控网络流量，攻击者可能将交易或区块与 IP 地址关联，从而危及用户隐私。如果某实体运行大量 Bitcoin 节点，情况尤为严重，因为这增强了其监视交易的能力。

## 更多

有关隐私攻击和防御的完整列表，请参见 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# 匿名 Bitcoin 交易

## 获取 Bitcoins 的匿名方式

- **Cash Transactions**: 通过现金获取 bitcoin。
- **Cash Alternatives**: 购买礼品卡并在线兑换为 bitcoin。
- **Mining**: 获得 bitcoins 最私密的方法是挖矿，尤其是单独挖矿，因为矿池可能知道矿工的 IP 地址。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: 理论上，窃取 bitcoin 也可能是另一种匿名获取方式，但这是非法且不推荐的。

## Mixing Services

通过使用混币服务，用户可以发送比特币并收到不同的比特币作为回报，这使得追踪原始所有者变得困难。然而，这需要信任该服务不会保留日志并且会实际返还比特币。替代的混合选项包括 Bitcoin 赌场。

## CoinJoin

**CoinJoin** 将不同用户的多笔交易合并为一笔，增加了试图匹配输入和输出者的难度。尽管它有效，但具有独特输入和输出规模的交易仍可能被追踪。

可能使用 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

欲了解更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。在 Ethereum 上类似的服务请查看 [Tornado Cash](https://tornado.cash)，它使用矿工的资金对交易进行匿名处理。

## PayJoin

作为 CoinJoin 的一种变体，**PayJoin**（或 P2EP）将两方（例如客户和商家）之间的交易伪装成普通交易，不具有 CoinJoin 那种特征性的等额输出。这使其极难被检测，并可能使交易监控实体使用的 common-input-ownership 启发式无效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# 隐私最佳实践（加密货币）

## **Wallet Synchronization Techniques**

为了维护隐私和安全，与区块链同步钱包至关重要。以下两种方法尤为重要：

- **Full node**：通过下载整个区块链，full node 可确保最大的隐私。所有历史交易都会本地存储，使对手无法识别用户感兴趣的是哪笔交易或哪个地址。
- **Client-side block filtering**：该方法为区块链中的每个区块创建过滤器，允许钱包在不向网络观察者暴露特定兴趣的情况下识别相关交易。轻量级钱包下载这些过滤器，只有在与用户地址匹配时才获取完整区块。

## **Utilizing Tor for Anonymity**

鉴于 Bitcoin 在点对点网络上运行，建议使用 Tor 来掩盖你的 IP 地址，从而在与网络交互时增强隐私。

## **Preventing Address Reuse**

为保护隐私，每笔交易使用新地址是至关重要的。地址重用会通过将交易关联到同一实体来损害隐私。现代钱包通过设计来阻止地址重用。

## **Strategies for Transaction Privacy**

- **Multiple transactions**：将付款拆分成多笔交易可以模糊交易金额，抵御隐私攻击。
- **Change avoidance**：选择不需要找零输出的交易可以通过破坏找零检测方法来增强隐私。
- **Multiple change outputs**：如果无法避免找零，生成多个找零输出仍能改善隐私。

# **Monero: A Beacon of Anonymity**

Monero 解决了数字交易中对绝对匿名的需求，为隐私设定了高标准。

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas 用于衡量在 Ethereum 上执行操作所需的计算工作量，计价单位为 **gwei**。例如，一笔花费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas limit 和 base fee，并包含用于激励矿工的 tip。用户可以设置 max fee 以确保不会过付，多余部分会被退还。

## **Executing Transactions**

Ethereum 的交易涉及发送方和接收方，接收方可以是用户地址或智能合约地址。交易需要支付费用并且必须被挖矿。交易中的关键信息包括接收方、发送方的签名、数额、可选的数据、gas limit 和费用。值得注意的是，发送方地址是可以从签名推导出来的，因此不需要在交易数据中显式包含发送方地址。

这些做法和机制是任何希望在优先考虑隐私和安全的前提下参与加密货币的人必须掌握的基础。

## Value-Centric Web3 Red Teaming

- 清点价值承载组件（signers、oracles、bridges、automation）以了解谁可以移动资金以及如何移动。
- 将每个组件映射到相关的 MITRE AADAPT tactics，以揭示权限提升路径。
- 演练 flash-loan/oracle/credential/cross-chain 攻击链以验证影响并记录可被利用的前置条件。

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- 对 wallet UIs 的供应链篡改可以在签名前改变 EIP-712 payloads，从而收集有效签名用于基于 delegatecall 的 proxy 接管（例如，覆盖 Safe masterCopy 的 slot-0）。

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- 常见的 smart-account 故障模式包括绕过 `EntryPoint` 访问控制、未签名的 gas 字段、有状态验证、ERC-1271 重放，以及通过 revert-after-validation 的 fee-drain。

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- 使用 mutation testing 来发现测试套件中的盲点：

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

如果你正在研究 DEXes 和 AMMs 的实际利用（Uniswap v4 hooks、rounding/precision abuse、flash‑loan 放大阈值越过交换），请查看：

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

对于缓存虚拟余额且在 `supply == 0` 时可被污染的多资产加权池，请研究：

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
