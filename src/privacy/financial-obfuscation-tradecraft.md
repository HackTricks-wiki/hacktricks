# 金融混淆 Tradecraft

支付隐私是归因问题，而不是支付品牌问题。当价值被获取、转移、兑换、消费和交付时，一次行动就会留下证据。Public-chain 地址可能是 pseudonymous 的，但交易所、发卡机构、商户、移动设备或运输摄像头都可能识别出其背后的人。

本页解释网络犯罪和国家关联行动中使用的金融混淆模式，帮助防御人员识别这些模式。它**不**提供洗钱、规避制裁、虚假身份或绕过 KYC 的操作流程。

## 端到端价值图谱
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
攻击者试图阻止任何观察者同时看到两端。调查人员则反其道而行：在每个边界保留记录，统一时间/价值/费用，并识别**重新汇聚点**，即不同身份重新使用同一 facilitator、设备、账户、商户或目的地的地点。

## 工具及其实际观察者

| 工具 | 对商户/公众隐藏的内容 | 仍对以下对象可见 |
|---|---|---|
| 发行方虚拟卡/token | 底层卡号 | 发行方、网络/token provider、钱包、商户账户和配送系统 |
| 预付/礼品价值 | 普通购买时有时隐藏法定姓名 | 零售商/支付轨道、激活/兑换服务、摄像头、设备和配送方 |
| 现金 | 公共账本和远程发行方 | 交易对手、摄像头、适用时的取款/序列号控制、实体搜查 |
| Bitcoin/新地址 | 直接法定姓名 | 每个 blockchain observer；钱包/网络 peers；获取/出金服务 |
| CoinJoin/PayJoin | 简单的共同输入/支付启发式分析 | 公共交易、协调方/peer/网络元数据以及后续消费行为 |
| Privacy coin | 公开的发送方/接收方/金额，取决于协议 | 获取/出金方、钱包端点、网络观察者和交易对手 |
| Centralized mixer | 直接的存入到提取关联 | mixer operator/logs、区块链进入/退出集合和交易对手 |
| Cross-chain bridge/swap | 单一区块链上的连续性 | 两条区块链、bridge/swap 服务、时间/价值以及流动性约束 |
| OTC/P2P broker | 某些情况下隐藏直接交易账户 | broker、通信记录、银行/现金流动、交易对手和设备 |

## 卡、预付价值、名义持有人和资金 mule

### 虚拟卡和 masked cards

发行方可以创建绑定商户或一次性的卡号。这会减少商户暴露，并避免卡号在不同商户之间重复使用。发行方仍会将其映射到客户、资金账户、设备、IP 和交易。账单描述符、商户账户、配送地址和浏览器数据仍可被关联。

“无姓名”卡的营销并不意味着匿名结算。受监管的发行方和分销商可能执行身份检查、保留记录、施加地域/金额限制，并响应法律程序。通过盗用身份获得的卡会增加 identity theft；它不会消除发行方/设备/商户的 telemetry。

### 预付和礼品价值

预付卡和礼品码将后续兑换与原始支付工具分开，但会创建一个带编号的对象，并产生购买、激活、余额查询和兑换事件。需要关注的模式包括批量购买、反复购买略低于控制阈值的面额、远距离快速兑换、一个设备查询多个余额，或多张卡汇聚到同一商户/账户。

### 名义持有人、资金 mule 和商户掩护

名义持有人或资金 mule 提供账户和法定身份，处于 operator 与服务之间。网络可能分层使用招募者、账户持有人、支付处理商、空壳商户和套现 broker。这会制造距离，但每个参与者都会增加通信记录、费用、行为不一致性以及潜在的合作证人。掩护公司还会产生注册、税务、银行、董事、发票、hosting 和运输记录。

防御人员应调查共享设备/IP、受益人重复使用、地理位置矛盾、与账户历史不一致的交易速度、循环转账、多个无关发送方汇聚，以及资金立即继续转移的情况。不要假定名义账户持有人就是控制方；应将其视为需要确定角色的节点。

## 公共链交易混淆模式

### 地址轮换和 coin control

每次收款都创建新地址，可以防止简单的地址重复使用，但交易仍可能通过共同输入、找零识别、精确金额/时间以及后续合并来关联所有权。**Coin control** 允许钱包选择要花费的输出，并避免将不同 compartment 关联起来。它能改善 hygiene，但无法消除已经公开的关联。

### Peel chains

Peel chain 会反复花费一笔较大余额，将较小金额发送到外部地址，并把剩余金额返回到新地址：
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
地址在每一步都会变化，但价值连续性、交易节奏和交易结构通常会形成一条可识别的链。合法交易所的热钱包也可能表现出类似特征，因此归因需要服务/上下文证据。DOJ 曾在与 DPRK 相关的没收案件中使用剥离链分析。<sup>[[1]](#references)</sup>

### Structuring 和 fan-out/fan-in

- **Fan-out：** 一个来源拆分到多个地址，以增加调查工作量或准备并行转换。
- **Fan-in：** 多个来源汇聚到一个收集地址，从而暴露共同控制或某项服务。
- **Structuring：** 反复进行较小额转账，试图避开审查阈值或融入普通交易量。
- **Commingling：** 非法资金与无关资金共享钱包、资金池或服务，使简单的按比例认定不可靠。

图形结构只能作为线索，不能作为证据。分析人员应考虑手续费、UTXO/account model、服务行为和找零惯例。

### CoinJoin 和 PayJoin

在典型的 CoinJoin 中，多个参与者贡献输入，并在一笔协作交易中接收输出，输出金额通常相等。这打破了“交易中的每个输入和输出都属于同一所有者”的假设。匿名集的大小受参与者数量和后续行为限制：不等额找零、毒性找零、归集，或与已知服务发生交互，都可能重新建立关联。

PayJoin 修改普通支付，使付款方和收款方都贡献输入，从而直接使该交易中的常见输入所有权启发式失效。它主要是一种支付隐私协议，而不是大规模洗钱服务。检测时应避免认定所有输入均为同一所有者，并应表达不确定性，而不是强行形成错误的集群。

### Centralized mixers 和 tumblers

Centralized mixer 接受存款，之后从混合储备中支付不同的币，通常会收取费用并设置延迟。其隐私性取决于资金池规模、提款政策、日志、运营者诚信以及抗扣押能力。通过入账和出账的时间/价值分析、存款地址、服务钱包聚类和记录，可以缩小范围。运营者可能窃取资金，或保留完整的映射关系。

法律风险重大且因司法管辖区而异。DOJ 针对 ChipMixer、Samourai Wallet 以及 Tornado Cash 开发者/运营者的案件和不断变化的制裁诉讼表明，协议、托管、控制权和资金传输事实都很重要；“去中心化”之类的标签并不能构成法律结论。<sup>[[2]](#references)</sup>

### Cross-chain hopping、swaps 和 bridges

Chain hopping 会转换资产或通过 bridge 转移资产，打破基于单一账本的查询，但不会消除经济连续性：
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
分析人员会关联 bridge contracts/service deposit addresses、交易顺序、时间窗口、汇率、费用、流动性和独特金额。重复 swaps 可能扩大歧义，同时增加 provider/API/wallet telemetry。FATF 明确指出，当 chain hopping、mixers、peer-to-peer services 和 anonymity-enhanced currencies 与可疑背景结合时，它们属于风险指标。<sup>[[3]](#references)</sup>

### NFTs、赌博和商户购买

自我交易或串通的 NFT 交易可以为资金提供表面上的销售叙事；赌博可能将存款兑换为提款；商品可以将数字价值转换为可转售库存。这些路径会留下 marketplace accounts、creator/royalty links、wash-trading graphs、odds/play history、device logs、delivery 和 resale 证据。损失或费用并不能证明资金来源已经消失。

## 隐私保护型加密货币

隐私协议在技术上各不相同：

- **Monero** 使用一次性地址、环签名和保密金额，降低公开可见的发送方、接收方和金额信息。Network observation、wallet compromise、acquisition/off-ramp 和 counterparty records 仍不受这些链上保护措施覆盖。
- **Zcash shielded pools** 在使用 shielded transactions 时可以隐藏发送方、接收方和金额；transparent addresses 以及 pool 之间的转换仍然公开，而使用模式会影响有效 anonymity set。
- **Bitcoin** 默认是透明的。新地址、CoinJoin、PayJoin 和 Lightning 会改变特定的关联假设，但不会使所有层面都实现隐私。

隐私技术具有正当的安全和商业用途。从调查角度看，当 ledger 提供的信息减少时，endpoint、service、network 和 human evidence 变得更加重要。绝不能仅凭选择隐私保护型协议就推断存在犯罪行为。

## DPRK 多层案例模型

公开的 DOJ 指控和没收行动描述的是一个组合流程，而不是单一技巧：<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers 使用虚构或盗用的身份材料和 VPN 来获得远程工作；
2. employers 支付 cryptocurrency，包括 stablecoins；
3. funds 以较小金额转移，跨越 chains 或 tokens，购买 NFTs，或被混合；
4. 其他 stolen funds 进入 mixers；
5. OTC traders 和 front companies 将价值转换为法币支付或商品；
6. 重复出现的 facilitators、accounts 和 blockchain paths 使调查人员能够重新连接这些层。

Treasury 表示，Lazarus 使用 Blender.io 处理 Axie Infinity/Ronin 盗窃案中的部分资金；FBI 则公布了地址，并敦促 bridges、exchanges、RPC operators 和 analytics firms 阻止与后续 TraderTraitor 盗窃案相关的资金。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

其启示具有双向性：state actors 会使用普通的商业/犯罪服务，而 public blockchains 使 defenders 能够追踪价值，即使最初不知道相关人员的姓名。

## Detection workflow

1. **保留原始 transaction identifiers 和 records。** Screenshots 和四舍五入后的法币数值是不够的。
2. **规范化 assets 和 time。** 记录 chain、token contract、units、block time、service time zone、fees 和 exchange-rate source。
3. **标注 evidence confidence。** 区分 service-published address、deterministic contract event、clustering heuristic 和 external intelligence。
4. **追踪两个方向。** 查找 funding origin、immediate dispersal、reconvergence、bridge exits、service deposits 以及 spend/delivery。
5. **关联 off-chain evidence。** Account KYC、device、IP、support tickets、API keys、bank/payment、shipping 和 communication records 通常可以消除歧义。
6. **测试替代解释。** Exchanges、custodians、payroll 和 privacy protocols 可能产生 fan-in/out 或 co-spends，但不代表具有共同的 beneficial ownership。
7. **进行监控，而不是过早结束。** 某个 dormant output 之后到达某项服务时，可能变得可归属。
8. **在法律顾问参与下适用当前的 sanctions/AML obligations。** Rules 和 designations 会发生变化；历史关联不能替代当前的法律分析。

## Safe red-team procurement model

经授权的团队可能需要让目标 SOC 无法识别其 hosting payment，同时由 engagement controller 保持问责：

- 使用 engagement-specific organization card 或有记录的 corporate wallet；
- 保持 billing、tax 和 provider records 的准确性；
- 将 operator 与 procurement duties 分离，并限制其访问 attribution map；
- 绝不使用 mule、false identity、stolen card、sanctions workaround 或 unlicensed exchanger；
- 记录 asset、amount、owner、service、date、refund path 和 teardown evidence；
- 在 exercise 完成后，向 controller 披露相关 payment/provider indicators。

这会造成**对 exercise participant 的盲点**，而不是对法律、provider 或 governance 的盲点。

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework（peel-chain 示例和 DPRK 调查）](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer 查封行动](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank 代表因参与 crypto-laundering conspiracies 被起诉](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — 关于据称为 DPRK 洗钱 774 万美元的没收申诉](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions 和 Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea 对 2025 年 Bybit 盗窃案负责](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
