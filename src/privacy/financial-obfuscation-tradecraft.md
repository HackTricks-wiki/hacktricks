# 金融混淆 Tradecraft

{{#include ../banners/hacktricks-training.md}}

支付隐私是归因问题，而不是支付品牌问题。当价值被获取、转移、转换、消费和交付时，一项行动就会留下证据。公共链地址可能是 pseudonymous 的，但交易所、发卡机构、商户、移动设备或运输摄像头都可能识别出其背后的个人。

本页面解释网络犯罪和与国家有关联的行动中使用的金融混淆模式，以便防御者识别这些模式。它**不**提供洗钱、规避制裁、虚假身份或绕过 KYC 的操作流程。

## 端到端价值图
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
某个行为者试图阻止任何观察者同时看到两端。调查人员则反其道而行之：保留每个边界处的记录，统一时间/价值/费用，并识别出**重新汇合点**，即不同身份重新使用同一中介、设备、账户、商户或目的地的位置。

## 工具及其实际观察者

| 工具 | 对商户/公众隐藏的内容 | 仍对以下对象可见 |
|---|---|---|
| 发卡机构虚拟卡/令牌 | 底层卡号 | 发卡机构、网络/令牌提供商、钱包、商户账户和交付系统 |
| 预付价值/礼品价值 | 普通购买时有时隐藏法定姓名 | 零售商/支付轨道、激活/兑换服务、摄像头、设备和交付环节 |
| 现金 | 公共账本和远程发卡机构 | 交易对手、摄像头、适用时的取款/序列号控制、实体搜查 |
| Bitcoin/新地址 | 直接法定姓名 | 每个区块链观察者；钱包/网络节点；获取/出金服务 |
| CoinJoin/PayJoin | 简单的共同输入/支付启发式分析 | 公开交易、协调者/节点/网络元数据以及后续支出行为 |
| 隐私币 | 公开发送方/接收方/金额，具体取决于协议 | 获取/出金服务、钱包端点、网络观察者和交易对手 |
| 集中式 mixer | 直接存入到提取之间的关联 | mixer 运营方/日志、区块链进出集合和交易对手 |
| 跨链桥接/交换 | 单一区块链上的连续性 | 两条区块链、桥接/交换服务、时间/价值和流动性约束 |
| OTC/P2P 经纪商 | 某些情况下隐藏直接交易账户 | 经纪商、通信记录、银行/现金流动、交易对手和设备 |

## 卡片、预付价值、名义持有人和资金骡子

### 虚拟卡和掩码卡

发卡机构可以创建与商户绑定或一次性使用的卡号。这会减少商户侧的信息暴露以及跨商户重复使用卡号的情况。发卡机构仍可将其映射到客户、资金账户、设备、IP 和交易。账单描述符、商户账户、配送地址和浏览器数据仍然可以建立关联。

“无姓名”卡片的营销并不意味着匿名结算。受监管的发卡机构和分销商可能执行身份核验、留存记录、施加地域/金额限制，并响应法律程序。通过被盗身份取得的卡片会增加身份盗窃问题；它不会消除发卡机构/设备/商户的遥测数据。

### 预付价值和礼品价值

预付卡和礼品码将后续兑换与原始支付工具分离，但会产生一个带编号的对象，其上存在购买、激活、余额查询和兑换事件。需要关注的模式包括批量购买、反复购买略低于控制阈值的面额、异地快速兑换、同一设备查询大量余额，或多张卡汇聚到同一商户/账户。

### 名义持有人、资金骡子和商户掩护实体

名义持有人或资金骡子提供账户和法定身份，介于运营者与服务之间。网络可能分层使用招募者、账户持有人、支付处理商、空壳商户和套现经纪商。这会制造距离，但每个参与者都会增加通信记录、费用、行为不一致性以及潜在的合作证人。掩护公司还会产生注册、税务、银行、董事、发票、托管和运输记录。

防御人员应调查共享设备/IP、受益人重复使用、地理位置矛盾、与账户历史不一致的交易速度、循环转账、多个无关发送方汇聚，以及资金立即继续转移的情况。不要假定登记的账户持有人就是控制行为者；应将其视为一个需要确定角色的节点。

## 公链交易混淆模式

### 地址轮换和 Coin control

为每笔收款创建新地址可以避免简单的地址重复使用，但交易仍可能通过共同输入、找零识别、精确金额/时间以及后续归集而被关联。**Coin control** 允许钱包选择要支出的输出，并避免将不同隔离区连接起来。它可以改善操作卫生；但无法消除已经公开的关联。

### Peel chains

Peel chains 会反复支出一笔较大余额，将较小金额发送到外部地址，并把剩余金额退回到新地址：
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
地址在每一步都会发生变化，但价值连续性、交易节奏和交易结构通常会形成可识别的链条。合法的交易所 hot wallet 也可能表现出类似特征，因此归因需要服务商/上下文证据。DOJ 曾在与 DPRK 相关的没收案件中使用 peel-chain 分析。<sup>[[1]](#references)</sup>

### Structuring 和 fan-out/fan-in

- **Fan-out：** 一个来源拆分到多个地址，以增加调查工作量，或准备并行转换。
- **Fan-in：** 多个来源汇聚到一个收集地址，从而暴露共同控制关系或某项服务。
- **Structuring：** 反复进行较小额转账，试图规避审查阈值，或混入普通交易量。
- **Commingling：** 非法资金与无关资金共用钱包、池或服务，使简单的按比例归因不再安全。

图结构只能作为线索，不能作为证据。分析人员应考虑费用、UTXO/account model、服务行为和找零惯例。

### CoinJoin 和 PayJoin

在典型的 CoinJoin 中，多个参与者向一笔协作交易提供 inputs，并接收 outputs，且 outputs 通常具有相等的面额。这打破了“一笔交易中的每个 input 和 output 都只有一个所有者”这一假设。匿名集的大小受参与者数量和后续行为限制：不等额找零、危险找零、资金 consolidation，或经过已知服务，都可能重新建立关联。

PayJoin 修改普通支付，使付款方和收款方都提供 inputs，从而直接使该交易中的 common-input ownership heuristic 失效。它主要是一种支付隐私协议，而不是批量洗钱服务。检测时应避免认定所有 inputs 都属于同一所有者，并应表达不确定性，而不是强行生成错误的 cluster。

### Centralized mixers 和 tumblers

Centralized mixer 接收存款，之后从 pooled reserve 中支付不同的 coins，通常会经过收费和延迟。其隐私性取决于池的规模、提现政策、日志、运营者的诚信以及抵抗扣押的能力。通过分析进入和退出的时间/价值、存款地址、服务钱包聚类和记录，可以缩小范围。运营者可能窃取资金，或保留完整的映射关系。

法律风险很高，并且因司法管辖区而异。DOJ 针对 ChipMixer、Samourai Wallet 以及 Tornado Cash 开发者/运营者的案件，加上不断变化的制裁诉讼表明，协议、托管、控制权和资金传输事实都很重要；“去中心化”这样的标签并不能构成法律结论。<sup>[[2]](#references)</sup>

### Cross-chain hopping、swaps 和 bridges

Chain hopping 会转换资产，或通过 bridge 转移资产，从而打断单一账本查询，但不会打破经济连续性：
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
分析人员会关联 bridge contracts/service deposit addresses、交易顺序、时间窗口、汇率、费用、流动性和独特金额。重复 swaps 可能扩大歧义，同时增加 provider/API/wallet telemetry。FATF 特别指出，当与可疑背景结合时，chain hopping、mixers、peer-to-peer services 和 anonymity-enhanced currencies 属于风险指标。<sup>[[3]](#references)</sup>

### NFTs、赌博和商户购买

Self-dealing 或 collusive NFT trades 可以赋予资金一种表面上的销售叙事；赌博可能将存款兑换为提款；商品可以将数字价值转换为可转售库存。这些路径会留下 marketplace accounts、creator/royalty links、wash-trading graphs、odds/play history、device logs、delivery 和 resale 证据。损失或费用并不能证明资金来源已经消失。

## Privacy-preserving cryptocurrencies

Privacy protocols 在技术上各不相同：

- **Monero** 使用一次性地址、ring signatures 和 confidential amounts，降低公开可见的发送方/接收方/金额信息。Network observation、wallet compromise、acquisition/off-ramp 和 counterparty records 仍不受这些链上保护措施覆盖。
- **Zcash shielded pools** 在使用 shielded transactions 时可以隐藏发送方、接收方和金额；transparent addresses 以及 pool 之间的转换仍然公开，并且使用模式会影响实际的 anonymity set。
- **Bitcoin** 默认是透明的。New addresses、CoinJoin、PayJoin 和 Lightning 会改变特定的关联假设，但不会使所有层都具备隐私性。

Privacy technology 具有合法的安全和商业用途。从调查角度看，当 ledger 提供的信息较少时，endpoint、service、network 和 human evidence 会变得更加重要。绝不要仅凭选择 privacy-preserving protocol 就推断存在犯罪行为。

## DPRK multi-layer case model

公开的 DOJ 指控和没收行动描述的是一个组合流程，而不是单一技巧：<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers 使用虚构/盗用的身份材料和 VPN 来获取远程工作；
2. employers 支付 cryptocurrency，包括 stablecoins；
3. 资金以较小金额转移，跨越不同 chains 或 tokens，购买 NFTs，或与其他资金 commingled；
4. 其他被盗资金进入 mixers；
5. OTC traders 和 front companies 将价值转换为 fiat payments 或 goods；
6. 重复出现的 facilitators、accounts 和 blockchain paths 使调查人员能够重新连接这些层级。

Treasury 表示，Lazarus 使用 Blender.io 处理 Axie Infinity/Ronin theft 的部分资金；与此同时，FBI 发布了相关 addresses，并敦促 bridges、exchanges、RPC operators 和 analytics firms 阻止与后续 TraderTraitor thefts 相关的资金。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

这里的启示是双向的：state actors 使用普通的商业/犯罪服务，而 public blockchains 使 defenders 能够追踪价值，即使最初不知道相关人员的姓名。

## Detection workflow

1. **保留原始 transaction identifiers 和 records。** Screenshots 和四舍五入后的 fiat values 不足够。
2. **标准化 assets 和 time。** 记录 chain、token contract、units、block time、service time zone、fees 和 exchange-rate source。
3. **标注 evidence confidence。** 区分 service-published address、deterministic contract event、clustering heuristic 和 external intelligence。
4. **追踪两个方向。** 查找 funding origin、immediate dispersal、reconvergence、bridge exits、service deposits 以及 spend/delivery。
5. **关联 off-chain evidence。** Account KYC、device、IP、support tickets、API keys、bank/payment、shipping 和 communication records 通常可以解决歧义。
6. **测试替代性解释。** Exchanges、custodians、payroll 和 privacy protocols 可能产生 fan-in/out 或 co-spends，而不代表存在共同的 beneficial ownership。
7. **进行监控，而不是过早结束调查。** Dormant output 之后进入某项 service 时，可能变得可归属。
8. **在法律顾问协助下适用当前的 sanctions/AML obligations。** Rules 和 designations 会变化；历史关联不能替代当前的法律分析。

## Safe red-team procurement model

经过授权的团队可能需要让目标 SOC 无法识别其 hosting payment，同时由 engagement controller 保留问责责任：

- 使用 engagement-specific organization card 或有文档记录的 corporate wallet；
- 确保 billing、tax 和 provider records 准确；
- 将 operator 与 procurement duties 分离，并限制其访问 attribution map；
- 绝不使用 mule、false identity、stolen card、sanctions workaround 或 unlicensed exchanger；
- 记录 asset、amount、owner、service、date、refund path 和 teardown evidence；
- 在 exercise 结束后，向 controller 披露相关的 payment/provider indicators。

这会造成的是**对 exercise participant 的盲区**，而不是对法律、provider 或 governance 的盲区。

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework（peel-chain 示例和 DPRK 调查）](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer 查封行动](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators（Virtual Assets 红旗指标）](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies（DPRK Foreign Trade Bank 代表因参与 crypto-laundering conspiracies 被起诉）](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK（关于据称为 DPRK 洗钱的 774 万美元提出的没收申诉）](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions and Lazarus funds（Blender.io sanctions 和 Lazarus funds）](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft（North Korea 对 2025 Bybit theft 负责）](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers（将 regulations 适用于 virtual-currency users、administrators 和 exchangers）](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
