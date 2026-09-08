# Anonymous Payment Technique Catalog

本目录涵盖从普通现金、blind-signature e-cash 到 public-chain obfuscation 的各类支付**家族**。“Anonymous”始终指相对于某个具名观察者的匿名性。merchant、issuer、mint、exchange、blockchain analyst、network provider、employer 和 physical observer 看到的事实各不相同。

以下流程适用于合法资金、真实账户和经授权的采购。被引用案例中以 laundering、sanctions evasion 或 identity fraud 为目的的技术，将予以说明和检测，但其流程是合成的取证练习，而不是实施犯罪的指令。

## Coverage matrix

| Family | Main privacy property | Main observer/trust | Treatment |
|---|---|---|---|
| Cash and cash equivalents | 无远程支付网络记录 | recipient 和 physical environment | 合法工作流 |
| Prepaid/gift/voucher value | 将 redemption 与 primary card 分离 | seller、issuer 和 redemption service | 合法工作流，因司法辖区而异 |
| Virtual/tokenized card | 隐藏可复用 PAN 或将 merchants 分离 | issuer/network/wallet 仍可识别 payer | 合法工作流 |
| Payment app/intermediary | merchant 可能只看到 alias/intermediary | app 收集 identity/device/transaction | 对比基线 |
| Bitcoin hygiene/Silent Payments | pseudonyms 和 recipient unlinkability | public graph 和 wallet/network boundary | 可部署 |
| PayJoin/CoinJoin | 削弱 common ownership/linkage heuristics | participants/coordinator/network/public graph | 在支持时可部署；需进行法律审查 |
| Lightning/BOLT 12 | off-chain routing 和 receiver-path reduction | endpoints、hops、services 和 channel graph | 在支持时可部署 |
| Monero/Zcash/MWEB | protocol-level on-chain confidentiality | acquisition、endpoint、network 和 boundary 仍存在 | 在合法/支持时可部署 |
| Ethereum ZK application | 隐藏指定的 statement/action link | public inputs、RPC、relayer 和 app | 特定于应用 |
| Cashu/Fedimint/Taler | blind-signature payer privacy | mint/federation/exchange custody 和 boundaries | 新兴/特定于部署 |
| Stablecoins | 便捷的数字结算 | transparent chain 加 issuer freeze/control | 不是匿名基线 |
| Swaps/bridges/DEX | 跨资产/链转移价值 | 两侧 graphs、contracts 和 providers | 取证机制；仅限普通合法 swaps |
| Mixers/peel/structuring | 增加 graph ambiguity/work | entry/exit graph 和 service records | 仅限合成检测练习 |
| Nominees/mules/OTC/fronts | 插入 human/business intermediaries | facilitators、banks、communications | 仅限犯罪滥用分析 |
| Reusable/stealth payment addresses | 每次支付使用新的 recipient address | public announcement/notification 和 wallet boundaries | 在支持时可部署 |
| Confidential sidechain/state channel | 隐藏 amount/asset 或中间 updates | peers、bridge/federation 和 lifecycle settlement | 特定于协议 |
| Carrier/open-banking/platform billing | 对 merchant 隐藏 primary card | carrier、bank/PISP 或 platform 识别 customer | 普通的已识别支付 |
| Mutual credit/net settlement | 更少的外部结算记录 | private ledger operator 拥有完整映射 | 仅限已识别参与者 |

## Cash

**Mechanics:** physical bearer value 在双方之间转移，无需 online issuer authorization 或 public ledger。

**Pros:** merchant 不必了解 bank/card identity；没有远程 transaction graph；普遍易懂且具有最终性。

**Cons:** 仅限面对面交易；可能被盗/遗失；找零、收据、serial 或 reporting controls；withdrawal、摄像头、证人和地点仍可能将 payer 关联起来。

**Procedure:** (1) 确认 cash 合法/被接受，以及任何金额/reporting rule；(2) 合法地 withdraw 或 receive，并保留 private accounting records；(3) 向普通 merchant 支付，不必要时不要提供 loyalty/account identifiers；(4) 仅索取所需 receipt；(5) 如果购买不需要，避免提供 shipping/account data；(6) 在内部记录 legitimate business purpose。

**Detection:** 根据适用 policy 核对 till/receipt/inventory、摄像头和 access logs；调查异常 cash refunding 或反复略低于控制阈值的金额，但不要仅因正常使用 cash 就视为可疑。

## Money order, postal order, cashier instrument and cash on delivery

**Mechanics:** regulated issuer 将 cash/account funds 转换为编号 instrument，支付给具名 recipient；COD 将收款推迟到交付时。

**Pros:** recipient 可能无法获得 payer 的 primary bank/card number；适用于无法远程携带 cash 的场景；receipt 清晰。

**Cons:** issuer/retailer 会按要求保留 purchase/identity data；serial tracking；recipient/delivery address；遗失/欺诈和地区限制；通常不 anonymous。

**Procedure:** (1) 检查 issuer rules、limits、identification 和 recipient acceptance；(2) 使用真实信息和合法资金购买；(3) 立即填写 payee/amount；(4) 保存 serial/receipt；(5) 根据价值使用适当的 tracked delivery；(6) 核对 redemption/refund。

**Detection:** issuer purchase/redemption record、instrument serial、retailer/camera、shipping 和 recipient account；标记篡改、重复 serial 以及地理位置不一致的快速 redemption。

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential 针对 prepaid balance 授权，而不是 primary credit account。

**Pros:** 限制 merchant exposure 和损失；将 merchant 与 main PAN 分离；在接受该卡的 online 场景可使用。

**Cons:** purchase/activation/reload/registration 和 device records；KYC 与 limits 因地区而异；billing-address failures；cash-out/refund restrictions；“no name”不代表没有 issuer record。

**Procedure:** (1) 核实当前 issuer identity、fees、KYC、geography 以及 online/recurring support；(2) 通过 authorized seller 使用合法资金获取；(3) 注册真实的 required data；(4) 用于一个 compartment/purpose；(5) 不要 structuring loads 或伪造 residency；(6) 保留 purchase/expense evidence，并依照 issuer terms 关闭/处置。

**Detection:** 关联 seller/activation、funding、device/IP、merchant authorization、balance checks 和 redemption/refund。模式比 prepaid 标签更重要。

## Closed-loop gift card, voucher and transferable service credit

**Mechanics:** numbered value 只能在一个 merchant/service 或 ecosystem 中 redeem。Airtime/game/store credits 是其变体。

**Pros:** recipient merchant 可能只看到 code/balance；影响范围有限；便于 gifting 和 budget separation。

**Cons:** seller 和 service 记录 purchase/activation/redemption；account/device/delivery 仍可建立关联；scams、resale discounts 和 expiry/region limits；refund rights 较弱。

**Procedure:** (1) 仅从 authorized channels 购买；(2) 记录 code value，但不要暴露 secret；(3) 不必要时避免绑定 identifying loyalty account；(4) 通过独立的 legitimate merchant account/context redeem；(5) 在 accepted 前保留 receipt；(6) 绝不要为未经请求的“tax/support/ransom”要求购买 codes。

**Detection:** code issuance/redemption time、device/account convergence、bulk/threshold-pattern purchase、一个 device 查询许多 balances，以及远距离快速 redemption。

## Cryptocurrency-funded card or gift-code broker

**Mechanics:** intermediary 接受 cryptocurrency 并签发 card、voucher 或 merchant code。这是一次 cross-rail conversion：merchant 看到普通 card/gift value，而 broker 将 on-chain deposit 与 issuance/delivery 关联。

**Pros:** merchant 不会收到 funding wallet；适用于不接受 crypto 的合法 merchants；具有边界的 stored value。

**Cons:** 对 broker/issuer 而言并不 anonymous；KYC、sanctions、exchange 和 card-program rules；public deposit graph；account/device/email 和 code redemption 会重新连接两侧；scam/insolvency risk。

**Procedure:** (1) 核实 legal entity、card issuer、supported jurisdiction、KYC、fees 和 refund policy；(2) 仅使用有记录的合法资金；(3) 先测试最小 denomination；(4) 购买前核实 network/merchant restrictions；(5) 为 accounting 保留 blockchain transaction 和 broker receipt；(6) 绝不要使用承诺 identity fraud、sanctions bypass 或“untraceable” cash-out 的 broker。

**Detection:** 关联 broker deposit addresses、unique amount/time、account/device 与 issued-card authorization 或 gift-code redemption；issuer 和 broker records 可将 public chain 连接到 merchant。

## Virtual or merchant-locked card

**Mechanics:** issuer 将 generated PAN/token 映射到 real account，通常限制 merchant、amount 或 expiration。

**Pros:** 防止暴露可复用 PAN；merchant compartmentation；spend limits 和 easy revocation；成熟的 fraud control。

**Cons:** issuer 仍了解 payer、funding、merchant、device/IP 和 time；merchant 看到 account/delivery；某些 refunds/recurring charges 会失败；不 anonymous。

**Procedure:** (1) 使用 regulated issuer 的 official feature；(2) 为一个 merchant/engagement 创建一张 card；(3) 设置最小可用 limit 和 expiry；(4) 在需要时使用准确的 billing information；(5) 核实 statement descriptor/refund behavior；(6) final settlement 后 freeze/delete，同时保留 audit evidence。

**Detection:** issuer token-to-account mapping、merchant authorization、device 和 delivery。Defenders 使用 merchant-specific reuse、velocity 和 account takeover signals。

## Mobile-wallet network token

**Mechanics:** EMV payment tokenization 使用受约束的 credential 替代 PAN，通常绑定到 device、merchant 或 payment scenario。<sup>[[1]](#references)</sup>

**Pros:** merchant 不会收到可复用 PAN；device cryptography/dynamic data 降低 cloning 风险；无需更换 card 即可 revoke。

**Cons:** issuer、token service、wallet platform 和 network 保留 mappings/transactions；device/platform account 和 location 可能识别 payer。

**Procedure:** (1) 在 official wallet 中注册 legitimate card；(2) 使用 strong authentication 保护 platform account/device；(3) 在 purchase 时核实 device token/last digits；(4) 在支持时禁用不必要的 location/analytics；(5) 立即移除遗失的 devices/token；(6) 检查 issuer 和 wallet records。

**Detection:** token requestor/device cryptogram 和 issuer mapping、wallet/account telemetry、merchant terminal 以及 physical evidence。

## Payment app, marketplace wallet and centralized intermediary

**Mechanics:** service 在内部账户之间或通过 bank/card rails 维护 accounts 和 transfers；merchant 可能看到 alias，而 service 能看到双方。

**Pros:** 便利、dispute/refund mechanisms；recipient 不一定能看到 bank/card details。

**Cons:** centralized identity/social/transaction/device graph；freezes 和 legal process；counterparties 可能暴露 profile；data use 可能超出 payment necessity。<sup>[[2]](#references)</sup>

**Procedure:** (1) 阅读 identity、privacy、retention 和 buyer-protection terms；(2) 减少可选的 profile/contact synchronization；(3) 仅在 terms 允许时使用独立且真实的 account；(4) 启用 MFA/alerts；(5) 核实 recipient 以及 memo/profile 的 privacy；(6) 导出 records 并关闭不使用的 links。

**Detection:** provider account、device/IP、contact graph、funding/withdrawal、memo 和 merchant records。Alias 对 counterparty 而言是 pseudonymity，而不是对 platform 的 anonymity。

## Bank transfer, ACH, wire and instant-account payment

**Mechanics:** regulated institutions 在已识别 accounts 之间转移 value，并交换 required payment data。

**Pros:** 快速、可问责、在有限情况下可逆、records 完整；virtual account numbers 可能减少 merchant disclosure。

**Cons:** banks/processors 知道双方；statements 和 references；不 anonymous；存在 cross-border 和 Travel Rule/AML data。

**Procedure:** 仅在可接受 accountability 时使用：独立核实 beneficiary，减少可选 memo data，在可用时使用 bank-provided virtual account/reference，启用 alerts，保留 invoice 并核对。

**Detection:** deterministic bank/payment records、beneficiary/account ownership、device/session 和 fraud controls。这是 baseline，不是 anonymity technique。

## Account and merchant compartmentation

**Mechanics:** 分离 lawful identities/accounts、email aliases、cards 和 delivery contexts，防止不相关 merchants 轻易合并 activity，同时 issuer/controller 保留 mapping。

**Pros:** 减少 breach 和 cross-merchant linkage；便于 audit；兼容 regulated payments。

**Cons:** provider 仍会映射 compartments；recovery phone/device/IP 和 shipping 可重新建立关联；policy 可能禁止 multiple accounts。

**Procedure:** (1) 定义一个 purpose；(2) 仅创建符合 terms 的 aliases/subaccounts；(3) 使用 merchant-specific token/card；(4) 禁用 cross-account contact/ad personalization；(5) 保存 encrypted controller ledger；(6) refund/retention needs 结束后 retire identifiers。

**Detection:** providers 通过 recovery、device、funding 和 IP 进行关联；merchants 通过 delivery、browser 和 account behavior 进行关联。Defenders 应区分 legitimate compartmentation 与 synthetic identity fraud。

## Controlled red-team procurement

**Mechanics:** SOC 对某次 purchase 不知情，而 exercise controller 保留 legal entity、operator 和 infrastructure mapping。

**Pros:** 真实的 detection exercise；无 personal exposure；即时 deconfliction 和 audit。

**Cons:** 对 organization/provider 并不 anonymous；治理开销；controller ledger 处理不当会造成 leaks。

**Procedure:** (1) 分配 engagement-specific organization card/wallet/budget；(2) 分离 purchaser/operator roles；(3) 记录 asset、amount、service、purpose 和 kill date；(4) 将 attribution mapping 存放在限制访问的 controller 中；(5) 绝不使用 false identity/mule/stolen funds；(6) 在结束时揭示并核对 indicators 和 refunds。

**Detection:** controller 将 provider invoice 与 asset 关联；SOC 通过 domain、certificate、hosting 和 traffic，而不是 cardholder data，测试独立发现能力。

## Bitcoin address hygiene and coin control

**Mechanics:** fresh receive addresses、local labeling 和 selective UTXO spending 可减少 address reuse 以及 accidental compartment merging on a public ledger。

**Pros:** 支持广泛；self-custodial；避免最简单的 public linkage。

**Cons:** 所有 transactions/amounts 仍公开；common-input/change/timing 和后续 consolidation 会建立关联；acquisition/RPC/network records 仍存在。

**Procedure:** (1) 安装/验证 maintained wallet；(2) 备份并测试 seed recovery；(3) 每张 invoice 使用新 address；(4) 在本地标记 source/purpose；(5) 使用 coin control 避免合并 contexts；(6) 优先使用 local node 或 privacy-aware connection；(7) 预览 change/fees 并保留合法 accounting。<sup>[[3]](#references)</sup>

**Detection:** address graph、带不确定性的 common-input/change heuristics、exact amount/time、consolidation、service deposits、node/RPC broadcast timing 和 off-chain records。

## Bitcoin Silent Payments

**Mechanics:** BIP 352 允许 receiver 发布 static code，而 senders 通过 ECDH 派生 unique Taproot outputs；外部 observers 无法直接将 outputs 与 code 关联。<sup>[[4]](#references)</sup>

**Pros:** 可复用 public identifier 且不 reuse address；无需交互式 address request 或 notification output；与 Taproot outputs 融合。

**Cons:** receiver scanning cost；wallet support 各不相同；amount/sender graph 和 spending 仍公开；index server 可观察 scans。

**Procedure:** (1) 选择 current BIP 352 wallet；(2) 备份/测试 descriptor 和 scanning recovery；(3) 在支持时生成 labeled code；(4) authentication published code；(5) sender 检查 inputs 并发送 small test；(6) receiver 优先通过 own node 扫描；(7) 保持 received UTXOs 分离。

**Detection:** 按设计，单凭 output 无法可靠识别；analysts 使用 sender inputs、amount/time、later spending、wallet/network/index 和 counterparty records。

## PayJoin

**Mechanics:** payer 和 payee 各自向一次 payment transaction 提供 inputs，打破“所有 inputs 属于同一 owner”的假设。<sup>[[5]](#references)</sup>

**Pros:** 具有 improved privacy 的普通支付；通过削弱 common heuristic 使整体 graph 受益；无需 equal-output crowd。

**Cons:** 需要 interactive/support；receiver endpoint availability；amount 和 final transaction 公开；存在 implementation 和 fallback metadata。

**Procedure:** (1) 确认双方 maintained wallets 支持相同 PayJoin version；(2) authentication invoice/endpoint；(3) 从 wallet 的 PayJoin-enabled payment URI 开始；(4) 检查 final amount/fee，仅对预期 inputs 签名；(5) 避免手动修改 transaction；(6) 验证 broadcast 和 receipt；(7) negotiation 失败时记录 fallback。

**Detection:** blockchain analysts 不应强行进行 common-input clustering；endpoint/provider 可能记录 negotiation；应使用 wallet/network 和 later-spend evidence，而非仅凭 transaction shape。

## CoinJoin

**Mechanics:** 多个 participants 协作创建包含多个 inputs/outputs 的 transaction，通常使用 equal denominations，从而增加 input-output correspondence 的 ambiguity。

**Pros:** 更大的 on-chain ambiguity set；存在 self-custodial designs；round structure 可衡量。

**Cons:** coordinator/peer/network metadata；fees/liquidity；可识别的 transaction shape；toxic change 和 later consolidation 会破坏收益；法律/provider availability 各异。

**Procedure:** (1) 核实 current wallet/coordinator availability 和 legality；(2) 安装 official wallet 并备份；(3) 仅使用 lawful UTXOs；(4) 了解 denomination、fee 和 coordinator model；(5) 标记并分离 change 和 mixed outputs；(6) 绝不将它们 consolidate 在一起；(7) 按官方支持方式 route network traffic，并保留 accounting。

**Detection:** 识别 collaborative structure，但不要假定犯罪；计算 possible mappings/anonymity set，然后观察 change/consolidation、service boundaries 和 network/coordinator records。

## Lightning Network

**Mechanics:** HTLC payments 经由 onion-routed channels 传输；大多数 payment details 不发布到 chain，但 funding/closing 和 public channel information 会公开。

**Pros:** 快速、低费；intermediaries 通常只看到相邻 hops；普通 payment details 保持 off chain。

**Cons:** sender/receiver 和 first/last hop 了解更多；probing、timing、channel graph、liquidity/wallet/LSP records；custodial wallets 会识别 users。

**Procedure:** (1) 明确选择 self-custodial 或 custodial；(2) 验证 wallet/seed/channel recovery；(3) 对 exact payment 使用 invoice；(4) 在了解权衡后再使用 private channels/LSP features；(5) 必要时通过受支持的 Tor 保护 node IP；(6) 避免 reuse identifying invoices；(7) 保留 channel 和 payment accounting。<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs、channel graph/probes、payment failure/timing 以及 on-chain funding/closure；没有 public transaction 不代表没有 records。

## BOLT 12 offers and route blinding

**Mechanics:** reusable offer 生成 fresh invoices，并可公布 blinded paths，使 payer 无需获知 receiver 的 clear node/path。

**Pros:** receiver privacy；无需 static invoice 的 reusable donation/payment endpoint；集成 Lightning onion routing。

**Cons:** wallet support 各异；endpoints、selected hops 和 funding 仍存在；public contact 或 network endpoint 可重新识别 receiver。

**Procedure:** (1) 确认匹配的 BOLT 12 support；(2) authentication offer；(3) request fresh invoice；(4) 检查 amount/issuer/recurrence；(5) 通过 wallet 支付；(6) 验证 receipt/refund behavior；(7) 减少 node alias/contact 并保留 accounting。<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP 和 first/last-hop telemetry、offer distribution account、timing/value 以及 funding graph；route blinding 会有意限制 payer visibility。

## Monero

**Mechanics:** one-time stealth addresses 隐藏 recipient linkage，RingCT 隐藏 amounts，ring signatures 提供 sender ambiguity。

**Pros:** privacy 默认启用 on chain；sender/receiver/amount confidentiality；成熟的专用 wallet/node ecosystem。

**Cons:** acquisition/off-ramp 和 endpoint/network/counterparty records；remote node 可看到 queries/IP；exchange support/legal treatment 各异；小的 operational mistakes 仍会连接 contexts。

**Procedure:** (1) 合法 acquire 并保留 basis/source；(2) 安装/验证 official maintained wallet；(3) 备份/测试 seed；(4) 使用 local node 或 documented Tor/I2P remote-node path；(5) 每个 payer/invoice 使用新的 subaddress；(6) 在本地标记 contexts；(7) 仅在有意为之时披露 transaction proof/view access。<sup>[[8]](#references)</sup>

**Detection:** 重点查看 exchange/merchant/device/network 和 seized-wallet evidence；protocol use 本身并不可疑，public chain 也有意暴露更少信息。

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs 在 sender、receiver 和 amount 加密的情况下验证 shielded transfers；transparent pools 和 pool transitions 仍公开。

**Pros:** 强大的 shielded on-chain confidentiality；viewing keys 可支持 scoped audit；由 protocol 强制 validity。

**Cons:** wallet/exchange support 和实际 pool choice 各异；transparent boundary 的 timing/value correlation；network/RPC 和 endpoint 仍存在。

**Procedure:** (1) 选择 maintained Orchard shielded-by-default wallet；(2) verify/back up；(3) 合法 obtain ZEC；(4) 接收到 supported Unified Address 并确认 pool；(5) 优先 shielded-to-shielded；(6) 使用 supported network privacy；(7) 在 audit 前用小额 wallet 测试 viewing-key disclosure。<sup>[[9]](#references)</sup>

**Detection:** transparent boundary 和 service records、wallet/network metadata，以及合法提供的 viewing keys；不要假定所有 Unified Address payments 都是 shielded。

## Mimblewimble and Litecoin MWEB

**Mechanics:** confidential transactions 隐藏 amounts，Mimblewimble-style aggregation 移除传统的 address-rich history；Litecoin 在 transparent chain 旁实现 optional extension block。

**Pros:** private domain 中的 confidential amounts 和 improved fungibility；高效 pruning/aggregation。

**Cons:** opt-in boundary peg-in/out 公开且可关联；wallet/exchange support；interactive/address model differences；network 和 acquisition records。

**Procedure:** (1) 选择明确支持 MWEB 的 maintained wallet；(2) verify/back up 并测试小额；(3) 合法 acquire；(4) peg into MWEB 并确认 balance domain；(5) 仅与 compatible receiver transact；(6) 避免立即进行 distinctive peg-out；(7) 保留 private audit records。<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value、exchange/wallet/node data 和后续 transparent spends；内部 confidential transfer details 有意被减少。

## Ethereum zero-knowledge privacy applications

**Mechanics:** circuit 在不披露 secret 的情况下证明 statement——例如 membership、valid note ownership 或 authorization——并由 verifier contract 检查。Deposits、withdrawals、public inputs、events 和 gas 仍可能暴露 links。

**Pros:** programmable selective disclosure；anonymous-set applications；无需暴露全部数据即可验证 rules。

**Cons:** contract/circuit bugs；small anonymity set；public boundaries；RPC/IP/session/analytics/gas funding；application 和 sanctions/legal risk。

**Procedure:** (1) 明确定义 proof 隐藏的内容；(2) 在合法情况下使用 audited maintained application；(3) 检查 public inputs/events 和 deposit/withdraw rules；(4) 按 protocol 设计分离 action wallet 和 gas sponsorship；(5) 使用 privacy-aware RPC/network path；(6) 使用小额测试；(7) 保留 compliance records。<sup>[[11]](#references)</sup>

**Detection:** contract events、deposit/withdraw timing/value、relayer/paymaster、RPC/session、frontend storage/analytics 以及 eventual exchange/merchant boundary。不要声称 ZK proof 隐藏了被声明为 public 的 fields。

## Stablecoins

**Mechanics:** tokens 在 public chain 上转移；centralized issuers 可能 freeze/blacklist，或针对 identified accounts redeem。

**Pros:** price stability、liquidity 和 merchant support；快速 settlement；便于 accounting。

**Cons:** transparent address/amount/contract graph；gas funding；issuer 和 exchange identity/control；sanctions screening；通常 anonymity 较差。

**Procedure:** 将其视为 identified payment：仅为 compartmentation 使用 fresh business address，核实 token contract/network，先进行 small test，保护 wallet，使用 trusted RPC/local node，保留 basis/source 并筛查 required parties。

**Detection:** complete token event graph、issuer freeze list/actions、exchange/RPC/device 和 gas-funding relationships。

## Cashu Chaumian e-cash

**Mechanics:** mint 对 client-generated bearer secrets 进行 blind signing，并由 mint 的 Bitcoin/Lightning reserves 支撑；它可以在不直接关联 issuance 与后续 redemption 的情况下防止 double-spend。

**Pros:** accountless bearer tokens；instant peer transfer；mint 无法直接将 blinded withdrawal 与 spend 关联；tokens 可作为 data/QR 传输。

**Cons:** mint custody/solvency/censorship；bearer data loss/theft；denomination/timing 和 Lightning boundaries；network metadata；软件生态仍处早期。<sup>[[12]](#references)</sup>

**Procedure:** (1) 先使用 official test mint 或极小 disposable value；(2) 安装 maintained wallet，并测试 backup/restore limitations；(3) authentication mint 并查看 custody/fees；(4) mint 小额；(5) 通过 authenticated private channel/QR 发送 token；(6) receiver 在将其视为 final 前 swap token；(7) redeem 并 reconcile。绝不要在 untrusted mint 中存储有意义的 value。

**Detection:** mint 看到 network、issue/redeem/Lightning boundaries 和 spent-token set，但 blinding 移除了 direct token linkage；endpoints/messages 和 distinctive amount/timing 仍可能恢复 links。

## Fedimint federated e-cash

**Mechanics:** threshold guardians 持有 reserves 并 blind-sign e-cash；internal bearer transfers 对 guardians private，而 Lightning gateways 连接 external payments。

**Pros:** 分散 custody；private internal transfer；community governance；在 threshold 以下没有单一 guardian 能控制 reserve。

**Cons:** guardian quorum/custody/software risk；gateway 观察 invoices/timing；deposit/withdraw boundaries；client-state recovery complexity。

**Procedure:** (1) 核实 federation invite/guardians/quorum/jurisdiction；(2) 安装 maintained client 并测试 recovery；(3) 存入少量合法资金；(4) 使用 fresh internal payment requests；(5) 将 gateway 视为 Lightning observer；(6) 测试 redemption；(7) 将 source/tax records 保留在 public payment data 之外。<sup>[[13]](#references)</sup>

**Detection:** federation 看到 aggregate issuance/redemption，gateways 看到 external invoices，Bitcoin/Lightning 显示 boundaries，endpoint/communication evidence 可能连接 internal transfers。

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash 旨在让 payer 对 merchants anonymous，同时保持 merchants 和 income accountable。

**Pros:** payer privacy by design；ordinary currency；merchant accountability/refunds；无需 speculative token。

**Cons:** deployments 有限；exchange/bank 看到 funding；merchant 看到 order/delivery；wallet bearer/recovery risk；regulated operators。

**Procedure:** (1) 为 jurisdiction/currency 查找 current exchange/merchant；(2) 阅读 KYC/fees/privacy；(3) 安装 official wallet；(4) 从 supported bank/exchange 合法 withdraw；(5) 检查 merchant contract；(6) 支付并保留 receipt/refund data；(7) 避免不必要的 merchant session identifiers。<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal 和 merchant deposit 是 accountable boundaries；即使 coins 被 blinded，merchant order/device/delivery 和 timing 仍可能产生 correlation。

## Cross-chain bridge, atomic swap and decentralized exchange

**Mechanics:** contract/service lock/burn 一个 asset 并 release/mint 另一个，或 counterparties 进行 atomic exchange。它会打破 single-ledger view，但不会打破 economic continuity。

**Pros:** asset/network interoperability；可避免单一 centralized custodian；适用于普通 portfolio/liquidity use。

**Cons:** 两条 chains 都是 public；time/value/fees/liquidity 和 contracts 可产生关联；bridge/relayer/frontend/RPC records；smart-contract/counterparty 和 regulatory risk。

**Procedure for lawful swaps:** (1) 核实 official contract/service 和 legal availability；(2) 检查 custody/audit/fees/slippage；(3) 使用 small test；(4) 记录两个 transaction IDs 和 rate；(5) 保护 approvals；(6) 核对 destination asset 并 revoke 不必要的 approval。不要使用 swaps 来掩饰 source of funds。

**Detection:** bridge deposit/withdraw events、unique amount minus fees、time order、liquidity、relayer/RPC/frontend 以及后续 service deposits。

## Centralized mixer or tumbler

**Mechanics:** service 将 deposits 接收到 pool 中，稍后返还不同 units，试图隐藏 direct input-output mapping。

**Pros:** 理论上可以扩大 transaction ambiguity。

**Cons:** operator 可能 steal/log；entry/exit timing/value analysis；sanctions/money-transmission 和 criminal exposure；seizures 可能暴露 mappings；taint/rejection risk。

**Procedure:** 不提供 operational mixing guide。通过扩展 [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) 安全地复现 graph：创建 synthetic deposits、pooled outputs、fees 和 delays；向 analysts 提供不完整 mappings；衡量哪些 heuristics 有效；然后揭示 ground truth。

**Detection:** service wallet/contract identification、entry/exit candidate sets、amount/fee/timing、deposit address reuse、seized/provider logs 和 downstream consolidation。标注 probabilistic attribution。

## Peel chains, fan-out/fan-in and structuring

**Mechanics:** repeated transactions 从 change 中剥离小额 payments，将 value 分散到多个 addresses，重新汇聚 collectors，或分割 amounts 以避免 review。

**Pros:** 增加 naive analyst workload 和 address count。

**Cons:** 可识别的 value/cadence/transaction continuity；consolidation 和 service endpoints；structuring 本身可能违法；fees 和 operational errors。

**Procedure:** 仅使用 synthetic CSV/testnet data：生成 large source、repeated payment/change edges、parallel branches 和一个 collector；加入 benign exchange-like examples；调整 detection 并记录 false positives。

**Detection:** graph continuity、repeated change pattern、cadence、just-below-control amounts、common service endpoint 和 off-chain records。Exchange hot wallets 可能呈现类似模式，因此必须结合 context。<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mechanics:** 由其他 person/account/company 接收、转换或花费 funds，在 controller 与 transaction 之间插入 legal 和 operational layers。

**Pros to an adversary:** named account 不会立即识别 controller；可连接 cash、crypto、goods 和 jurisdictions。

**Cons:** identity fraud/money-laundering exposure；每个 participant 都会增加 communications、bank/company/tax/shipping records、fees、矛盾和 witnesses；facilitator reuse 会形成 hubs。

**Procedure:** 不要用真实 people/accounts emulation。构建包含 controller、recruiter、mule、OTC、shell merchant 和 beneficiary 的 synthetic graph；植入 device/IP/message/bank edges；要求 investigators 区分 account holder 与 controller，并记录 evidence confidence。

**Detection:** shared device/IP/recovery、unusual beneficiary/velocity、many unrelated senders、immediate onward movement、company/director/invoice inconsistency、communications 以及 cash/commodity delivery。

## NFTs, gambling, merchant goods and refund loops

**Mechanics:** 将 value 转换成 self-priced asset、wagering balance、resalable goods 或 refunds，以制造不同的 transaction narrative。

**Pros to an adversary:** 改变 asset form，并引入 marketplace/merchant intermediaries。

**Cons:** marketplace/account/device 和 wash-trade graph；odds/play 和 refund records；delivery/resale evidence；fees/losses；fraud/laundering liability。

**Procedure:** 不提供 concealment workflow。使用 synthetic marketplace data，其中包含 related-wallet self-trades、implausible pricing、minimal play、mismatched refund instrument 和 common shipping；根据 legitimate collectors/customers 验证 detection。

**Detection:** circular/self-funded trades、common ownership/funding、price outliers、immediate resale/refund、minimal economic activity、shared device/delivery 和 proceeds reconvergence。

## Physical bearer wallet or offline token transfer

**Mechanics:** device、paper/QR、hardware bearer instrument 或 e-cash token 在交接时转移 secret 的控制权，而不是 broadcast payment。

**Pros:** exchange 时没有 live network event；可 offline 使用；类似 physical cash 的 custody。

**Cons:** copy/theft/loss 和 exclusivity 不确定；后续 redemption/broadcast 会建立关联；physical meeting/shipping；counterfeit/tamper risk。

**Procedure:** (1) 仅使用 reviewed instrument/protocol；(2) 私下 initialize/verify authenticity；(3) 仅加载少量合法 value；(4) 在 documented authorized context 中 transfer；(5) receiver 按 protocol 要求及时 verify 或 sweep；(6) 绝不要假定 sender 未保留 copy；(7) 私下记录 ownership/tax evidence。

**Detection:** purchase/funding 和 eventual sweep/redemption、device serial/tamper evidence、delivery/meeting 以及 endpoint records。

## Merchant-scoped invoice or one-time payment request

**Mechanics:** merchant 创建 single-use request，其中包含 amount、expiry 和 order reference。payer 通过 supported rail 结算，而无需直接向 merchant 暴露 reusable credential；issuer 或 payment processor 仍可能识别双方。

**Pros:** 限制 credential reuse 和 accidental cross-merchant identifiers；exact amount/expiry 减少 errors；兼容 ordinary accounting 和 refunds。

**Cons:** invoice、delivery、browser、processor 和 issuer 仍会关联 order；unique amount/time 可能加强 correlation；malicious payment links 很常见。

**Procedure:** (1) 独立 authentication merchant；(2) request fresh invoice，确认 exact amount、asset/network 和 expiry；(3) 检查 destination 和 refund rules；(4) 从 approved engagement compartment 支付；(5) 验证 merchant 确认的是同一 invoice；(6) 保留 receipt 和 transaction reference；(7) expire 而不是 reuse request。

**Detection:** merchant 和 processor 将 invoice、session 与 settlement 关联；unique amounts/timing 和 delivery 可识别 payer。**Captured wallet/device:** invoice history 会暴露 counterparties 和 purpose；减少不必要的 memo data、加密 device，并将 authoritative accounting 保存在 controlled finance system 中。

## Prepaid service credit and capability token

**Mechanics:** service 将 conventional payment 转换为 bounded internal credits 或 bearer capability。后续 API/resource use 可避免每次 request 都提交 original card，但 service 通常可将 issuance 与 redemption 映射。

**Pros:** 限制 spend 和 compromise loss；将 day-to-day workers 与 funding credential 分离；支持 per-project budgets 和 revocation。

**Cons:** 通常是 pseudonymous 而非 anonymous；service database、redemption IP 和 unique usage pattern 会关联 activity；bearer tokens 可能被盗；refund 可能需要 original payer。

**Procedure:** (1) 通过 organization account 购买 credits；(2) 创建一个 project 和 budget；(3) 签发具有 service、amount 和 expiry constraints 的 narrow token；(4) 仅存储在 approved secret manager 或 workload identity path 中；(5) 测试 scope 外和 expiry 后的 rejection；(6) 监控 consumption；(7) revoke 并 reconcile unused value。

**Detection:** provider 关联 funding account、project、token issuance 和 usage；defenders 针对 geographic/process changes 和 anomalous consumption 发出 alerts。**Captured node:** 假定其 remaining capability 可被花费；使用 short expiry、low balance、audience binding 和 immediate server-side revocation。

## Privacy Pass or blinded authorization token

**Mechanics:** issuer 生成 privacy-preserving authorization token，origin 可在不将 redemption 与 issuance 关联的情况下验证。它可代表 paid entitlement 或 rate-limited access，但本身不是 general currency。架构分离 client、attester、issuer 和 origin roles，并警告 IP/timing 或 collusion 可能破坏 unlinkability。<sup>[[18]](#references)</sup>

**Pros:** 对 supported services 可实现 unlinkable redemption；origin 无 reusable account cookie；cached tokens 可在时间上分离 issuance 和 use。

**Cons:** application-specific；issuer/attester trust 和 anonymity-set partitioning；IP 和 browser metadata 仍存在；token theft 或 distinctive issuance timing 可关联 use。

**Procedure:** (1) 使用符合 relevant Privacy Pass token type 的 implementation；(2) 明确定义 token 证明的 entitlement；(3) 在 threat model 要求时分离 issuer 和 origin administration；(4) 减少 challenge metadata；(5) 签发多个 test tokens，并在自有 origins 各 redeem 一次；(6) 对比 logs，检查 forbidden stable identifiers；(7) 测试 replay、expiry 和 revocation/abuse controls。

**Detection:** origins 看到 redemption IP/time 和 token validity；issuers/attesters 看到 issuance context；analysts 测试 timing 和 metadata partitions，但不要假设存在 cryptographic break。**Captured client:** unspent bearer tokens 可能仍可使用；限制其 value、lifetime 和 audience，绝不要将 funding credential 与其缓存在一起。

## Delegated organization procurement or fiscal sponsor

**Mechanics:** authorized procurement team、reseller 或 fiscal sponsor 签订合同并付款，而 operational team 获得 bounded service。这是 role separation，使用真实 records，并非 nominee 或 false identity。

**Pros:** vendors 不必获得每个 operator 的 identity 或 personal payment details；central compliance、tax 和 refund handling；清晰的 budget 和 offboarding。

**Cons:** sponsor 知道 beneficiary 和 purpose；contracts、approvals、delivery 和 accounts 仍保留；增加 delay/fees；如果同一个人管理所有 layers，separation 会很弱。

**Procedure:** (1) 记录 business purpose、beneficiary 和 approving authority；(2) 选择 organization-approved intermediary；(3) 使用真实 details 签约；(4) 提供没有 personal billing credential 的 project-scoped subaccount；(5) 将 finance administrators 与 operators 分离；(6) 核对 invoices 和 access；(7) 结束时终止 service 和 delegated access。

**Detection:** procurement、identity-provider、vendor 和 delivery records 会连接整个 chain。**Captured operational device:** 应暴露 service project，但不暴露 finance credentials；将 invoices 和 payer identities 保留在 finance system，而不是 field nodes。

## Escrow or conditional settlement

**Mechanics:** trusted escrow agent 或 smart contract 持有 value，直到 documented conditions 满足。它可减少 payer 与 payee 之间的 direct disclosure，但 escrow 和 underlying payment rails 仍保留 relationship。

**Pros:** dispute 和 delivery protection；payer 与 merchant 可较少互相暴露 reusable credentials；release conditions 可审计。

**Cons:** escrow custody/contract risk、fees 和 identity obligations；on-chain contracts 公开；order、shipping 和 dispute data 仍存在；对 intermediary 并不 anonymous。

**Procedure:** (1) 核实 legal entity、custody、fees、dispute forum 和 supported assets；(2) 创建准确的 written milestone 和 refund path；(3) 从 approved organization account funding；(4) 独立验证 receipt 和 release authorization；(5) 仅在有 evidence 后 release；(6) 保留完整 audit record；(7) 关闭未使用的 permissions 或 contract approvals。

**Detection:** escrow account/contract events、funding 和 release time、beneficiary 及 dispute records 会揭示 transaction。**Captured device:** session tokens 或 contract approvals 可能允许 release；要求 separate approver/MFA，并在丢失时 revoke active sessions。

## Batched or pooled organization settlement

**Mechanics:** 多项 approved obligations 被聚合，并以较少的 bank 或 blockchain transactions 结算，通过 private internal ledger 分配各自 shares。Batching 可减少 public per-purchase detail，但 coordinator 保留完整 attribution。

**Pros:** 更低 fees；更少 public graph edges；当 amounts 聚合时，可向 public observer 隐藏 individual line items；内部 accounting 简单。

**Cons:** coordinator 是 complete observer 和 high-value target；distinctive totals/timing 可产生关联；custody 和 reconciliation risk；滥用时可能看起来像 structuring。

**Procedure:** (1) 在 accounting system 定义 participants 和 lawful obligations；(2) 设置有 regular、business justification 的 batch window，而不是设计为规避 controls 的 thresholds；(3) 要求对 aggregate 进行 dual approval；(4) 结算至 authenticated recipients；(5) 将每条 internal line 与 batch 核对；(6) 将 refunds 作为 linked corrections 处理；(7) 保护 ledger access 并按 policy 保留。

**Detection:** coordinator ledger、approval 和 beneficiary records 提供 ground truth；public analysts 应谨慎使用 input/output/value/time clustering。**Captured payer device:** 只应包含其 requisition，不应包含 pool 的 signing key 或 participant ledger。

## Account-abstraction paymaster or sponsored gas

**Mechanics:** relayer/bundler 提交 smart-account operation，paymaster 支付 transaction fees，避免 user wallet 直接产生 native-gas funding edge。它改善一个 graph property，但 operation、contract 和 service telemetry 仍公开或可观察。<sup>[[19]](#references)</sup>

**Pros:** 移除常见 gas-funding link；支持 scoped sponsorship 和 rate limits；改善 legitimate privacy applications 的 onboarding。

**Cons:** paymaster/bundler/RPC/front end 可关联 requests；contract events 和 public inputs 仍存在；sponsorship policy 会为 cohort 建立 fingerprint；malicious contracts 或 approvals 可能盗取 assets。

**Procedure:** (1) 在正确 network 上使用 audited maintained smart account 和 paymaster；(2) 检查哪些 fields 是 public 以及 sponsor 记录什么；(3) 按 contract、function、amount、nonce 和 expiry 限制 sponsorship；(4) 使用 low value 测试；(5) 通过 application 预期的 privacy-aware path 提交；(6) 在 chain 上验证 operation 和 fee payer；(7) revoke allowances/session keys 并保留 compliance records。

**Detection:** 关联 UserOperation、EntryPoint、paymaster、bundler/RPC 和 application logs；谨慎聚类相同 sponsorship policy。**Captured wallet:** 即使没有 gas，session keys 和 pending approvals 仍可能可用；严格限定其 scope，并通过 account recovery policy revoke。

## Threshold or multisignature payment authorization

**Mechanics:** spending 需要 threshold 个独立 signers。它不会隐藏 transaction，但可将 payment authority 与 captured laptop、field node 或单个 operator 分离。

**Pros:** 强大的 compromise 和 insider resistance；accountable approval；没有单个 field device 持有完整 signing authority；支持 recovery。

**Cons:** coordination 和 availability；signer/device/account metadata 可能关联 participants；糟糕的 backup design 会导致损失；public multisig patterns 可能可识别。

**Procedure:** (1) 在 funding 前定义 signers、threshold、limits 和 recovery；(2) 在 separate supported hardware/accounts 上 initialize；(3) 独立验证 addresses 和 backups；(4) 只向 field workloads 提供 unsigned requisition capability；(5) 对 recipient、amount 和 purpose 进行 out-of-band review；(6) 用 small value 测试 recovery 和 one-signer loss；(7) compromise 后 rotate signer。

**Detection:** approval system、signer device 和 public script/contract 提供 evidence；defenders 针对 policy 或 signer-set changes 发 alerts。**Captured node:** 最多应暴露一个 low-authority session key 或 unsigned request；绝不要将 quorum material 缓存在一起。

## Closed-loop community or event currency

**Mechanics:** cooperative、conference 或 private test environment 签发仅可在 enrolled participants 之间 redeem 的 credits。Internal transfer 可能较少暴露给 global payment networks，但 operator 控制 issuance 和 redemption。

**Pros:** bounded economic domain；可测试 offline 或 privacy-preserving payment UX；限制 external card exposure；实验控制清晰。

**Cons:** small anonymity set；operator 和 merchants 观察 activity；acceptance 和 redemption 有限；即使是 local value，也可能适用 licensing、consumer-protection 和 tax rules。

**Procedure:** (1) 获得 legal/compliance review 并公布 issuer terms；(2) enroll consenting test participants；(3) 限制 issuance 并禁止 cash-like misuse；(4) 使用 fresh payment requests，减少 public participant identifiers；(5) 记录 aggregate reserves 和 private individual receipts；(6) 测试 loss/refund/redemption；(7) 关闭 ledger，并按承诺返还 residual value。

**Detection:** issuer ledger、enrollment、merchant 和 redemption records 可重建 flows；unusual circular transfers 或 rapid cash-out 应接受 review。**Captured wallet:** local balance 和 counterparties 可能暴露；限制 value、加密 state，并支持带 audit record 的 issuer-side freeze/reissue。

## Bitcoin reusable payment codes and private payment instructions

**Mechanics:** BIP 47 payment codes 使用 reusable public identifier 加 ECDH-derived one-time deposit addresses；BIP 351 规定较新的 private-payment instruction design。它们减少 public address reuse，同时允许 recipient 发布稳定的 payment instructions。Notification、wallet support、funding 和 subsequent coin selection 仍会影响 privacy。<sup>[[20]](#references)</sup>

**Pros:** 一个 public instruction 可产生 distinct addresses；recipient 无需发布每个 invoice address；compatible wallets 可监控 derived payments；适用于 repeated lawful donors/customers。

**Cons:** wallet interoperability 各异；notification transactions 或 published payment code 会连接 relationship context；sender、recipient 和 public graph 仍可看到 transactions；粗心的 consolidation 或 change handling 会破坏收益。

**Procedure:** (1) 确认双方 maintained wallets 支持完全相同的 specification/version；(2) 在 low-value wallet 上备份并测试 recovery；(3) out of band authentication recipient payment code；(4) 发送小额合法 test；(5) 验证使用了 fresh derived address；(6) 在本地标记 relationship 并应用 coin control；(7) 依赖之前测试 recovery 和 refund behavior。

**Detection:** analysts 检查 notification patterns、funding/change、later consolidation 和 service boundaries；即使 deposit addresses 不同，public-code publication 仍可识别 recipient context。**Capture-resilient OPSEC:** 将 spend keys 保持在 field devices 之外，最多暴露 watch-only relationship view。**Monitoring:** 对 unexpected notification transactions、reused derived addresses、wallet gap-limit/recovery errors 和 unplanned consolidation 发 alerts。

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender 从 recipient 的 stealth meta-address 派生 one-time stealth account，并发布包含 ephemeral public key 和 view tag 的 announcement。recipient 使用 viewing key 扫描 announcements 并派生对应 spend key。Recipient linkage 得到改善，但 sender、amount/token、gas、announcement 和 later spending 仍可见。<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address；reusable meta-address；分离 viewing 和 spending roles；适用于 supported EVM assets/applications。

**Cons:** announcement scanning 和 spam；为 new address funding gas 可能重新建立关联；sender 知道 recipient；public token/amount 和 eventual consolidation 仍存在；implementation 和 wallet support 各异。

**Procedure:** (1) 首先在 test network 使用 audited maintained implementation；(2) 生成并备份 separate viewing 和 spending material；(3) authentication meta-address；(4) 发送 low-value test 和 announcement；(5) scan 并 derive stealth account；(6) 测试 supported gas sponsorship，避免 personal funding edge；(7) 记录 public fields 并保留 lawful accounting。

**Detection:** 跟踪 announcement caller、token/amount、timing、gas sponsor、spending 和 consolidation；view key 可证明 receipt，但不会授予 spend。**Capture-resilient OPSEC:** networked scanner 在支持时只应具有 viewing role；将 spend 和 recovery keys 存放在其他位置。**Monitoring:** 对 malformed/spam announcements、view-key access、unexpected spend derivation 和未经 approval 移动的 stealth outputs 发 alerts。

## Liquid Confidential Transactions

**Mechanics:** Liquid 默认使用 commitments 和 proofs 对 output amounts 和 asset types 进行 blinding，同时保留 transaction graph、input/output count、fee 和 block time 可见。Peg-in/peg-out 和 service boundaries 仍可关联，users 可选择性披露 blinding data。<sup>[[22]](#references)</sup>

**Pros:** confidential amount 和 asset type 默认启用；快速 sidechain settlement；通过 blinding keys/descriptors 进行 selective audit；向 public observers 隐藏 commercially sensitive values。

**Cons:** graph structure 和 timing 仍存在；federation/bridge 和 exchange trust；peg boundaries 和 unconfidential outputs；wallet/node/network records；receiver 和 sender 知道自己的 transaction。

**Procedure:** (1) 选择 maintained Liquid wallet 并验证 backup model；(2) 使用 testnet 或 small lawful amount；(3) 接收到 confidential address，并验证 wallet 将 output 标记为 blinded；(4) 发送 test confidential transaction；(5) 检查哪些 explorer fields 仍 public；(6) 仅导出 audit 所需范围的 blinding proof；(7) 记录 peg/exchange boundaries 并 reconcile funds。

**Detection:** 分析 visible graph/fee/time、peg 和 exchange records、network metadata 以及后续 unblinding evidence；不要推断 hidden amount 或 asset。**Capture-resilient OPSEC:** 分离 spend seed、blinding/view data 和 watch-only operations。**Monitoring:** 对 accidental unconfidential addresses、unknown peg requests、descriptor changes 和未经批准的 unblinding-key export 发 alerts。

## General payment or state channel

**Mechanics:** participants lock funds，交换 signed off-chain state updates，并只将 opening、closing 或 disputed state 发布到 chain。Intermediate payments 不会向 global broadcast，但 peers 和 routing/intermediary services 会看到各自部分，endpoints 必须保留最新的 enforceable state。<sup>[[23]](#references)</sup>

**Pros:** 许多快速、低费、private-to-public-ledger interactions；更少 global transaction detail；bounded channel balance；适合 metered services 和 repeated counterparties。

**Cons:** channel peers 了解彼此并可保留 updates；opening/closing/value/timing 可关联；challenge windows 内可能需要 online monitoring；implementation 和 liquidity risk；本身不是 large anonymity set。

**Procedure:** (1) 选择 maintained audited implementation 并了解 dispute window；(2) 在 owned parties 之间建立 low-value test channel；(3) 使用 unique nonces 交换 signed state updates；(4) 备份 latest enforceable state；(5) cooperative close；(6) 在 testnet 演练 stale-state rejection；(7) 保留 accounting 和 channel-peer records。

**Detection:** public chain 暴露 lifecycle/disputes；peers、watch services 和 application transport 暴露 off-chain timing 和 parties。**Capture-resilient OPSEC:** 限制 hot balance，将 latest signed state 保存在与 field nodes 分离的 encrypted recoverable store 中。**Monitoring:** 持续监控 stale-state publication、missed backup、peer-key change 和 approaching challenge deadline。

## Mobile carrier billing

**Mechanics:** online service 通过 carrier billing system 将 purchase 计入 mobile subscription 或 prepaid balance。merchant 可能收到 carrier authorization 而非 card/bank details，而 carrier 知道 subscriber/line、device/network context、merchant、amount 和 time。<sup>[[24]](#references)</sup>

**Pros:** merchant 无 card number；phone availability 广泛；适用于 low-value digital goods；carrier 可限制和 reverse charges。

**Cons:** 通过 SIM/account 以及通常的 device 强识别；limits 小且 fees 高；merchant category restrictions；account takeover/SIM-swap risk；carrier 和 aggregator 创建完整 transaction trail。

**Procedure:** (1) 向 organization carrier account 确认 service availability、limit、fee 和 refund terms；(2) 如有理由，仅在 dedicated organization line 上启用；(3) 设置最低可用 spend cap；(4) 购买 benign test item；(5) 核实 merchant 和 carrier receipts；(6) 禁用 recurring authorization；(7) reconcile，并在 assessment 后关闭 feature。

**Detection:** carrier、aggregator 和 merchant records 将 line、subscriber、IP/device 与 charge 关联；enterprise telecom invoices 会暴露它。**Capture-resilient OPSEC:** 不要使用 personal number，并要求 carrier-account MFA 位于 field device 之外。**Monitoring:** 启用 instant charge/SIM-change alerts，发现 unexpected premium-service enrollment、forwarding 或 account recovery 时立即停止。

## Open-banking payment initiation

**Mechanics:** 经 explicit user consent，regulated payment-initiation service provider (PISP) 请求 account-servicing bank 发起 transfer。merchant 可能不会获得 card credentials，但 PISP 和 banks 保留 regulated payer、payee、consent、device 和 transaction records。<sup>[[25]](#references)</sup>

**Pros:** checkout 时无需 reusable card number；strong bank authentication；准确的 account-to-account settlement；consent 和 status APIs；reconciliation 清晰。

**Cons:** 对 banks/PISP 不 anonymous；payee 通常看到 legal account details 或 reference；phishing/redirect risk；jurisdiction 和 refund protections 各异；consent metadata 增加另一观察者。

**Procedure:** (1) 核实 PISP 当前受监管，并确认 merchant callback domain authentic；(2) 从 merchant request 开始；(3) 在 bank 端检查 payee、amount、reference 和 requested consent；(4) 只授权 single payment；(5) 独立验证 final status；(6) 如有 residual consent 则 revoke；(7) 保留 receipt 并 reconcile。

**Detection:** bank/PISP/merchant logs 和 transfer references 提供 strong attribution。**Capture-resilient OPSEC:** 将 banking authentication 和 recovery 保留在 operational/field devices 之外；device 只应持有 paid-service entitlement。**Monitoring:** 使用 bank transaction/consent alerts，调查 new PISP grants、changed payee 或 expected session 外的 status callbacks。

## Platform wallet, app-store balance or in-app credit

**Mechanics:** platform 向 user 收费或 redeem account credit，然后向 application 签发 signed receipt 或 entitlement。app developer 可能不会收到 original funding instrument，而 platform 会映射 account、device、funding、product 和 redemption。<sup>[[26]](#references)</sup>

**Pros:** merchant/developer 不获得 primary PAN；fraud/refund 和 family/business controls；small prepaid balance 可限制 exposure；signed receipts 简化 entitlement verification。

**Cons:** platform account 是强大的 identity 和 behavior hub；device 和 storefront geography；gift-balance purchase/redemption trail；cash-out 有限；fraud controls 可能 freeze funds；不是 cross-platform money。

**Procedure:** (1) 在 policy 允许时使用 organization-managed platform account；(2) 检查 funding、region、refund 和 transferable-value rules；(3) 仅添加 approved budget；(4) 通过 official store 购买 benign product；(5) 核实 application 只收到预期的 receipt fields；(6) 禁用 recurring purchase；(7) reconcile，并从 operational hardware 移除 account。

**Detection:** platform receipts/server notifications、account/device login 和 funding records 可重建 purchase。**Capture-resilient OPSEC:** 绝不要让 field node 登录 personal store account；尽可能只提供 scoped app entitlement。**Monitoring:** 启用 new-device/purchase alerts，调查 receipt replay、family/account changes 或 unexpected restore events。

## Mutual credit, clearing or periodic net settlement

**Mechanics:** participants 在 private ledger 中记录 obligations，并定期仅结算各自 net position。Individual service events 不必产生 separate public payments，但 ledger operator 和 counterparties 保留详细 attribution。

**Pros:** 更少 external transactions 和 fees；public observers 只看到 net settlement；适用于 repeated organizations；明确的 credit limits 可限制 exposure。

**Cons:** centralized ledger 是 complete evidence 和 fraud target；counterparty/default risk；legal/accounting/tax duties；membership set 小；unusual net transfers 仍可能揭示 relationships。

**Procedure:** (1) 仅与已识别且同意的 organizations 使用，并获得 legal/accounting approval；(2) 定义 unit、credit limit、settlement interval 和 dispute rules；(3) 使用 immutable approval 记录每项 obligation；(4) 由 separate finance roles 计算并批准 net positions；(5) 通过 ordinary lawful rail settlement；(6) 将 individual lines 与 settlement 核对；(7) 按 policy 关闭 access 并保留 records。

**Detection:** ledger、invoices、approvals 和 final bank/chain settlement 提供 ground truth；analysts 不应仅凭 net transfer 推断 missing gross activity。**Capture-resilient OPSEC:** operational devices 可提交 bounded requisitions，但不能编辑 balances 或 authorize settlement。**Monitoring:** 对 credit-limit breach、backdated entries、administrator changes、reconciliation mismatch 和 settlement to a new beneficiary 发 alerts。

## Capture/compromise exposure matrix

这适用于每个 family 的 seizure/loss test。目标是在保留 lawful accounting 的同时限制 spend authority 和 unrelated identity disclosure，而不是删除 transactions 或妨碍 investigation。

| Technique family | A captured wallet/device/account can reveal | Minimum authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts、serials、notes、remaining bearer value 和 physical contacts | 仅携带 approved amount；分离 private accounting；及时报告 loss；不制作 false records |
| Prepaid, gift, voucher, service credits | balance、issuer、activation、redemption 和 account/session tokens | low balance；one purpose；truthful registration；在可用时使用 issuer freeze/revocation |
| Virtual/tokenized card, wallet token, payment app | issuer account、device token、transactions、recovery 和 merchant history | device lock；transaction alerts；merchant scope；remote issuer suspension；不共享 recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization、approvers、vendor、invoices 和 project | role separation；least-privilege subaccount；finance credentials 绝不放在 operational/field nodes |
| Invoice, escrow, batch settlement | counterparty、purpose、pending approval、coordinator 或 dispute trail | single-use request；separate approver；limited session；central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys、labels、addresses、transaction graph 和 network configuration | hardware/offline signing；encrypted wallet；passphrase limits；watch-only field view；documented recovery |
| Lightning/BOLT 12 | seed、channels、invoices、peers/LSP 和 payment database | minimal hot balance；encrypted backup；separate node identity；按 documented plan close/recover |
| Monero, Zcash, MWEB, ZK applications | spend/view keys、local wallet history、RPC 和 boundary transactions | separate spend/view roles；在可用时使用 hardware support；field node 不登录 exchange session |
| Stablecoins, swaps, bridges and DEX | transparent graph、approvals、RPC/front-end state 和 destination assets | revoke allowances；verified contracts；low-value test；complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens、mint/federation/exchange、issuance/redemption cache | small balance；按 protocol 支持进行 encrypted backup；redeem/reissue；绝不将 funding credential 放在一起 |
| Paymaster, multisig/threshold | session key、one signer、pending operations 和 sponsor policy | narrow session key；independent quorum；signer rotation；field device 不能访问 threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider、communications、graph 和 participant records | 不进行 operational use；仅使用 synthetic/testnet evidence emulation |
| Community/event currency | enrollment、local balance、counterparties 和 redemption | capped value；issuer freeze/reissue；consent 和 private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys、relationship metadata、announcements 和 derived outputs | watch/view-only network role；offline/hardware spend role；无 personal funding session |
| Liquid confidential/state channels | seed、blinding data/latest state、peers、boundaries 和 disputes | separate spend/view/state backup；low hot balance；independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account、consent、receipt、device 和 funding source | organization account；external MFA；low limit；field hardware 不使用 personal account |
| Mutual-credit clearing | members、obligations、limits、approvals 和 settlement ledger | operational requisition only；separate immutable ledger 和 dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial、compliance review 或 wallet offline 并不能证明存在 investigation。仅监控 organization 有权观察的 accounts、ledgers 和 infrastructure；绝不要 probe providers 或 counterparties 来测试其是否与 investigators 合作。

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch、duplicate serial、unexpected redemption/refund 或 loss report | missing instrument、approved order 外的 redemption、altered receipt 或 custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts、new device/consent/payee、token reuse、SIM/account recovery | unknown authorization、payee change、new recovery factor、SIM swap 或 recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project、role/token/budget change、invoice 和 consumption | cross-project token、unknown admin、limit breach、invoice mismatch 或 unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry、approval/release、ledger integrity、reconciliation 和 beneficiary change | altered amount/payee、backdated ledger、unilateral release 或 unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions、notification/scan state、address reuse、UTXO labels 和 consolidation | unknown spend、reused recipient output、wallet gap/recovery failure 或 unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees、coordinator availability、final transaction equality | substituted output、excessive fee、unexpected input disclosure 或 coordinator policy change |
| Lightning/BOLT12/general channels | channel backup、invoice/offer use、liquidity、peer/LSP 和 chain dispute | unknown invoice payment、peer-key change、stale close 或 approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events、pool/domain/address type、descriptor 和 boundary transaction | spend without approval、transparent/unconfidential downgrade、key export 或 unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement、RPC/bundler、gas sponsor、allowance/session key 和 issuer action | wrong contract/public field、unknown approval/spend、paymaster change 或 issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health、token double-spend/replay、gateway 和 bearer balance | unknown redemption、mint key/terms change、restore failure 或 balance inconsistency |
| Swaps/bridges/DEX | verified contract、allowance、both-chain confirmations、rate 和 destination | contract/route mismatch、unlimited approval、missing destination 或 bridge incident |
| Multisig/threshold | signer-set/policy change、pending proposal、quorum 和 recovery audit | unknown proposal/signer、threshold reduction、recovery activation 或 policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | 仅 synthetic lab ground truth 和 detection output | 任何真实 account、person 或 value 进入 emulation：立即停止 |

## Selection and verification workflow

1. 明确哪个 party 不得获知哪个 field。
2. 识别 issuer/mint/custodian、public ledger、network/RPC、merchant 和 physical observers。
3. 验证当前 support、legality、limits、custody、recovery 和 refund behavior。
4. 使用少量合法资金进行端到端测试。
5. 检查 merchant receipt、provider statement、public chain 和 wallet/node logs。
6. 测试 backup/recovery 和 deliberate audit disclosure。
7. 准确记录 required source、ownership、tax、sanctions 和 engagement records，并进行 access control。

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — 大型支付平台数据收集的观察](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — 保护你的隐私](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — 简单的 Payjoin 提案](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — 技术规格与网络隐私](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — 使用 zero-knowledge proofs 构建隐私应用](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — 工作原理](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — 虚拟货币的 administrators、exchangers 和 users](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Privacy Pass 架构](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — 使用 Alternative Mempool 的 Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
