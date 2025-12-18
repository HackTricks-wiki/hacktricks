# 以价值为中心的 Web3 红队演练 (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) 矩阵捕捉了那些操纵数字价值而不仅仅是基础设施的攻击者行为。将其视为一个威胁建模的骨干：枚举所有可以 mint、定价、授权或路由资产的组件，把这些触点映射到 AADAPT 技术，然后推动红队场景以衡量环境能否抵御不可逆的经济损失。

## 1. 清点承载价值的组件
绘制一张地图，列出所有能影响价值状态的事物，即使它们在链外。

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs)。收集 key IDs、policies、automation identities 和 approval workflows。
- **Admin & upgrade paths** for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries)。包括谁/什么可以调用它们，以及在何种 quorum 或 delay 下。
- **On-chain protocol logic** 处理 lending、AMMs、vaults、staking、bridges，或结算通道。记录它们假设的不变量（oracle prices、collateral ratios、rebalance cadence…）。
- **Off-chain automation** 会构建交易（market-making bots、CI/CD pipelines、cron jobs、serverless functions）。这些通常持有 API keys 或 service principals，能够请求签名。
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence)。记录每一个被自动化风控逻辑依赖的上游。
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) 将链或托管堆栈连接在一起。

交付物：一张价值流图，展示资产如何移动，谁授权移动，以及哪些外部信号影响业务逻辑。

## 2. 将组件映射到 AADAPT 行为
把 AADAPT 分类学翻译成针对每个组件的具体攻击候选。

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

这个映射确保你不仅测试合约，还测试所有能间接引导价值的身份/自动化组件。

## 3. 按攻击者可行性与业务影响优先级排序

1. **Operational weaknesses**：暴露的 CI 凭据、权限过大的 IAM 角色、配置错误的 KMS policies、能请求任意签名的 automation accounts、包含 bridge 配置的公共 buckets 等等。
2. **Value-specific weaknesses**：脆弱的 oracle 参数、没有多方审批的可升级合约、对 flash-loan 敏感的流动性、能绕过 timelocks 的治理操作。

像对手一样处理待办：从今天可能成功的运营立足点开始，然后推进到深层的协议/经济操控路径。

## 4. 在受控且接近生产的环境中执行
- **Forked mainnets / isolated testnets**：复制 bytecode、storage 和流动性，这样 flash-loan 路径、oracle 漂移和 bridge 流程可以端到端运行，而不触及真实资金。
- **Blast-radius planning**：在触发场景前定义断路器、可暂停模块、回滚操作手册和仅测试用的 admin keys。
- **Stakeholder coordination**：通知 custodians、oracle operators、bridge partners 和合规方，让他们的监控团队预期到这些流量。
- **Legal sign-off**：在模拟可能跨越监管通道时，记录范围、授权和停止条件。

## 5. 与 AADAPT 技术对齐的遥测
为每个场景提供可操作的检测数据，给遥测流打上仪表。

- **Chain-level traces**：完整的调用图、gas 使用、交易 nonce、区块时间戳——用于重建 flash-loan 包、类重入结构和跨合约跳转。
- **Application/API logs**：将每笔 on-chain tx 关联回一个人或自动化身份（session ID、OAuth client、API key、CI job ID），附带 IP 和认证方法。
- **KMS/HSM logs**：每次签名记录 key ID、caller principal、policy result、destination address 和 reason codes。基线变更窗口和高风险操作要被标注。
- **Oracle/feed metadata**：每次更新的 data source 组成、上报值、与滚动平均值的偏差、触发的阈值和启用的故障转移路径。
- **Bridge/swap traces**：将 lock/mint/unlock 事件跨链关联，包含 correlation IDs、chain IDs、relayer identity 和跳转时间。
- **Anomaly markers**：派生指标，如滑点激增、异常的抵押率、异常 gas 密度或跨链速度。

为所有内容打上 scenario IDs 或 synthetic user IDs，以便分析人员将可观测项与正在演练的 AADAPT 技术对齐。

## 6. Purple-team 循环与成熟度指标
1. 在受控环境中运行场景并捕获检测（告警、仪表盘、响应人员被呼叫）。
2. 将每一步映射到具体的 AADAPT 技术以及在链/应用/KMS/oracle/bridge 平面产生的可观测项。
3. 制定并部署检测假设（阈值规则、关联搜索、不变量检查）。
4. 反复运行，直到 mean time to detect (MTTD) 和 mean time to contain (MTTC) 达到业务容忍度并且 playbooks 能可靠阻止价值损失。

在三个轴上跟踪项目成熟度：
- **Visibility**：每条关键价值路径在每个平面都有遥测。
- **Coverage**：端到端演练的优先 AADAPT 技术的比例。
- **Response**：在不可逆损失发生前暂停合约、撤销密钥或冻结流量的能力。

典型里程碑：(1) 完成价值清单 + AADAPT 映射，(2) 第一个端到端场景且已实现检测，(3) 每季度的 purple-team 周期，扩大覆盖并降低 MTTD/MTTC。

## 7. 场景模板
使用这些可重复的蓝图来设计直接映射到 AADAPT 行为的模拟。

### Scenario A – Flash-loan economic manipulation
- **Objective**：在一个交易内借入瞬时资本以扭曲 AMM 的价格/流动性，从而在还款前触发错误定价的借款、清算或 mint。
- **Execution**：
1. Fork the target chain 并为池注入类似生产的流动性。
2. 通过 flash loan 借取大额名义资金。
3. 执行校准的 swaps 以跨越被 lending、vault 或衍生品逻辑依赖的价格/阈值边界。
4. 在扭曲后立即调用受害合约（borrow、liquidate、mint）并偿还 flash loan。
- **Measurement**：不变量违规是否成功？滑点/价格偏离监控、断路器或 governance pause 钩子是否触发？分析何时标记出异常的 gas/调用图模式？

### Scenario B – Oracle/data-feed poisoning
- **Objective**：确定被操纵的 feeds 是否能触发破坏性的自动化动作（大规模清算、错误结算）。
- **Execution**：
1. 在 fork/testnet 中部署恶意 feed 或调整 aggregator 权重/quorum/update cadence 到超出容差的程度。
2. 让依赖的合约消费被投毒的值并执行其标准逻辑。
- **Measurement**：feed 级别的带外告警、fallback oracle 的激活、min/max 边界的执行，以及从异常开始到操作员响应的延迟。

### Scenario C – Credential/signing abuse
- **Objective**：测试妥协单个 signer 或自动化身份是否能导致未授权的升级、参数更改或金库抽取。
- **Execution**：
1. 枚举具有敏感签名权限的身份（operators、CI tokens、调用 KMS/HSM 的 service accounts、multisig 参与者）。
2. 在实验范围内模拟妥协（重用它们的凭据/密钥）。
3. 尝试执行特权操作：upgrade proxies、change risk parameters、mint/pause assets 或触发 governance proposals。
- **Measurement**：KMS/HSM 日志是否引发异常告警（时段、目的地偏移、高风险操作突增）？Policies 或 multisig 阈值能否阻止单方面滥用？是否有节流/速率限制或额外审批被强制执行？

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**：评估防御方在资产通过 bridges、DEX routers 和隐私跳点快速洗净时能多快追踪并制止。
- **Execution**：
1. 将常见桥按锁/铸造操作串联起来，在每个跳点交替进行 swaps/mixers，并为每跳保留 correlation IDs。
2. 加速转移以压测监控延迟（多跳在几分钟/区块内完成）。
- **Measurement**：跨遥测与商业链分析关联事件所需时间、重建路径的完整性、在真实事件中识别冻结节点的能力，以及异常跨链速度/价值的告警精度。

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
