# 以价值为中心的 Web3 Red Teaming（MITRE AADAPT）

MITRE Adversarial Actions in Digital Asset Payment Techniques（AADAPT）框架对针对数字资产系统的对抗性操作和技术进行分类。<sup>[[1]](#references)</sup> 将其视为**威胁建模骨架**：枚举所有能够铸造、定价、授权或路由资产的组件，将这些接触点映射到 AADAPT 技术，然后推动 Red Team 场景，衡量环境抵御不可逆经济损失的能力。

## 1. 清点承载价值的组件
建立一张能够影响价值状态的所有事物的地图，即使它们位于链下也是如此。<sup>[[2]](#references)</sup>

- **托管签名服务**（HSM/KMS 集群、Vault/KMaaS、bot 或后台作业使用的签名 API）。记录 key ID、策略、自动化身份和审批工作流。
- **合约的 Admin 与 upgrade 路径**（proxy admin、治理 timelock、紧急 pause key、参数注册表）。包括谁/什么可以调用它们，以及所需的 quorum 或 delay。
- **处理借贷、AMM、vault、staking、bridge 或结算轨道的链上协议逻辑**。记录其假设的 invariant（oracle 价格、抵押率、rebalance 周期……）。
- **构建交易的链下自动化**（做市 bot、CI/CD pipeline、cron job、serverless function）。它们通常持有可请求签名的 API key 或 service principal。
- **Oracle 与数据 feed**（聚合器组成、quorum、偏差阈值、更新周期）。记录自动化风险逻辑所依赖的每个上游数据源。
- **Bridge 和跨链 router**（lock/mint 合约、relayer、结算 job），用于连接不同链或托管栈。

交付物：一张价值流图，展示资产如何移动、谁授权移动，以及哪些外部信号会影响业务逻辑。

## 2. 将组件映射到 AADAPT 行为
将 AADAPT taxonomy 转化为每个组件对应的具体攻击候选。<sup>[[2]](#references)</sup>

| 组件 | 主要 AADAPT 关注点 |
| --- | --- |
| Signing/KMS estates | Credential theft、policy bypass、signing-abuse、governance takeover |
| Oracles/feeds | Input poisoning、aggregation manipulation、deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation、invariant breaking、parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities、batch replay、unauthorized deployment |
| Bridges/routers | Cross-chain evasion、rapid hop laundering、settlement desynchronization |

这种映射确保测试的不只是合约，还包括所有能够间接操控价值的身份/自动化。

## 3. 根据攻击者可行性与业务影响确定优先级

1. **运营弱点**：暴露的 CI credential、权限过大的 IAM role、配置错误的 KMS policy、能够请求任意签名的自动化账户、包含 bridge 配置的公开 bucket 等。
2. **价值相关弱点**：脆弱的 oracle 参数、缺少多方审批的可升级合约、对 flash loan 敏感的流动性、可绕过 timelock 的治理操作。

像攻击者一样处理队列：先从今天即可成功的运营 foothold 开始，然后推进到深层的协议/经济操控路径。<sup>[[2]](#references)</sup>

## 4. 在受控且贴近生产环境的环境中执行
- **Forked mainnet / 隔离 testnet**：复制 bytecode、storage 和流动性，使 flash-loan 路径、oracle 漂移和 bridge 流程能够端到端运行，同时不接触真实资金。<sup>[[2]](#references)</sup>
- **Blast radius 规划**：在引爆场景前定义 circuit breaker、可 pause 模块、rollback runbook 和仅用于测试的 admin key。
- **Stakeholder 协调**：通知 custodian、oracle operator、bridge 合作方和合规团队，使其监控团队预期会出现相关流量。
- **法律签字确认**：当模拟可能跨越受监管轨道时，记录范围、授权和停止条件。

## 5. 与 AADAPT 技术对齐的 Telemetry
对 telemetry 流进行 instrument，使每个场景都产生可执行的检测数据。<sup>[[2]](#references)</sup>

- **链级 trace**：完整的调用图、gas 使用量、交易 nonce、区块 timestamp，用于重建 flash-loan bundle、类似 reentrancy 的结构和跨合约跳转。
- **应用/API log**：通过 session ID、OAuth client、API key、CI job ID、IP 和认证方式，将每笔链上 tx 关联回人工或自动化身份。
- **KMS/HSM log**：记录每次签名的 key ID、调用方 principal、policy 结果、目标地址和 reason code。为变更窗口及高风险操作建立 baseline。
- **Oracle/feed metadata**：记录每次更新的数据源组成、报告值、相对于滚动平均值的偏差、触发的阈值以及执行的 failover 路径。
- **Bridge/swap trace**：使用 correlation ID、chain ID、relayer 身份和跳转时间，关联不同链上的 lock/mint/unlock 事件。
- **Anomaly marker**：派生 slippage 峰值、异常抵押率、异常 gas 密度或跨链速度等指标。

为所有数据标记场景 ID 或 synthetic user ID，使分析人员能够将可观测信号与正在演练的 AADAPT 技术对应起来。

## 6. Purple-team 循环与成熟度指标
1. 在受控环境中运行场景并捕获检测结果（alert、dashboard、被呼叫的响应人员）。<sup>[[2]](#references)</sup>
2. 将每个步骤映射到具体的 AADAPT 技术，以及在 chain/app/KMS/oracle/bridge 平面产生的可观测信号。
3. 制定并部署检测假设（阈值规则、关联搜索、invariant 检查）。
4. 重复运行，直到 mean time to detect（MTTD）和 mean time to contain（MTTC）达到业务容忍度，并且 playbook 能够可靠地阻止价值损失。

从三个轴跟踪项目成熟度：<sup>[[2]](#references)</sup>
- **Visibility**：每条关键价值路径在每个平面都有 telemetry。
- **Coverage**：端到端演练的优先 AADAPT 技术占比。
- **Response**：在发生不可逆损失前 pause 合约、revoke key 或 freeze 流程的能力。

典型里程碑：(1) 完成价值清点与 AADAPT 映射；(2) 完成首个具有检测能力的端到端场景；(3) 按季度执行 Purple-team cycle，扩大覆盖范围并降低 MTTD/MTTC。<sup>[[2]](#references)</sup>

## 7. 场景模板
使用以下可重复的 blueprint 设计能够直接映射到 AADAPT 行为的模拟。<sup>[[2]](#references)</sup>

### 场景 A – Flash-loan 经济操控
- **目标**：在单笔交易内借入临时资金，扭曲 AMM 价格/流动性，并在归还前触发错误定价的借贷、清算或 mint。
- **执行**：
1. Fork 目标链，并使用类似生产环境的流动性为池子注资。
2. 通过 flash loan 借入大额名义资金。
3. 执行经过校准的 swap，跨越借贷、vault 或衍生品逻辑所依赖的价格/阈值边界。
4. 在价格扭曲后立即调用受害合约（borrow、liquidate、mint），并归还 flash loan。
- **测量**：invariant violation 是否成功？是否触发 slippage/price-deviation monitor、circuit breaker 或 governance pause hook？analytics 多久能够标记异常 gas/调用图模式？

### 场景 B – Oracle/数据 feed poisoning
- **目标**：确定被操控的 feed 是否能够触发破坏性的自动化操作（大规模清算、错误结算）。
- **执行**：
1. 在 fork/testnet 中部署恶意 feed，或调整 aggregator 权重、quorum、更新周期，使其超出可容忍的偏差范围。
2. 让依赖合约使用被 poisoning 的值并执行其标准逻辑。
- **测量**：feed 级 out-of-band alert、fallback oracle 激活、min/max bound 强制执行，以及从异常开始到 operator 响应之间的延迟。

### 场景 C – Credential/signing abuse
- **目标**：测试攻陷单个 signer 或自动化身份是否能够实现未授权的 upgrade、参数变更或 treasury drain。
- **执行**：
1. 枚举拥有敏感 signing 权限的身份（operator、CI token、调用 KMS/HSM 的 service account、multisig participant）。
2. 模拟攻陷（在实验室范围内重新使用其 credential/key）。
3. 尝试特权操作：upgrade proxy、修改风险参数、mint/pause 资产或触发治理提案。
- **测量**：KMS/HSM log 是否产生 anomaly alert（时间段、目标地址漂移、高风险操作突发）？policy 或 multisig threshold 能否阻止单方面滥用？是否强制执行 throttle/rate limit 或额外审批？

### 场景 D – 跨链规避与可追踪性缺口
- **目标**：评估防御者追踪并快速拦截经 bridge、DEX router 和隐私 hop 快速 laundering 的资产的能力。
- **执行**：
1. 在常见 bridge 之间串联 lock/mint 操作，在每个 hop 中穿插 swap/mixer，并维护每个 hop 的 correlation ID。
2. 加速 transfer 以给监控延迟施压（在数分钟/区块内完成多 hop）。
- **测量**：跨 telemetry 与商业 chain analytics 关联事件所需的时间、重建路径的完整性、在真实事件中识别冻结 choke point 的能力，以及针对异常跨链速度/价值的 alert fidelity。

## References

- [1] [AADAPT(TM) 数字资产 Cyber Threat Framework（MITRE）](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework 作为 Red Team 路线图（Bishop Fox）](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
