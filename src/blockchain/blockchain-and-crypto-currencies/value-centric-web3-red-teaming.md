# 以价值为中心的 Web3 Red Teaming（MITRE AADAPT）

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques（AADAPT）框架对针对数字资产系统的对抗性行动和技术进行分类。<sup>[[1]](#references)</sup> 将其视为 **threat-modeling 骨架**：枚举所有能够铸造、定价、授权或路由资产的组件，将这些接触点映射到 AADAPT 技术，然后推动 red-team 场景，以衡量环境抵御不可逆经济损失的能力。

## 1. 清点承载价值的组件
构建一张能够影响价值状态的所有事物的地图，即使它们位于链下。<sup>[[2]](#references)</sup>

- **托管签名服务**（HSM/KMS 集群、Vault/KMaaS、bot 或后台任务使用的签名 API）。记录 key ID、策略、自动化身份和审批工作流。
- **合约的 Admin 与升级路径**（proxy admin、治理 timelock、紧急暂停密钥、参数注册表）。包括谁/什么可以调用它们，以及需要满足何种 quorum 或 delay。
- **处理链上协议逻辑**的组件，包括 lending、AMM、vault、staking、bridge 或结算通道。记录它们所假设的不变量（oracle 价格、抵押率、再平衡周期……）。
- **构建交易的链下自动化**（做市 bot、CI/CD pipeline、cron 任务、serverless 函数）。这些组件通常持有 API key 或 service principal，可请求签名。
- **Oracle 与数据 feed**（聚合器组成、quorum、偏差阈值、更新周期）。记录自动化风险逻辑所依赖的每个上游来源。
- **Bridge 与跨链 router**（lock/mint 合约、relayer、结算任务），用于连接不同链或托管体系。

交付成果：绘制价值流图，展示资产如何移动、谁授权移动，以及哪些外部信号会影响业务逻辑。

## 2. 将组件映射到 AADAPT 行为
将 AADAPT 分类法转化为每个组件对应的具体攻击候选。<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

这种映射确保测试的不只是合约，还包括所有能够间接操控价值的 identity/automation。

## 3. 根据攻击者可行性与业务影响确定优先级

1. **运营弱点**：暴露的 CI credential、权限过大的 IAM role、配置错误的 KMS policy、能够请求任意签名的 automation account、包含 bridge 配置的公开 bucket 等。
2. **价值特定弱点**：脆弱的 oracle 参数、缺少多方审批的可升级合约、对 flash-loan 敏感的流动性、可绕过 timelock 的治理操作。

像 adversary 一样处理队列：先从今天就可能成功的运营 foothold 开始，然后深入到协议和经济操纵路径。<sup>[[2]](#references)</sup>

## 4. 在受控且贴近生产的环境中执行
- **Forked mainnet / 隔离 testnet**：复制 bytecode、storage 和流动性，使 flash-loan 路径、oracle 漂移和 bridge 流程能够端到端运行，同时不接触真实资金。<sup>[[2]](#references)</sup>
- **Blast radius 规划**：在引爆场景前定义 circuit breaker、可暂停模块、rollback runbook 和仅供测试使用的 admin key。
- **利益相关者协调**：通知 custodian、oracle operator、bridge partner 和合规团队，使其监控团队预期会出现相关流量。
- **法律批准**：当模拟可能触及受监管通道时，记录范围、授权和停止条件。

## 5. 使 Telemetry 与 AADAPT 技术对齐
对 telemetry 流进行 instrument，使每个场景都产生可执行的检测数据。<sup>[[2]](#references)</sup>

- **链级 trace**：完整的 call graph、gas 使用量、交易 nonce、区块时间戳，用于重建 flash-loan bundle、类似 reentrancy 的结构和跨合约跳转。
- **应用/API 日志**：将每笔链上 tx 关联回人类或 automation identity（session ID、OAuth client、API key、CI job ID），并记录 IP 和认证方式。
- **KMS/HSM 日志**：记录每次签名的 key ID、caller principal、policy 结果、目标地址和 reason code。建立变更窗口和高风险操作的基线。
- **Oracle/feed metadata**：记录每次更新的数据源组成、报告值、与滚动平均值的偏差、触发的阈值以及执行的 failover 路径。
- **Bridge/swap trace**：使用 correlation ID、chain ID、relayer identity 和 hop timing，关联不同链上的 lock/mint/unlock 事件。
- **异常标记**：生成 slippage 峰值、异常抵押率、不寻常的 gas 密度或跨链速度等派生指标。

为所有内容添加 scenario ID 或 synthetic user ID，使分析人员能够将 observables 与正在测试的 AADAPT 技术对应起来。

## 6. Purple-team 循环与成熟度指标
1. 在受控环境中运行场景，并记录检测结果（alert、dashboard、被呼叫的 responder）。<sup>[[2]](#references)</sup>
2. 将每个步骤映射到具体的 AADAPT 技术，以及在 chain/app/KMS/oracle/bridge 层产生的 observables。
3. 制定并部署检测假设（threshold rule、correlation search、invariant check）。
4. 重复运行，直到 mean time to detect（MTTD）和 mean time to contain（MTTC）符合业务容忍度，并且 playbook 能够可靠地阻止价值损失。

从三个轴跟踪项目成熟度：<sup>[[2]](#references)</sup>
- **可见性**：每条关键价值路径在各个层面都有 telemetry。
- **覆盖率**：端到端测试的优先 AADAPT 技术占比。
- **响应能力**：在发生不可逆损失前暂停合约、撤销密钥或冻结流程的能力。

典型里程碑包括：(1) 完成价值清点和 AADAPT 映射；(2) 完成首个实现检测能力的端到端场景；(3) 每季度执行 Purple-team 循环，扩大覆盖率并降低 MTTD/MTTC。<sup>[[2]](#references)</sup>

## 7. 场景模板
使用以下可重复的蓝图设计能够直接映射到 AADAPT 行为的模拟。<sup>[[2]](#references)</sup>

### 场景 A – Flash-loan 经济操纵
- **目标**：在单笔交易中借入短期资金，扭曲 AMM 价格/流动性，并在归还前触发错误定价的借款、清算或铸造。
- **执行**：
1. Fork 目标链，并使用接近生产环境的流动性为池子注资。
2. 通过 flash loan 借入大额名义资金。
3. 执行经过校准的 swap，使价格/阈值跨越 lending、vault 或 derivative 逻辑所依赖的边界。
4. 在扭曲发生后立即调用受害合约（borrow、liquidate、mint），然后归还 flash loan。
- **测量**：不变量破坏是否成功？是否触发 slippage/price-deviation monitor、circuit breaker 或 governance pause hook？analytics 多久能够标记出异常的 gas/call graph 模式？

### 场景 B – Oracle/数据 feed poisoning
- **目标**：确定被操纵的 feed 是否能够触发破坏性自动操作（大规模清算、错误结算）。
- **执行**：
1. 在 fork/testnet 中部署恶意 feed，或调整 aggregator 权重、quorum/update cadence，使其超出可容忍的偏差。
2. 让依赖合约使用被 poisoning 的数值，并执行其标准逻辑。
- **测量**：feed 层面的带外 alert、fallback oracle 激活、最小/最大边界强制执行，以及从异常开始到 operator 响应之间的延迟。

### 场景 C – Credential/签名滥用
- **目标**：测试攻陷单个 signer 或 automation identity 是否会导致未授权升级、参数修改或 treasury drain。
- **执行**：
1. 枚举具有敏感签名权限的 identity（operator、CI token、调用 KMS/HSM 的 service account、multisig participant）。
2. 模拟 compromise（在 lab 范围内重新使用其 credential/key）。
3. 尝试特权操作：升级 proxy、修改风险参数、mint/pause asset，或触发 governance proposal。
- **测量**：KMS/HSM 日志是否产生 anomaly alert（操作时间、目标地址漂移、高风险操作突发）？policy 或 multisig threshold 能否阻止单方面滥用？是否强制执行 throttle/rate limit 或额外审批？

### 场景 D – 跨链规避与可追踪性缺口
- **目标**：评估 defenders 追踪并快速拦截通过 bridge、DEX router 和隐私 hop 迅速 laundering 的资产的能力。
- **执行**：
1. 在常见 bridge 之间串联 lock/mint 操作，在每个 hop 中交错执行 swap/mixer，并维护每个 hop 的 correlation ID。
2. 加速 transfer 以对监控延迟施压（在数分钟/区块内完成 multi-hop）。
- **测量**：跨 telemetry 与商业 chain analytics 关联事件所需的时间、重建路径的完整性、真实事件中识别可冻结 choke point 的能力，以及针对异常跨链速度/价值的 alert fidelity。

## References

- [1] [面向数字资产的 AADAPT(TM) Cyber Threat Framework（MITRE）](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework 作为 Red Team 路线图（Bishop Fox）](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
