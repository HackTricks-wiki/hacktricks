# 以价值为中心的 Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) 矩阵描述了操纵数字价值而不仅是基础设施的攻击者行为。将其视为**威胁建模骨干**：枚举每个能够铸造、定价、授权或路由资产的组件，将这些接触点映射到 AADAPT techniques，然后设计 Red Teaming 场景，以衡量环境抵御不可逆经济损失的能力。

## 1. 清点承载价值的组件
构建一份能够影响价值状态的所有要素清单，即使它们位于链下也是如此。<sup>[[1]](#references)</sup>

- **托管签名服务**（HSM/KMS 集群、Vault/KMaaS、bot 或后台任务使用的签名 API）。记录 key ID、策略、自动化身份和审批工作流。
- **合约的 Admin 与升级路径**（proxy admin、治理 timelock、紧急暂停 key、参数注册表）。包括谁/什么可以调用它们，以及需要满足何种 quorum 或 delay。
- **处理借贷、AMM、vault、staking、bridge 或结算通道的链上协议逻辑**。记录它们所假设的不变量（oracle 价格、抵押率、rebalance 周期……）。
- **构建交易的链下自动化**（做市 bot、CI/CD pipeline、cron job、serverless function）。这些组件通常持有 API key 或 service principal，可请求签名。
- **Oracle 与数据 feed**（aggregator 组成、quorum、偏差阈值、更新周期）。记录自动化风险逻辑所依赖的每个上游数据源。
- **Bridge 与跨链 router**（lock/mint 合约、relayer、结算任务），用于连接不同链或托管系统。

交付物：一张价值流图，展示资产如何移动、谁授权移动，以及哪些外部信号会影响业务逻辑。

## 2. 将组件映射到 AADAPT 行为
将 AADAPT taxonomy 转换为每个组件对应的具体攻击候选项。<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft、policy bypass、signing-abuse、governance takeover |
| Oracles/feeds | Input poisoning、aggregation manipulation、deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation、invariant breaking、parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities、batch replay、unauthorized deployment |
| Bridges/routers | Cross-chain evasion、rapid hop laundering、settlement desynchronization |

这一映射可确保测试的不只是合约，还包括所有能够间接操纵价值的 identity/automation。

## 3. 按攻击者可行性与业务影响进行优先级排序

1. **Operational weaknesses**：暴露的 CI credentials、权限过大的 IAM role、配置错误的 KMS policy、能够请求任意签名的 automation account、包含 bridge 配置的 public bucket 等。
2. **Value-specific weaknesses**：脆弱的 oracle 参数、缺少 multi-party approval 的可升级合约、对 flash loan 敏感的流动性、能够绕过 timelock 的治理操作。

以 adversary 的方式处理队列：先从今天即可成功的 operational foothold 开始，再推进到深层的 protocol/economic manipulation 路径。<sup>[[1]](#references)</sup>

## 4. 在受控且贴近生产的环境中执行
- **Forked mainnet / isolated testnet**：复制 bytecode、storage 和 liquidity，使 flash-loan 路径、oracle 漂移及 bridge 流程能够端到端运行，同时不接触真实资金。<sup>[[1]](#references)</sup>
- **Blast-radius 规划**：在引爆场景前，定义 circuit breaker、可暂停模块、rollback runbook 和仅用于测试的 admin key。
- **Stakeholder 协调**：通知 custodian、oracle operator、bridge partner 和 compliance 团队，使其 monitoring 团队预期会出现相关流量。
- **Legal sign-off**：当模拟可能经过受监管通道时，记录 scope、授权和停止条件。

## 5. 与 AADAPT techniques 对齐的 Telemetry
对 telemetry stream 进行 instrument，使每个场景都能产生可执行的 detection data。<sup>[[1]](#references)</sup>

- **链级 trace**：完整 call graph、gas 使用量、transaction nonce、block timestamp，用于重建 flash-loan bundle、类似 reentrancy 的结构以及跨合约跳转。
- **Application/API log**：将每个链上 tx 关联到 human 或 automation identity（session ID、OAuth client、API key、CI job ID），并记录 IP 和 auth method。
- **KMS/HSM log**：记录每次签名的 key ID、caller principal、policy result、destination address 和 reason code。为变更窗口及高风险操作建立 baseline。
- **Oracle/feed metadata**：记录每次更新的数据源组成、上报值、与 rolling average 的偏差、触发的阈值以及执行的 failover 路径。
- **Bridge/swap trace**：使用 correlation ID、chain ID、relayer identity 和 hop timing，关联不同链上的 lock/mint/unlock 事件。
- **Anomaly marker**：派生 slippage spike、异常抵押率、异常 gas density 或跨链 velocity 等指标。

为所有内容添加 scenario ID 或 synthetic user ID，使 analyst 能够将 observables 与正在执行的 AADAPT technique 对齐。

## 6. Purple-team 循环与成熟度指标
1. 在受控环境中运行场景并记录 detection（alert、dashboard、被呼叫的 responder）。<sup>[[1]](#references)</sup>
2. 将每个步骤映射到具体的 AADAPT techniques，以及在 chain/app/KMS/oracle/bridge 层产生的 observables。
3. 制定并部署 detection hypothesis（threshold rule、correlation search、invariant check）。
4. 重复运行，直到 mean time to detect (MTTD) 和 mean time to contain (MTTC) 达到业务容忍范围，并且 playbook 能够可靠地阻止价值损失。

从三个维度跟踪项目成熟度：<sup>[[1]](#references)</sup>
- **Visibility**：每条关键价值路径在各个层面都有 telemetry。
- **Coverage**：端到端执行的优先 AADAPT techniques 占比。
- **Response**：能否在发生不可逆损失前暂停合约、撤销 key 或冻结流程。

典型里程碑：(1) 完成价值清单与 AADAPT 映射；(2) 完成第一个包含 detection 的端到端场景；(3) 每季度执行 Purple-team cycle，扩大 coverage 并降低 MTTD/MTTC。<sup>[[1]](#references)</sup>

## 7. 场景模板
使用以下可重复的 blueprint 设计能够直接映射到 AADAPT 行为的模拟。<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**：在单笔交易中借入临时资本，扭曲 AMM 价格/流动性，并在归还前触发错误定价的借贷、清算或 mint。
- **Execution**：
1. Fork 目标链，并使用类似生产环境的 liquidity 为 pool 注资。
2. 通过 flash loan 借入大额名义资金。
3. 执行经过校准的 swap，使价格/阈值跨过借贷、vault 或 derivative 逻辑所依赖的边界。
4. 在价格扭曲后立即调用 victim contract（borrow、liquidate、mint），然后归还 flash loan。
- **Measurement**：是否成功造成 invariant violation？是否触发 slippage/price-deviation monitor、circuit breaker 或 governance pause hook？analytics 多久能够标记异常 gas/call graph pattern？

### Scenario B – Oracle/data-feed poisoning
- **Objective**：确定被操纵的 feed 是否能够触发破坏性自动操作（大规模清算、错误结算）。
- **Execution**：
1. 在 fork/testnet 中部署 malicious feed，或调整 aggregator weight/quorum/update cadence，使其超出可接受的 deviation。
2. 让依赖合约读取被污染的 value，并执行其标准逻辑。
- **Measurement**：feed-level out-of-band alert、fallback oracle 激活、min/max bound enforcement，以及从异常开始到 operator 响应之间的 latency。

### Scenario C – Credential/signing abuse
- **Objective**：测试攻陷单个 signer 或 automation identity 是否会导致未授权升级、参数修改或 treasury drain。
- **Execution**：
1. 枚举拥有敏感 signing 权限的 identity（operator、CI token、调用 KMS/HSM 的 service account、multisig participant）。
2. 模拟 compromise（在 lab scope 内复用其 credential/key）。
3. 尝试 privileged action：升级 proxy、修改 risk parameter、mint/pause asset 或触发 governance proposal。
- **Measurement**：KMS/HSM log 是否针对 anomaly 发出 alert（time-of-day、destination drift、高风险操作突发增加）？policy 或 multisig threshold 能否阻止单方面 abuse？是否实施 throttle/rate limit 或额外 approval？

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**：评估 defenders 能否有效追踪并快速拦截经过 bridge、DEX router 和 privacy hop 快速 laundering 的资产。
- **Execution**：
1. 在常用 bridge 上串联 lock/mint 操作，在每一跳交错执行 swap/mixer，并维护每一跳的 correlation ID。
2. 加速 transfer，以压力测试 monitoring latency（在数分钟/数个 block 内完成 multi-hop）。
- **Measurement**：跨 telemetry 与 commercial chain analytics 关联事件所需的时间、重建路径的完整性、真实 incident 中识别可冻结 choke point 的能力，以及针对异常跨链 velocity/value 的 alert fidelity。

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
