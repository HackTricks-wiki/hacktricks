# Value-Centric Web3 Red Teaming (MITRE AADAPT)

MITRE Adversarial Actions in Digital Asset Payment Techniques（AADAPT）framework は、デジタルアセットシステムを標的とする adversarial actions と techniques を分類します。<sup>[[1]](#references)</sup> これを **threat-modeling の基盤**として扱い、アセットを mint、price、authorize、route できるすべてのコンポーネントを列挙し、それらの接点を AADAPT techniques にマッピングしたうえで、環境が不可逆的な経済的損失に耐えられるかを測定する red-team シナリオを実行します。

## 1. Inventory value-bearing components
off-chain であっても、value state に影響を与えられるすべての対象のマップを作成します。<sup>[[2]](#references)</sup>

- **Custodial signing services**（HSM/KMS clusters、Vault/KMaaS、bot や back-office jobs が使用する signing APIs）。key IDs、policies、automation identities、approval workflows を記録します。
- **Admin & upgrade paths** for contracts（proxy admins、governance timelocks、emergency pause keys、parameter registries）。誰または何が呼び出せるのか、どの quorum または delay のもとで実行されるのかを含めます。
- **On-chain protocol logic** handling lending、AMMs、vaults、staking、bridges、または settlement rails。想定している invariants（oracle prices、collateral ratios、rebalance cadence…）を文書化します。
- **Off-chain automation** that builds transactions（market-making bots、CI/CD pipelines、cron jobs、serverless functions）。これらは、signatures を要求できる API keys や service principals を保持していることが多くあります。
- **Oracles & data feeds**（aggregator composition、quorum、deviation thresholds、update cadence）。自動化された risk logic が依存する upstream をすべて記録します。
- **Bridges and cross-chain routers**（lock/mint contracts、relayers、settlement jobs）。chains または custodial stacks を相互接続するものです。

成果物: アセットがどのように移動し、誰が移動を authorize し、どの external signals が business logic に影響を与えるかを示す value-flow diagram。

## 2. Map components to AADAPT behaviors
AADAPT taxonomy を各コンポーネントに対する具体的な attack candidates に変換します。<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft、policy bypass、signing-abuse、governance takeover |
| Oracles/feeds | Input poisoning、aggregation manipulation、deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation、invariant breaking、parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities、batch replay、unauthorized deployment |
| Bridges/routers | Cross-chain evasion、rapid hop laundering、settlement desynchronization |

このマッピングにより、contracts だけでなく、間接的に value を steer できるすべての identities/automation もテストできます。

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: exposed CI credentials、over-privileged IAM roles、misconfigured KMS policies、arbitrary signatures を要求できる automation accounts、bridge configs を含む public buckets など。
2. **Value-specific weaknesses**: fragile oracle parameters、multi-party approvals のない upgradable contracts、flash-loan sensitive liquidity、timelocks を bypass する governance actions。

adversary と同じように queue に取り組みます。まず、今日すぐに成功する可能性がある operational footholds から開始し、その後、deep protocol/economic manipulation paths に進みます。<sup>[[2]](#references)</sup>

## 4. Execute in controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: bytecode、storage、liquidity を再現し、real funds に触れることなく flash-loan paths、oracle drifts、bridge flows を end-to-end で実行できるようにします。<sup>[[2]](#references)</sup>
- **Blast-radius planning**: シナリオを実行する前に、circuit breakers、pausable modules、rollback runbooks、test-only admin keys を定義します。
- **Stakeholder coordination**: custodians、oracle operators、bridge partners、compliance に通知し、それぞれの monitoring teams がこのトラフィックを想定できるようにします。
- **Legal sign-off**: simulations が regulated rails に及ぶ可能性がある場合は、scope、authorization、stop conditions を文書化します。

## 5. Telemetry aligned with AADAPT techniques
すべてのシナリオが actionable detection data を生成するように telemetry streams を instrument します。<sup>[[2]](#references)</sup>

- **Chain-level traces**: full call graphs、gas usage、transaction nonces、block timestamps を取得し、flash-loan bundles、reentrancy-like structures、cross-contract hops を再構成します。
- **Application/API logs**: 各 on-chain tx を human または automation identity（session ID、OAuth client、API key、CI job ID）に、IPs と auth methods を付けて紐付けます。
- **KMS/HSM logs**: すべての signature について、key ID、caller principal、policy result、destination address、reason codes を記録します。change windows と high-risk operations の baseline を作成します。
- **Oracle/feed metadata**: 各 update について、data source composition、reported value、rolling averages からの deviation、triggered thresholds、実行された failover paths を記録します。
- **Bridge/swap traces**: chains 間の lock/mint/unlock events を、correlation IDs、chain IDs、relayer identity、hop timing とともに相関させます。
- **Anomaly markers**: slippage spikes、abnormal collateralization ratios、unusual gas density、cross-chain velocity などの derived metrics。

すべてに scenario IDs または synthetic user IDs を付け、analysts が observables と実行対象の AADAPT technique を対応付けられるようにします。

## 6. Purple-team loop & maturity metrics
1. controlled environment でシナリオを実行し、detections（alerts、dashboards、responders paged）を取得します。<sup>[[2]](#references)</sup>
2. 各 step を specific AADAPT techniques と、chain/app/KMS/oracle/bridge planes で生成された observables にマッピングします。
3. detection hypotheses（threshold rules、correlation searches、invariant checks）を策定して deploy します。
4. mean time to detect（MTTD）と mean time to contain（MTTC）が business tolerances を満たし、playbooks が value loss を確実に停止できるまで再実行します。

program maturity を次の3軸で追跡します。<sup>[[2]](#references)</sup>
- **Visibility**: すべての critical value paths に、各 plane の telemetry が存在する。
- **Coverage**: 優先順位付けされた AADAPT techniques のうち、end-to-end で実行された割合。
- **Response**: irreversible loss の前に contracts を pause、keys を revoke、または flows を freeze できる能力。

Typical milestones: (1) value inventory + AADAPT mapping の完了、(2) detections を実装した最初の end-to-end scenario、(3) coverage を拡大し MTTD/MTTC を削減する quarterly purple-team cycles。<sup>[[2]](#references)</sup>

## 7. Scenario templates
AADAPT behaviors に直接マッピングできる simulations を設計するため、これらの repeatable blueprints を使用します。<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: 1つの transaction 内で一時的な capital を借り、AMM prices/liquidity を distortion させ、mispriced borrows、liquidations、または mints を trigger してから返済します。
- **Execution**:
1. target chain を fork し、production-like liquidity を pools に seed します。
2. flash loan で large notional を借ります。
3. lending、vault、または derivative logic が依存する price/threshold boundaries を超えるよう、calibrated swaps を実行します。
4. distortion の直後に victim contract を invoke します（borrow、liquidate、mint）。その後 flash loan を返済します。
- **Measurement**: invariant violation は成功したか。slippage/price-deviation monitors、circuit breakers、または governance pause hooks は trigger されたか。analytics が abnormal gas/call graph pattern を flag するまでの時間はどの程度か。

### Scenario B – Oracle/data-feed poisoning
- **Objective**: manipulated feeds によって destructive automated actions（mass liquidations、incorrect settlements）が trigger されるかを判断します。
- **Execution**:
1. fork/testnet で malicious feed を deploy するか、aggregator weights/quorum/update cadence を tolerated deviation の範囲外に調整します。
2. dependent contracts に poisoned values を consume させ、standard logic を実行させます。
- **Measurement**: feed-level out-of-band alerts、fallback oracle activation、min/max bound enforcement、anomaly onset から operator response までの latency。

### Scenario C – Credential/signing abuse
- **Objective**: 1つの signer または automation identity の compromise により、unauthorized upgrades、parameter changes、または treasury drains が可能になるかをテストします。
- **Execution**:
1. sensitive signing rights を持つ identities（operators、CI tokens、KMS/HSM を invoke する service accounts、multisig participants）を列挙します。
2. compromise を simulate します（lab scope 内で their credentials/keys を再利用）。
3. privileged actions を試行します。proxy の upgrade、risk parameters の変更、assets の mint/pause、または governance proposals の trigger などです。
- **Measurement**: KMS/HSM logs は anomaly alerts（time-of-day、destination drift、high-risk operations の burst）を raise するか。policies または multisig thresholds は unilateral abuse を防止できるか。throttles/rate limits または additional approvals は enforced されているか。

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: bridges、DEX routers、privacy hops を通じて rapid laundering された assets を defenders がどの程度 trace し、迅速に interdict できるかを評価します。
- **Execution**:
1. common bridges 上で lock/mint operations を連鎖させ、各 hop で swaps/mixers を interleave し、per-hop correlation IDs を維持します。
2. monitoring latency に負荷をかけるため、transfers を accelerate します（数分または数 blocks 内の multi-hop）。
- **Measurement**: telemetry と commercial chain analytics 間で events を correlate するまでの時間、reconstructed path の完全性、real incident で freeze の choke points を特定する能力、abnormal cross-chain velocity/value に対する alert fidelity。

## References

- [1] [デジタルアセット向け AADAPT(TM) Cyber Threat Framework（MITRE）](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap としての MITRE AADAPT Framework（Bishop Fox）](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
