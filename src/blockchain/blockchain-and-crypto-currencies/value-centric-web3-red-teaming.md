# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) framework は、デジタル資産システムを標的とする敵対的なアクションと technique を分類します。<sup>[[1]](#references)</sup> これを **threat-modeling の基盤**として扱い、資産の mint、価格付け、承認、またはルーティングを行えるすべてのコンポーネントを列挙し、それらの接点を AADAPT techniques にマッピングして、環境が不可逆的な経済的損失に耐えられるかを測定する red-team シナリオを実行します。

## 1. 価値を持つコンポーネントのインベントリ作成
オンチェーンでなくても、value state に影響を与えられるすべての要素をマッピングします。<sup>[[2]](#references)</sup>

- **Custodial signing services**（HSM/KMS clusters、Vault/KMaaS、bot や back-office jobs が使用する signing APIs）。key IDs、policies、automation identities、approval workflows を記録します。
- **Admin & upgrade paths** for contracts（proxy admins、governance timelocks、emergency pause keys、parameter registries）。それらを呼び出せる主体または要素と、必要な quorum または delay も含めます。
- **On-chain protocol logic** handling lending、AMMs、vaults、staking、bridges、または settlement rails。前提としている invariants（oracle prices、collateral ratios、rebalance cadence…）を文書化します。
- **Off-chain automation** that builds transactions（market-making bots、CI/CD pipelines、cron jobs、serverless functions）。これらは、signature を要求できる API keys や service principals を保持していることがよくあります。
- **Oracles & data feeds**（aggregator composition、quorum、deviation thresholds、update cadence）。automated risk logic が依存するすべての upstream を記録します。
- **Bridges and cross-chain routers**（lock/mint contracts、relayers、settlement jobs）。chain 間または custodial stacks 間を接続する要素です。

成果物: assets がどのように移動し、誰がその移動を承認し、どの外部シグナルが business logic に影響するかを示す value-flow diagram。

## 2. コンポーネントを AADAPT behaviors にマッピング
AADAPT taxonomy を各コンポーネントに対する具体的な attack candidates に変換します。<sup>[[2]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft、policy bypass、signing-abuse、governance takeover |
| Oracles/feeds | Input poisoning、aggregation manipulation、deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation、invariant breaking、parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities、batch replay、unauthorized deployment |
| Bridges/routers | Cross-chain evasion、rapid hop laundering、settlement desynchronization |

このマッピングにより、contracts だけでなく、間接的に value を操作できるすべての identity/automation もテストできます。

## 3. attacker feasibility と business impact に基づく優先順位付け

1. **Operational weaknesses**: exposed CI credentials、over-privileged IAM roles、misconfigured KMS policies、任意の signatures を要求できる automation accounts、bridge configs を含む public buckets など。
2. **Value-specific weaknesses**: 脆弱な oracle parameters、multi-party approvals のない upgradable contracts、flash-loan に敏感な liquidity、timelocks を bypass できる governance actions。

adversary のように queue に取り組みます。まず、今日成功する可能性がある operational footholds から始め、その後、深い protocol/economic manipulation paths へ進みます。<sup>[[2]](#references)</sup>

## 4. 管理された production-realistic environments で実行
- **Forked mainnets / isolated testnets**: bytecode、storage、liquidity を再現し、real funds に触れることなく flash-loan paths、oracle drifts、bridge flows を end-to-end で実行します。<sup>[[2]](#references)</sup>
- **Blast-radius planning**: scenario を実行する前に、circuit breakers、pausable modules、rollback runbooks、test-only admin keys を定義します。
- **Stakeholder coordination**: custodians、oracle operators、bridge partners、compliance に通知し、それぞれの monitoring teams が該当 traffic を想定できるようにします。
- **Legal sign-off**: simulations が regulated rails を越える可能性がある場合、scope、authorization、stop conditions を文書化します。

## 5. AADAPT techniques に対応した telemetry
すべての scenario が実行可能な detection data を生成するよう、telemetry streams を instrument します。<sup>[[2]](#references)</sup>

- **Chain-level traces**: full call graphs、gas usage、transaction nonces、block timestamps。flash-loan bundles、reentrancy-like structures、cross-contract hops を再構成するために使用します。
- **Application/API logs**: 各 on-chain tx を human または automation identity（session ID、OAuth client、API key、CI job ID）に関連付け、IPs と auth methods も記録します。
- **KMS/HSM logs**: 各 signature について、key ID、caller principal、policy result、destination address、reason codes を記録します。change windows と high-risk operations の baseline を作成します。
- **Oracle/feed metadata**: update ごとの data source composition、reported value、rolling averages からの deviation、triggered thresholds、実行された failover paths。
- **Bridge/swap traces**: correlation IDs、chain IDs、relayer identity、hop timing とともに、chain 間の lock/mint/unlock events を関連付けます。
- **Anomaly markers**: slippage spikes、abnormal collateralization ratios、unusual gas density、cross-chain velocity などの derived metrics。

すべてに scenario IDs または synthetic user IDs を付与し、analysts が observables と実行対象の AADAPT technique を関連付けられるようにします。

## 6. Purple-team loop と maturity metrics
1. controlled environment で scenario を実行し、detections（alerts、dashboards、responders paged）を取得します。<sup>[[2]](#references)</sup>
2. 各 step を specific AADAPT techniques と、chain/app/KMS/oracle/bridge planes で生成された observables にマッピングします。
3. detection hypotheses（threshold rules、correlation searches、invariant checks）を策定して deploy します。
4. mean time to detect (MTTD) と mean time to contain (MTTC) が business tolerances を満たし、playbooks が value loss を確実に停止できるまで再実行します。

program maturity を次の 3 軸で追跡します。<sup>[[2]](#references)</sup>
- **Visibility**: すべての critical value paths に、各 plane の telemetry が存在する。
- **Coverage**: 優先度付けされた AADAPT techniques のうち、end-to-end で実行された割合。
- **Response**: irreversible loss の前に contracts を pause し、keys を revoke し、flows を freeze する能力。

一般的な milestones: (1) 完了した value inventory + AADAPT mapping、(2) detections を実装した最初の end-to-end scenario、(3) coverage を拡大し、MTTD/MTTC を短縮する quarterly purple-team cycles。<sup>[[2]](#references)</sup>

## 7. Scenario templates
AADAPT behaviors に直接マッピングできる simulations を設計するため、これらの反復可能な blueprints を使用します。<sup>[[2]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**: 1 transaction 内で一時的な capital を borrow し、AMM prices/liquidity を distort して、mispriced borrows、liquidations、または mints を trigger し、その前に返済する。
- **Execution**:
1. target chain を fork し、production-like liquidity で pools を seed します。
2. flash loan を介して大きな notional を borrow します。
3. lending、vault、または derivative logic が依存する price/threshold boundaries を越えるよう、calibrated swaps を実行します。
4. distortion の直後に victim contract（borrow、liquidate、mint）を invoke し、flash loan を返済します。
- **Measurement**: invariant violation は成功したか。slippage/price-deviation monitors、circuit breakers、または governance pause hooks は trigger されたか。analytics が abnormal gas/call graph pattern を検知するまでにどれだけ時間がかかったか。

### Scenario B – Oracle/data-feed poisoning
- **Objective**: manipulated feeds が destructive automated actions（mass liquidations、incorrect settlements）を trigger できるかを判定する。
- **Execution**:
1. fork/testnet 上で malicious feed を deploy するか、aggregator weights/quorum/update cadence を tolerated deviation の範囲を超えるように変更します。
2. dependent contracts に poisoned values を消費させ、標準 logic を実行させます。
- **Measurement**: feed-level out-of-band alerts、fallback oracle activation、min/max bound enforcement、anomaly onset から operator response までの latency。

### Scenario C – Credential/signing abuse
- **Objective**: single signer または automation identity の compromise により、unauthorized upgrades、parameter changes、または treasury drains が可能になるかをテストする。
- **Execution**:
1. sensitive signing rights を持つ identities（operators、CI tokens、KMS/HSM を invoke する service accounts、multisig participants）を列挙します。
2. compromise を simulate します（lab scope 内でその credentials/keys を再利用）。
3. privileged actions を試行します。proxy の upgrade、risk parameters の変更、assets の mint/pause、または governance proposals の trigger などです。
- **Measurement**: KMS/HSM logs は anomaly alerts（time-of-day、destination drift、high-risk operations の burst）を raise するか。policies または multisig thresholds は unilateral abuse を防止できるか。throttles/rate limits または additional approvals は enforcement されているか。

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: bridges、DEX routers、privacy hops を介して rapid laundering された assets を、defenders がどの程度正確に trace し、迅速に interdict できるかを評価する。
- **Execution**:
1. common bridges を介した lock/mint operations を chain し、各 hop で swaps/mixers を interleave しながら、per-hop correlation IDs を維持します。
2. monitoring latency に負荷をかけるため transfers を accelerate します（数分または数 blocks 内の multi-hop）。
- **Measurement**: telemetry と commercial chain analytics 間で events を correlate するまでの時間、reconstructed path の完全性、real incident で freeze する choke points を特定する能力、abnormal cross-chain velocity/value に対する alert fidelity。

## References

- [1] [デジタル資産向け AADAPT(TM) Cyber Threat Framework (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Red Team Roadmap としての MITRE AADAPT Framework (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
