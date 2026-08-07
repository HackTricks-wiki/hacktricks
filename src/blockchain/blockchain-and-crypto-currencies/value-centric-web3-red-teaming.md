# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE Adversarial Actions in Digital Asset Payment Techniques（AADAPT）matrix は、単なるインフラではなく、デジタル価値を操作する攻撃者の行動を捉えます。これを**脅威モデリングの基盤**として扱い、資産を mint、価格付け、承認、またはルーティングできるすべてのコンポーネントを列挙し、それらの接点を AADAPT techniques にマッピングします。そのうえで、環境が不可逆的な経済的損失に耐えられるかを測定する Red Team シナリオを実行します。

## 1. 価値を持つコンポーネントのインベントリ作成
オンチェーンでなくても、価値の状態に影響を与えられるすべての要素のマップを作成します。<sup>[[1]](#references)</sup>

- **Custodial signing services**（HSM/KMS クラスター、Vault/KMaaS、bot やバックオフィスのジョブが使用する signing API）。key ID、policy、automation identity、承認ワークフローを記録します。
- **コントラクトの Admin および upgrade path**（proxy admin、governance timelock、emergency pause key、parameter registry）。誰が、または何が、どの quorum や delay のもとで呼び出せるのかを含めます。
- **Lending、AMM、vault、staking、bridge、settlement rail を処理する On-chain protocol logic**。それらが前提とする invariant（oracle price、collateral ratio、rebalance cadence…）を文書化します。
- **トランザクションを構築する Off-chain automation**（market-making bot、CI/CD pipeline、cron job、serverless function）。これらは、署名を要求できる API key や service principal を保持していることが多くあります。
- **Oracle および data feed**（aggregator の構成、quorum、deviation threshold、update cadence）。自動化された risk logic が依存するすべての upstream を記録します。
- **Bridge および cross-chain router**（lock/mint contract、relayer、settlement job）。chain や custodial stack を相互接続するものです。

成果物：資産がどのように移動し、誰がその移動を承認し、どの外部シグナルが business logic に影響を与えるのかを示す value-flow diagram。

## 2. コンポーネントを AADAPT behaviors にマッピング
AADAPT taxonomy を、各コンポーネントに対する具体的な攻撃候補へ変換します。<sup>[[1]](#references)</sup>

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft、policy bypass、signing-abuse、governance takeover |
| Oracles/feeds | Input poisoning、aggregation manipulation、deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation、invariant breaking、parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities、batch replay、unauthorized deployment |
| Bridges/routers | Cross-chain evasion、rapid hop laundering、settlement desynchronization |

このマッピングにより、contract だけでなく、間接的に value を操作できるすべての identity/automation を確実にテストできます。

## 3. 攻撃者の実行可能性と business impact に基づく優先順位付け

1. **Operational weaknesses**：露出した CI credential、過剰な権限を持つ IAM role、誤設定された KMS policy、任意の署名を要求できる automation account、bridge 設定を含む public bucket など。
2. **Value-specific weaknesses**：脆弱な oracle parameter、multi-party approval のない upgradable contract、flash-loan に影響を受けやすい liquidity、timelock を回避できる governance action。

攻撃者のように queue を処理します。まず、今日でも成功する可能性がある operational foothold から始め、その後、深い protocol/economic manipulation path へ進みます。<sup>[[1]](#references)</sup>

## 4. 制御された本番環境に近い環境で実行
- **Forked mainnet / isolated testnet**：bytecode、storage、liquidity を再現し、実際の資金に触れることなく、flash-loan path、oracle drift、bridge flow を end-to-end で実行します。<sup>[[1]](#references)</sup>
- **Blast-radius planning**：シナリオを実行する前に、circuit breaker、pausable module、rollback runbook、test-only admin key を定義します。
- **Stakeholder coordination**：custodian、oracle operator、bridge partner、compliance に通知し、それぞれの monitoring team がトラフィックを想定できるようにします。
- **Legal sign-off**：simulation が規制対象の rail に及ぶ可能性がある場合、scope、authorization、stop condition を文書化します。

## 5. AADAPT techniques に合わせた Telemetry
すべてのシナリオから実行可能な detection data が生成されるよう、telemetry stream を整備します。<sup>[[1]](#references)</sup>

- **Chain-level trace**：完全な call graph、gas 使用量、transaction nonce、block timestamp。flash-loan bundle、reentrancy に類似した構造、contract 間の hop を再構成するために使用します。
- **Application/API log**：各 on-chain tx を human または automation identity（session ID、OAuth client、API key、CI job ID）に紐付け、IP と auth method も記録します。
- **KMS/HSM log**：すべての署名について、key ID、caller principal、policy result、destination address、reason code を記録します。変更 window と high-risk operation の baseline を作成します。
- **Oracle/feed metadata**：更新ごとの data source 構成、reported value、rolling average からの deviation、trigger された threshold、実行された failover path。
- **Bridge/swap trace**：chain 間の lock/mint/unlock event を correlation ID、chain ID、relayer identity、hop timing と関連付けます。
- **Anomaly marker**：slippage spike、異常な collateralization ratio、通常と異なる gas density、cross-chain velocity などの derived metric。

すべてに scenario ID または synthetic user ID を付与し、analyst が observables と実行対象の AADAPT technique を対応付けられるようにします。

## 6. Purple-team loop と maturity metric
1. 制御された環境でシナリオを実行し、detection（alert、dashboard、呼び出された responder）を取得します。<sup>[[1]](#references)</sup>
2. 各ステップを具体的な AADAPT technique と、chain/app/KMS/oracle/bridge plane で生成された observable にマッピングします。
3. detection hypothesis（threshold rule、correlation search、invariant check）を策定して deploy します。
4. mean time to detect（MTTD）と mean time to contain（MTTC）が business tolerance を満たし、playbook が value loss を確実に停止できるまで再実行します。

program maturity を次の 3 軸で追跡します。<sup>[[1]](#references)</sup>
- **Visibility**：すべての critical value path に、各 plane の telemetry が存在する。
- **Coverage**：優先度を付けた AADAPT technique のうち、end-to-end で実行した割合。
- **Response**：不可逆的な損失が発生する前に、contract を pause し、key を revoke し、または flow を freeze できる能力。

一般的な milestone は、(1) value inventory と AADAPT mapping の完了、(2) detection を実装した最初の end-to-end scenario、(3) coverage を拡大し、MTTD/MTTC を低下させる quarterly purple-team cycle です。<sup>[[1]](#references)</sup>

## 7. Scenario template
AADAPT behaviors に直接マッピングできる simulation を設計するため、以下の反復可能な blueprint を使用します。<sup>[[1]](#references)</sup>

### Scenario A – Flash-loan economic manipulation
- **Objective**：1 つの transaction 内で一時的な capital を借り、AMM の price/liquidity を歪め、返済前に mispriced borrow、liquidation、または mint を発生させる。
- **Execution**：
1. 対象 chain を fork し、本番に近い liquidity を pool に投入します。
2. flash loan で大きな notional を借ります。
3. lending、vault、または derivative logic が依存する price/threshold boundary を超えるよう、調整した swap を実行します。
4. distortion の直後に victim contract（borrow、liquidate、mint）を呼び出し、flash loan を返済します。
- **Measurement**：invariant violation は成功したか。slippage/price-deviation monitor、circuit breaker、または governance pause hook は trigger されたか。異常な gas/call graph pattern が analytics に検知されるまでにどれだけ時間がかかったか。

### Scenario B – Oracle/data-feed poisoning
- **Objective**：manipulated feed が破壊的な automated action（大量 liquidation、誤った settlement）を trigger できるかを確認する。
- **Execution**：
1. fork/testnet 上で malicious feed を deploy するか、許容される deviation を超えるよう aggregator weight/quorum/update cadence を調整します。
2. 依存する contract に poisoned value を消費させ、標準の logic を実行させます。
- **Measurement**：feed-level の out-of-band alert、fallback oracle の activation、min/max bound の enforcement、anomaly の発生から operator response までの latency。

### Scenario C – Credential/signing abuse
- **Objective**：単一の signer または automation identity の compromise により、unauthorized upgrade、parameter change、または treasury drain が可能になるかをテストする。
- **Execution**：
1. sensitive signing right を持つ identity（operator、CI token、KMS/HSM を呼び出す service account、multisig participant）を列挙します。
2. compromise を simulation します（lab scope 内でそれらの credential/key を再利用します）。
3. privileged action を試行します。proxy の upgrade、risk parameter の変更、asset の mint/pause、または governance proposal の trigger などです。
- **Measurement**：KMS/HSM log は anomaly alert（time-of-day、destination drift、high-risk operation の burst）を生成するか。policy または multisig threshold は unilateral abuse を防げるか。throttle/rate limit または追加承認は enforcement されているか。

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**：bridge、DEX router、privacy hop をまたいで迅速に laundering された asset を、defender がどの程度正確に追跡し、阻止できるかを評価する。
- **Execution**：
1. 複数の一般的な bridge にまたがる lock/mint operation を連結し、各 hop で swap/mixer を挟み、hop ごとの correlation ID を維持します。
2. monitoring latency に負荷をかけるため transfer を高速化します（数分または数 block 以内の multi-hop）。
- **Measurement**：telemetry と commercial chain analytics にまたがる event の correlation に要する時間、再構成された path の完全性、実際の incident で freeze するための choke point を特定できる能力、異常な cross-chain velocity/value に対する alert fidelity。

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
