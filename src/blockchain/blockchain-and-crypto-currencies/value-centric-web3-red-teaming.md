# Value-Centric Web3 Red Teaming (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

The MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix captures attacker behaviors that manipulate digital value rather than just infrastructure. Treat it as a **threat-modeling backbone**: enumerate every component that can mint, price, authorize, or route assets, map those touchpoints to AADAPT techniques, and then drive red-team scenarios that measure whether the environment can resist irreversible economic loss.

## 1. Inventory value-bearing components
価値状態に影響を与え得るすべての要素（オンチェーン外のものも含む）をマッピングする。

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs)。キーID、ポリシー、自動化用の識別子、承認ワークフローを記録する。
- **Admin & upgrade paths** for contracts (proxy admins, governance timelocks, emergency pause keys, parameter registries)。誰・何が呼べるか、どのクォーラムや遅延で実行されるかを含める。
- **On-chain protocol logic** handling lending, AMMs, vaults, staking, bridges, or settlement rails。彼らが前提とする不変条件（oracle prices、collateral ratios、rebalance cadence など）をドキュメント化する。
- **Off-chain automation** that builds transactions (market-making bots, CI/CD pipelines, cron jobs, serverless functions)。これらはしばしばAPIキーやservice principalsを保有し、署名を要求できる。
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence)。自動化されたリスクロジックが依存するすべての上流を記録する。
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) tying chains or custodial stacks together。

Deliverable: 資産がどのように移動するか、誰が移動を承認するか、どの外部シグナルがビジネスロジックに影響を与えるかを示す value-flow diagram。

## 2. Map components to AADAPT behaviors
AADAPT分類を各コンポーネントごとの具体的な攻撃候補に翻訳する。

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

このマッピングにより、契約そのものだけでなく、間接的に価値を操れるすべてのアイデンティティや自動化もテストできる。

## 3. Prioritize by attacker feasibility vs. business impact

1. **Operational weaknesses**: 公開されたCI認証情報、権限が過剰なIAMロール、誤設定されたKMSポリシー、任意署名を要求できる自動化アカウント、bridge構成が置かれたpublic buckets など。
2. **Value-specific weaknesses**: 脆弱なoracleパラメータ、マルチパーティ承認のないupgradable contracts、flash-loanに弱い流動性、timelocksを迂回できるgovernanceアクション。

攻撃者のようにキューを処理する：今日成功し得る運用上の足場から始め、次に深いプロトコル／経済操作の経路へ進む。

## 4. Execute in controlled, production-realistic environments
- **Forked mainnets / isolated testnets**: バイトコード、ストレージ、流動性を再現して、flash-loan経路、oracleドリフト、bridgeフローが実運用資金に触れずにエンドツーエンドで動くようにする。
- **Blast-radius planning**: 回路遮断、pausable modules、ロールバック手順、テスト専用のadminキーを定義してからシナリオを実行する。
- **Stakeholder coordination**: custodians、oracle operators、bridge partners、compliance を通知して監視チームがトラフィックを期待できるようにする。
- **Legal sign-off**: シミュレーションが規制対象のレールを横断する可能性がある場合は範囲、権限、停止条件を文書化する。

## 5. Telemetry aligned with AADAPT techniques
各シナリオが実行可能な検出データを生成するようにテレメトリストリームを計測する。

- **Chain-level traces**: フルコールグラフ、gas使用量、transaction nonces、block timestamps — flash-loanバンドル、再入可能性に似た構造、クロスコントラクトホップを再構築するため。
- **Application/API logs**: 各オンチェーントランザクションを人か自動化のアイデンティティ（session ID、OAuth client、API key、CI job ID）に紐付け、IPと認証方法を記録する。
- **KMS/HSM logs**: key ID、caller principal、policy result、destination address、各署名のreason codes。変更ウィンドウと高リスク操作のベースラインを取る。
- **Oracle/feed metadata**: 各アップデートのデータソース構成、報告値、ローリング平均からの乖離、しきい値トリガー、フェイルオーバー経路。
- **Bridge/swap traces**: lock/mint/unlock イベントをチェーン間で相関付け、correlation IDs、chain IDs、relayer identity、hop timing を含める。
- **Anomaly markers**: slippageの急増、異常なcollateralization ratios、異常なgas密度、クロスチェーンのvelocity などの派生指標。

すべてに scenario IDs や synthetic user IDs をタグ付けして、アナリストが観測データを実行中の AADAPT 技術と整合できるようにする。

## 6. Purple-team loop & maturity metrics
1. 制御された環境でシナリオを実行し、検出を収集する（アラート、ダッシュボード、応答者のページング）。
2. 各ステップを特定の AADAPT 技術および chain/app/KMS/oracle/bridge プレーンで生成された観測子にマッピングする。
3. 検出仮説（しきい値ルール、相関検索、不変条件チェック）を作成して展開する。
4. MTTD（mean time to detect）と MTTC（mean time to contain）がビジネス許容値を満たし、プレイブックが信頼性をもって価値損失を停止できるまで再実行する。

プログラム成熟度を3つの軸で追跡する：
- **Visibility**: 重要な価値経路ごとに各プレーンのテレメトリが存在すること。
- **Coverage**: 優先された AADAPT 技術のうちエンドツーエンドで演習された割合。
- **Response**: 不可逆な損失が発生する前に契約を一時停止、キーを無効化、フローを凍結できる能力。

典型的なマイルストーン: (1) 完了した価値インベントリ + AADAPT マッピング、(2) 検出を実装した最初のエンドツーエンドシナリオ、(3) カバレッジを拡大し MTTD/MTTC を低下させる四半期ごとの purple-team サイクル。

## 7. Scenario templates
これらの再利用可能なブループリントを使い、AADAPT 振る舞いに直接マップするシミュレーションを設計する。

### Scenario A – Flash-loan economic manipulation
- **Objective**: 1トランザクション内で一時的な資本を借り、AMMの価格／流動性を歪めて、借入・清算・mint を誤価格で誘発し、返済前に利益を確定する。
- **Execution**:
1. ターゲットチェーンをforkし、プロダクションに近い流動性でプールをシードする。
2. flash loan で大口を借りる。
3. 貸し出し、vault、デリバティブロジックが依存する価格／しきい値を超えるように調整されたスワップを実行する。
4. 歪曲直後に被害者コントラクトを呼び出す（borrow、liquidate、mint など）そして flash loan を返済する。
- **Measurement**: 不変条件の違反は成功したか？ slippage/price-deviation モニタ、回路遮断、governance pause フックはトリガーされたか？異常な gas/call graph パターンが分析にフラグされるまでにどれくらいかかったか？

### Scenario B – Oracle/data-feed poisoning
- **Objective**: 操作されたfeedが破壊的な自動処理（大規模清算、誤った決済）を引き起こせるかを確認する。
- **Execution**:
1. fork/testnet 内で悪意あるfeedをデプロイするか、aggregatorの重み／quorum／update cadence を許容される乖離を超えるように調整する。
2. 依存するコントラクトが毒された値を消費して標準ロジックを実行するのを許す。
- **Measurement**: feedレベルのアウトオブバンドアラート、fallback oracle の起動、min/max境界の施行、異常開始からオペレータ応答までの遅延。

### Scenario C – Credential/signing abuse
- **Objective**: 単一のsignerや自動化アイデンティティの侵害で、未承認のアップグレード、パラメータ変更、トレジャリードレインが可能かをテストする。
- **Execution**:
1. 敏感な署名権を持つアイデンティティ（operators、CI tokens、KMS/HSMを呼ぶservice accounts、multisig参加者）を列挙する。
2. ラボ範囲内でそのコンプロマイズをシミュレートする（資格情報／キーを再利用）。
3. 特権アクションを試みる：proxyのupgrade、リスクパラメータの変更、資産のmint/pause、governance proposal のトリガーなど。
- **Measurement**: KMS/HSM logs は異常アラートを上げるか（時刻帯、送信先の乖離、高リスク操作のバースト）？ポリシーやmultisigのしきい値で単独の悪用を防げるか？スロットル／レート制限や追加承認は適用されるか？

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: bridges、DEX routers、privacy hops を経由して迅速に洗浄された資産を、守備側がどれだけ速く追跡・阻止できるかを評価する。
- **Execution**:
1. 一般的なbridgesを跨いで lock/mint 操作を連結し、各ホップでスワップ／ミキサーを織り交ぜ、ホップごとに correlation IDs を維持する。
2. 監視レイテンシに負荷をかけるためにトランスファーを加速する（数分／数ブロックでのマルチホップ）。
- **Measurement**: テレメトリ＋商用チェーン解析でイベントを相関付ける時間、再構築された経路の完全性、実際のインシデントで凍結するためのチョークポイントを特定する能力、異常なクロスチェーン velocity/value に対するアラートの精度。

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
