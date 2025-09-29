# AI リスク

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASPはAIシステムに影響を与える可能性のある機械学習のトップ10の脆弱性を特定しています。これらの脆弱性は、data poisoning、model inversion、adversarial attacksなどを含むさまざまなセキュリティ問題につながる可能性があります。安全なAIシステムを構築するには、これらの脆弱性を理解することが重要です。

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: 攻撃者は**incoming data**に微細で目に見えない変更を加え、モデルに誤った判断をさせます。\
*例*: 停止標識に少量のペイントを付けると、self‑driving carがそれを速度制限標識として「認識」してしまう。

- **Data Poisoning Attack**: **training set**が悪意あるサンプルで意図的に汚染され、モデルに有害な規則を学習させます。\
*例*: マルウェアのバイナリがアンチウイルスの学習コーパスで「benign」と誤ラベルされ、類似のマルウェアが後で見逃される。

- **Model Inversion Attack**: 出力をプローブすることで、攻撃者は元の入力の機密特徴を再構築する**reverse model**を構築します。\
*例*: 癌検出モデルの予測から患者のMRI画像を再現する。

- **Membership Inference Attack**: 攻撃者は信頼度の違いを見つけることで、特定の**record**が学習に使われたかどうかを判定します。\
*例*: ある人物の銀行取引がfraud‑detection modelのトレーニングデータに含まれていることを確認する。

- **Model Theft**: 繰り返しクエリを送ることで、攻撃者は意思決定境界を学習し、**clone the model's behavior**（および知的財産）を盗用します。\
*例*: ML‑as‑a‑Service APIから十分なQ&Aペアを集めて、ほぼ同等のローカルモデルを構築する。

- **AI Supply‑Chain Attack**: **ML pipeline**内の任意のコンポーネント（データ、ライブラリ、pre‑trained weights、CI/CD）を侵害して下流のモデルを汚染します。\
*例*: model‑hubの依存関係が汚染され、バックドア付きのsentiment‑analysis modelが多くのアプリに配布される。

- **Transfer Learning Attack**: 悪意あるロジックが**pre‑trained model**に植え付けられ、被害者のタスクへのfine‑tuning後も残存します。\
*例*: 隠れたトリガーを持つvision backboneが医療画像用に適応されてもラベルを反転させ続ける。

- **Model Skewing**: 微妙に偏ったまたは誤ラベルされたデータにより、**shifts the model's outputs**して攻撃者の意図を有利にします。\
*例*: 「clean」なspamメールをhamとしてラベル付けして注入し、今後同様のメールをspamフィルタが通すようにする。

- **Output Integrity Attack**: 攻撃者は**alters model predictions in transit**し、モデル自体を改変することなく下流システムを騙します。\
*例*: ファイル隔離前にmalware classifierの「malicious」判定を「benign」に書き換える。

- **Model Poisoning** --- 書き込みアクセスを得た後などに、**model parameters**自体に直接かつ標的的な変更を加えて行動を変えます。\
*例*: 本番中のfraud‑detection modelの重みを微調整し、特定のカードの取引が常に承認されるようにする。


## Google SAIF Risks

Googleの[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)は、AIシステムに関連するさまざまなリスクを概説しています:

- **Data Poisoning**: 悪意のあるアクターがtraining/tuningデータを改変または注入して精度を低下させ、バックドアを埋め込んだり結果を歪めたりして、データライフサイクル全体でモデルの整合性を損なう。

- **Unauthorized Training Data**: 著作権のあるデータ、機密データ、許可されていないデータセットを取り込むと、モデルが許可されていないデータから学習するため、法的・倫理的・パフォーマンス上の責任が生じる。

- **Model Source Tampering**: サプライチェーンや内部関係者によるモデルコード、依存関係、weightsの改変が、再学習後も残る隠れたロジックを埋め込む可能性がある。

- **Excessive Data Handling**: 不十分なデータ保持やガバナンスによって、必要以上の個人データを保存・処理してしまい、露出やコンプライアンスリスクが高まる。

- **Model Exfiltration**: 攻撃者がmodel files/weightsを盗むと、知的財産の喪失や模倣サービス、追随攻撃を可能にする。

- **Model Deployment Tampering**: 攻撃者がモデルアーティファクトやservingインフラを改変すると、稼働中のモデルが検証済みのバージョンと異なり、動作が変わる可能性がある。

- **Denial of ML Service**: APIを洪水させたり「sponge」入力を送ることでcompute/energyを枯渇させ、モデルをオフラインにする（従来のDoS攻撃と類似）。

- **Model Reverse Engineering**: 大量の入力‑出力ペアを収集することで、攻撃者はモデルをクローンまたは蒸留し、模倣製品やカスタマイズされたadversarial攻撃を促進する。

- **Insecure Integrated Component**: 脆弱なプラグイン、エージェント、上流サービスにより、攻撃者がAIパイプライン内にコードを注入したり権限昇格したりできる。

- **Prompt Injection**: 直接または間接的にプロンプトを作成してシステム意図を上書きする命令を密輸入させ、モデルに意図しないコマンドを実行させる。

- **Model Evasion**: 精巧に設計された入力がモデルを誤分類させたり、hallucinateさせたり、許可されていない出力を生成させ、安全性と信頼を損なう。

- **Sensitive Data Disclosure**: モデルがトレーニングデータやユーザーコンテキストから個人情報や機密情報を漏えいさせ、プライバシーや規制に違反する。

- **Inferred Sensitive Data**: モデルが提供されていない個人属性を推測し、推論による新たなプライバシー被害を生む。

- **Insecure Model Output**: サニタイズされていない応答が有害なコード、誤情報、不適切なコンテンツをユーザーや下流システムに渡してしまう。

- **Rogue Actions**: 自律的に統合されたエージェントが、十分なユーザー監視なしに（ファイル書き込み、API呼び出し、購入など）意図しない現実世界の操作を実行する。

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)は、AIシステムに関連するリスクを理解し軽減するための包括的なフレームワークを提供します。これは、攻撃者がAIモデルに対して使用するさまざまな攻撃手法や戦術を分類し、AIシステムを使用して異なる攻撃を実行する方法についても整理しています。

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻撃者はアクティブなセッショントークンやcloud API credentialsを盗んで、無許可で有料のcloud‑hosted LLMを呼び出します。アクセスはしばしば被害者のアカウントをフロントするreverse proxiesを通じて再販されます（例: "oai-reverse-proxy" deployments）。結果として、金銭的損失、ポリシー外でのモデルの悪用、被害テナントへの帰属といった問題が発生します。

TTPs:
- 感染したdeveloper machinesやbrowsersからtokensを収集する；CI/CDのシークレットを盗む；leaked cookiesを購入する。
- 本物のプロバイダへリクエストを転送するreverse proxyを立ち上げ、upstream keyを隠しつつ多くの顧客を多重化する。
- enterprise guardrailsやレート制限を回避するために、直接base‑model endpointsを悪用する。

Mitigations:
- tokensをdevice fingerprint、IP範囲、client attestationにバインドする；短い有効期限を強制し、MFAでリフレッシュさせる。
- 鍵のスコープを最小限にする（ツールアクセス不可、可能な場合はread‑only）；異常時にローテーションする。
- 安全フィルタ、ルートごとのクォータ、テナント分離を強制するポリシーゲートウェイの背後でサーバー側からすべてのトラフィックを終端させる。
- 異常な使用パターン（急激な支出のスパイク、通常と異なるリージョン、UA strings）を監視し、疑わしいセッションを自動で取り消す。
- 長期の静的APIキーよりも、IdPが発行するmTLSや署名付きJWTsを優先する。

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
