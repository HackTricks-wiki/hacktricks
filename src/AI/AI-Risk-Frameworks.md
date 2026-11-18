# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owaspは、AIシステムに影響を及ぼす可能性がある機械学習の脆弱性トップ10を特定しています。これらの脆弱性は、データポイズニング、モデル反転、敵対的攻撃など、さまざまなセキュリティ上の問題につながる可能性があります。安全なAIシステムを構築するには、これらの脆弱性を理解することが重要です。

機械学習の脆弱性トップ10の最新かつ詳細な一覧は、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)プロジェクトを参照してください。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 攻撃者は**入力データ**にごくわずかな、しばしば目に見えない変更を加え、モデルに誤った判断をさせます。\
    *例*: 一時停止標識に付いたわずかなペンキの点が自動運転車を欺き、標識を制限速度標識だと「認識」させます。

- **Data Poisoning Attack**: **訓練データセット**に意図的に不正なサンプルを混入し、モデルに有害なルールを学習させます。\
*例*: ウイルス対策ソフトの訓練データに含まれるマルウェアのバイナリを「無害」と誤ってラベル付けし、後から類似のマルウェアを検知できないようにします。

- **Model Inversion Attack**: 出力を調べることで、攻撃者は元の入力に含まれる機密性の高い特徴を復元する**逆モデル**を構築します。\
*例*: がん検出モデルの予測結果から患者のMRI画像を再現します。

- **Membership Inference Attack**: 攻撃者は信頼度の違いを見分けて、**特定のレコード**が訓練に使われたかどうかを判定します。\
*例*: ある人の銀行取引が不正検出モデルの訓練データに含まれていることを確認します。

- **Model Theft**: 繰り返しクエリを送ることで、攻撃者は決定境界を学習し、モデルの挙動（および知的財産）を**複製**します。\
*例*: ML-as-a-Service APIから十分な数のQ&Aペアを収集し、ほぼ同等のローカルモデルを構築します。

- **AI Supply‑Chain Attack**: **MLパイプライン**内のコンポーネント（データ、ライブラリ、事前学習済み重み、CI/CD）を侵害し、後続のモデルを汚染します。\
*例*: model-hub上の汚染された依存関係により、複数のアプリにバックドア入り感情分析モデルがインストールされます。

- **Transfer Learning Attack**: 悪意あるロジックを**事前学習済みモデル**に仕込み、被害者のタスクでファインチューニングした後も残存させます。\
*例*: 隠されたトリガーを持つ画像認識のバックボーンモデルが、医療画像向けに適応された後もラベルを反転させます。

- **Model Skewing**: 微妙に偏った、または誤ってラベル付けされたデータが**モデルの出力を変化させ**、攻撃者の目的に沿うようにします。\
*例*: 「正常」なスパムメールをhamとラベル付けして注入し、スパムフィルターが今後の類似メールを通過させるようにします。

- **Output Integrity Attack**: 攻撃者はモデル自体ではなく、**転送中のモデル予測を改ざん**して、下流のシステムを欺きます。\
*例*: マルウェア分類器の「悪意あり」という判定を、ファイル隔離処理に渡る前に「無害」へと反転させます。

- **Model Poisoning** --- 多くの場合、書き込み権限を得た後に**モデルパラメーター**自体を直接、標的を絞って変更し、挙動を変えます。\
*例*: 本番環境の不正検出モデルの重みを変更し、特定のカードによる取引を常に承認させます。


## Google SAIF Risks

Googleの[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)では、AIシステムに関連するさまざまなリスクが説明されています。<sup>[[2]](#references)</sup>

- **Data Poisoning**: 悪意ある行為者が訓練・チューニングデータを改変または注入し、モデルの精度を低下させたり、バックドアを仕込んだり、結果を歪めたりします。これにより、データライフサイクル全体にわたってモデルの完全性が損なわれます。 

- **Unauthorized Training Data**: 著作権で保護されたデータ、機密データ、または使用許可のないデータセットを取り込むと、モデルが使用を許可されていないデータから学習するため、法的・倫理的・性能上の問題が生じます。 

- **Model Source Tampering**: 訓練前または訓練中に、サプライチェーンや内部関係者がモデルのコード、依存関係、重みを改ざんすると、再訓練後も残る隠れたロジックが埋め込まれる可能性があります。 

- **Excessive Data Handling**: データ保持とガバナンスの管理が不十分だと、システムが必要以上の個人データを保存または処理し、情報漏えいのリスクやコンプライアンス上のリスクが高まります。 

- **Model Exfiltration**: 攻撃者がモデルファイルや重みを盗み、知的財産の損失を引き起こすとともに、模倣サービスや後続の攻撃を可能にします。 

- **Model Deployment Tampering**: 攻撃者がモデルの成果物やサービング基盤を改ざんし、実行中のモデルを検証済みのバージョンと異なるものにすることで、挙動を変える可能性があります。 

- **Denial of ML Service**: APIへの大量リクエストや「スポンジ」入力の送信により、計算資源や電力を使い果たしてモデルを停止させます。従来のDoS攻撃と同様です。 

- **Model Reverse Engineering**: 大量の入力と出力のペアを収集することで、攻撃者はモデルを複製または蒸留でき、模倣製品やカスタマイズされた敵対的攻撃につながります。 

- **Insecure Integrated Component**: 脆弱なプラグイン、エージェント、または上流サービスによって、攻撃者がAIパイプライン内にコードを注入したり、権限を昇格させたりする可能性があります。 

- **Prompt Injection**: プロンプトを直接または間接的に細工して、システムの意図を上書きする指示を紛れ込ませ、モデルに意図しないコマンドを実行させます。 

- **Model Evasion**: 入念に設計された入力によって、モデルに誤分類、ハルシネーション、または許可されていないコンテンツの出力を引き起こし、安全性と信頼性を損ないます。 

- **Sensitive Data Disclosure**: モデルが訓練データやユーザーのコンテキストから個人情報または機密情報を漏らし、プライバシーや規制に関する要件に違反します。 

- **Inferred Sensitive Data**: モデルが提供されていない個人属性を推測し、推論によって新たなプライバシー侵害を引き起こします。 

- **Insecure Model Output**: サニタイズされていない応答により、有害なコード、誤情報、不適切なコンテンツがユーザーや下流システムに渡されます。 

- **Rogue Actions**: 自律的に統合されたエージェントが、十分なユーザーの監視なしに、意図しない現実世界の操作（ファイル書き込み、API呼び出し、購入など）を実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)は、AIシステムに関連するリスクを理解し、軽減するための包括的なフレームワークです。攻撃者がAIモデルに対して使用する可能性のあるさまざまな攻撃テクニックや戦術に加え、AIシステムを使ってさまざまな攻撃を実行する方法も分類しています。<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻撃者は有効なセッショントークンやcloud API認証情報を盗み、許可なく有料のcloud-hosted LLMを呼び出します。アクセス権は、被害者のアカウントを中継するreverse proxyを通じて再販売されることがよくあります。例として「oai-reverse-proxy」のデプロイがあります。これにより、金銭的損失、ポリシーに反するモデルの悪用、被害者のテナントへの責任帰属が生じる可能性があります。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- 感染した開発者のマシンやブラウザーからトークンを収集し、CI/CDのシークレットを盗み、漏えいしたCookieを購入します。<sup>[[5]](#references)</sup>
- 正規プロバイダーにリクエストを転送するreverse proxyを構築し、上流のキーを隠して複数の顧客に対応します。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 直接のbase-modelエンドポイントを悪用して、企業のガードレールやレート制限を回避します。<sup>[[4]](#references)</sup>

**ホスト内でのAPIキー再利用:** ホストを侵害した後、インプラントは被害者ホストから直接モデルAPIリクエストを送信し、ローカルのAI CLIを起動したりcloud APIキーを外部に持ち出したりせずに、応答をC2経由で中継できます。確認されたハンドラーでは、C2から提供されたキーが優先されます。キーがない場合に限り、インプラントは自身のプロセス環境から`OPENAI_API_KEY`を読み取ります。したがって、被害者のアカウントを利用するには、そのプロセスから参照できる有効なキーとモデルAPIへのアクセスが必要です。オペレーターのプロンプトはChat Completions APIに送信され、モデルの出力とトークン使用量はC2経由で返されます。これは、[ローカルAI CLIやMCP設定の悪用](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md)とは異なり、開発者のAIツールを実行せずに被害者の有料モデルアクセスを消費できます。<sup>[[14]](#references)</sup>

緩和策:
- トークンをデバイスフィンガープリント、IP範囲、クライアントアテステーションに紐付け、短い有効期限を適用し、MFAで更新します。
- キーのスコープを最小限に抑え（ツールへのアクセスを許可せず、可能な場合は読み取り専用にする）、異常時にはローテーションします。
- すべてのトラフィックをポリシーゲートウェイの背後でサーバー側から終端し、安全性フィルター、ルートごとのクォータ、テナント分離を適用します。
- 不審な使用パターン（急激な支出の増加、通常と異なる地域、UA文字列）を監視し、疑わしいセッションを自動的に失効させます。
- 長期間有効な静的APIキーではなく、IdPが発行するmTLSまたは署名付きJWTを優先します。

## Self-hosted LLM inference hardening

機密データを扱うローカルLLMサーバーの実行には、cloud-hosted APIとは異なる攻撃対象領域があります。推論／デバッグエンドポイントからプロンプトが漏えいする可能性があり、サービングスタックは通常reverse proxyを公開し、GPUのデバイスノードは広範な`ioctl()`攻撃対象領域へのアクセスを与えます。オンプレミスの推論サービスを評価またはデプロイする場合は、少なくとも以下の点を確認してください。<sup>[[8]](#references)</sup>

### デバッグおよび監視エンドポイント経由のプロンプト漏えい

推論APIを**複数ユーザーが利用する機密性の高いサービス**として扱ってください。デバッグまたは監視ルートから、プロンプトの内容、スロットの状態、モデルのメタデータ、内部キューの情報が漏れる可能性があります。`llama.cpp`では、`/slots`エンドポイントはスロットごとの状態を公開し、スロットの検査・管理のみを目的としているため、特に機密性が高いものです。<sup>[[8]](#references)</sup>

公開されているモデルランナーや関連するAIサービスのブラックボックスフィンガープリントとテストについては、[Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)を確認してください。

- 推論サーバーの前段にreverse proxyを配置し、**デフォルトで拒否**します。
- クライアント／UIで必要なHTTPメソッドとパスの組み合わせのみを、厳密にallowlistに登録します。
- 可能であれば、`llama-server --no-slots`などを使って、バックエンド自体のイントロスペクションエンドポイントを無効にします。<sup>[[9]](#references)</sup>
- reverse proxyを`127.0.0.1`にバインドし、LAN上に公開する代わりに、SSHのローカルポートフォワーディングなどの認証済みトランスポート経由で公開します。

nginxのallowlistの例:

```nginx
map "$request_method:$uri" $llm_whitelist {
    default 0;

    "GET:/health"              1;
    "GET:/v1/models"           1;
    "POST:/v1/completions"     1;
    "POST:/v1/chat/completions" 1;
}

server {
    listen 127.0.0.1:80;

    location / {
        if ($llm_whitelist = 0) { return 403; }
        proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
    }
}
```

### ネットワークなしの rootless コンテナと UNIX ソケット

推論デーモンが UNIX ソケットでのリッスンに対応している場合は、TCP よりもこちらを優先し、コンテナを**ネットワークスタックなし**で実行します。<sup>[[8]](#references)</sup>

```bash
podman run --rm -d \
  --network none \
  --user 1000:1000 \
  --userns=keep-id \
  --umask=007 \
  --volume /var/lib/models:/models:ro \
  --volume /srv/llm/socks:/run/llama-cpp \
  ghcr.io/ggml-org/llama.cpp:server-cuda13 \
    --host /run/llama-cpp/llama-cpp.sock \
    --model /models/model.gguf \
    --parallel 4 \
    --no-slots
```

Benefits:
- `--network none` はインバウンド/アウトバウンドの TCP/IP エクスポージャーをなくし、rootless コンテナで本来必要となる user-mode helper を回避します。
- UNIX socket を使うことで、socket パス上の POSIX permissions/ACLs を最初のアクセス制御レイヤーとして利用できます。
- `--userns=keep-id` と rootless Podman により、コンテナブレイクアウトの影響を軽減できます。これは、コンテナ内の root がホストの root ではないためです。
- モデルを読み取り専用でマウントすると、コンテナ内からモデルが改ざんされる可能性を減らせます。

永続的なデプロイでは、同じ制限を Podman Quadlet unit で設定できます。Container Device Interface 経由で GPU アクセスを委譲する場合は、すべてのアクセラレータ node を公開するのではなく、CDI device specification を可能な限り限定してください。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device node の最小化

GPU を使った推論では、`/dev/nvidia*` ファイルは、広範な driver `ioctl()` handler や共有 GPU memory-management path を公開する可能性があるため、価値の高いローカル攻撃対象領域です。<sup>[[8]](#references)</sup>

- `/dev/nvidia*` を全ユーザーに書き込み可能な状態にしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rule、ACL を使って `nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、マッピングされたコンテナ UID だけがこれらを開けるようにしてください。
- ヘッドレス推論ホストでは、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要な module を blacklist に追加してください。
- 推論の起動時に runtime が必要に応じて `modprobe` するのではなく、起動時に必要な module だけを preload してください。

例:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

重要なレビュー項目の1つは **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していなくても、最近の CUDA runtime では `nvidia-uvm` が必要になる場合があります。このデバイスは共有され、GPU の仮想メモリ管理を担うため、テナント間のデータ漏えいにつながる攻撃対象として扱ってください。inference backend が対応している場合、Vulkan backend は、コンテナに `nvidia-uvm` をまったく公開せずに済む可能性があるため、興味深いトレードオフとなります。<sup>[[8]](#references)</sup>

### inference worker の LSM による制限

inference プロセスを多層防御で保護するために、AppArmor/SELinux/seccomp を使用してください。<sup>[[8]](#references)</sup>

- 実際に必要な共有ライブラリ、モデルパス、ソケットディレクトリ、GPU デバイスノードのみを許可します。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの高リスクな capabilities を明示的に拒否します。
- モデルディレクトリを読み取り専用にし、書き込み可能なパスはランタイムのソケット／キャッシュディレクトリのみに限定します。
- 拒否ログを監視します。モデルサーバーや post-exploitation payload が想定された動作から逸脱しようとした際に、有用な検知テレメトリーが得られるためです。

GPU を使用する worker 向けの AppArmor ルールの例：

```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```

## Phantom Squatting: AIが幻覚したドメインを利用するAIサプライチェーン攻撃

Phantom squattingは、**slopsquattingのドメイン/URL版**です。存在しないパッケージ名を幻覚する代わりに、LLMは実在するブランドの**ポータル、API、webhook、請求、SSO、ダウンロード、サポート用ドメイン**をもっともらしく幻覚し、人間やエージェントが使用する前に攻撃者がその名前空間を登録します。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

これは、多くのAI支援ワークフローで、モデルの出力が**信頼できる依存関係**として扱われるため重要です。
- 開発者は提案されたエンドポイントをコードやCI/CD統合に貼り付けます。
- AIエージェントはドキュメント、スキーマ、APK、ZIP、webhookの送信先を自動的に取得します。
- 生成されたrunbookやドキュメントに、偽のURLが正式なものとして埋め込まれることがあります。

### 攻撃ワークフロー

1. **幻覚が生じる範囲を探る**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app`の各ポータルなど、現実的なワークフローについて、ブランド固有の質問をします。<sup>[[12]](#references)</sup>
2. **候補を正規化する**: 生成されたURLを解決し、NXDOMAINの応答を登録可能な親ドメインに集約して、プロンプト群の重複を除去します。プロンプトコーパスには多様性を持たせ、たとえば**Jaccard類似度**を使って類似性の高い重複を取り除きます。
3. **予測しやすい幻覚を優先する**:
   - **Thermal Hallucination Persistence (THP)**: 低温の`T=0.1`を含め、温度を変えても同じ偽ドメインが出現すること。
   - **モデル間のコンセンサス**: 複数のLLMファミリーが同じ偽ドメインを生成すること。
4. 親ドメインを**登録して兵器化**し、フィッシング、偽のAPK/ZIPダウンロード、認証情報を収集する仕組み、悪意のあるドキュメント、またはシークレット/webhookのペイロードを収集するAPIエンドポイントをホストします。攻撃者が名前空間全体を制御できるため、**ドメインレベルのみの幻覚**が最も簡単に収益化できます。正規化した親ドメインが未登録なら、サブドメイン/パスの幻覚も悪用できます。
5. **ゼロレピュテーション期間を悪用する**: 新しく登録されたドメインには、ブロックリストの履歴、URLレピュテーション、十分なテレメトリがないことが多く、検知が追いつくまで対策を回避できます。クローラーにだけ無害な応答を返す、リダイレクトを隠蔽する、CAPTCHAで制限する、ペイロードの配信を遅らせるなどして、この期間を引き延ばせます。

### エージェントにとって危険な理由

人間の被害者の場合、偽ドメインへのアクセスには通常、クリックとその後の操作が必要です。一方、**エージェント型ワークフロー**では、LLMが**誘導役**と**実行者**を兼ねる場合があります。エージェントは幻覚されたURLを受け取り、それを取得して応答を解析し、トークンをleakしたり、指示を実行したり、依存関係をダウンロードしたり、あるいは人間による確認なしに汚染されたデータをCI/CDに投入したりする可能性があります。<sup>[[12]](#references)</sup>

### 実用的な攻撃者向けプロンプト

効果の高いプロンプトは、明示的なフィッシングの誘いではなく、通常の企業タスクのように見えることが多いです。<sup>[[12]](#references)</sup>
- 「`<brand>`の連携で使用するpayment sandbox URLは何ですか？」
- 「`<brand>`のビルド通知には、どのwebhookエンドポイントを使えばよいですか？」
- 「`<brand>`の従業員向けbenefits / billing / SSOポータルはどこですか？」
- 「`<brand>`のAndroid APKまたはデスクトップクライアントを直接ダウンロードできる場所を教えてください。」

### 防御側の対策

これは、prompt injectionの問題だけでなく、事前のドメイン監視の問題として扱います。<sup>[[12]](#references)</sup>
- **ブランド別プロンプトコーパス**を作成し、ユーザー/エージェントが利用するLLMを定期的に調査します。
- 幻覚されたURLを保存し、温度やモデルを変えても安定して出現するかを追跡します。
- **Adversarial Exploitation Window (AEW)**、つまり最初の幻覚から攻撃者による登録までの時間を追跡します。AEWが正なら、攻撃者が兵器化する前に防御側が事前登録、sinkhole化、または事前ブロックできます。
- 親ドメインの**NXDOMAINから登録への遷移**を監視します。
- 登録されたら、レジストラ、作成日、ネームサーバー、プライバシー保護、ページのコンテンツ、スクリーンショット、パーキングページの状態、ブランド資産との類似性を調査します。
- エージェント/開発者が**LLM生成ドメインをデフォルトで信頼しない**よう、ポリシーによるゲートを追加します。初回使用前に、許可リスト、所有権の検証、CT/RDAPチェック、または人間の承認を必須にします。

これは、**AIサプライチェーン攻撃**、**安全でないモデル出力**、そしてエージェントが幻覚されたURLを自律的に利用する場合の**rogue actions**という、複数のAIリスク分類に同時に該当します。

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP機械学習における脆弱性トップ10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – リスク](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS脅威マトリクス](https://atlas.mitre.org/)
- [4] [Unit 42 – コードアシスタントLLMのリスク: 有害なコンテンツ、悪用、欺瞞](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: 新たなAI攻撃で盗まれたクラウド認証情報が悪用される](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMjackingの概要 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (盗んだLLMアクセスの再販)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - オンプレミスの低権限LLMサーバーの導入に関する詳細解説](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cppサーバーREADME](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)仕様](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AIが幻覚したドメインを利用するソフトウェアサプライチェーン攻撃](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AIの幻覚が新たなサプライチェーン攻撃を引き起こす仕組み](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: 新たなAI対応コマンド＆コントロールフレームワーク](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
