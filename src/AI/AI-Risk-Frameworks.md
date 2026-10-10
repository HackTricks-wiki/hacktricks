# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASPは、AIシステムに影響を及ぼす可能性のある、機械学習における上位10件の脆弱性を特定しています。これらの脆弱性は、データポイズニング、モデル反転、敵対的攻撃など、さまざまなセキュリティ上の問題につながる可能性があります。安全なAIシステムを構築するには、これらの脆弱性を理解することが重要です。

機械学習における上位10件の脆弱性の最新かつ詳細な一覧については、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)プロジェクトを参照してください。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 攻撃者は**入力データ**に、ごく小さく、多くの場合は目に見えない変更を加え、モデルに誤った判断をさせます。\
    *例*: 一時停止標識に付いた少量の塗料が、自動運転車に速度制限標識だと「認識」させます。

- **Data Poisoning Attack**: **学習データセット**に意図的に不正なサンプルを混入させ、モデルに有害なルールを学習させます。\
*例*: ウイルス対策ソフトの学習コーパスでマルウェアのバイナリを「無害」と誤分類し、後に類似のマルウェアを検知できないようにします。

- **Model Inversion Attack**: 出力を調べることで、攻撃者は**逆モデル**を構築し、元の入力に含まれる機微な特徴を再構成します。\
*例*: がん検出モデルの予測結果から、患者のMRI画像を再現します。

- **Membership Inference Attack**: 攻撃者は信頼度の差を見分け、**特定のレコード**が学習に使われたかどうかを検証します。\
*例*: ある人物の銀行取引が不正検出モデルの学習データに含まれていることを確認します。

- **Model Theft**: 繰り返しクエリを送ることで、攻撃者は決定境界を学習し、モデルの動作（および知的財産）を**複製**します。\
*例*: ML-as-a-Service APIから十分な数のQ&Aペアを収集し、ほぼ同等のローカルモデルを構築します。

- **AI Supply‑Chain Attack**: **MLパイプライン**内の任意のコンポーネント（データ、ライブラリ、事前学習済みの重み、CI/CD）を侵害し、後続のモデルを汚染します。\
*例*: model hub上の汚染された依存関係によって、バックドア付きの感情分析モデルが多くのアプリにインストールされます。

- **Transfer Learning Attack**: 悪意あるロジックを**事前学習済みモデル**に仕込み、被害者のタスクでファインチューニングした後も残存させます。\
*例*: 隠されたトリガーを持つ画像認識のバックボーンモデルが、医用画像向けに適応された後もラベルを反転させます。

- **Model Skewing**: 微妙に偏ったデータや誤ってラベル付けされたデータによって、**モデルの出力を変化させ**、攻撃者の意図に沿わせます。\
*例*: 「正常な」スパムメールをhamとして注入し、スパムフィルターが今後の類似メールを通過させるようにします。

- **Output Integrity Attack**: 攻撃者はモデル自体ではなく、**転送中のモデル予測を改ざん**し、後続システムを欺きます。\
*例*: ファイル隔離処理に渡される前に、マルウェア分類器の「悪意あり」という判定を「無害」に書き換えます。

- **Model Poisoning** --- 多くの場合、書き込みアクセスを得た後に**モデルパラメーター**を直接、標的を定めて変更し、動作を改変します。\
*例*: 本番環境の不正検出モデルの重みを調整し、特定のカードによる取引が常に承認されるようにします。


## Google SAIFのリスク

Googleの[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)は、AIシステムに関連するさまざまなリスクを概説しています。<sup>[[2]](#references)</sup>

- **Data Poisoning**: 悪意ある攻撃者が学習・調整データを改変または注入し、精度を低下させたり、バックドアを埋め込んだり、結果を偏らせたりして、データライフサイクル全体にわたりモデルの完全性を損ないます。

- **Unauthorized Training Data**: 著作権のあるデータ、機微なデータ、または使用許可のないデータセットを取り込むと、モデルが使用を許可されていないデータから学習するため、法的、倫理的、性能上のリスクが生じます。

- **Model Source Tampering**: 学習前または学習中に、サプライチェーンや内部関係者によってモデルのコード、依存関係、重みが改ざんされると、再学習後も残る隠れたロジックが埋め込まれる可能性があります。

- **Excessive Data Handling**: データ保持とガバナンスの管理が不十分だと、システムが必要以上の個人データを保存または処理し、情報漏えいリスクやコンプライアンスリスクが高まります。

- **Model Exfiltration**: 攻撃者がモデルファイルや重みを盗み、知的財産の損失を招くとともに、模倣サービスや後続の攻撃を可能にします。

- **Model Deployment Tampering**: 攻撃者がモデルの成果物やサービングインフラを改変し、実行中のモデルを検証済みバージョンと異なるものにすることで、動作が変化する可能性があります。

- **Denial of ML Service**: APIへの大量リクエストや「スポンジ」入力の送信によって計算資源やエネルギーを枯渇させ、モデルをオフラインにします。これは従来のDoS攻撃に相当します。

- **Model Reverse Engineering**: 大量の入出力ペアを収集することで、攻撃者はモデルを複製または蒸留し、模倣製品やカスタマイズされた敵対的攻撃に利用します。

- **Insecure Integrated Component**: 脆弱なプラグイン、エージェント、上流サービスによって、攻撃者はAIパイプライン内にコードを注入したり、権限を昇格させたりできます。

- **Prompt Injection**: プロンプトを直接または間接的に細工して、システムの意図を上書きする指示を紛れ込ませ、モデルに意図しないコマンドを実行させます。

- **Model Evasion**: 注意深く細工された入力によって、モデルに誤分類やハルシネーションを起こさせたり、許可されていないコンテンツを出力させたりして、安全性と信頼を損ないます。

- **Sensitive Data Disclosure**: モデルが学習データやユーザーのコンテキストに含まれる個人情報または機密情報を開示し、プライバシーや規制への違反を招きます。

- **Inferred Sensitive Data**: モデルが、与えられていない個人属性を推論し、推論によって新たなプライバシー侵害を引き起こします。

- **Insecure Model Output**: サニタイズされていない応答によって、有害なコード、誤情報、不適切なコンテンツがユーザーや後続システムに渡されます。

- **Rogue Actions**: 自律的に統合されたエージェントが、ユーザーによる適切な監督なしに、意図しない実世界での操作（ファイル書き込み、API呼び出し、購入など）を実行します。

## MITRE AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)は、AIシステムに関連するリスクを理解し、軽減するための包括的なフレームワークです。攻撃者がAIモデルに対して使用する可能性のあるさまざまな攻撃手法や戦術と、AIシステムを用いてさまざまな攻撃を実行する方法を分類しています。<sup>[[3]](#references)</sup>

## LLMJacking（トークン窃取とクラウドホスト型LLMアクセスの転売）

攻撃者は有効なセッショントークンやクラウドAPI認証情報を盗み、認可を受けずに有料のクラウドホスト型LLMを呼び出します。アクセスは、被害者のアカウントを経由するリバースプロキシを使って転売されることが多く、たとえば「oai-reverse-proxy」のデプロイなどがあります。その結果、金銭的損失、ポリシーに反するモデルの悪用、被害者テナントへの責任帰属が発生します。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- 感染した開発者のマシンやブラウザーからトークンを収集し、CI/CDのシークレットを盗み、漏えいしたcookieを購入します。<sup>[[5]](#references)</sup>
- 正規プロバイダーにリクエストを転送するリバースプロキシを構築し、上流のキーを隠しながら複数の顧客のリクエストを多重化します。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 直接のベースモデルエンドポイントを悪用し、エンタープライズ向けガードレールやレート制限を回避します。<sup>[[4]](#references)</sup>

緩和策:
- トークンをデバイスフィンガープリント、IP範囲、クライアント認証に紐付け、有効期限を短く設定し、MFAで更新します。
- キーのスコープは最小限にし（ツールアクセスなし、適用可能な場合は読み取り専用）、異常を検知したらローテーションします。
- すべてのトラフィックをポリシーゲートウェイの背後にあるサーバー側で終端し、安全フィルター、ルートごとのクォータ、テナント分離を適用します。
- 突然の支出増加、異常な地域、UA文字列など、通常と異なる利用パターンを監視し、不審なセッションを自動的に無効化します。
- 長期間有効な静的APIキーよりも、mTLSまたはIdPが発行する署名済みJWTを優先します。

## セルフホストLLM推論の強化

機密データを扱うローカルLLMサーバーを運用する場合、クラウドホスト型APIとは異なる攻撃対象領域が生じます。推論・デバッグエンドポイントからプロンプトが漏えいする可能性があり、サービングスタックは通常リバースプロキシを公開し、GPUデバイスノードからは広範な`ioctl()`攻撃対象領域にアクセスできます。オンプレミスの推論サービスを評価またはデプロイする場合は、少なくとも以下の点を確認してください。<sup>[[8]](#references)</sup>

### デバッグおよび監視エンドポイント経由のプロンプト漏えい

推論APIを**複数ユーザーが利用する機微なサービス**として扱ってください。デバッグまたは監視用のルートから、プロンプトの内容、スロットの状態、モデルのメタデータ、内部キューの情報が漏れる可能性があります。`llama.cpp`では、`/slots`エンドポイントはスロットごとの状態を公開するため、特に機微な情報を扱います。このエンドポイントはスロットの確認・管理専用です。<sup>[[8]](#references)</sup>

- 推論サーバーの前段にリバースプロキシを置き、**デフォルトですべて拒否**します。
- クライアント/UIで必要なHTTPメソッドとパスの組み合わせのみを許可リストに登録します。
- 可能な場合は、バックエンド自体でイントロスペクションエンドポイントを無効にします。例: `llama-server --no-slots`。<sup>[[9]](#references)</sup>
- リバースプロキシを`127.0.0.1`にバインドし、LAN上で公開するのではなく、SSHローカルポートフォワーディングなどの認証済みトランスポート経由で公開します。

nginxでの許可リストの例:

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

推論デーモンが UNIX ソケットでの待ち受けに対応している場合は、TCP よりもこちらを優先し、**ネットワークスタックなし**でコンテナを実行します。<sup>[[8]](#references)</sup>

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
- `--network none` はインバウンド／アウトバウンドの TCP/IP エクスポージャーをなくし、rootless コンテナで通常必要となるユーザーモードのヘルパーを回避します。
- UNIX socket を使うと、socket path の POSIX permissions/ACLs を最初のアクセス制御レイヤーとして利用できます。
- `--userns=keep-id` と rootless Podman により、コンテナからのブレイクアウトの影響を軽減できます。コンテナ内の root はホストの root ではないためです。
- モデルを read-only でマウントすると、コンテナ内部からモデルが改ざんされる可能性を低減できます。

永続的なデプロイでは、同じ制限を Podman Quadlet units で設定できます。Container Device Interface を通じて GPU アクセスを委譲する場合は、すべてのアクセラレータノードを公開するのではなく、CDI device specification を可能な限り限定してください。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node の最小化

GPU を利用する推論では、`/dev/nvidia*` ファイルは価値の高いローカル攻撃対象領域です。大規模なドライバーの `ioctl()` ハンドラーや、共有 GPU メモリ管理経路にアクセスできる可能性があるためです。<sup>[[8]](#references)</sup>

- `/dev/nvidia*` を全ユーザーに書き込み可能な状態にしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使って `nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、マッピングされたコンテナ UID だけがこれらを開けるようにしてください。
- ヘッドレス推論ホストでは、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要なモジュールをブラックリストに登録してください。
- 推論の起動時に runtime が場当たり的に `modprobe` するのではなく、起動時に必要なモジュールのみを事前ロードしてください。

例:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

重要なレビュー項目の1つは **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していなくても、最近の CUDA runtime では `nvidia-uvm` が必要になる場合があります。このデバイスは共有され、GPU の仮想メモリ管理を担うため、テナント間のデータ漏えいにつながる攻撃面として扱ってください。inference backend が対応している場合は、コンテナに `nvidia-uvm` を一切公開せずに済む可能性があるため、Vulkan backend は興味深いトレードオフとなります。<sup>[[8]](#references)</sup>

### inference worker のLSMによる隔離

inference process の多層防御として、AppArmor/SELinux/seccomp を使用してください。<sup>[[8]](#references)</sup>

- 実際に必要な共有ライブラリ、model のパス、socket ディレクトリ、GPU device node のみを許可します。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの高リスクな capability を明示的に拒否します。
- model ディレクトリは読み取り専用にし、書き込み可能なパスは runtime の socket/cache ディレクトリのみに制限します。
- 拒否ログを監視します。model server や post-exploitation payload が想定された動作から逸脱しようとした際に、有用な検知 telemetry が得られます。

GPU を利用する worker 向けの AppArmor ルールの例：

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

## Phantom Squatting: LLMが幻覚したドメインをAIサプライチェーンの攻撃ベクトルとして悪用

Phantom squattingは、**slopsquattingのドメイン/URL版**です。存在しないパッケージ名を幻覚する代わりに、LLMは実在するブランドの**ポータル、API、webhook、請求、SSO、ダウンロード、サポート用ドメイン**としてもっともらしいものを幻覚し、人間やエージェントが使う前に攻撃者がその名前空間を登録します。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

これは、多くのAI支援ワークフローでモデルの出力が**信頼できる依存先**として扱われるため、重要です。
- 開発者は、提案されたエンドポイントをコードやCI/CD連携に貼り付けます。
- AIエージェントは、ドキュメント、スキーマ、APK、ZIP、webhookの送信先を自動的に取得します。
- 生成されたrunbookやドキュメントに、偽のURLが正式なものとして埋め込まれることがあります。

### 攻撃ワークフロー

1. **幻覚が生じる対象を調べる**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app`のポータルなど、現実的なワークフローに関するブランド固有の質問をします。<sup>[[12]](#references)</sup>
2. **候補を正規化する**: 生成されたURLを解決し、NXDOMAIN応答を登録可能な親ドメインに集約し、プロンプトの種類ごとに重複を除きます。プロンプトコーパスの多様性を保つため、たとえば **Jaccard類似度**を使って類似度の高いものを除外します。
3. **予測しやすい幻覚を優先する**:
   - **Thermal Hallucination Persistence (THP)**: 同じ偽ドメインが、`T=0.1`のような低温を含む複数の温度設定で現れます。
   - **モデル間の合意**: 複数のLLMファミリーが同じ偽ドメインを生成します。
4. 親ドメインを**登録して悪用**し、フィッシング、偽のAPK/ZIPダウンロード、認証情報窃取、悪意あるドキュメント、秘密情報やwebhookのペイロードを収集するAPIエンドポイントをホストします。**ドメイン単位だけの幻覚**は、攻撃者が名前空間全体を管理できるため、最も収益化しやすいものです。正規化された親ドメインが未登録であれば、サブドメインやパスの幻覚も悪用できます。
5. **レピュテーションがゼロの期間を悪用する**: 新規登録ドメインには、ブロックリストの履歴、URLレピュテーション、十分なテレメトリがないことが多く、検知が追いつくまでセキュリティ制御を回避できます。攻撃者は、crawlerにだけ無害な応答を返す、リダイレクトを隠蔽する、CAPTCHAを設ける、ペイロードの配信を遅らせるなどして、この期間を引き延ばせます。

### エージェントにとって危険な理由

人間が被害に遭う場合、通常は偽ドメインをクリックし、さらに何らかの操作をする必要があります。一方、**agentic workflow**では、LLMが**誘い手**と**実行者**の両方になり得ます。エージェントは幻覚されたURLを受け取り、取得して応答を解析し、その後、人間の確認なしにトークンを漏らしたり、指示を実行したり、依存関係をダウンロードしたり、汚染されたデータをCI/CDに送信したりする可能性があります。<sup>[[12]](#references)</sup>

### 攻撃者が使う実用的なプロンプト

効果の高いプロンプトは、明示的なフィッシングの誘い文句ではなく、通常の企業業務に見えるものです。<sup>[[12]](#references)</sup>
- 「`<brand>`連携で使う決済sandboxのURLは何ですか？」
- 「`<brand>`のビルド通知に使うwebhookエンドポイントは何ですか？」
- 「`<brand>`の従業員向け福利厚生／請求／SSOポータルはどこですか？」
- 「`<brand>`のAndroid APKまたはデスクトップクライアントを直接ダウンロードできる場所を教えてください。」

### 防御への転用

これは、prompt injectionだけの問題ではなく、事前のドメイン監視の問題として扱います。<sup>[[12]](#references)</sup>
- **ブランド別プロンプトコーパス**を作成し、ユーザーやエージェントが利用するLLMを定期的に調査します。
- 幻覚されたURLを保存し、温度やモデルを変えても安定して現れるものを追跡します。
- **Adversarial Exploitation Window (AEW)**、すなわち最初の幻覚から攻撃者による登録までの時間を追跡します。AEWが正であれば、防御側は悪用される前に先回りして登録、シンクホール化、またはブロックできます。
- 親ドメインの**NXDOMAINから登録済みへの変化**を監視します。
- 登録を確認したら、レジストラ、作成日、ネームサーバー、プライバシー保護の有無、ページの内容、スクリーンショット、パーキングページの状態、ブランド資産との類似性を調査します。
- エージェントや開発者が**LLM生成ドメインをデフォルトで信頼しない**よう、ポリシーによるゲートを設けます。初回利用の前に、許可リスト、所有者の検証、CT/RDAPチェック、または人間による承認を必須にします。

これは、**AIサプライチェーン攻撃**、**安全でないモデル出力**、そしてエージェントが幻覚されたURLを自律的に利用する場合の**不正な操作**など、複数のAIリスク分類に同時に該当します。

## References

- [1] [OWASP 機械学習の脆弱性トップ10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF（Secure AI Framework）– リスク](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 脅威マトリックス](https://atlas.mitre.org/)
- [4] [Unit 42 – コードアシスタントLLMのリスク: 有害なコンテンツ、悪用、欺瞞](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: 盗まれたcloud認証情報を使った新たなAI攻撃](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJackingの手口の概要 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（盗んだLLMアクセスの再販）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - オンプレミスの低権限LLMサーバー導入の詳細解説](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface（CDI）仕様](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AIが幻覚したドメインをソフトウェアサプライチェーンの攻撃ベクトルとして悪用](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AIの幻覚が新たなサプライチェーン攻撃を生み出す仕組み](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
