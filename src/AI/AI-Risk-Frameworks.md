# AIリスク

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASPは、AIシステムに影響を及ぼす可能性がある、machine learningの脆弱性トップ10を特定しています。これらの脆弱性は、data poisoning、model inversion、adversarial attackなど、さまざまなセキュリティ上の問題につながる可能性があります。安全なAIシステムを構築するには、これらの脆弱性を理解することが重要です。

machine learningの脆弱性トップ10に関する最新かつ詳細な一覧は、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)プロジェクトを参照してください。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 攻撃者は**入力データ**に小さく、しばしば目に見えない変更を加え、モデルに誤った判断をさせます。\
    *例*: 一時停止標識に付けた少量の塗料の点が、自動運転車に標識を速度制限標識だと誤認させる。

- **Data Poisoning Attack**: **training set**を意図的に不正なサンプルで汚染し、モデルに有害なルールを学習させます。\
*例*: antivirusのtraining corpusでmalwareのバイナリを「無害」と誤ってラベル付けし、類似のmalwareが後に検知をすり抜けるようにする。

- **Model Inversion Attack**: 出力を調べることで、攻撃者は元の入力に含まれる機微な特徴を再構成する**逆モデル**を作成します。\
*例*: がん検出モデルの予測から患者のMRI画像を再現する。

- **Membership Inference Attack**: 攻撃者は信頼度の差を見つけ、**特定のレコード**がtraining中に使われたかどうかを判定します。\
*例*: ある人の銀行取引が不正検知モデルのtraining dataに含まれていることを確認する。

- **Model Theft**: 繰り返し問い合わせることで、攻撃者はdecision boundaryを学習し、モデルの動作（およびIP）を**複製**します。\
*例*: ML-as-a-Service APIから十分な数のQ&Aを収集し、ほぼ同等のローカルモデルを構築する。

- **AI Supply‑Chain Attack**: **ML pipeline**内のコンポーネント（data、library、pre-trained weight、CI/CD）を侵害し、後続のモデルを汚染します。\
*例*: model hub上の汚染されたdependencyにより、複数のアプリにbackdoor付きのsentiment-analysisモデルがインストールされる。

- **Transfer Learning Attack**: **pre-trained model**に悪意あるロジックを仕込み、被害者のタスク向けにfine-tuningした後も残存させます。\
*例*: 隠されたtriggerを含むvision backboneが、医療画像向けに適応された後もラベルを反転させる。

- **Model Skewing**: 微妙に偏ったデータや誤ってラベル付けされたデータによって、攻撃者の目的に沿うよう**モデルの出力を変化**させます。\
*例*: 「無害」とラベル付けした「クリーン」なspamメールを注入し、spam filterに今後の類似メールを通過させる。

- **Output Integrity Attack**: 攻撃者はモデル自体ではなく、**モデルの予測を転送中に改変**し、後続システムを欺きます。\
*例*: file quarantineの段階に届く前に、malware classifierの「悪意あり」という判定を「無害」に書き換える。

- **Model Poisoning** --- 多くの場合、書き込みアクセスを得た後に、動作を変えるため**モデルのparameter**自体を直接、標的を絞って変更します。\
*例*: 本番環境の不正検知モデルのweightを調整し、特定のカードによる取引を常に承認させる。


## Google SAIFのリスク

Googleの[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)では、AIシステムに関連するさまざまなリスクについて説明しています。<sup>[[2]](#references)</sup>

- **Data Poisoning**: 悪意ある攻撃者がtraining/tuning dataを改変または注入し、精度を低下させたり、backdoorを埋め込んだり、結果を偏らせたりして、data lifecycle全体にわたるモデルの完全性を損ないます。

- **Unauthorized Training Data**: 著作権のあるデータ、機微なデータ、または使用許可のないデータセットを取り込むと、使用が許可されていないデータからモデルが学習するため、法的、倫理的、性能上のリスクが生じます。

- **Model Source Tampering**: trainingの前または最中に、supply chainや内部関係者によってモデルのcode、dependency、weightが改ざんされると、再training後も残る隠れたロジックが埋め込まれる可能性があります。

- **Excessive Data Handling**: data retentionやgovernanceの管理が不十分だと、必要以上の個人データをシステムが保存または処理し、情報漏えいとコンプライアンス上のリスクが高まります。

- **Model Exfiltration**: 攻撃者がモデルのfileやweightを盗み、知的財産の損失を招くほか、模倣サービスや後続の攻撃を可能にします。

- **Model Deployment Tampering**: 攻撃者がモデルartifactやserving infrastructureを改変し、稼働中のモデルを検証済みのversionと異なるものにして、動作を変える可能性があります。

- **Denial of ML Service**: APIへの大量のリクエストや「sponge」入力によって計算資源やエネルギーを枯渇させ、従来のDoS attackと同様にモデルを停止させます。

- **Model Reverse Engineering**: 大量の入力と出力のペアを収集することで、攻撃者はモデルを複製または蒸留し、模倣製品やカスタマイズされたadversarial attackに利用します。

- **Insecure Integrated Component**: 脆弱なplugin、agent、または上流サービスによって、攻撃者がAI pipeline内にcodeを注入したり、privilegeを昇格させたりできるようになります。

- **Prompt Injection**: 直接または間接的に、systemの意図を覆す指示を紛れ込ませるpromptを作成し、モデルに意図しないコマンドを実行させます。

- **Model Evasion**: 慎重に設計された入力によって、モデルに誤分類、hallucination、または禁止されたコンテンツの出力をさせ、安全性と信頼性を損ないます。

- **Sensitive Data Disclosure**: モデルがtraining dataやユーザーのcontextに含まれる個人情報や機密情報を明らかにし、プライバシーや規制に関する要件に違反します。

- **Inferred Sensitive Data**: モデルが、提供されていない個人属性を推測し、推論によって新たなプライバシー侵害を引き起こします。

- **Insecure Model Output**: サニタイズされていない応答によって、有害なcode、誤情報、不適切なコンテンツがユーザーや後続システムに渡されます。

- **Rogue Actions**: AIに統合されたagentが、十分なユーザーの監督なしに、意図しない現実世界の操作（fileの書き込み、API呼び出し、購入など）を自律的に実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)は、AIシステムに関連するリスクを理解し、軽減するための包括的なframeworkです。攻撃者がAIモデルに対して使用する可能性のあるさまざまな攻撃手法やtacticと、AIシステムを使ってさまざまな攻撃を行う方法を分類しています。<sup>[[3]](#references)</sup>

## LLMJacking（Tokenの窃取とcloud-hosted LLMアクセスの転売）

攻撃者は有効なsession tokenやcloud API credentialを盗み、許可なく有料のcloud-hosted LLMを利用します。被害者のaccountを経由するreverse proxyを通じてアクセスが転売されることが多く、例として「oai-reverse-proxy」のdeploymentがあります。結果として、金銭的損失、policyに反するモデルの悪用、被害者tenantへの責任の帰属が生じます。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP:
- 感染した開発者のマシンやbrowserからtokenを収集し、CI/CD secretを盗み、leakしたcookieを購入する。<sup>[[5]](#references)</sup>
- 正規providerにrequestを転送するreverse proxyを構築し、上流のkeyを隠しながら複数の顧客に利用させる。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- enterpriseのguardrailやrate limitを回避するため、base modelのendpointに直接アクセスする。<sup>[[4]](#references)</sup>

Mitigation:
- tokenをdevice fingerprint、IP range、client attestationに紐付け、短い有効期限を設定し、MFAを使って更新する。
- keyの権限を必要最小限にする（tool accessを与えず、可能な場合はread-onlyにする）。異常を検知したらrotateする。
- すべてのtrafficをpolicy gatewayの背後にあるserver-sideで終端し、安全性filter、routeごとのquota、tenant isolationを適用する。
- 不自然な利用パターン（急激な利用額の増加、通常と異なるregion、UA string）を監視し、疑わしいsessionを自動的に取り消す。
- 有効期間の長いstatic API keyではなく、IdPが発行するmTLSまたは署名付きJWTを優先する。

## Self-hosted LLM inferenceのhardening

機密データを扱うためにローカルLLM serverを稼働させると、cloud-hosted APIとは異なるattack surfaceが生じます。inference/debug endpointからpromptが漏れる可能性があり、serving stackには通常reverse proxyが公開され、GPU device nodeから広範な`ioctl()`のattack surfaceにアクセスできます。オンプレミスのinference serviceを評価または導入する場合は、少なくとも以下の点を確認してください。<sup>[[8]](#references)</sup>

### debugおよびmonitoring endpointを介したprompt漏えい

inference APIを**複数ユーザーが利用する機微なservice**として扱ってください。debugまたはmonitoring用のrouteから、promptの内容、slotの状態、モデルmetadata、内部queueの情報が漏れる可能性があります。`llama.cpp`では、`/slots` endpointは特に機微です。slotごとの状態を公開し、slotの検査や管理のみを目的としているためです。<sup>[[8]](#references)</sup>

公開されているmodel runnerや関連するAI serviceのblack-box fingerprintingおよびテストについては、[Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)を確認してください。

- inference serverの前にreverse proxyを置き、**デフォルトですべて拒否**する。
- client/UIに必要な、HTTP methodとpathの正確な組み合わせのみをallowlistに登録する。
- 可能な場合は、`llama-server --no-slots`のようにbackend自体でintrospection endpointを無効にする。<sup>[[9]](#references)</sup>
- reverse proxyを`127.0.0.1`にbindし、LAN上に公開するのではなく、SSH local port forwardingなどの認証済みtransportを通じて公開する。

nginxでのallowlistの例:

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

### ネットワークなしのrootlessコンテナとUNIXソケット

推論デーモンがUNIXソケットでのリスニングをサポートしている場合は、TCPよりもそちらを優先し、**ネットワークスタックなし**でコンテナを実行してください：<sup>[[8]](#references)</sup>

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

利点:
- `--network none` により、インバウンド／アウトバウンドの TCP/IP への露出をなくし、rootless コンテナで必要になる user-mode helpers を回避できます。
- UNIX socket を使うと、socket path に対する POSIX permissions/ACLs を最初のアクセス制御層として利用できます。
- `--userns=keep-id` と rootless Podman により、コンテナからの脱出が発生しても、コンテナ内の root がホストの root ではないため、影響を軽減できます。
- モデルを read-only でマウントすると、コンテナ内部からモデルが改ざんされる可能性を低減できます。

永続的なデプロイでは、同じ制限を Podman Quadlet units で表現できます。Container Device Interface を通じて GPU access を委譲する場合は、すべての accelerator node を公開するのではなく、CDI device specification を可能な限り限定してください。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU デバイスノードの最小化

GPU を使った推論では、`/dev/nvidia*` files は、広範な driver `ioctl()` handlers や、共有 GPU memory-management paths にアクセスできるため、価値の高いローカル攻撃対象領域になります。<sup>[[8]](#references)</sup>

- `/dev/nvidia*` を誰でも書き込み可能な状態にしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使って `nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、マッピングされたコンテナ UID だけが開けるようにしてください。
- ヘッドレス推論ホストでは、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` など、不要な modules をブラックリストに追加してください。
- 推論の起動時に runtime が必要に応じて `modprobe` するのではなく、起動時に必要な modules のみを事前ロードしてください。

例:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

重要なレビュー項目の1つは **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していなくても、最近の CUDA runtime では `nvidia-uvm` が必要になる場合があります。このデバイスは共有され、GPU の仮想メモリ管理を担うため、テナント間のデータ漏えいにつながる可能性のある攻撃対象として扱ってください。inference backend が対応している場合、Vulkan backend は、コンテナに `nvidia-uvm` を一切公開せずに済む可能性があるため、興味深いトレードオフとなります。<sup>[[8]](#references)</sup>

### inference worker の LSM による制限

inference process の多層防御として、AppArmor/SELinux/seccomp を使用してください。<sup>[[8]](#references)</sup>

- 実際に必要な共有ライブラリ、model のパス、socket ディレクトリ、GPU device node のみを許可します。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` など、リスクの高い capability を明示的に拒否します。
- model ディレクトリは読み取り専用にし、書き込み可能なパスは runtime の socket/cache ディレクトリのみに限定します。
- 拒否ログを監視してください。model server や post-exploitation payload が想定された動作から逸脱しようとした際に、有用な検知テレメトリとなります。

GPU を使用する worker 向けの AppArmor ルールの例:

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

## Phantom Squatting: LLMが幻覚するドメインを利用したAIサプライチェーン攻撃

Phantom squattingは、**slopsquattingのドメイン/URL版**です。存在しないパッケージ名を幻覚する代わりに、LLMは実在ブランドの**ポータル、API、webhook、請求、SSO、ダウンロード、サポート用ドメイン**をそれらしく幻覚し、人間やagentが使う前に攻撃者がその名前空間を登録します。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

これは、多くのAI支援ワークフローでモデルの出力が**信頼できる依存関係**として扱われるため、重要な問題です。
- 開発者は、提案されたendpointをコードやCI/CD連携に貼り付けます。
- AI agentは、ドキュメント、schema、APK、ZIP、webhookの送信先を自動的に取得します。
- 生成されたrunbookやドキュメントには、偽のURLが正規のものとして埋め込まれることがあります。

### 攻撃ワークフロー

1. **幻覚の対象領域を探る**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app`の各ポータルなど、現実的なワークフローについてブランド固有の質問をします。<sup>[[12]](#references)</sup>
2. **候補を正規化する**: 生成されたURLを解決し、NXDOMAIN応答を登録可能な親ドメインにまとめ、プロンプト群の重複を排除します。プロンプトコーパスには多様性を保つ必要があります。たとえば、**Jaccard類似度**で近似重複を除外します。
3. **予測可能な幻覚を優先する**:
   - **Thermal Hallucination Persistence (THP)**: `T=0.1`のような低温を含め、温度を変えても同じ偽ドメインが出現すること。
   - **モデル間の合意**: 複数のLLMファミリーが同じ偽ドメインを生成すること。
4. 親ドメインを**登録して武器化**し、フィッシング、偽のAPK/ZIPダウンロード、認証情報収集サイト、悪意あるドキュメント、または秘密情報/webhookペイロードを収集するAPI endpointをホストします。**ドメインレベルだけの幻覚**は、攻撃者が名前空間全体を支配できるため、最も収益化しやすいものです。正規化された親ドメインが未登録であれば、サブドメイン/パスの幻覚も悪用できます。
5. **レピュテーションが確立される前の期間を悪用する**: 新規登録ドメインには、ブロックリストの履歴、URLレピュテーション、成熟したテレメトリがないことが多く、検知が追いつくまで制御をすり抜ける可能性があります。攻撃者は、crawlerにだけ無害な応答を返す、redirect cloaking、CAPTCHAゲート、ペイロードの遅延配置などで、この期間を引き延ばせます。

### agentにとって危険な理由

人間を狙う場合、通常は偽ドメインをクリックさせ、さらに別の操作をさせる必要があります。**agentic workflow**では、LLMが**誘い手**と**実行者**の両方になり得ます。agentは幻覚されたURLを受け取り、取得して応答を解析し、その後、人間の確認なしにtokenを漏えいさせたり、命令を実行したり、依存関係をダウンロードしたり、汚染されたデータをCI/CDに送り込んだりする可能性があります。<sup>[[12]](#references)</sup>

### 攻撃者が使う実用的なプロンプト

効果の高いプロンプトは、明示的なフィッシングの誘いではなく、通常の企業業務に見えるものが多くあります。<sup>[[12]](#references)</sup>
- 「`<brand>`連携用の決済sandbox URLは何ですか？」
- 「`<brand>`のビルド通知には、どのwebhook endpointを使えばよいですか？」
- 「`<brand>`の従業員向け福利厚生 / billing / SSOポータルはどこですか？」
- 「`<brand>`のAndroid APKまたはデスクトップクライアントを直接ダウンロードできる場所を教えてください。」

### 防御への転換

これは、prompt injectionの問題だけでなく、事前のドメイン監視の問題として扱います。<sup>[[12]](#references)</sup>
- **ブランド別プロンプトコーパス**を作成し、ユーザー/agentが依存するLLMを定期的に調査します。
- 幻覚されたURLを保存し、温度やモデルを変えても安定して出現するものを追跡します。
- **Adversarial Exploitation Window (AEW)**、つまり最初の幻覚から攻撃者による登録までの時間を追跡します。AEWが正であれば、防御側は武器化される前に先行登録、sinkhole化、または事前ブロックできます。
- 親ドメインの**NXDOMAINから登録済みへの移行**を監視します。
- 登録されたら、registrar、作成日、nameserver、プライバシー保護、ページ内容、スクリーンショット、パーキングページの状態、ブランドアセットとの類似性を調査します。
- agent/開発者が**LLM生成ドメインをデフォルトで信頼しない**よう、ポリシー上のゲートを設けます。初回利用前に、allowlist、所有権の検証、CT/RDAPチェック、または人間による承認を必須にします。

これは、複数のAIリスク分類に同時に該当します。**AIサプライチェーン攻撃**、**安全でないモデル出力**、そしてagentが幻覚されたURLを自律的に利用することによる**rogue actions**です。

## References

- [1] [OWASP機械学習の脆弱性トップ10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF（Secure AI Framework）– リスク](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS脅威マトリクス](https://atlas.mitre.org/)
- [4] [Unit 42 – コードアシスタントLLMのリスク：有害コンテンツ、悪用、欺瞞](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking：盗まれたクラウド認証情報を利用した新たなAI攻撃](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJackingスキームの概要 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（盗まれたLLMアクセスの再販）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - オンプレミスの低権限LLMサーバーの導入を詳しく解説](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)仕様](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting：AIが幻覚するドメインを利用したソフトウェアサプライチェーン攻撃](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting：AIの幻覚が新たなサプライチェーン攻撃を生み出す仕組み](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
