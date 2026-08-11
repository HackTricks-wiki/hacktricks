# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owaspは、AIシステムに影響を及ぼす可能性がある機械学習の主要な10個の脆弱性を特定しています。これらの脆弱性は、データポイズニング、モデルインバージョン、敵対的攻撃など、さまざまなセキュリティ問題につながる可能性があります。安全なAIシステムを構築するには、これらの脆弱性を理解することが重要です。

機械学習の主要な10個の脆弱性について、更新された詳細な一覧は、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projectを参照してください。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 攻撃者は、**incoming data**に非常に小さく、しばしば目に見えない変更を加え、モデルに誤った判断をさせます。\
*Example*: 一時停止標識に付着した数個の塗料の斑点によって、自動運転車がそれを速度制限標識だと「認識」してしまいます。

- **Data Poisoning Attack**: **training set**に悪意のあるサンプルを意図的に混入し、モデルに有害なルールを学習させます。\
*Example*: ウイルス対策ソフトのtraining corpusで、マルウェアのバイナリを「benign」と誤分類し、後に類似したマルウェアをすり抜けさせます。

- **Model Inversion Attack**: 出力を調査することで、攻撃者は元の入力に含まれる機密性の高い特徴を再構築する**reverse model**を作成します。\
*Example*: がん検出モデルの予測から、患者のMRI画像を再現します。

- **Membership Inference Attack**: 攻撃者は、信頼度の違いを見つけることで、**specific record**がtraining中に使用されたかどうかを検証します。\
*Example*: ある人物の銀行取引が、詐欺検出モデルのtraining dataに含まれていることを確認します。

- **Model Theft**: 繰り返しqueryを送ることで、攻撃者は判断境界と**clone the model's behavior**（およびIP）を学習できます。\
*Example*: ML-as-a-Service APIから十分なQ&Aペアを収集し、ほぼ同等のローカルモデルを構築します。

- **AI Supply-Chain Attack**: **ML pipeline**内のコンポーネント（data、libraries、pre-trained weights、CI/CD）のいずれかを侵害し、下流のモデルを破壊します。\
*Example*: model-hub上のpoisoned dependencyが、バックドア付きのsentiment-analysis modelを多数のアプリにインストールします。

- **Transfer Learning Attack**: **pre-trained model**に悪意のあるロジックを埋め込み、被害者のtaskでfine-tuningした後も存続させます。\
*Example*: 隠されたtriggerを持つvision backboneが、medical imaging向けに適応された後もラベルを反転させます。

- **Model Skewing**: 微妙に偏った、または誤ってラベル付けされたdataによって、攻撃者の意図に有利になるように**shifts the model's outputs**します。\
*Example*: 「clean」なspamメールをhamとラベル付けして注入し、spam filterに類似した今後のメールを通過させます。

- **Output Integrity Attack**: 攻撃者はモデル自体ではなく、**model predictions in transit**を変更し、下流のシステムを欺きます。\
*Example*: ファイルのquarantine stageが確認する前に、マルウェアclassifierの「malicious」判定を「benign」に反転させます。

- **Model Poisoning** --- 多くの場合、書き込みアクセスを取得した後に、**model parameters**自体を直接かつ標的を絞って変更し、挙動を変えます。\
*Example*: 本番環境のfraud-detection modelのweightsを調整し、特定のカードによる取引を常に承認させます。


## Google SAIF Risks

Googleの[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)は、AIシステムに関連するさまざまなリスクを概説しています。<sup>[[2]](#references)</sup>

- **Data Poisoning**: 悪意のある攻撃者がtraining/tuning dataを変更または注入し、精度を低下させ、backdoorを埋め込み、または結果を歪めることで、data-lifecycle全体にわたってmodel integrityを損ないます。

- **Unauthorized Training Data**: 著作権のある、機密性の高い、または許可されていないdatasetを取り込むと、モデルが使用を許可されていないdataから学習するため、法的、倫理的、性能上の責任が発生します。

- **Model Source Tampering**: training前またはtraining中に、model code、dependencies、weightsをsupply-chainまたは内部者が操作すると、retraining後も存続する隠れたロジックが埋め込まれる可能性があります。

- **Excessive Data Handling**: data-retentionとgovernanceの管理が弱いと、システムが必要以上の個人dataを保存または処理し、情報漏えいとcomplianceのリスクが高まります。

- **Model Exfiltration**: 攻撃者がmodel files/weightsを盗み、知的財産の損失を引き起こすとともに、模倣サービスや後続攻撃を可能にします。

- **Model Deployment Tampering**: 攻撃者がmodel artifactsまたはserving infrastructureを変更し、実行中のモデルを検証済みのversionと異なるものにすることで、挙動を変える可能性があります。

- **Denial of ML Service**: APIへのfloodingや「sponge」inputsの送信によってcompute/energyを枯渇させ、モデルをofflineにします。これは従来のDoS攻撃に類似しています。

- **Model Reverse Engineering**: 大量のinput-output pairsを収集することで、攻撃者はモデルをcloneまたはdistilし、模倣製品やカスタマイズされたadversarial attacksに利用できます。

- **Insecure Integrated Component**: 脆弱なplugins、agents、またはupstream servicesによって、攻撃者がAI pipeline内にcodeを注入したり、privilegesを昇格させたりできます。

- **Prompt Injection**: promptを（直接または間接的に）細工して、system intentを上書きするinstructionsを紛れ込ませ、モデルに意図しないcommandsを実行させます。

- **Model Evasion**: 注意深く設計されたinputsによって、モデルに誤分類、hallucination、または許可されていないcontentの出力を引き起こし、安全性と信頼性を損ないます。

- **Sensitive Data Disclosure**: モデルがtraining dataまたはuser contextからprivateまたはconfidentialな情報を明らかにし、privacyと規制に違反します。

- **Inferred Sensitive Data**: モデルが提供されていない個人属性を推測し、inferenceを通じて新たなprivacy上の被害を生み出します。

- **Insecure Model Output**: サニタイズされていないresponsesが有害なcode、misinformation、または不適切なcontentをusersや下流のシステムに渡します。

- **Rogue Actions**: 自律的に統合されたagentsが、十分なuser oversightなしに、意図しない現実世界のoperations（file writes、API calls、purchasesなど）を実行します。

## Mitre AI ATLAS Matrix

[M​​ITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)は、AIシステムに関連するリスクを理解し、軽減するための包括的なframeworkを提供します。これは、攻撃者がAIモデルに対して使用する可能性のあるさまざまなattack techniquesとtactics、およびAIシステムを使用してさまざまな攻撃を実行する方法を分類しています。<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻撃者は、active session tokensまたはcloud API credentialsを盗み、許可なく有料のcloud-hosted LLMsを呼び出します。アクセスは、被害者のaccountを前面に置くreverse proxiesを通じて再販売されることが多く、例えば「oai-reverse-proxy」deploymentsなどがあります。結果として、金銭的損失、policy外でのmodel misuse、被害者tenantへの責任帰属が発生します。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- 感染したdeveloper machinesやbrowsersからtokensを収集し、CI/CD secretsを盗み、leaked cookiesを購入します。<sup>[[5]](#references)</sup>
- genuine providerにrequestsを転送するreverse proxyを構築し、upstream keyを隠しながら多数のcustomersをmultiplexingします。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- direct base-model endpointsを悪用し、enterprise guardrailsとrate limitsを回避します。<sup>[[4]](#references)</sup>

Mitigations:
- tokensをdevice fingerprint、IP ranges、client attestationにbindし、短いexpirationを強制してMFAでrefreshします。
- keysのscopeを最小限にします（tool accessなし、該当する場合はread-only）。異常時にはrotateします。
- すべてのtrafficをpolicy gatewayの背後でserver-sideにterminateし、安全性filters、routeごとのquotas、tenant isolationを強制します。
- 異常なusage patterns（突然のspend spikes、通常と異なるregions、UA strings）を監視し、疑わしいsessionsを自動的にrevokeします。
- 長期間有効なstatic API keysではなく、IdPが発行するmTLSまたはsigned JWTsを優先します。

## Self-hosted LLM inference hardening

機密dataのためにlocal LLM serverを実行すると、cloud-hosted APIsとは異なるattack surfaceが生じます。inference/debug endpointsからpromptsがleakする可能性があり、serving stackは通常reverse proxyを公開し、GPU device nodesは大規模な`ioctl()` surfacesへのアクセスを提供します。on-prem inference serviceを評価またはdeployする場合は、少なくとも以下の点を確認してください。<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

inference APIを**multi-user sensitive service**として扱います。debugまたはmonitoring routesによって、prompt contents、slot state、model metadata、またはinternal queue informationが公開される可能性があります。`llama.cpp`では、`/slots` endpointはslotごとのstateを公開するため特に機密性が高く、slotのinspection/management専用です。<sup>[[8]](#references)</sup>

- inference serverの前段にreverse proxyを配置し、**deny by default**にします。
- client/UIに必要な正確なHTTP method + path combinationsのみをallowlistに追加します。
- 可能な限りbackend自体でintrospection endpointsを無効化します。例えば`llama-server --no-slots`です。<sup>[[9]](#references)</sup>
- reverse proxyを`127.0.0.1`にbindし、LAN上に公開するのではなく、SSH local port forwardingなどのauthenticated transportを通じて公開します。

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
### ネットワークなしのRootless containersとUNIX sockets

推論 daemonがUNIX socketでlistenできる場合は、TCPよりもUNIX socketを優先し、**ネットワークスタックなし**でcontainerを実行します:<sup>[[8]](#references)</sup>
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
メリット:
- `--network none` は inbound/outbound TCP/IP exposure を排除し、rootless containers が otherwise 必要とする user-mode helpers を回避します。
- UNIX socket を使用すると、socket path の POSIX permissions/ACLs を first access-control layer として利用できます。
- `--userns=keep-id` と rootless Podman により、container breakout の影響を軽減できます。これは container root が host root ではないためです。
- Read-only model mounts により、container 内部からの model tampering の可能性を低減できます。

Persistent deployments では、同じ restrictions を Podman Quadlet units として表現できます。GPU access を Container Device Interface 経由で委譲する場合は、すべての accelerator node を expose するのではなく、CDI device specification を可能な限り narrow に保ってください。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node の最小化

GPU-backed inference では、`/dev/nvidia*` files は高価値の local attack surfaces です。これらは大規模な driver `ioctl()` handlers と、共有される可能性のある GPU memory-management paths を expose するためです。<sup>[[8]](#references)</sup>

- `/dev/nvidia*` を world writable のままにしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使用して、`nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、mapped container UID のみがこれらを open できるようにします。
- Headless inference hosts では、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要な modules を blacklist します。
- Inference startup 中に runtime が opportunistically `modprobe` するのではなく、boot 時に必要な modules のみを preload します。

例:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
重要なレビュー項目の1つが **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していない場合でも、最近の CUDA runtime では `nvidia-uvm` が必要になることがあります。このデバイスは共有され、GPU virtual memory management を処理するため、cross-tenant data-exposure surface として扱ってください。inference backend が対応している場合、Vulkan backend は興味深いトレードオフになる可能性があります。これは、container に `nvidia-uvm` を公開する必要が完全になくなる場合があるためです。<sup>[[8]](#references)</sup>

### inference workers の LSM confinement

AppArmor/SELinux/seccomp は、inference process の周囲で defense in depth として使用すべきです。<sup>[[8]](#references)</sup>

- 実際に必要な shared libraries、model paths、socket directory、GPU device nodes のみを許可します。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの high-risk capabilities を明示的に拒否します。
- model directory は read-only のままにし、書き込み可能な paths は runtime socket/cache directories のみに限定します。
- denial logs を監視します。model server または post-exploitation payload が想定された behaviour から脱出しようとした際に、有用な detection telemetry が得られるためです。

GPU-backed worker 用の AppArmor rules の例:
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
## Phantom Squatting: LLMが幻覚したドメインをAIサプライチェーン攻撃ベクトルとして利用

Phantom squattingは、**slopsquattingのドメイン/URL版**です。存在しないパッケージ名を幻覚させる代わりに、LLMは実在するブランドの**ポータル、API、webhook、請求、SSO、ダウンロード、またはサポート用ドメイン**らしいものを幻覚させ、攻撃者は人間またはagentが利用する前に、そのnamespaceを登録します。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

これは、多くのAI支援ワークフローで、モデルの出力が**信頼された依存関係**として扱われるため重要です。
- 開発者が、提案されたendpointをコードやCI/CD integrationに貼り付ける。
- AI agentがドキュメント、schema、APK、ZIP、またはwebhook targetを自動的に取得する。
- 生成されたrunbookやドキュメントに、権威あるものとして偽URLが埋め込まれる。

### Offensive workflow

1. **幻覚対象の範囲を調査する**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、または`mobile app`ポータルなど、現実的なワークフローについてブランド固有の質問を行います。<sup>[[12]](#references)</sup>
2. **候補を正規化する**: 生成されたURLを解決し、NXDOMAIN responseを親の登録可能なドメインに集約し、prompt familyの重複を排除します。Prompt corpusは、例えば**Jaccard similarity**によって近似重複を削除するなど、多様性を維持する必要があります。
3. **予測可能な幻覚を優先する**:
- **Thermal Hallucination Persistence (THP)**: 同じ偽ドメインが、`T=0.1`のような低temperatureを含め、異なるtemperatureで出現する。
- **Cross-model consensus**: 複数のLLM familyが同じ偽ドメインを生成する。
4. **親ドメインを登録してweaponizeする**。その後、phishing、偽APK/ZIP download、credential harvester、悪意のあるドキュメント、またはsecret/webhook payloadを収集するAPI endpointをホストします。**純粋なドメインレベルの幻覚**は、攻撃者がnamespace全体を制御できるため、最も収益化しやすいものです。subdomain/pathの幻覚も、正規化された親ドメインが未登録であれば悪用できます。
5. **zero-reputation windowを悪用する**: 新しく登録されたドメインには、blocklist履歴、URL reputation、成熟したtelemetryがないことが多く、検知が追いつくまでcontrolを回避できます。攻撃者は、crawlerにのみ良性のresponseを返す、redirect cloaking、CAPTCHA gate、またはpayload stagingの遅延によって、このwindowを引き延ばせます。

### なぜagentにとって危険なのか

人間の被害者の場合、偽ドメインには通常、clickと追加の操作が必要です。しかし**agentic workflow**では、LLMが**lure**と**executor**の両方になり得ます。agentは幻覚したURLを受け取り、それをfetchしてresponseをparseし、その後、人間によるreviewなしにtokenをleakしたり、instructionをexecuteしたり、dependencyをdownloadしたり、汚染されたdataをCI/CDにpushしたりする可能性があります。<sup>[[12]](#references)</sup>

### 実用的な攻撃者向けprompt

効果の高いpromptは、明示的なphishing lureではなく、通常のenterprise taskに見えるものです。<sup>[[12]](#references)</sup>
- 「`<brand>` integration向けのpayment sandbox URLは何ですか？」
- 「`<brand>`のbuild notificationには、どのwebhook endpointを使うべきですか？」
- 「`<brand>`のemployee benefits / billing / SSO portalはどこですか？」
- 「`<brand>`向けのAndroid APKまたはdesktop clientの直接download先を教えてください。」

### 防御的な反転

これは単なるprompt-injectionの問題ではなく、proactiveなdomain-monitoringの問題として扱います。<sup>[[12]](#references)</sup>
- **brand prompt corpus**を構築し、ユーザー/agentが依存するLLMを定期的にprobeする。
- 幻覚されたURLを保存し、temperature/model間で安定しているものを追跡する。
- **Adversarial Exploitation Window (AEW)**を追跡する。これは、最初の幻覚から攻撃者による登録までの時間です。AEWが正であれば、防御側はweaponizationの前にpre-register、sinkhole、またはpre-blockできます。
- 親ドメインにおける**NXDOMAIN → registered**の遷移を監視する。
- 登録時に、registrar、creation date、nameserver、privacy shielding、page content、screenshot、parked-page status、brand assetとの類似性をtriageする。
- agent/developerが**デフォルトでLLM生成ドメインを信頼しない**ようpolicy gateを追加する。初回利用の前に、allowlist、ownership validation、CT/RDAP check、またはhuman approvalを必須にする。

これは複数のAI risk bucketに同時に該当します。すなわち、**AI supply-chain attack**、**insecure model output**、そしてagentが幻覚されたURLを自律的に消費する場合の**rogue actions**です。

## References

- [1] [OWASP Machine Learning Vulnerability Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF（Secure AI Framework）– Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLMのリスク: 有害なコンテンツ、悪用、欺瞞](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: 盗まれたCloud Credentialが新たなAI攻撃に利用される](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking schemeの概要 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（盗んだLLM accessのreselling）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - on-premiseのlow-privileged LLM serverのdeploymentに関するdeep-dive](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AIが幻覚したドメインをSoftware Supply Chain Vectorとして利用](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AIの幻覚が新たなSupply Chain Attack Classを生み出す仕組み](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
