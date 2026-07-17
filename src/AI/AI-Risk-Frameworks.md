# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owaspは、AI systemsに影響を与える可能性のあるmachine learning vulnerabilitiesのtop 10を特定しています。これらのvulnerabilitiesは、data poisoning、model inversion、adversarial attacksなど、さまざまなsecurity issuesにつながる可能性があります。安全なAI systemsを構築するには、これらのvulnerabilitiesを理解することが重要です。

machine learning vulnerabilitiesのtop 10について、最新かつ詳細な一覧は、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projectを参照してください。

- **Input Manipulation Attack**: 攻撃者は**incoming data**にごく小さな、しばしば目に見えない変更を加え、modelに誤った判断をさせます。\
*Example*: stop signに付着した少数の塗料の斑点によって、自動運転車がそれをspeed-limit signだと「認識」してしまいます。

- **Data Poisoning Attack**: **training set**に悪意のあるサンプルを意図的に混入し、modelに有害なルールを学習させます。\
*Example*: antivirus training corpus内のmalware binariesを「benign」と誤ってlabel付けし、後に類似したmalwareをすり抜けさせます。

- **Model Inversion Attack**: 出力をprobeすることで、攻撃者は**reverse model**を構築し、元のinputsに含まれるsensitive featuresを再構成します。\
*Example*: cancer-detection modelのpredictionsから、患者のMRI imageを再作成します。

- **Membership Inference Attack**: adversaryはconfidenceの違いを見つけることで、**specific record**がtraining中に使用されたかどうかを検証します。\
*Example*: ある人物のbank transactionがfraud-detection modelのtraining dataに含まれていることを確認します。

- **Model Theft**: 繰り返しqueryすることで、攻撃者はdecision boundariesを学習し、**model's behavior**（およびIP）をcloneできます。\
*Example*: ML-as-a-Service APIから十分なQ&A pairsを収集し、ほぼ同等のlocal modelを構築します。

- **AI Supply-Chain Attack**: **ML pipeline**内の任意のcomponent（data、libraries、pre-trained weights、CI/CD）をcompromiseし、下流のmodelsを破壊します。\
*Example*: model-hub上のpoisoned dependencyがbackdoored sentiment-analysis modelをinstallし、多数のappsに展開します。

- **Transfer Learning Attack**: **pre-trained model**に悪意のあるlogicを仕込み、victimのtaskでfine-tuningした後も存続させます。\
*Example*: hidden triggerを持つvision backboneが、medical imaging向けにadaptされた後もlabelsを反転させます。

- **Model Skewing**: 微妙にbiasedまたはmislabeledなdataによって、**model's outputs**を攻撃者のagendaに有利な方向へ移動させます。\
*Example*: 「clean」なspam emailsをhamとしてlabel付けして注入し、spam filterが今後の類似emailsを通過させるようにします。

- **Output Integrity Attack**: 攻撃者はmodel自体ではなく、**model predictions in transit**を変更して、downstream systemsを欺きます。\
*Example*: file-quarantine stageが確認する前に、malware classifierの「malicious」判定を「benign」に反転させます。

- **Model Poisoning** --- 多くの場合write accessを取得した後、**model parameters**自体に直接かつtargetedな変更を加え、behaviorを変更します。\
*Example*: production環境のfraud-detection modelのweightsを調整し、特定のcardsからのtransactionsが常に承認されるようにします。


## Google SAIF Risks

Googleの[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)は、AI systemsに関連するさまざまなrisksを概説しています。

- **Data Poisoning**: 悪意のあるactorsがtraining/tuning dataを変更または注入し、accuracyを低下させ、backdoorsを埋め込み、またはresultsを歪めます。これにより、data-lifecycle全体にわたってmodel integrityが損なわれます。

- **Unauthorized Training Data**: copyrighted、sensitive、または許可されていないdatasetsを取り込むと、modelが使用を許可されていないdataから学習するため、legal、ethical、performance上のliabilitiesが生じます。

- **Model Source Tampering**: training前またはtraining中にmodel code、dependencies、またはweightsをsupply-chainまたはinsiderが操作すると、retraining後も存続するhidden logicを埋め込む可能性があります。

- **Excessive Data Handling**: data-retentionおよびgovernance controlsが弱いと、systemsが必要以上のpersonal dataを保存または処理し、exposureおよびcompliance riskが高まります。

- **Model Exfiltration**: 攻撃者がmodel files/weightsを盗み、intellectual propertyの損失を引き起こすとともに、copy-cat servicesや後続のattacksを可能にします。

- **Model Deployment Tampering**: adversariesがmodel artifactsまたはserving infrastructureを変更し、実行中のmodelを検証済みversionと異なるものにします。これによりbehaviorが変化する可能性があります。

- **Denial of ML Service**: APIsをfloodしたり「sponge」inputsを送信したりしてcompute/energyを枯渇させ、modelをofflineにします。これは従来のDoS attacksに類似しています。

- **Model Reverse Engineering**: 大量のinput-output pairsを収集することで、攻撃者はmodelをcloneまたはdistilし、imitation productsやcustomized adversarial attacksに利用します。

- **Insecure Integrated Component**: vulnerableなplugins、agents、またはupstream servicesによって、攻撃者がAI pipeline内にcodeを注入したり、privilegesをescalateしたりできます。

- **Prompt Injection**: promptsを直接または間接的に細工し、system intentをoverrideするinstructionsを紛れ込ませることで、modelに意図しないcommandsを実行させます。

- **Model Evasion**: carefully designed inputsによってmodelにmis-classify、hallucinate、またはdisallowed contentの出力をさせ、安全性とtrustを損ないます。

- **Sensitive Data Disclosure**: modelがtraining dataまたはuser contextからprivateまたはconfidential informationを明らかにし、privacyおよびregulationsに違反します。

- **Inferred Sensitive Data**: modelが提供されていないpersonal attributesを推測し、inferenceを通じて新たなprivacy harmsを生み出します。

- **Insecure Model Output**: unsanitized responsesがharmful code、misinformation、またはinappropriate contentをusersやdownstream systemsに渡します。

- **Rogue Actions**: 自律的にintegrateされたagentsが、十分なuser oversightなしに意図しないreal-world operations（file writes、API calls、purchasesなど）を実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)は、AI systemsに関連するrisksを理解し、mitigateするための包括的なframeworkを提供します。adversariesがAI modelsに対して使用する可能性のあるさまざまなattack techniquesおよびtacticsを分類し、AI systemsを利用してさまざまなattacksを実行する方法も示しています。


## LLMJacking（Token Theft & Cloud-hosted LLM AccessのResale）

攻撃者はactive session tokensまたはcloud API credentialsを盗み、許可なく有料のcloud-hosted LLMsをinvokeします。Accessは、victimのaccountを前面に出すreverse proxiesを介してresellされることが多く、例として「oai-reverse-proxy」deploymentsがあります。Consequencesにはfinancial loss、policy外でのmodel misuse、victim tenantへのattributionなどが含まれます。

TTPs:
- 感染したdeveloper machinesまたはbrowsersからtokensをharvestし、CI/CD secretsを盗み、leaked cookiesを購入します。
- genuine providerにrequestsをforwardするreverse proxyをstand upし、upstream keyを隠して多数のcustomersをmultiplexします。
- enterprise guardrailsおよびrate limitsをbypassするため、direct base-model endpointsをabuseします。

Mitigations:
- tokensをdevice fingerprint、IP ranges、client attestationにbindし、short expirationsを強制してMFAでrefreshします。
- keysのscopeを最小限にします（tool accessなし、該当する場合はread-only）。anomaly発生時にはrotateします。
- safety filters、routeごとのquotas、tenant isolationをenforceするpolicy gatewayの背後に、すべてのtrafficをserver-sideでterminateします。
- unusual usage patterns（突然のspend spikes、atypical regions、UA strings）をmonitorし、疑わしいsessionsをauto-revokeします。
- long-lived static API keysよりも、IdPが発行するmTLSまたはsigned JWTsを優先します。

## Self-hosted LLM inference hardening

confidential data向けにlocal LLM serverを実行すると、cloud-hosted APIsとは異なるattack surfaceが生じます。inference/debug endpointsからpromptsがleakする可能性があり、serving stackは通常reverse proxyをexposeし、GPU device nodesは大規模な`ioctl()` surfacesへのaccessを提供します。on-prem inference serviceをassessmentまたはdeployする場合は、少なくとも以下のpointsをreviewしてください。

### Debugおよびmonitoring endpoints経由のPrompt leakage

inference APIを**multi-user sensitive service**として扱ってください。Debugまたはmonitoring routesは、prompt contents、slot state、model metadata、internal queue informationをexposeする可能性があります。`llama.cpp`では、`/slots` endpointはper-slot stateをexposeし、slot inspection/managementのみを目的としているため、特にsensitiveです。

- inference serverの前段にreverse proxyを配置し、**deny by default**にします。
- client/UIに必要なexactなHTTP method + path combinationsのみをallowlistします。
- 可能な場合はbackend自体のintrospection endpointsをdisableします。たとえば`llama-server --no-slots`を使用します。
- reverse proxyを`127.0.0.1`にbindし、LAN上でpublishするのではなく、SSH local port forwardingなどのauthenticated transportを通じてexposeします。

nginxを使用したallowlistの例:
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
### network と UNIX sockets を使用しない Rootless containers

inference daemon が UNIX socket での listen をサポートしている場合は、TCP よりもそちらを優先し、**network stack なし**で container を実行します：
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
- `--network none` は inbound/outbound TCP/IP exposure を削除し、rootless containers が otherwise 必要とする user-mode helpers を回避します。
- UNIX socket により、socket path 上の POSIX permissions/ACLs を first access-control layer として使用できます。
- `--userns=keep-id` と rootless Podman により、container breakout の影響を軽減できます。これは、container root が host root ではないためです。
- Read-only model mounts により、container 内部からの model tampering の可能性を低減できます。

### GPU device-node minimization

GPU-backed inference では、`/dev/nvidia*` files は、広範な driver `ioctl()` handlers と、共有される可能性のある GPU memory-management paths を公開するため、high-value local attack surfaces です。

- `/dev/nvidia*` を world writable のままにしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使用して、`nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、mapped container UID のみがそれらを open できるようにしてください。
- headless inference hosts では、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要な modules を blacklist してください。
- inference startup 中に runtime が opportunistically `modprobe` できるようにするのではなく、boot 時に必要な modules のみを preload してください。

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
重要なレビュー項目の1つが **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していない場合でも、最近の CUDA runtime では `nvidia-uvm` が必要になることがあります。この device は共有され、GPU virtual memory management を担うため、cross-tenant data-exposure surface として扱ってください。inference backend が対応している場合、Vulkan backend は興味深いトレードオフになる可能性があります。これは、container に `nvidia-uvm` を公開する必要自体を回避できる場合があるためです。

### inference worker の LSM confinement

inference process の周囲では、defense in depth として AppArmor/SELinux/seccomp を使用してください。

- 実際に必要な shared library、model path、socket directory、GPU device node のみを許可します。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの high-risk capability を明示的に拒否します。
- model directory は read-only のままにし、書き込み可能な path は runtime socket/cache directory のみに限定します。
- denial log を監視します。model server または post-exploitation payload が想定された挙動から escape しようとした際に、有用な detection telemetry が得られるためです。

GPU-backed worker 用の AppArmor rule の例:
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
## Phantom Squatting: LLMが幻覚したドメインによるAIサプライチェーン攻撃ベクトル

Phantom squattingは、**slopsquattingのドメイン/URL版**です。存在しないパッケージ名を幻覚する代わりに、LLMは実在するブランドのもっともらしい**ポータル、API、webhook、請求、SSO、download、support用ドメイン**を幻覚し、人間やagentが使用する前に攻撃者がそのnamespaceを登録します。

これは、多くのAI支援ワークフローでモデルの出力が**信頼された依存関係**として扱われるため重要です。
- 開発者が提案されたendpointをコードやCI/CD integrationsに貼り付ける。
- AI agentsがdocumentation、schemas、APK、ZIP、webhook targetsを自動的に取得する。
- 生成されたrunbooksやdocsに、偽のURLが権威あるものとして埋め込まれる可能性がある。

### Offensive workflow

1. **幻覚面をプローブする**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app`ポータルなど、現実的なworkflowについてbrand-specificな質問を行う。
2. **候補を正規化する**: 生成されたURLをresolveし、NXDOMAIN responsesを親のregisterable domainに集約し、prompt familiesの重複を排除する。Prompt corporaは、例えば**Jaccard similarity**によって近似重複を除外するなど、多様性を維持する。
3. **予測可能な幻覚を優先する**:
- **Thermal Hallucination Persistence (THP)**: `T=0.1`のような低temperatureを含め、同じ偽ドメインが複数のtemperatureで出現する。
- **Cross-model consensus**: 複数のLLM familiesが同じ偽ドメインを生成する。
4. **親ドメインを登録してweaponize**し、phishing、偽APK/ZIP downloads、credential harvesters、malicious docs、またはsecrets/webhook payloadsを収集するAPI endpointsをホストする。**Pure domain-level hallucinations**は、攻撃者がnamespace全体を制御できるため最もmonetizeしやすい。subdomain/path hallucinationsも、正規化された親が未登録であれば悪用できる。
5. **zero-reputation windowを悪用する**: 新規登録されたドメインにはblocklist history、URL reputation、成熟したtelemetryが存在しないことが多く、detectionsが追いつくまでcontrolsを回避できる。攻撃者は、crawler-onlyの良性responses、redirect cloaking、CAPTCHA gates、遅延させたpayload stagingによって、このwindowを引き延ばせる。

### なぜagentsにとって危険なのか

人間の被害者の場合、通常、偽ドメインにはclickと追加の操作が必要です。しかし**agentic workflow**では、LLMが**lure**と**executor**の両方になり得ます。agentは幻覚されたURLを受け取り、それをfetchしてresponseをparseし、その後tokensをleakしたり、instructionsをexecuteしたり、dependencyをdownloadしたり、人間のreviewなしにCI/CDへpoisoned dataをpushしたりする可能性があります。

### Practical attacker prompts

高い成果が得られるpromptsは、明示的なphishing luresではなく、通常のenterprise tasksに見えるものです。
- 「`<brand>` integrations用のpayment sandbox URLは何ですか？」
- 「`<brand>` build notificationsには、どのwebhook endpointを使うべきですか？」
- 「`<brand>`のemployee benefits / billing / SSO portalはどこですか？」
- 「`<brand>`用のAndroid APKまたはdesktop clientの直接downloadを教えてください。」

### Defensive inversion

これはprompt-injection problemだけでなく、proactiveなdomain-monitoring problemとして扱います。
- **brand prompt corpus**を構築し、ユーザーやagentsが依存するLLMsを定期的にprobeする。
- 幻覚されたURLsを保存し、temperature/models間で安定しているものを追跡する。
- **Adversarial Exploitation Window (AEW)**を追跡する。これは最初の幻覚から攻撃者による登録までの時間である。AEWがpositiveであれば、defendersはweaponizationの前にpre-register、sinkhole、またはpre-blockできる。
- 親ドメインの**NXDOMAIN → registered**遷移をmonitorする。
- 登録時に、registrar、creation date、nameservers、privacy shielding、page content、screenshots、parked-page status、brand-asset similarityをtriageする。
- agents/developersが**デフォルトでLLM-generated domainsをtrustしない**ようpolicy gatesを追加する。初回使用前に、allowlists、ownership validation、CT/RDAP checks、またはhuman approvalを要求する。

これは複数のAI risk bucketsに同時に該当します。**AI supply-chain attack**、**insecure model output**、そしてagentsが幻覚されたURLを自律的にconsumeする場合の**rogue actions**です。

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
