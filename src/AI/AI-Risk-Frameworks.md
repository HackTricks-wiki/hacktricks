# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp は、AI システムに影響を与える可能性のある machine learning の脆弱性トップ 10 を特定しています。これらの脆弱性は、data poisoning、model inversion、adversarial attacks など、さまざまな security issues につながる可能性があります。安全な AI システムを構築するには、これらの脆弱性を理解することが重要です。

machine learning の脆弱性トップ 10 の最新かつ詳細な一覧については、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project を参照してください。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: attacker が **incoming data** に、非常に小さく、多くの場合は目に見えない変更を加え、model に誤った判断をさせます。\
*Example*: stop-sign に数個の塗料の斑点を付けるだけで、自動運転車に speed-limit sign と「認識」させます。

- **Data Poisoning Attack**: **training set** に悪意のあるサンプルを意図的に混入し、model に有害なルールを学習させます。\
*Example*: antivirus の training corpus で malware binaries に "benign" と誤ったラベルを付け、後に類似した malware をすり抜けさせます。

- **Model Inversion Attack**: 出力を調査することで、attacker は元の入力に含まれる機密性の高い特徴を再構成する **reverse model** を構築します。\
*Example*: cancer-detection model の予測結果から患者の MRI 画像を再現します。

- **Membership Inference Attack**: adversary は信頼度の差を見つけることで、**specific record** が training 中に使用されたかどうかを検証します。\
*Example*: ある人物の bank transaction が fraud-detection model の training data に含まれていることを確認します。

- **Model Theft**: 繰り返し query を送ることで、attacker は decision boundaries と **clone the model's behavior**（および IP）を学習できます。\
*Example*: ML-as-a-Service API から十分な Q&A pairs を収集し、ほぼ同等の local model を構築します。

- **AI Supply-Chain Attack**: **ML pipeline** 内の任意の component（data、libraries、pre-trained weights、CI/CD）を compromise し、下流の model を破壊します。\
*Example*: model-hub 上の poisoned dependency により、backdoored sentiment-analysis model が多数の app にインストールされます。

- **Transfer Learning Attack**: **pre-trained model** に悪意のある logic を仕込み、victim の task に対する fine-tuning 後も存続させます。\
*Example*: hidden trigger を持つ vision backbone が、medical imaging 用に適応された後も labels を反転させます。

- **Model Skewing**: subtle に偏った、または誤ったラベルの data により、**shifts the model's outputs** が attacker の agenda に有利になるように変化します。\
*Example*: "clean" な spam emails に ham のラベルを付けて注入し、spam filter に類似した将来の emails を通過させます。

- **Output Integrity Attack**: attacker は model 自体ではなく、**alters model predictions in transit** によって model predictions を転送中に変更し、下流の systems を欺きます。\
*Example*: file-quarantine stage が判定を確認する前に、malware classifier の "malicious" verdict を "benign" に反転させます。

- **Model Poisoning** --- 多くの場合、write access を取得した後に **model parameters** 自体を直接かつ標的を絞って変更し、挙動を変化させます。\
*Example*: production 環境の fraud-detection model の weights を調整し、特定の cards からの transactions を常に承認させます。


## Google SAIF Risks

Google の [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) は、AI systems に関連するさまざまな risks の概要を示しています。<sup>[[2]](#references)</sup>

- **Data Poisoning**: malicious actors が training/tuning data を変更または注入し、accuracy を低下させ、backdoors を埋め込み、または results を歪めます。これにより、data-lifecycle 全体で model integrity が損なわれます。

- **Unauthorized Training Data**: copyright で保護された data、sensitive な data、または許可されていない datasets を取り込むと、model が使用を許可されていなかった data から学習するため、legal、ethical、performance 上の liabilities が生じます。

- **Model Source Tampering**: training の前または training 中に model code、dependencies、または weights を supply-chain または insider が manipulation すると、retraining 後も存続する hidden logic が組み込まれる可能性があります。

- **Excessive Data Handling**: data-retention と governance の controls が弱いと、systems が必要以上の personal data を保存または処理し、exposure と compliance の risk が高まります。

- **Model Exfiltration**: attackers が model files/weights を盗み、intellectual property の損失を引き起こすほか、copy-cat services や後続の attacks を可能にします。

- **Model Deployment Tampering**: adversaries が model artifacts または serving infrastructure を変更し、実行中の model が検証済み version と異なる状態にします。これにより behaviour が変化する可能性があります。

- **Denial of ML Service**: APIs を flood したり “sponge” inputs を送信したりすることで、compute/energy を枯渇させて model を offline にし、従来の DoS attacks と同様の影響を与えます。

- **Model Reverse Engineering**: 大量の input-output pairs を収集することで、attackers は model を clone または distil でき、模倣 products やカスタマイズされた adversarial attacks を助長します。

- **Insecure Integrated Component**: vulnerable な plugins、agents、または upstream services により、attackers は AI pipeline 内に code を注入したり、privileges を escalate したりできます。

- **Prompt Injection**: prompts を直接または間接的に細工して、system intent を override する instructions を紛れ込ませ、model に意図しない commands を実行させます。

- **Model Evasion**: carefully designed inputs により、model に mis-classify、hallucinate、または disallowed content の出力を実行させ、安全性と trust を損ないます。

- **Sensitive Data Disclosure**: model が training data または user context から private または confidential information を明らかにし、privacy と regulations に違反します。

- **Inferred Sensitive Data**: model が提供されていない personal attributes を推測し、inference による新たな privacy harms を生み出します。

- **Insecure Model Output**: unsanitized responses が harmful code、misinformation、または inappropriate content を users や downstream systems に渡します。

- **Rogue Actions**: autonomously-integrated agents が、適切な user oversight なしに、意図しない real-world operations（file writes、API calls、purchases など）を実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) は、AI systems に関連する risks を理解し、mitigate するための包括的な framework を提供します。これは adversaries が AI models に対して使用する可能性のあるさまざまな attack techniques と tactics、および AI systems を使用してさまざまな attacks を実行する方法を分類しています。<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers は active session tokens または cloud API credentials を盗み、許可なく有料の cloud-hosted LLMs を invoke します。access は、victim の account を前面に置く reverse proxies を通じて resell されることが多く、例として "oai-reverse-proxy" deployments があります。結果として、financial loss、policy 外での model misuse、victim tenant への attribution などが発生します。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- infected developer machines または browsers から tokens を harvest し、CI/CD secrets を盗み、leaked cookies を購入します。<sup>[[5]](#references)</sup>
- genuine provider に requests を転送する reverse proxy を立ち上げ、upstream key を隠し、多数の customers を multiplex します。<sup>[[5]](#references)[[7]](#references)</sup>
- direct base-model endpoints を abuse して、enterprise guardrails と rate limits を bypass します。<sup>[[4]](#references)</sup>

Mitigations:
- tokens を device fingerprint、IP ranges、client attestation に bind し、short expirations を強制して MFA で refresh します。
- keys の scope を最小限にします（tool access なし、該当する場合は read-only）。anomaly 発生時には rotate します。
- safety filters、per-route quotas、tenant isolation を強制する policy gateway の背後に、すべての traffic を server-side で terminate します。
- unusual usage patterns（sudden spend spikes、atypical regions、UA strings）を monitor し、疑わしい sessions を自動的に revoke します。
- long-lived static API keys よりも、IdP が発行する mTLS または signed JWTs を優先します。

## Self-hosted LLM inference hardening

confidential data 用に local LLM server を実行すると、cloud-hosted APIs とは異なる attack surface が生じます。inference/debug endpoints から prompts が leak する可能性があり、serving stack は通常 reverse proxy を公開し、GPU device nodes は大規模な `ioctl()` surfaces への access を提供します。on-prem inference service を assess または deploy する場合は、少なくとも以下の points を review してください。<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

inference API は **multi-user sensitive service** として扱います。debug または monitoring routes により、prompt contents、slot state、model metadata、または internal queue information が露出する可能性があります。`llama.cpp` では、`/slots` endpoint は per-slot state を露出し、slot inspection/management のためだけに使用されるため、特に sensitive です。<sup>[[8]](#references)</sup>

- inference server の前に reverse proxy を配置し、**deny by default** にします。
- client/UI に必要な exact HTTP method + path combinations のみを allowlist します。
- 可能な場合は backend 自体の introspection endpoints を disable します。たとえば `llama-server --no-slots` です。<sup>[[9]](#references)</sup>
- reverse proxy を `127.0.0.1` に bind し、LAN に publish する代わりに、SSH local port forwarding などの authenticated transport を通じて expose します。

Example allowlist with nginx:
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
### ネットワークなしおよび UNIX ソケットを使用する Rootless containers

推論デーモンが UNIX ソケットでのリッスンをサポートしている場合は、TCP よりもそちらを優先し、**ネットワークスタックなし**でコンテナを実行します。<sup>[[8]](#references)</sup>
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
- `--network none` は inbound/outbound の TCP/IP exposure を除去し、rootless containers が通常必要とする user-mode helpers を回避します。
- UNIX socket を使用すると、socket path 上の POSIX permissions/ACLs を最初の access-control layer として利用できます。
- `--userns=keep-id` と rootless Podman により、container breakout の影響を軽減できます。これは、container root が host root ではないためです。
- Read-only model mounts により、container 内部からの model tampering の可能性を低減できます。

### GPU device-node minimization

GPU-backed inference では、`/dev/nvidia*` files は高価値な local attack surfaces です。これは、大規模な driver `ioctl()` handlers と、共有される可能性のある GPU memory-management paths を公開するためです。<sup>[[8]](#references)</sup>

- `/dev/nvidia*` を world writable のままにしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使用して、`nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、mapped container UID のみがそれらを open できるようにしてください。
- headless inference hosts では、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要な modules を blacklist してください。
- inference startup 中に runtime が opportunistically `modprobe` するのではなく、boot 時に必要な modules のみを preload してください。

例:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
重要なレビュー項目の1つが **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していない場合でも、最近の CUDA runtime では `nvidia-uvm` が必要になることがあります。このデバイスは共有され、GPU virtual memory management を処理するため、cross-tenant data-exposure surface として扱ってください。inference backend がサポートしている場合、Vulkan backend は興味深いトレードオフとなる可能性があります。これは、container に `nvidia-uvm` を公開せずに済む場合があるためです。<sup>[[8]](#references)</sup>

### inference worker の LSM confinement

inference process の周囲では、defense in depth として AppArmor/SELinux/seccomp を使用してください。<sup>[[8]](#references)</sup>

- 実際に必要な shared libraries、model paths、socket directory、GPU device nodes のみを許可します。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの high-risk capabilities を明示的に拒否します。
- model directory は read-only にし、書き込み可能な paths は runtime socket/cache directories のみに限定します。
- denial logs を監視してください。model server または post-exploitation payload が想定された behaviour から escape を試みた際に、有用な detection telemetry となります。

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
## Phantom Squatting: LLMが幻覚したドメインを利用するAIサプライチェーン攻撃ベクトル

Phantom squattingは、**slopsquattingにおけるドメイン/URL版**です。存在しないパッケージ名を幻覚する代わりに、LLMは実在するブランドの**portal、API、webhook、billing、SSO、download、supportドメイン**らしい、もっともらしい名前を幻覚し、人間やagentが使用する前に攻撃者がそのnamespaceを登録します。<sup>[[12]](#references)[[13]](#references)</sup>

これは、多くのAI支援ワークフローでモデルの出力が**信頼されたdependency**として扱われるため重要です。
- 開発者が提案されたendpointをcodeやCI/CD integrationsに貼り付ける。
- AI agentsがdocumentation、schemas、APK、ZIP、webhook targetsを自動的に取得する。
- 生成されたrunbooksやdocsに、偽URLが権威あるものとして埋め込まれる可能性がある。

### Offensive workflow

1. **幻覚される可能性のある領域を調査する**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app`など、現実的なworkflowについてbrand-specificな質問を行う。<sup>[[12]](#references)</sup>
2. **候補を正規化する**: 生成されたURLをresolveし、NXDOMAIN responsesを親の登録可能なdomainに集約し、prompt familiesの重複を排除する。Prompt corporaは、例えば**Jaccard similarity**を使って類似しすぎるpromptを削除し、多様性を維持する。
3. **予測可能な幻覚を優先する**:
- **Thermal Hallucination Persistence (THP)**: `T=0.1`のような低temperatureを含め、複数のtemperatureで同じ偽domainが出現する。
- **Cross-model consensus**: 複数のLLM familiesが同じ偽domainを生成する。
4. **親domainを登録してweaponizeする**。その後、phishing、偽APK/ZIP downloads、credential harvesters、malicious docs、またはsecret/webhook payloadsを収集するAPI endpointsをホストする。**Pure domain-level hallucinations**は、攻撃者がnamespace全体を管理できるため、もっともmonetizeしやすい。subdomain/path hallucinationsも、正規化された親domainが未登録であれば悪用できる。
5. **zero-reputation windowを悪用する**: 新規登録されたdomainsには、blocklist history、URL reputation、成熟したtelemetryが存在しないことが多く、detectionsが追いつくまでcontrolsを回避できる。攻撃者は、crawlerに対してのみbenign responsesを返す、redirect cloaking、CAPTCHA gates、payload stagingの遅延などによって、このwindowを引き延ばせる。

### なぜagentsにとって危険なのか

人間のvictimの場合、偽domainには通常、clickと追加の操作が必要です。しかし**agentic workflow**では、LLMが**lure**と**executor**の両方になり得ます。agentは幻覚されたURLを受け取り、それをfetchしてresponseをparseし、その後tokensをleakしたり、instructionsを実行したり、dependencyをdownloadしたり、人間のreviewなしにpoisoned dataをCI/CDへpushしたりする可能性があります。<sup>[[12]](#references)</sup>

### Practical attacker prompts

高い効果が見込めるpromptsは、明示的なphishing luresではなく、通常のenterprise tasksのように見えるものです。<sup>[[12]](#references)</sup>
- 「`<brand>` integrations用のpayment sandbox URLは何ですか？」
- 「`<brand>` build notificationsには、どのwebhook endpointを使用すべきですか？」
- 「`<brand>`のemployee benefits / billing / SSO portalはどこですか？」
- 「`<brand>`用のAndroid APKまたはdesktop client downloadへのdirect linkを教えてください。」

### Defensive inversion

これは単なるprompt-injection問題ではなく、proactiveなdomain-monitoring問題として扱います。<sup>[[12]](#references)</sup>
- **brand prompt corpus**を構築し、users/agentsが依存するLLMsを定期的にprobeする。
- 幻覚されたURLsを保存し、temperature/modelsをまたいで安定しているものを追跡する。
- **Adversarial Exploitation Window (AEW)**を追跡する。これは、最初の幻覚から攻撃者によるregistrationまでの時間を指す。AEWが正の値であれば、defendersはweaponizationの前にpre-register、sinkhole、またはpre-blockできる。
- 親domainsにおける**NXDOMAIN → registered**の遷移をmonitorする。
- registration時に、registrar、creation date、nameservers、privacy shielding、page content、screenshots、parked-page status、brand-asset similarityをtriageする。
- agents/developersが**デフォルトでLLM-generated domainsを信頼しない**ようpolicy gatesを追加する。初回使用前に、allowlists、ownership validation、CT/RDAP checks、またはhuman approvalを必須にする。

これは複数のAI risk bucketsに同時に該当します。**AI supply-chain attack**、**insecure model output**、そしてagentsが幻覚されたURLを自律的にconsumeした場合の**rogue actions**です。

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
