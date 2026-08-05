# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp は、AI systems に影響を与える可能性がある machine learning vulnerabilities の上位 10 件を特定しています。これらの vulnerabilities は、data poisoning、model inversion、adversarial attacks など、さまざまな security issues につながる可能性があります。安全な AI systems を構築するには、これらの vulnerabilities を理解することが重要です。

machine learning vulnerabilities の上位 10 件について、最新かつ詳細な一覧は [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project を参照してください。<sup>[[10]](#references)</sup>

- **Input Manipation Attack**: attacker は **incoming data** に非常に小さく、しばしば見えない変更を加え、model に誤った判断をさせます。\
*Example*: stop sign に付着した数個の塗料の斑点によって、自動運転車がそれを speed-limit sign と「認識」してしまう。

- **Data Poisoning Attack**: **training set** に悪意のあるサンプルを意図的に混入し、model に有害なルールを学習させます。\
*Example*: antivirus training corpus 内で malware binaries に "benign" という誤ったラベルを付け、後に類似した malware が検知をすり抜けられるようにする。

- **Model Inversion Attack**: attacker は出力を probing することで、元の入力に含まれる sensitive features を再構成する **reverse model** を作成します。\
*Example*: cancer-detection model の predictions から患者の MRI image を再作成する。

- **Membership Inference Attack**: adversary は confidence の違いを見つけることで、**specific record** が training 中に使用されたかどうかを検証します。\
*Example*: ある人物の bank transaction が fraud-detection model の training data に含まれていることを確認する。

- **Model Theft**: 繰り返し querying することで、attacker は decision boundaries と **clone the model's behavior**（および IP）を学習できます。\
*Example*: ML-as-a-Service API から十分な Q&A pairs を収集し、ほぼ同等の local model を構築する。

- **AI Supply-Chain Attack**: **ML pipeline** 内の data、libraries、pre-trained weights、CI/CD など、いずれかの component を compromise し、下流の models を改ざんします。\
*Example*: model-hub 上の poisoned dependency によって backdoored sentiment-analysis model がインストールされ、多数の apps に展開される。

- **Transfer Learning Attack**: **pre-trained model** に悪意のある logic を埋め込み、victim の task に対する fine-tuning 後も存続させます。\
*Example*: hidden trigger を持つ vision backbone が、medical imaging 用に適応された後も labels を反転させる。

- **Model Skewing**: subtly biased または誤って labeled された data により、**shifts the model's outputs** が発生し、attacker の agenda に有利な結果になります。\
*Example*: "clean" な spam emails に ham のラベルを付けて投入し、spam filter が将来の類似 emails を通過させる。

- **Output Integrity Attack**: attacker は model 自体ではなく、**alters model predictions in transit** することで downstream systems を欺きます。\
*Example*: file-quarantine stage が確認する前に、malware classifier の "malicious" という verdict を "benign" に変更する。

- **Model Poisoning** --- 多くの場合 write access を取得した後、**model parameters** 自体に直接かつ標的を絞った変更を加え、挙動を変化させます。\
*Example*: production 環境の fraud-detection model の weights を調整し、特定の cards による transactions を常に承認させる。


## Google SAIF Risks

Google の [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) は、AI systems に関連するさまざまな risks を概説しています。<sup>[[11]](#references)</sup>

- **Data Poisoning**: malicious actors が training/tuning data を変更または注入し、accuracy を低下させたり、backdoors を埋め込んだり、results を歪めたりします。これにより、data-lifecycle 全体で model integrity が損なわれます。

- **Unauthorized Training Data**: copyrighted、sensitive、または許可されていない datasets を取り込むと、model が使用を許可されていない data から学習するため、legal、ethical、performance 上の liabilities が生じます。

- **Model Source Tampering**: training 前または training 中に、supply-chain または insider が model code、dependencies、weights を manipulation すると、retraining 後も残存する hidden logic が埋め込まれる可能性があります。

- **Excessive Data Handling**: data-retention と governance controls が弱いと、systems が必要以上の personal data を保存または処理し、exposure と compliance risk が高まります。

- **Model Exfiltration**: attackers が model files/weights を盗み、intellectual property の損失を引き起こすほか、copy-cat services や follow-on attacks を可能にします。

- **Model Deployment Tampering**: adversaries が model artifacts または serving infrastructure を変更し、実行中の model が検証済み version と異なる状態にします。その結果、behaviour が変化する可能性があります。

- **Denial of ML Service**: APIs を flooding したり、“sponge” inputs を送信したりすることで、compute/energy を枯渇させ、model を offline にします。これは従来の DoS attacks に類似しています。

- **Model Reverse Engineering**: 大量の input-output pairs を収集することで、attackers は model を clone または distil し、imitation products や customized adversarial attacks に利用できます。

- **Insecure Integrated Component**: vulnerable plugins、agents、または upstream services により、attackers が AI pipeline 内へ code を inject したり、privileges を escalate したりできます。

- **Prompt Injection**: prompts を直接または間接的に細工して、system intent を上書きする instructions を忍び込ませ、model に意図しない commands を実行させます。

- **Model Evasion**: carefully designed inputs により、model が mis-classify、hallucinate、または disallowed content を出力するよう誘導し、safety と trust を損なわせます。

- **Sensitive Data Disclosure**: model が training data または user context に含まれる private または confidential information を明らかにし、privacy と regulations に違反します。

- **Inferred Sensitive Data**: model が提供されていない personal attributes を推測し、推論を通じて新たな privacy harms を生み出します。

- **Insecure Model Output**: unsanitized responses が harmful code、misinformation、または inappropriate content を users や downstream systems に渡します。

- **Rogue Actions**: autonomously-integrated agents が、十分な user oversight なしに意図しない real-world operations（file writes、API calls、purchases など）を実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) は、AI systems に関連する risks の理解と mitigation のための包括的な framework を提供します。これは adversaries が AI models に対して使用する可能性のあるさまざまな attack techniques と tactics を分類し、AI systems を利用して異なる attacks を実行する方法も示しています。<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers は active session tokens または cloud API credentials を盗み、許可なく有料の cloud-hosted LLMs を呼び出します。Access は、victim の account を前面に置く reverse proxies を通じて再販売されることが多く、例として "oai-reverse-proxy" deployments があります。結果として financial loss、policy 外での model misuse、victim tenant への attribution が発生します。<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- 感染した developer machines や browsers から tokens を harvest し、CI/CD secrets を盗み、leaked cookies を購入する。
- genuine provider に requests を転送する reverse proxy を立ち上げ、upstream key を隠しながら多数の customers を multiplex する。
- direct base-model endpoints を悪用して enterprise guardrails と rate limits を bypass する。

Mitigations:
- tokens を device fingerprint、IP ranges、client attestation に bind し、短い expiration を適用して MFA で refresh する。
- keys の scope を最小限にする（tool access は付与せず、該当する場合は read-only）。anomaly 発生時には rotate する。
- safety filters、per-route quotas、tenant isolation を適用する policy gateway の背後に server-side ですべての traffic を terminate する。
- unusual usage patterns（突然の spend spikes、atypical regions、UA strings）を monitor し、疑わしい sessions を自動 revoke する。
- 長期間有効な static API keys よりも、IdP が発行する mTLS または signed JWTs を優先する。

## Self-hosted LLM inference hardening

confidential data 用に local LLM server を実行すると、cloud-hosted APIs とは異なる attack surface が生じます。inference/debug endpoints から prompts が leak する可能性があり、serving stack は通常 reverse proxy を公開し、GPU device nodes は大規模な `ioctl()` surfaces への access を与えます。on-prem inference service を assessment または deployment する場合は、少なくとも以下の points を確認してください。<sup>[[4]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

inference API を **multi-user sensitive service** として扱ってください。debug または monitoring routes は、prompt contents、slot state、model metadata、internal queue information を expose する可能性があります。`llama.cpp` では、`/slots` endpoint は per-slot state を expose し、slot inspection/management のためだけに使用されるため、特に sensitive です。<sup>[[4]](#references)[[5]](#references)</sup>

- inference server の前段に reverse proxy を配置し、**deny by default** にする。
- client/UI に必要な正確な HTTP method + path combinations のみを allowlist する。
- 可能な場合は backend 自体で introspection endpoints を disable する。例: `llama-server --no-slots`。
- reverse proxy を `127.0.0.1` に bind し、LAN 上で publish するのではなく、SSH local port forwarding などの authenticated transport を通じて expose する。

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
- `--network none` により inbound/outbound TCP/IP exposure がなくなり、rootless containers が通常必要とする user-mode helpers も回避できます。
- UNIX socket を使用すると、socket path の POSIX permissions/ACLs を最初の access-control layer として利用できます。
- `--userns=keep-id` と rootless Podman により、container breakout の影響を軽減できます。これは container root が host root ではないためです。
- Read-only model mounts により、container 内部からの model tampering の可能性を低減できます。

### GPU device-node の最小化

GPU-backed inference では、`/dev/nvidia*` files は高価値な local attack surfaces です。これは、大規模な driver `ioctl()` handlers と、共有される可能性のある GPU memory-management paths を公開するためです。<sup>[[4]](#references)</sup>

- `/dev/nvidia*` を world writable のままにしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使用して、`nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、mapped container UID のみがこれらを open できるようにします。
- headless inference hosts では、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要な modules を blacklist に登録します。
- inference startup 中に runtime が opportunistically `modprobe` できるようにするのではなく、boot 時に必要な modules のみを preload します。

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
重要なレビュー項目の1つが **`/dev/nvidia-uvm`** です。workload が明示的に `cudaMallocManaged()` を使用していない場合でも、最近の CUDA runtime では `nvidia-uvm` が必要になることがあります。この device は共有され、GPU の virtual memory management を処理するため、cross-tenant data-exposure surface として扱ってください。inference backend が対応している場合、Vulkan backend は興味深い trade-off になる可能性があります。これは、container に `nvidia-uvm` を公開する必要自体をなくせる場合があるためです。

### inference worker の LSM confinement

AppArmor/SELinux/seccomp は、inference process の周囲で defense in depth として使用してください:<sup>[[4]](#references)</sup>

- 実際に必要な shared library、model path、socket directory、GPU device node のみを許可する。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの high-risk capability を明示的に拒否する。
- model directory は read-only にし、書き込み可能な path は runtime socket/cache directory のみに限定する。
- denial log を監視する。model server または post-exploitation payload が想定された behaviour から escape しようとした際に、有用な detection telemetry が得られるためである。

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
## Phantom Squatting: LLMが幻覚したドメインを利用するAIサプライチェーン攻撃ベクトル

Phantom squattingは、**slopsquattingに相当するdomain/URL版**です。存在しないpackage名を幻覚する代わりに、LLMは実在するブランド向けの、もっともらしい**portal、API、webhook、billing、SSO、download、support用ドメイン**を幻覚し、人間またはagentが使用する前に攻撃者がそのnamespaceを登録します。<sup>[[8]](#references)[[9]](#references)</sup>

これは、多くのAI支援workflowでmodelの出力が**信頼されたdependency**として扱われるため重要です。
- 開発者が提案されたendpointをcodeやCI/CD integrationに貼り付ける。
- AI agentがdocumentation、schema、APK、ZIP、webhook targetを自動的に取得する。
- 生成されたrunbookやdocに、権威あるものとしてfake URLが埋め込まれる可能性がある。

### Offensive workflow

1. **hallucination surfaceを調査する**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app`など、現実的なworkflowについてbrand固有の質問を行う。
2. **候補を正規化する**: 生成されたURLを解決し、NXDOMAIN responseを親のregisterable domainに集約し、prompt familyの重複を排除する。Prompt corpusは、例えば**Jaccard similarity**によって近似重複を削除するなど、多様性を維持する必要がある。
3. **予測可能なhallucinationを優先する**:
- **Thermal Hallucination Persistence (THP)**: `T=0.1`のような低いtemperatureを含め、同じfake domainが複数のtemperatureで出現する。
- **Cross-model consensus**: 複数のLLM familyが同じfake domainを生成する。
4. 親domainを**登録してweaponize**し、phishing、fake APK/ZIP download、credential harvester、malicious document、またはsecret/webhook payloadを収集するAPI endpointをホストする。**domain-levelのみのhallucination**は、攻撃者がnamespace全体を管理できるため、最もmonetizeしやすい。subdomain/pathのhallucinationも、正規化された親domainが未登録であれば悪用できる。
5. **zero-reputation windowを悪用する**: 新規登録domainにはblocklist履歴、URL reputation、成熟したtelemetryがないことが多く、detectionが追いつくまでcontrolsを回避できる。攻撃者は、crawlerにだけbenign responseを返す、redirect cloaking、CAPTCHA gate、遅延したpayload stagingなどによって、このwindowを引き延ばせる。

### なぜagentにとって危険なのか

人間の被害者の場合、fake domainには通常、clickと追加の操作が必要です。しかし**agentic workflow**では、LLMが**lure**と**executor**の両方になり得ます。agentはhallucinated URLを受け取り、それをfetchしてresponseをparseし、その後tokenをleakしたり、instructionをexecuteしたり、dependencyをdownloadしたり、人間によるreviewなしにCI/CDへpoisoned dataをpushしたりする可能性があります。<sup>[[8]](#references)</sup>

### Practical attacker prompts

高い効果が見込めるpromptは、明示的なphishing lureではなく、通常のenterprise taskのように見えることが多いです。
- 「`<brand>` integration向けのpayment sandbox URLは何ですか？」
- 「`<brand>`のbuild notificationには、どのwebhook endpointを使用すべきですか？」
- 「`<brand>`のemployee benefits / billing / SSO portalはどこですか？」
- 「`<brand>`用のAndroid APKまたはdesktop clientのdirect downloadを教えてください。」

### Defensive inversion

これは単なるprompt-injection問題ではなく、proactiveなdomain-monitoring問題として扱います。
- **brand prompt corpus**を構築し、ユーザーやagentが依存するLLMを定期的にprobeする。
- hallucinated URLを保存し、temperature/model間でどれがstableかを追跡する。
- **Adversarial Exploitation Window (AEW)**を追跡する。これは、最初のhallucinationから攻撃者による登録までの時間です。AEWがpositiveであれば、defenderはweaponization前にpre-register、sinkhole、またはpre-blockできる。
- 親domainについて、**NXDOMAIN → registered**のtransitionを監視する。
- 登録時には、registrar、creation date、nameserver、privacy shielding、page content、screenshot、parked-page status、brand assetとのsimilarityをtriageする。
- agent/developerが**LLM-generated domainをデフォルトで信頼しない**ようpolicy gateを追加する。初回使用前に、allowlist、ownership validation、CT/RDAP check、またはhuman approvalを必須にする。

これは複数のAI risk bucketに同時に該当します。すなわち、**AI supply-chain attack**、**insecure model output**、そしてagentがhallucinated URLを自律的にconsumeする際の**rogue actions**です。

## References
- [1] [Unit 42 – Code Assistant LLMのrisks: 有害なcontent、misuse、deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking schemeのoverview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy（盗まれたLLM accessのreselling）](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - on-premiseのlow-privileged LLM server deploymentに関するdeep-dive](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: AIがhallucinateしたdomainをsoftware supply chain vectorとして利用](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: AI hallucinationが新たなsupply chain attack classを生み出す仕組み](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
