# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp は、AI systems に影響を与える可能性がある machine learning vulnerabilities の top 10 を特定しています。これらの vulnerabilities は、data poisoning、model inversion、adversarial attacks など、さまざまな security issues につながる可能性があります。安全な AI systems を構築するには、これらの vulnerabilities を理解することが重要です。

machine learning vulnerabilities の top 10 の最新かつ詳細な一覧については、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project を参照してください。

- **Input Manipation Attack**: 攻撃者は **incoming data** に、非常に小さく、多くの場合は見えない変更を加え、model に誤った判断をさせます。\
*Example*: stop sign に数個の paint の斑点を付けるだけで、自動運転車に speed-limit sign と「認識」させます。

- **Data Poisoning Attack**: **training set** に悪意のあるサンプルを意図的に混入し、model に有害なルールを学習させます。\
*Example*: antivirus training corpus 内で malware binaries に「benign」という誤ったラベルを付け、後に類似した malware が検出をすり抜けられるようにします。

- **Model Inversion Attack**: 出力を probing することで、攻撃者は元の入力に含まれる機密性の高い features を再構成する **reverse model** を構築します。\
*Example*: cancer-detection model の predictions から患者の MRI image を再現します。

- **Membership Inference Attack**: adversary は、confidence の違いを見つけることで、**specific record** が training 中に使用されたかどうかを検証します。\
*Example*: ある人物の bank transaction が fraud-detection model の training data に含まれていることを確認します。

- **Model Theft**: 繰り返し querying することで、攻撃者は decision boundaries と **clone the model's behavior**（および IP）を学習できます。\
*Example*: ML-as-a-Service API から十分な Q&A pairs を収集し、ほぼ同等の local model を構築します。

- **AI Supply-Chain Attack**: **ML pipeline** 内の component（data、libraries、pre-trained weights、CI/CD など）のいずれかを compromise し、下流の models を破壊します。\
*Example*: model-hub 上の poisoned dependency が backdoored sentiment-analysis model を多くの apps にインストールします。

- **Transfer Learning Attack**: 悪意のある logic を **pre-trained model** に埋め込み、victim の task で fine-tuning した後も存続させます。\
*Example*: hidden trigger を持つ vision backbone が、medical imaging 用に適応された後も labels を反転させます。

- **Model Skewing**: 微妙に偏った、または誤ったラベルの data により、**model's outputs** が攻撃者の agenda に有利な方向へ変化します。\
*Example*: 「clean」な spam emails に ham のラベルを付けて注入し、spam filter が今後の類似 emails を通過させるようにします。

- **Output Integrity Attack**: 攻撃者は model 自体ではなく、**alters model predictions in transit** して downstream systems を欺きます。\
*Example*: file-quarantine stage が確認する前に、malware classifier の「malicious」という判定を「benign」に反転させます。

- **Model Poisoning** --- 多くの場合、write access を取得した後に、**model parameters** 自体へ直接かつ標的を絞った変更を加え、behavior を変化させます。\
*Example*: production 環境の fraud-detection model の weights を調整し、特定の cards からの transactions が常に承認されるようにします。


## Google SAIF Risks

Google の [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) は、AI systems に関連するさまざまな risks を概説しています。

- **Data Poisoning**: malicious actors が training/tuning data を変更または注入し、accuracy を低下させたり、backdoors を埋め込んだり、results を偏らせたりします。これにより、data-lifecycle 全体にわたって model integrity が損なわれます。

- **Unauthorized Training Data**: copyrighted、sensitive、または許可されていない datasets を取り込むと、model が使用を許可されていない data から学習するため、legal、ethical、performance 上の liabilities が生じます。

- **Model Source Tampering**: training 前または training 中に、supply-chain または insider が model code、dependencies、weights を操作すると、retraining 後も存続する hidden logic を埋め込む可能性があります。

- **Excessive Data Handling**: 弱い data-retention および governance controls により、systems が必要以上の personal data を保存または処理し、exposure と compliance の risks が高まります。

- **Model Exfiltration**: attackers が model files/weights を盗み、intellectual property の損失を引き起こすとともに、copy-cat services や後続の attacks を可能にします。

- **Model Deployment Tampering**: adversaries が model artifacts または serving infrastructure を変更し、実行中の model が検証済み version と異なる状態にします。これにより、behaviour が変化する可能性があります。

- **Denial of ML Service**: APIs を flooding したり、「sponge」inputs を送信したりすることで、compute/energy を枯渇させ、model を offline にします。これは従来の DoS attacks に類似しています。

- **Model Reverse Engineering**: 大量の input-output pairs を収集することで、attackers は model を clone または distil し、模倣 products やカスタマイズされた adversarial attacks に利用できます。

- **Insecure Integrated Component**: 脆弱な plugins、agents、または upstream services により、attackers は AI pipeline 内へ code を注入したり、privileges を escalate したりできます。

- **Prompt Injection**: prompts を（直接または間接的に）細工して、system intent を上書きする instructions を紛れ込ませ、model に意図しない commands を実行させます。

- **Model Evasion**: Carefully designed inputs により、model が誤分類、hallucinate、または許可されていない content を出力するよう誘導し、安全性と trust を損ないます。

- **Sensitive Data Disclosure**: model が training data または user context から private または confidential information を明らかにし、privacy と regulations に違反します。

- **Inferred Sensitive Data**: model が提供されていない personal attributes を推測し、inference による新たな privacy harms を生み出します。

- **Insecure Model Output**: sanitization されていない responses が harmful code、misinformation、または inappropriate content を users や downstream systems に渡します。

- **Rogue Actions**: 自律的に統合された agents が、十分な user oversight なしに、意図しない real-world operations（file writes、API calls、purchases など）を実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) は、AI systems に関連する risks を理解し、mitigate するための包括的な framework を提供します。これは adversaries が AI models に対して使用する可能性のあるさまざまな attack techniques と tactics を分類するとともに、AI systems を使ってさまざまな attacks を実行する方法も分類します。

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers は active session tokens または cloud API credentials を盗み、許可なく有料の cloud-hosted LLMs を呼び出します。アクセスは、被害者の account を前面に置く reverse proxies を介して再販されることが多く、例として「oai-reverse-proxy」deployments があります。Consequences には financial loss、policy 外での model misuse、victim tenant への attribution が含まれます。

TTPs:
- 感染した developer machines または browsers から tokens を harvest し、CI/CD secrets を盗み、leaked cookies を購入します。
- genuine provider に requests を転送する reverse proxy を立ち上げ、upstream key を隠し、多数の customers を multiplex します。
- direct base-model endpoints を悪用して enterprise guardrails と rate limits を bypass します。

Mitigations:
- tokens を device fingerprint、IP ranges、client attestation に bind し、short expirations を適用して MFA で refresh します。
- keys の scope を最小限にします（tool access は付与せず、該当する場合は read-only）。anomaly 発生時には rotate します。
- すべての traffic を policy gateway の背後で server-side に terminate し、safety filters、route ごとの quotas、tenant isolation を適用します。
- unusual usage patterns（突然の spend spikes、atypical regions、UA strings）を monitor し、疑わしい sessions を自動的に revoke します。
- 長期間有効な static API keys よりも、IdP が発行する mTLS または signed JWTs を優先します。

## Self-hosted LLM inference hardening

confidential data 用の local LLM server の実行は、cloud-hosted APIs とは異なる attack surface を生みます。inference/debug endpoints から prompts が leak する可能性があり、serving stack は通常 reverse proxy を公開し、GPU device nodes は大規模な `ioctl()` surfaces への access を提供します。on-prem inference service を assessment または deployment する場合は、少なくとも以下の points を確認してください。

### Prompt leakage via debug and monitoring endpoints

inference API を **multi-user sensitive service** として扱ってください。Debug または monitoring routes により、prompt contents、slot state、model metadata、internal queue information が露出する可能性があります。`llama.cpp` では、`/slots` endpoint は per-slot state を expose し、slot inspection/management のためだけに使用されるため、特に sensitive です。

- inference server の前段に reverse proxy を配置し、**deny by default** にします。
- client/UI に必要な正確な HTTP method + path combinations のみを allowlist します。
- 可能な場合は backend 自体で introspection endpoints を disable します。例: `llama-server --no-slots`
- reverse proxy を `127.0.0.1` に bind し、LAN に publish するのではなく、SSH local port forwarding などの authenticated transport を通じて expose します。

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
### ネットワークなしのRootless containersとUNIX sockets

inference daemonがUNIX socketでのリッスンをサポートしている場合は、TCPよりもこちらを優先し、**ネットワークスタックなし**でcontainerを実行します：
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
- `--network none` は受信および送信の TCP/IP への露出をなくし、rootless containers が通常必要とする user-mode helpers を回避します。
- UNIX socket を使用すると、socket path の POSIX permissions/ACLs を最初の access-control layer として利用できます。
- `--userns=keep-id` と rootless Podman により、container breakout の影響を軽減できます。これは、container root が host root ではないためです。
- Read-only model mounts により、container 内部からの model tampering の可能性を低減できます。

### GPU device-node minimization

GPU-backed inference では、`/dev/nvidia*` files は、広範な driver の `ioctl()` handlers と、共有される可能性のある GPU memory-management paths を公開するため、価値の高い local attack surfaces です。

- `/dev/nvidia*` を全ユーザーが書き込み可能な状態にしないでください。
- `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs を使用して、`nvidia`、`nvidiactl`、`nvidia-uvm` を制限し、mapped container UID のみがこれらを open できるようにしてください。
- headless inference hosts では、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` などの不要な modules を blacklist してください。
- inference startup 中に runtime が opportunistically `modprobe` できるようにするのではなく、boot 時に必要な modules のみを preload してください。

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
重要なレビュー項目の1つは **`/dev/nvidia-uvm`** です。ワークロードが明示的に `cudaMallocManaged()` を使用していなくても、最近の CUDA runtime では `nvidia-uvm` が必要になる場合があります。このデバイスは共有され、GPU の仮想メモリ管理を処理するため、tenant 間のデータ漏洩サーフェスとして扱ってください。inference backend が対応している場合、Vulkan backend はコンテナに `nvidia-uvm` を公開せずに済む可能性があるため、興味深いトレードオフになります。

### inference worker の LSM confinement

AppArmor/SELinux/seccomp は、inference process に対する defense in depth として使用してください。

- 実際に必要な shared library、model path、socket directory、GPU device node のみを許可する。
- `sys_admin`、`sys_module`、`sys_rawio`、`sys_ptrace` などの高リスクな capability を明示的に拒否する。
- model directory は read-only にし、書き込み可能な path は runtime socket/cache directory のみに限定する。
- denial log を監視する。model server や post-exploitation payload が想定された behaviour から escape を試みた際に、有用な検知 telemetry が得られるためである。

GPU-backed worker 用の AppArmor rule の例：
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
## Phantom Squatting: LLMが幻覚したドメインをAIサプライチェーンの攻撃ベクトルとして利用

Phantom squattingは、**slopsquattingのドメイン/URL版**です。存在しないパッケージ名を幻覚させる代わりに、LLMが実在するブランドのもっともらしい **portal、API、webhook、billing、SSO、download、support domain** を幻覚させ、人間やagentが利用する前に攻撃者がそのnamespaceを登録します。

これは、多くのAI支援workflowでは、modelの出力が**trusted dependency**として扱われるため重要です。
- 開発者が、提案されたendpointをcodeやCI/CD integrationに貼り付ける。
- AI agentがdocumentation、schema、APK、ZIP、webhook targetを自動的に取得する。
- 生成されたrunbookやdocsに、偽のURLが権威あるものとして埋め込まれる可能性がある。

### Offensive workflow

1. **hallucination surfaceをprobeする**: `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook`、`mobile app` portalなど、現実的なworkflowに関するbrand固有の質問を行う。
2. **candidateをnormalizeする**: 生成されたURLをresolveし、NXDOMAIN responseを親のregisterable domainに集約し、prompt familyをdeduplicateする。Prompt corpusは、例えば **Jaccard similarity** を使って近似重複を削除するなど、多様性を維持するべきである。
3. **予測可能なhallucinationを優先する**:
- **Thermal Hallucination Persistence (THP)**: `T=0.1`のような低temperatureを含め、複数のtemperatureで同じ偽ドメインが出現する。
- **Cross-model consensus**: 複数のLLM familyが同じ偽ドメインを生成する。
4. 親domainを**registerしてweaponize**し、phishing、偽APK/ZIP download、credential harvester、malicious document、またはsecret/webhook payloadを収集するAPI endpointをhostする。**Pure domain-level hallucination**は、攻撃者がnamespace全体を管理できるため、最もmonetizeしやすい。subdomain/path hallucinationでも、normalize後の親domainが未登録であれば悪用できる。
5. **zero-reputation windowを悪用する**: 新規登録されたdomainには、blocklistの履歴、URL reputation、成熟したtelemetryがないことが多く、detectionが追いつくまでcontrolを回避できる。攻撃者は、crawlerにだけbenign responseを返す、redirect cloaking、CAPTCHA gate、遅延payload stagingなどによって、このwindowを引き延ばせる。

### なぜagentにとって危険なのか

人間の被害者の場合、通常は偽domainへのclickと、その後の別の操作が必要です。しかし **agentic workflow** では、LLMが**lure**と**executor**の両方になり得ます。agentはhallucinationされたURLを受け取り、それをfetchしてresponseをparseし、その後human reviewなしにtokenをleakしたり、instructionをexecuteしたり、dependencyをdownloadしたり、CI/CDにpoisoned dataをpushしたりする可能性があります。

### Practical attacker prompts

高い成果が得られるpromptは、明示的なphishing lureではなく、通常のenterprise taskのように見えるものです。
- 「`<brand>` integration用のpayment sandbox URLは何ですか？」
- 「`<brand>`のbuild notificationには、どのwebhook endpointを使うべきですか？」
- 「`<brand>`のemployee benefits / billing / SSO portalはどこですか？」
- 「`<brand>`のAndroid APKまたはdesktop clientのdirect downloadを教えてください。」

### Defensive inversion

これはprompt-injection問題だけでなく、proactiveなdomain-monitoring問題として扱います。
- **brand prompt corpus**を構築し、ユーザー/agentが依存するLLMを定期的にprobeする。
- hallucinationされたURLを保存し、temperature/modelをまたいで安定して出現するものを追跡する。
- **Adversarial Exploitation Window (AEW)** を追跡する。これは、最初のhallucinationから攻撃者による登録までの時間です。AEWが正であれば、defenderはweaponization前にpre-register、sinkhole、またはpre-blockできる。
- 親domainの **NXDOMAIN → registered** transitionを監視する。
- 登録時に、registrar、creation date、nameserver、privacy shielding、page content、screenshot、parked-page status、brand assetとのsimilarityをtriageする。
- agent/developerが **LLM-generated domainをデフォルトでtrustしない** ようpolicy gateを追加する。初回利用前にallowlist、ownership validation、CT/RDAP check、またはhuman approvalを必須にする。

これは複数のAI risk bucketに同時に該当します。**AI supply-chain attack**、**insecure model output**、そしてagentがhallucinationされたURLを自律的にconsumeした場合の **rogue actions** です。

## References
- [Unit 42 – Code Assistant LLMのリスク：有害なコンテンツ、Misuse、Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking schemeの概要 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy（盗まれたLLM accessのreselling）](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - on-premiseのlow-privileged LLM server deploymentに関するDeep-dive](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
