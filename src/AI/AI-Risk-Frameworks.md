# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp 已确定可能影响 AI 系统的十大 Machine Learning 漏洞。这些漏洞可能导致各种安全问题，包括数据投毒、模型反演和对抗性攻击。理解这些漏洞对于构建安全的 AI 系统至关重要。

有关最新且详细的十大 Machine Learning 漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**：攻击者对**传入数据**添加微小且通常不可见的变化，使模型做出错误决策。\
*Example*：在停车标志上涂几处小斑点，就可能让自动驾驶汽车将其“看成”限速标志。

- **Data Poisoning Attack**：故意污染**training set**，用恶意样本训练模型，使其学会有害规则。\
*Example*：在 antivirus training corpus 中将恶意软件二进制文件错误标记为“良性”，使后续类似恶意软件能够绕过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**reverse model**，重建原始输入中的敏感特征。\
*Example*：根据癌症检测模型的预测结果，重新生成患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过观察置信度差异，测试某条**specific record** 是否曾用于训练。\
*Example*：确认某人的银行交易是否出现在 fraud-detection 模型的 training data 中。

- **Model Theft**：反复查询可以让攻击者了解决策边界，并**clone the model's behavior**（以及其 IP）。\
*Example*：从 ML-as-a-Service API 收集足够的问答对，构建一个近似等效的本地模型。

- **AI Supply-Chain Attack**：入侵**ML pipeline**中的任意组件（数据、libraries、pre-trained weights、CI/CD），以破坏下游模型。\
*Example*：model-hub 中的恶意 dependency 安装了带后门的 sentiment-analysis 模型，并将其部署到许多应用中。

- **Transfer Learning Attack**：将恶意逻辑植入**pre-trained model**，使其在针对受害者任务进行 fine-tuning 后仍然存在。\
*Example*：带有隐藏触发器的 vision backbone 在适配 medical imaging 后仍会翻转标签。

- **Model Skewing**：细微的偏置或错误标记数据会**shift the model's outputs**，使其偏向攻击者的目标。\
*Example*：注入被标记为 ham 的“干净”垃圾邮件，使 spam filter 放行未来类似的邮件。

- **Output Integrity Attack**：攻击者在传输过程中**alter model predictions**，而不是修改模型本身，从而欺骗下游系统。\
*Example*：在文件隔离阶段读取结果之前，将 malware classifier 的“恶意”判定翻转为“良性”。

- **Model Poisoning** --- 直接、有针对性地修改**model parameters**本身，通常发生在获得写入权限之后，以改变模型行为。\
*Example*：在生产环境中调整 fraud-detection 模型的权重，使来自某些银行卡的交易始终获得批准。


## Google SAIF Risks

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：<sup>[[11]](#references)</sup>

- **Data Poisoning**：恶意行为者修改或注入 training/tuning data，以降低准确性、植入后门或扭曲结果，破坏整个 data-lifecycle 中的模型完整性。

- **Unauthorized Training Data**：引入受版权保护、敏感或未经许可的数据集，会产生法律、伦理和性能方面的责任风险，因为模型学习了不被允许使用的数据。

- **Model Source Tampering**：在训练之前或期间对模型代码、dependencies 或 weights 进行 supply-chain 或内部人员操纵，可能植入即使 retraining 后仍然存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，从而提高暴露和合规风险。

- **Model Exfiltration**：攻击者窃取模型文件或 weights，导致知识产权损失，并支持仿冒服务或后续攻击。

- **Model Deployment Tampering**：对模型 artifacts 或 serving infrastructure 进行修改，使运行中的模型不同于经过审查的版本，可能改变其行为。

- **Denial of ML Service**：通过向 API 发送洪水请求或“sponge”输入耗尽计算资源和能源，使模型离线，类似经典 DoS 攻击。

- **Model Reverse Engineering**：通过收集大量输入-输出对，攻击者可以 clone 或 distil 模型，为仿冒产品和定制化对抗攻击提供支持。

- **Insecure Integrated Component**：存在漏洞的 plugins、agents 或上游服务允许攻击者在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：直接或间接构造 prompts，暗中加入覆盖系统意图的指令，使模型执行非预期命令。

- **Model Evasion**：精心设计的输入会触发模型进行错误分类、产生幻觉或输出不允许的内容，削弱安全性和信任。

- **Sensitive Data Disclosure**：模型泄露其 training data 或用户上下文中的私有或机密信息，违反隐私和法规要求。

- **Inferred Sensitive Data**：模型推断出从未提供过的个人属性，通过推理造成新的隐私危害。

- **Insecure Model Output**：未经清理的响应将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：自主集成的 agents 在缺乏充分用户监督的情况下，执行非预期的现实操作（文件写入、API 调用、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 为理解和缓解 AI 系统相关风险提供了一个综合框架。它对攻击者可能针对 AI 模型使用的各种攻击技术和战术进行分类，同时也说明了如何利用 AI 系统执行不同攻击。<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取活跃 session tokens 或 cloud API credentials，并在未经授权的情况下调用付费的 cloud-hosted LLM。访问权限通常通过 reverse proxies 转售，这些代理位于受害者账户的前端，例如“oai-reverse-proxy”部署。后果包括经济损失、违反策略的模型滥用，以及将活动归因于受害者 tenant。<sup>[[2]](#references)[[3]](#references)</sup>

TTPs：
- 从受感染的开发者机器或浏览器中收集 tokens；窃取 CI/CD secrets；购买泄露的 cookies。
- 建立一个 reverse proxy，将请求转发至真实 provider，同时隐藏上游 key 并为多个客户提供 multiplexing。
- 滥用 direct base-model endpoints，以绕过 enterprise guardrails 和 rate limits。

缓解措施：
- 将 tokens 绑定到 device fingerprint、IP ranges 和 client attestation；强制使用较短的有效期，并通过 MFA 进行刷新。
- 尽量缩小 keys 的权限范围（不授予 tool access，在适用情况下设为 read-only）；检测到异常时进行轮换。
- 将所有流量置于 server-side 的 policy gateway 后方，由其强制执行 safety filters、per-route quotas 和 tenant isolation。
- 监控异常使用模式（突然的费用激增、异常地区、UA strings），并自动撤销可疑 sessions。
- 优先使用由 IdP 签发的 mTLS 或 signed JWTs，而不是长期有效的 static API keys。

## Self-hosted LLM inference hardening

为机密数据运行本地 LLM server，其攻击面不同于 cloud-hosted APIs：inference/debug endpoints 可能泄露 prompts，serving stack 通常会暴露 reverse proxy，而 GPU device nodes 则提供对大型 `ioctl()` surfaces 的访问。如果你正在评估或部署 on-prem inference service，至少应检查以下要点。<sup>[[4]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

将 inference API 视为**multi-user sensitive service**。Debug 或 monitoring routes 可能暴露 prompt 内容、slot 状态、模型 metadata 或内部 queue 信息。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它暴露每个 slot 的状态，并且仅用于 slot inspection/management。<sup>[[4]](#references)[[5]](#references)</sup>

- 在 inference server 前放置 reverse proxy，并且**默认拒绝**。
- 仅 allowlist 客户端/UI 所需的确切 HTTP method + path 组合。
- 尽可能在 backend 本身禁用 introspection endpoints，例如 `llama-server --no-slots`。
- 将 reverse proxy 绑定到 `127.0.0.1`，并通过 SSH local port forwarding 等 authenticated transport 暴露，而不是将其发布到 LAN。

使用 nginx 的示例 allowlist：
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
### 无网络和 UNIX sockets 的 Rootless containers

如果 inference daemon 支持监听 UNIX socket，优先使用 UNIX socket 而不是 TCP，并在 **no network stack** 模式下运行 container：
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
优点：
- `--network none` 移除了入站/出站 TCP/IP 暴露，并避免使用 rootless containers 原本需要的用户态辅助程序。
- UNIX socket 允许你在 socket 路径上使用 POSIX 权限/ACL，将其作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可降低 container breakout 的影响，因为 container root 并不是 host root。
- 只读 model mounts 降低了从 container 内篡改 model 的可能性。

### GPU 设备节点最小化

对于基于 GPU 的 inference，`/dev/nvidia*` 文件属于高价值的本地攻击面，因为它们暴露了大量 driver `ioctl()` handlers，以及潜在的共享 GPU memory-management 路径。<sup>[[4]](#references)</sup>

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev rules 和 ACLs 限制 `nvidia`、`nvidiactl` 及 `nvidia-uvm`，确保只有映射后的 container UID 能够打开它们。
- 在 headless inference hosts 上禁用不必要的 modules，例如 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem`。
- 在 boot 时仅预加载必需的 modules，而不是让 runtime 在 inference startup 期间机会性地使用 `modprobe` 加载它们。

示例：
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使 workload 未显式使用 `cudaMallocManaged()`，近期的 CUDA runtimes 仍可能需要 `nvidia-uvm`。由于此 device 是共享的，并负责 GPU virtual memory management，应将其视为跨租户 data-exposure surface。如果 inference backend 支持，Vulkan backend 可能是一种有趣的权衡方案，因为它可能完全避免向 container 暴露 `nvidia-uvm`。

### inference workers 的 LSM confinement

应围绕 inference process 使用 AppArmor/SELinux/seccomp 作为 defense in depth：<sup>[[4]](#references)</sup>

- 仅允许实际需要的 shared libraries、model paths、socket directory 和 GPU device nodes。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险 capabilities。
- 将 model directory 保持为 read-only，并将 writable paths 限制为 runtime socket/cache directories。
- 监控 denial logs，因为当 model server 或 post-exploitation payload 试图逃逸其预期行为时，这些日志可提供有用的 detection telemetry。

GPU-backed worker 的 AppArmor rules 示例：
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
## Phantom Squatting：LLM 幻觉域名作为 AI 供应链攻击向量

Phantom squatting 是 **slopsquatting 的域名/URL 等价形式**。LLM 不再是幻觉生成一个不存在的 package name，而是为真实品牌幻觉生成一个看似合理的 **portal、API、webhook、billing、SSO、download 或 support domain**，攻击者则在人类或 agent 使用该 namespace 之前注册它。<sup>[[8]](#references)[[9]](#references)</sup>

这之所以重要，是因为在许多 AI-assisted workflow 中，模型输出会被当作 **trusted dependency**：
- 开发者将建议的 endpoint 粘贴到代码或 CI/CD integrations 中。
- AI agents 自动获取 documentation、schemas、APKs、ZIPs 或 webhook targets。
- 生成的 runbooks 或 docs 可能会嵌入 fake URL，并将其视为权威来源。

### Offensive workflow

1. **探测幻觉面**：针对品牌询问真实的 workflow，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` portals。
2. **规范化候选项**：解析生成的 URLs，将 NXDOMAIN responses 归并到 parent registerable domain，并对 prompt families 去重。Prompt corpora 应保持多样化，例如使用 **Jaccard similarity** 删除近似重复项。
3. **优先处理可预测的幻觉**：
- **Thermal Hallucination Persistence (THP)**：同一个 fake domain 会在不同 temperature 下反复出现，包括 `T=0.1` 这样的低 temperature。
- **Cross-model consensus**：多个 LLM families 生成同一个 fake domain。
4. **注册并 weaponize** parent domain，然后托管 phishing、fake APK/ZIP downloads、credential harvesters、malicious docs 或收集 secrets/webhook payloads 的 API endpoints。**纯 domain-level hallucinations** 最容易 monetized，因为攻击者控制整个 namespace；当 normalized parent 尚未注册时，subdomain/path hallucinations 仍然可以被滥用。
5. **利用 zero-reputation window**：新注册的 domains 通常缺少 blocklist history、URL reputation 和成熟的 telemetry，因此在 detections 追上之前可能绕过 controls。攻击者可以通过仅对 crawlers 返回 benign responses、redirect cloaking、CAPTCHA gates 或延迟 payload staging 来延长该窗口。

### Why it is dangerous for agents

对于 human victim，fake domain 通常仍然需要一次 click 以及后续操作。对于 **agentic workflow**，LLM 可以同时充当 **lure** 和 **executor**：agent 接收 hallucinated URL，获取它并解析 response，随后可能 leak tokens、execute instructions、download a dependency，或在没有任何 human review 的情况下将 poisoned data 推送到 CI/CD 中。<sup>[[8]](#references)</sup>

### Practical attacker prompts

High-yield prompts 通常看起来像普通的 enterprise tasks，而不是明确的 phishing lures：
- “`<brand>` integrations 使用的 payment sandbox URL 是什么？”
- “`<brand>` build notifications 应使用哪个 webhook endpoint？”
- “`<brand>` 的 employee benefits / billing / SSO portal 在哪里？”
- “给我 `<brand>` 的 direct Android APK 或 desktop client download。”

### Defensive inversion

将其视为 proactive domain-monitoring problem，而不仅是 prompt-injection problem：
- 构建 **brand prompt corpus**，定期探测用户/agents 所依赖的 LLMs。
- 存储 hallucinated URLs，并跟踪哪些 URL 在不同 temperatures/models 下保持稳定。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次 hallucination 到 attacker registration 的时间。正 AEW 表示 defenders 可以在 weaponization 前 pre-register、sinkhole 或 pre-block。
- 监控 parent domains 的 **NXDOMAIN → registered** transitions。
- 注册后，对 registrar、creation date、nameservers、privacy shielding、page content、screenshots、parked-page status 和 brand-asset similarity 进行 triage。
- 添加 policy gates，使 agents/developers **默认不信任 LLM-generated domains**：首次使用前要求 allowlists、ownership validation、CT/RDAP checks 或 human approval。

这同时符合多个 AI risk buckets：**AI supply-chain attack**、**insecure model output**，以及 agents 自主使用 hallucinated URL 时产生的 **rogue actions**。

## References
- [1] [Unit 42 – Code Assistant LLMs 的风险：有害内容、滥用与欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking scheme 概览 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy（转售被盗的 LLM access）](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - 深入分析 on-premise low-privileged LLM server 的部署](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets：podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting：AI-Hallucinated Domains 作为 Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting：AI Hallucinations 如何助推新型 Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
