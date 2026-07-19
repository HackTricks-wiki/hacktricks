# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp 已识别出可能影响 AI 系统的十大 Machine Learning 漏洞。这些漏洞可能导致各种安全问题，包括数据投毒、模型反演和对抗性攻击。理解这些漏洞对于构建安全的 AI 系统至关重要。

有关 Machine Learning 十大漏洞的最新详细列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。

- **Input Manipulation Attack**：攻击者向**传入数据**添加微小且通常不可见的更改，使模型做出错误决策。\
*示例*：在停止标志上涂上几小点油漆，欺骗自动驾驶汽车将其“看成”限速标志。

- **Data Poisoning Attack**：恶意污染**训练集**，通过错误样本教会模型有害规则。\
*示例*：在 antivirus 训练语料库中将恶意软件二进制文件错误标记为“良性”，使类似恶意软件随后能够绕过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**反向模型**，重建原始输入中的敏感特征。\
*示例*：根据癌症检测模型的预测结果，重新生成患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过发现置信度差异，测试某条**特定记录**是否被用于训练。\
*示例*：确认某人的银行交易是否出现在欺诈检测模型的训练数据中。

- **Model Theft**：反复查询使攻击者能够了解决策边界并**克隆模型的行为**（以及 IP）。\
*示例*：从 ML-as-a-Service API 收集足够的问答对，构建一个几乎等效的本地模型。

- **AI Supply-Chain Attack**：入侵**ML pipeline** 中的任意组件（数据、libraries、pre-trained weights、CI/CD），以破坏下游模型。\
*示例*：model-hub 中被投毒的 dependency 安装了带后门的 sentiment-analysis model，并将其传播到多个应用中。

- **Transfer Learning Attack**：将恶意逻辑植入**pre-trained model**，使其在受害者任务上进行 fine-tuning 后仍然存活。\
*示例*：带有隐藏触发器的 vision backbone 在适配 medical imaging 后仍会翻转标签。

- **Model Skewing**：经过细微操纵的偏置或错误标记数据**改变模型的输出**，使其偏向攻击者的目标。\
*示例*：注入被标记为 ham 的“干净”垃圾邮件，使 spam filter 放行未来类似的邮件。

- **Output Integrity Attack**：攻击者**在传输过程中修改模型预测结果**，而不是修改模型本身，从而欺骗下游系统。\
*示例*：在文件隔离阶段读取结果之前，将 malware classifier 的“恶意”判定翻转为“良性”。

- **Model Poisoning** --- 直接、有针对性地修改**模型参数**本身，通常是在获得写入权限后改变模型行为。\
*示例*：调整生产环境中 fraud-detection model 的权重，使来自某些银行卡的交易始终获得批准。


## Google SAIF Risks

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：

- **Data Poisoning**：恶意行为者修改或注入 training/tuning data，以降低准确率、植入后门或扭曲结果，破坏整个 data-lifecycle 中的 model integrity。

- **Unauthorized Training Data**：摄入受版权保护、敏感或未经许可的数据集会造成法律、伦理和性能方面的责任风险，因为模型从不被允许使用的数据中学习。

- **Model Source Tampering**：在训练之前或期间对 model code、dependencies 或 weights 进行 supply-chain 或内部人员操纵，可能植入即使 retraining 后仍然存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，从而增加暴露和合规风险。

- **Model Exfiltration**：攻击者窃取 model files/weights，导致 intellectual property 丢失，并使仿冒服务或后续攻击成为可能。

- **Model Deployment Tampering**：对 model artifacts 或 serving infrastructure 进行修改，使运行中的模型不同于经过审查的版本，可能改变其行为。

- **Denial of ML Service**：泛洪 APIs 或发送“sponge” inputs，可能耗尽计算资源/能源并使模型离线，这与经典 DoS attacks 类似。

- **Model Reverse Engineering**：通过收集大量 input-output pairs，攻击者可以克隆或 distil 模型，为仿冒产品和定制化 adversarial attacks 提供条件。

- **Insecure Integrated Component**：存在漏洞的 plugins、agents 或上游 services 可能使攻击者在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：直接或间接构造 prompts，偷偷插入覆盖 system intent 的指令，使模型执行非预期命令。

- **Model Evasion**：经过精心设计的 inputs 触发模型进行错误分类、产生幻觉或输出被禁止的内容，削弱安全性和信任。

- **Sensitive Data Disclosure**：模型泄露其 training data 或 user context 中的私人或机密信息，违反隐私和监管要求。

- **Inferred Sensitive Data**：模型推断从未被提供的个人属性，通过推断造成新的隐私危害。

- **Insecure Model Output**：未经清理的响应将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：自主集成的 agents 在缺乏充分用户监督的情况下，执行非预期的现实操作（文件写入、API calls、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 为理解和缓解与 AI 系统相关的风险提供了全面框架。它对 adversaries 可能针对 AI models 使用的各种 attack techniques 和 tactics 进行分类，同时也说明如何利用 AI systems 执行不同的 attacks。

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取 active session tokens 或 cloud API credentials，未经授权调用付费的 cloud-hosted LLMs。访问权限通常通过 reverse proxies 转售，这些 reverse proxies 以受害者账户作为前端，例如“oai-reverse-proxy”部署。后果包括经济损失、违反策略的模型滥用，以及将攻击行为归因于受害者 tenant。

TTPs：
- 从被感染的开发者机器或 browsers 中收集 tokens；窃取 CI/CD secrets；购买 leaked cookies。
- 搭建 reverse proxy，将请求转发至真实 provider，隐藏上游 key，并为多个客户复用连接。
- 滥用 direct base-model endpoints，绕过 enterprise guardrails 和 rate limits。

Mitigations：
- 将 tokens 绑定到 device fingerprint、IP ranges 和 client attestation；强制使用较短的过期时间，并通过 MFA 刷新。
- 尽可能缩小 keys 的权限范围（不授予 tool access，适用时设为 read-only）；出现异常时进行轮换。
- 在 server-side 将所有流量置于 policy gateway 之后，由其实施 safety filters、per-route quotas 和 tenant isolation。
- 监控异常使用模式（突然的费用激增、异常地区、UA strings），并自动撤销可疑 sessions。
- 优先使用由 IdP 签发的 mTLS 或 signed JWTs，而不是长期有效的 static API keys。

## Self-hosted LLM inference hardening

为机密数据运行本地 LLM server，其攻击面不同于 cloud-hosted APIs：inference/debug endpoints 可能泄露 prompts，serving stack 通常会暴露 reverse proxy，而 GPU device nodes 则提供对大型 `ioctl()` surfaces 的访问。如果你正在评估或部署 on-prem inference service，至少应审查以下几点。

### Prompt leakage via debug and monitoring endpoints

将 inference API 视为**多用户敏感服务**。Debug 或 monitoring routes 可能暴露 prompt contents、slot state、model metadata 或 internal queue information。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它会暴露 per-slot state，并且仅用于 slot inspection/management。

- 在 inference server 前放置 reverse proxy，并**默认拒绝**。
- 仅 allowlist 客户端/UI 所需的精确 HTTP method + path 组合。
- 尽可能在 backend 本身禁用 introspection endpoints，例如 `llama-server --no-slots`。
- 将 reverse proxy 绑定到 `127.0.0.1`，并通过 SSH local port forwarding 等 authenticated transport 暴露，而不是发布到 LAN。

使用 nginx 的 allowlist 示例：
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

如果 inference daemon 支持监听 UNIX socket，优先使用它而不是 TCP，并使用 **无网络栈** 运行 container：
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
优势：
- `--network none` 移除入站/出站 TCP/IP 暴露，并避免 rootless containers 原本需要的用户模式辅助程序。
- UNIX socket 允许你在 socket 路径上使用 POSIX permissions/ACLs，作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可降低 container breakout 的影响，因为 container root 并非 host root。
- 只读模型挂载可降低从 container 内部篡改模型的可能性。

### GPU device-node 最小化

对于基于 GPU 的推理，`/dev/nvidia*` 文件属于高价值的本地攻击面，因为它们暴露了大量 driver `ioctl()` handlers，以及潜在的共享 GPU memory-management 路径。

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev rules 和 ACLs 限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，确保只有映射后的 container UID 能够打开它们。
- 在无头推理主机上，禁用不必要的 modules，例如 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem`。
- 在 boot 时仅预加载所需的 modules，而不是让 runtime 在推理启动期间临时执行 `modprobe`。

示例：
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使 workload 没有显式使用 `cudaMallocManaged()`，近期的 CUDA runtimes 仍可能需要 `nvidia-uvm`。由于该 device 是共享的，并负责 GPU virtual memory management，应将其视为 cross-tenant data-exposure surface。如果 inference backend 支持，Vulkan backend 可能是一种有趣的权衡方案，因为它可以完全避免向 container 暴露 `nvidia-uvm`。

### inference workers 的 LSM confinement

应在 inference process 周围使用 AppArmor/SELinux/seccomp 作为 defense in depth：

- 仅允许实际需要的 shared libraries、model paths、socket directory 和 GPU device nodes。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险 capabilities。
- 将 model directory 保持为 read-only，并将可写路径限制为 runtime socket/cache directories。
- 监控 denial logs，因为当 model server 或 post-exploitation payload 尝试逃离其预期行为时，这些日志可以提供有用的 detection telemetry。

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

Phantom squatting 是 **slopsquatting 的域名/URL 等价形式**。LLM 不再是凭空生成一个不存在的 package 名称，而是为真实品牌生成一个看似合理的 **portal、API、webhook、billing、SSO、download 或 support domain**，攻击者则在人类或 agent 使用该命名空间之前注册它。

这之所以重要，是因为在许多 AI 辅助工作流中，模型输出会被视为**可信依赖**：
- 开发者将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agents 自动获取文档、schemas、APKs、ZIPs 或 webhook targets。
- 生成的 runbooks 或文档可能会嵌入 fake URL，并将其当作权威链接。

### Offensive workflow

1. **Probe the hallucination surface**：针对特定品牌询问真实的工作流，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` portals。
2. **Normalize candidates**：解析生成的 URLs，将 NXDOMAIN 响应归并到 parent registerable domain，并对 prompt families 去重。Prompt corpora 应保持多样性，例如通过 **Jaccard similarity** 删除近似重复项。
3. **Prioritize predictable hallucinations**：
- **Thermal Hallucination Persistence (THP)**：同一个 fake domain 在不同 temperatures 下都会出现，包括 `T=0.1` 这样的低 temperature。
- **Cross-model consensus**：多个 LLM families 生成同一个 fake domain。
4. **Register and weaponize** parent domain，然后托管 phishing、fake APK/ZIP downloads、credential harvesters、malicious docs 或收集 secrets/webhook payloads 的 API endpoints。**Pure domain-level hallucinations** 最容易变现，因为攻击者控制整个 namespace；当 normalized parent 尚未注册时，subdomain/path hallucinations 仍然可以被滥用。
5. **Exploit the zero-reputation window**：新注册的 domains 通常缺少 blocklist history、URL reputation 和成熟的 telemetry，因此在 detections 追上之前可以绕过 controls。攻击者可以通过仅对 crawlers 返回 benign responses、redirect cloaking、CAPTCHA gates 或延迟 payload staging 来延长这一窗口。

### Why it is dangerous for agents

对于 human victim，fake domain 通常仍需要点击及后续操作。对于 **agentic workflow**，LLM 既可以是**诱饵**，也可以是**执行者**：agent 接收 hallucinated URL，获取该 URL、解析响应，随后可能 leak tokens、execute instructions、download a dependency，或在没有任何 human review 的情况下将 poisoned data 推入 CI/CD。

### Practical attacker prompts

高价值 prompts 通常看起来像普通的 enterprise tasks，而不是明显的 phishing lures：
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

将其视为 proactive domain-monitoring 问题，而不仅仅是 prompt-injection 问题：
- 建立 **brand prompt corpus**，并定期 probe 用户/agents 所依赖的 LLMs。
- 保存 hallucinated URLs，并跟踪哪些 URLs 在不同 temperatures/models 下保持稳定。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次 hallucination 到攻击者注册之间的时间。正数 AEW 表示 defenders 可以在 weaponization 之前 pre-register、sinkhole 或 pre-block。
- 监控 parent domains 的 **NXDOMAIN → registered** transitions。
- 注册后，对 registrar、creation date、nameservers、privacy shielding、page content、screenshots、parked-page status 及 brand-asset similarity 进行 triage。
- 添加 policy gates，使 agents/developers **默认不信任 LLM-generated domains**：首次使用前要求 allowlists、ownership validation、CT/RDAP checks 或 human approval。

这同时符合多个 AI risk buckets：**AI supply-chain attack**、**insecure model output**，以及 agents 自主使用 hallucinated URL 时产生的 **rogue actions**。

## References
- [Unit 42 – Code Assistant LLMs 的风险：有害内容、滥用与欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme 概览 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy（转售被盗的 LLM access）](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - 深入分析 on-premise 低权限 LLM server 的部署](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets：podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting：AI-Hallucinated Domains 作为 Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting：AI Hallucinations 如何助推新型 Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
