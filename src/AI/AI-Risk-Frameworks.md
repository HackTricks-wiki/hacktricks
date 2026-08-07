# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp 已确定可能影响 AI 系统的十大机器学习漏洞。这些漏洞可能导致各种安全问题，包括 data poisoning、model inversion 和 adversarial attacks。理解这些漏洞对于构建安全的 AI 系统至关重要。

有关最新且详细的十大机器学习漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。<sup>[[1]](#references)</sup>

- **Input Manipation Attack**：攻击者对**输入数据**添加细微且通常不可见的更改，使模型做出错误决策。\
*示例*：在 stop sign 上涂上几处小斑点，就能让自动驾驶汽车将其“识别”为限速标志。

- **Data Poisoning Attack**：故意污染**training set**，通过错误样本教会模型有害规则。\
*示例*：在 antivirus training corpus 中将 malware 二进制文件错误标记为“benign”，使类似 malware 之后能够绕过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**reverse model**，从而重建原始输入中的敏感特征。\
*示例*：根据 cancer-detection model 的预测结果，重新构建患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过观察置信度差异，测试某条**特定记录**是否曾用于训练。\
*示例*：确认某人的银行交易记录是否出现在 fraud-detection model 的 training data 中。

- **Model Theft**：反复查询可让攻击者了解决策边界，并**克隆模型的行为**（以及 IP）。\
*示例*：从 ML-as-a-Service API 收集足够多的问答对，构建一个几乎等效的本地模型。

- **AI Supply-Chain Attack**：入侵**ML pipeline** 中的任意组件（data、libraries、pre-trained weights、CI/CD），以污染下游模型。\
*示例*：model-hub 中被投毒的 dependency 安装了一个带 backdoor 的 sentiment-analysis model，并将其部署到大量应用中。

- **Transfer Learning Attack**：将恶意逻辑植入**pre-trained model**，使其在针对受害者任务进行 fine-tuning 后仍然存在。\
*示例*：带有隐藏 trigger 的 vision backbone 在适配到 medical imaging 后仍会翻转标签。

- **Model Skewing**：经过细微偏置或错误标记的数据会**改变模型输出**，使其偏向攻击者的目的。\
*示例*：注入被标记为 ham 的“正常” spam emails，使 spam filter 放过之后类似的邮件。

- **Output Integrity Attack**：攻击者在传输过程中**修改 model predictions**，而不是修改模型本身，从而欺骗下游系统。\
*示例*：在 file-quarantine stage 看到结果之前，将 malware classifier 的“malicious”判定翻转为“benign”。

- **Model Poisoning** --- 直接、有针对性地修改**model parameters** 本身，通常是在获得写入权限后改变模型行为。\
*示例*：调整 production 中 fraud-detection model 的 weights，使来自某些银行卡的交易始终获批。


## Google SAIF Risks

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：<sup>[[2]](#references)</sup>

- **Data Poisoning**：恶意行为者修改或注入 training/tuning data，以降低准确率、植入 backdoors 或扭曲结果，破坏整个 data-lifecycle 中的模型完整性。

- **Unauthorized Training Data**：摄取受版权保护、敏感或未经许可的数据集会带来法律、伦理和性能方面的责任风险，因为模型从不被允许使用的数据中进行学习。

- **Model Source Tampering**：在训练之前或期间对 model code、dependencies 或 weights 进行 supply-chain 或内部人员篡改，可能植入即使 retraining 后仍会持续存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，从而增加暴露和合规风险。

- **Model Exfiltration**：攻击者窃取 model files/weights，导致知识产权损失，并支持仿冒服务或后续攻击。

- **Model Deployment Tampering**：攻击者修改 model artifacts 或 serving infrastructure，使运行中的模型不同于经过审核的版本，从而可能改变其行为。

- **Denial of ML Service**：向 APIs 发送洪水请求或“sponge” inputs，耗尽计算资源和能源并使模型离线，类似于传统的 DoS attacks。

- **Model Reverse Engineering**：通过收集大量 input-output pairs，攻击者可以克隆或 distil 模型，为仿冒产品和定制化 adversarial attacks 提供支持。

- **Insecure Integrated Component**：存在漏洞的 plugins、agents 或上游服务会让攻击者在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：直接或间接构造 prompts，偷偷注入覆盖系统意图的指令，使模型执行非预期命令。

- **Model Evasion**：经过精心设计的 inputs 会触发模型产生错误分类、hallucinate 或输出不允许的内容，从而削弱安全性和信任。

- **Sensitive Data Disclosure**：模型泄露 training data 或 user context 中的私人或机密信息，违反隐私和监管要求。

- **Inferred Sensitive Data**：模型推断出从未被提供的个人属性，通过推理造成新的隐私伤害。

- **Insecure Model Output**：未经清理的响应会将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：与系统自主集成的 agents 在缺乏充分用户监督的情况下，执行非预期的现实世界操作（file writes、API calls、purchases 等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 为理解和缓解 AI 系统相关风险提供了全面框架。它对攻击者可能针对 AI 模型使用的各种攻击技术和战术进行分类，同时也说明如何使用 AI 系统执行不同的攻击。<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取活动 session tokens 或 cloud API credentials，未经授权调用付费的 cloud-hosted LLM。访问权限通常通过 reverse proxies 转售，这些 reverse proxies 以受害者的账户作为前端，例如“oai-reverse-proxy”部署。后果包括经济损失、违反策略的模型滥用，以及将活动归因于受害者 tenant。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs：
- 从受感染的 developer machines 或 browsers 中收集 tokens；窃取 CI/CD secrets；购买 leaked cookies。<sup>[[5]](#references)</sup>
- 建立 reverse proxy，将请求转发给 genuine provider，同时隐藏上游 key，并为多个客户提供 multiplexing。<sup>[[5]](#references)[[7]](#references)</sup>
- 滥用 direct base-model endpoints，绕过 enterprise guardrails 和 rate limits。<sup>[[4]](#references)</sup>

缓解措施：
- 将 tokens 绑定到 device fingerprint、IP ranges 和 client attestation；强制执行较短的有效期，并使用 MFA 进行 refresh。
- 尽量限制 keys 的权限范围（不提供 tool access；适用时使用 read-only）；出现异常时进行 rotate。
- 将所有 traffic 在 server-side 置于 policy gateway 后方，由其执行 safety filters、per-route quotas 和 tenant isolation。
- 监控异常的使用模式（突然的 spend spikes、异常 regions、UA strings），并自动撤销可疑 sessions。
- 优先使用由 IdP 签发的 mTLS 或 signed JWTs，而不是长期有效的静态 API keys。

## Self-hosted LLM inference hardening

为机密数据运行 local LLM server 所产生的 attack surface 不同于 cloud-hosted APIs：inference/debug endpoints 可能泄露 prompts，serving stack 通常会暴露 reverse proxy，而 GPU device nodes 则提供对大型 `ioctl()` surfaces 的访问。如果你正在评估或部署 on-prem inference service，至少应检查以下事项。<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

将 inference API 视为**多用户敏感服务**。Debug 或 monitoring routes 可能暴露 prompt contents、slot state、model metadata 或 internal queue information。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它会暴露 per-slot state，且仅用于 slot inspection/management。<sup>[[8]](#references)</sup>

- 在 inference server 前置 reverse proxy，并**默认拒绝**。
- 仅 allowlist client/UI 所需的确切 HTTP method + path 组合。
- 尽可能在 backend 本身禁用 introspection endpoints，例如 `llama-server --no-slots`。<sup>[[9]](#references)</sup>
- 将 reverse proxy 绑定到 `127.0.0.1`，并通过 SSH local port forwarding 等 authenticated transport 暴露，而不是将其发布到 LAN。

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

如果 inference daemon 支持监听 UNIX socket，优先使用它而不是 TCP，并使用 **无 network stack** 运行 container：<sup>[[8]](#references)</sup>
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
- `--network none` 移除入站/出站 TCP/IP 暴露，并避免 rootless containers 原本需要的 user-mode helpers。
- UNIX socket 允许你将 POSIX permissions/ACLs 应用于 socket path，作为第一层 access-control。
- `--userns=keep-id` 和 rootless Podman 可降低 container breakout 的影响，因为 container root 并不是 host root。
- Read-only model mounts 可降低从 container 内部篡改 model 的可能性。

### GPU device-node 最小化

对于 GPU-backed inference，`/dev/nvidia*` 文件是高价值的本地 attack surface，因为它们暴露了大型 driver `ioctl()` handlers，以及潜在的共享 GPU memory-management paths。<sup>[[8]](#references)</sup>

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev rules 和 ACLs 限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，使其只能由映射后的 container UID 打开。
- 在 headless inference hosts 上 blacklist 不必要的 modules，例如 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem`。
- 在 boot 时仅 preload 必需的 modules，而不是允许 runtime 在 inference startup 期间机会性地 `modprobe` 它们。

示例：
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使工作负载没有显式使用 `cudaMallocManaged()`，近期的 CUDA runtimes 仍可能需要 `nvidia-uvm`。由于此设备是共享的，并负责 GPU 虚拟内存管理，应将其视为跨租户数据暴露面。如果 inference backend 支持，Vulkan backend 可能是一种有趣的权衡，因为它可能完全避免将 `nvidia-uvm` 暴露给 container。<sup>[[8]](#references)</sup>

### inference workers 的 LSM confinement

AppArmor/SELinux/seccomp 应围绕 inference process 作为纵深防御措施使用：<sup>[[8]](#references)</sup>

- 仅允许实际需要的 shared libraries、model paths、socket directory 和 GPU device nodes。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险 capabilities。
- 将 model directory 保持为只读，并将可写路径限制为 runtime socket/cache directories。
- 监控 denial logs，因为当 model server 或 post-exploitation payload 试图逃离其预期行为时，这些日志可提供有用的 detection telemetry。

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

Phantom squatting 是 **slopsquatting 在域名/URL 层面的对应形式**。LLM 不再是幻觉生成一个不存在的 package name，而是为真实品牌幻觉生成一个看似合理的 **portal、API、webhook、billing、SSO、download 或 support domain**，攻击者则在人类或 agent 使用该 namespace 之前注册它。<sup>[[12]](#references)[[13]](#references)</sup>

这之所以重要，是因为在许多 AI 辅助工作流中，模型输出会被当作**可信依赖**：
- 开发者将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agents 自动获取文档、schemas、APKs、ZIPs 或 webhook targets。
- 生成的 runbooks 或文档可能会嵌入 fake URL，并将其当作权威来源。

### Offensive workflow

1. **Probe the hallucination surface**：围绕特定品牌询问真实的工作流，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` portals。<sup>[[12]](#references)</sup>
2. **Normalize candidates**：解析生成的 URLs，将 NXDOMAIN responses 归并到 parent registerable domain，并对 prompt families 去重。Prompt corpora 应保持多样性，例如通过删除具有较高 **Jaccard similarity** 的近似重复项。
3. **Prioritize predictable hallucinations**：
- **Thermal Hallucination Persistence (THP)**：同一个 fake domain 会在不同 temperature 下反复出现，包括 `T=0.1` 这样的低 temperature。
- **Cross-model consensus**：多个 LLM families 生成同一个 fake domain。
4. **Register and weaponize** parent domain，然后托管 phishing、fake APK/ZIP downloads、credential harvesters、malicious docs 或收集 secrets/webhook payloads 的 API endpoints。**Pure domain-level hallucinations** 最容易变现，因为攻击者控制整个 namespace；当 normalized parent 尚未注册时，subdomain/path hallucinations 仍然可以被滥用。
5. **Exploit the zero-reputation window**：新注册的 domains 通常缺少 blocklist history、URL reputation 和成熟的 telemetry，因此在 detections 跟上之前可能绕过 controls。攻击者可以利用仅对 crawlers 返回 benign responses、redirect cloaking、CAPTCHA gates 或延迟 payload staging 来延长这个窗口。

### Why it is dangerous for agents

对于人类受害者，fake domain 通常仍需要一次点击和后续操作。对于 **agentic workflow**，LLM 既可以是**诱饵**，也可以是**执行者**：agent 接收 hallucinated URL、获取该 URL、解析 response，随后可能 leak tokens、执行 instructions、download a dependency，或在没有任何人工审核的情况下将 poisoned data 推送到 CI/CD 中。<sup>[[12]](#references)</sup>

### Practical attacker prompts

高价值 prompts 通常看起来像普通的企业任务，而不是明显的 phishing lures：<sup>[[12]](#references)</sup>
- “`<brand>` integrations 使用的 payment sandbox URL 是什么？”
- “我应该为 `<brand>` build notifications 使用哪个 webhook endpoint？”
- “`<brand>` 的 employee benefits / billing / SSO portal 在哪里？”
- “给我 `<brand>` 的 direct Android APK 或 desktop client download。”

### Defensive inversion

应将其视为主动的 domain-monitoring 问题，而不仅仅是 prompt-injection 问题：<sup>[[12]](#references)</sup>
- 构建 **brand prompt corpus**，并定期 probe 用户或 agents 所依赖的 LLMs。
- 存储 hallucinated URLs，并跟踪哪些 URLs 在不同 temperatures/models 下保持稳定。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次 hallucination 到攻击者注册之间的时间。AEW 为正意味着 defenders 可以在 weaponization 之前 pre-register、sinkhole 或 pre-block。
- 监控 parent domains 从 **NXDOMAIN → registered** 的转换。
- 注册后，对 registrar、creation date、nameservers、privacy shielding、page content、screenshots、parked-page status 和 brand-asset similarity 进行 triage。
- 添加 policy gates，使 agents/developers **默认不信任 LLM-generated domains**：在首次使用前要求 allowlists、ownership validation、CT/RDAP checks 或人工批准。

这同时符合多个 AI 风险类别：**AI supply-chain attack**、**insecure model output**，以及当 agents 自主使用 hallucinated URL 时产生的 **rogue actions**。

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
