# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp 已确定可能影响 AI 系统的十大机器学习漏洞。这些漏洞可能导致各种安全问题，包括数据投毒、模型反演和对抗性攻击。理解这些漏洞对于构建安全的 AI 系统至关重要。

如需查看更新且详细的机器学习十大漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。

- **Input Manipulation Attack**：攻击者向**输入数据**添加微小且通常不可见的变化，使模型做出错误决策。\
*示例*：在停车标志上涂几个小斑点，就能让自动驾驶汽车将其“识别”为限速标志。

- **Data Poisoning Attack**：故意污染**训练集**，使用恶意样本教会模型有害规则。\
*示例*：在杀毒软件训练语料中，将恶意软件二进制文件错误标记为“良性”，使类似恶意软件之后能够绕过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**反向模型**，重建原始输入中的敏感特征。\
*示例*：根据癌症检测模型的预测结果，重建患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过观察置信度差异，测试**特定记录**是否用于训练。\
*示例*：确认某人的银行交易是否出现在欺诈检测模型的训练数据中。

- **Model Theft**：反复查询使攻击者能够了解决策边界并**克隆模型的行为**（及其 IP）。\
*示例*：从 ML-as-a-Service API 收集足够多的问答对，构建功能近似的本地模型。

- **AI Supply-Chain Attack**：破坏 **ML pipeline** 中的任意组件（数据、库、预训练权重、CI/CD），以污染下游模型。\
*示例*：模型中心中的恶意依赖安装带有后门的情感分析模型，并扩散到多个应用中。

- **Transfer Learning Attack**：将恶意逻辑植入**预训练模型**，使其在受害者任务上进行 fine-tuning 后仍然存在。\
*示例*：带有隐藏触发器的视觉 backbone 在适配医学影像任务后仍会翻转标签。

- **Model Skewing**：经过细微偏置或错误标记的数据**改变模型输出**，使其偏向攻击者的目标。\
*示例*：注入被标记为 ham 的“干净”垃圾邮件，使垃圾邮件过滤器放行之后的类似邮件。

- **Output Integrity Attack**：攻击者**在传输过程中修改模型预测结果**，而不是修改模型本身，从而欺骗下游系统。\
*示例*：在文件隔离阶段读取结果之前，将恶意软件分类器的“恶意”判定改为“良性”。

- **Model Poisoning** --- 直接、有针对性地修改**模型参数**本身，通常发生在获得写入权限之后，以改变模型行为。\
*示例*：修改生产环境中欺诈检测模型的权重，使来自特定银行卡的交易始终获批。


## Google SAIF 风险

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：

- **Data Poisoning**：恶意行为者修改或注入训练/调优数据，以降低准确率、植入后门或扭曲结果，破坏整个数据生命周期中的模型完整性。

- **Unauthorized Training Data**：摄入受版权保护、敏感或未经许可的数据集会带来法律、伦理和性能方面的责任风险，因为模型学习了不被允许使用的数据。

- **Model Source Tampering**：在训练之前或期间，对模型代码、依赖项或权重进行供应链或内部人员篡改，可能植入即使重新训练后仍会存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，从而增加暴露和合规风险。

- **Model Exfiltration**：攻击者窃取模型文件/权重，造成知识产权损失，并 enable 仿冒服务或后续攻击。

- **Model Deployment Tampering**：对模型制品或 serving 基础设施进行修改，使运行中的模型不同于经过审查的版本，并可能改变其行为。

- **Denial of ML Service**：通过大量请求 API 或发送“sponge”输入耗尽计算资源/能源，使模型离线，类似于传统 DoS 攻击。

- **Model Reverse Engineering**：通过收集大量输入-输出对，攻击者可以克隆或蒸馏模型，为仿冒产品和定制化对抗性攻击提供支持。

- **Insecure Integrated Component**：存在漏洞的插件、agents 或上游服务可能允许攻击者在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：构造 prompt（直接或间接）以夹带覆盖系统意图的指令，使模型执行非预期命令。

- **Model Evasion**：精心设计的输入会触发模型错误分类、产生幻觉或输出不允许的内容，从而削弱安全性和信任。

- **Sensitive Data Disclosure**：模型泄露训练数据或用户上下文中的私有或机密信息，违反隐私要求和法规。

- **Inferred Sensitive Data**：模型推断出从未提供过的个人属性，通过推理造成新的隐私损害。

- **Insecure Model Output**：未经清理的响应将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：集成到系统中的 autonomous agents 在缺乏充分用户监督的情况下执行非预期的现实操作（文件写入、API 调用、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 为理解和缓解与 AI 系统相关的风险提供了综合框架。它对攻击者可能针对 AI 模型使用的各种攻击技术和战术进行分类，也涵盖如何使用 AI 系统执行不同攻击。


## LLMJacking（Token 窃取与云端 LLM 访问转售）

攻击者窃取活跃会话 token 或云 API 凭据，未经授权调用付费的云端 LLM。访问权限通常通过位于受害者账户前端的 reverse proxy 转售，例如 "oai-reverse-proxy" 部署。后果包括经济损失、违反策略使用模型，以及使受害者 tenant 成为归因对象。

TTPs：
- 从受感染的开发者机器或浏览器中收集 token；窃取 CI/CD secrets；购买 leaked cookies。
- 部署 reverse proxy，将请求转发给真实 provider，同时隐藏上游 key，并为多个客户复用连接。
- 滥用直接的 base-model endpoints，绕过企业 guardrails 和 rate limits。

缓解措施：
- 将 token 绑定到设备指纹、IP 范围和客户端 attestation；强制设置较短的过期时间，并通过 MFA 刷新。
- 尽量缩小 key 权限范围（不授予 tool 访问权限；适用时设为只读）；检测到异常时进行轮换。
- 将所有流量置于 server-side policy gateway 之后，由其强制执行 safety filters、per-route quotas 和 tenant isolation。
- 监控异常使用模式（突然的支出峰值、异常地区、UA 字符串），并自动撤销可疑会话。
- 优先使用由 IdP 签发的 mTLS 或 signed JWT，而不是长期有效的静态 API key。

## Self-hosted LLM inference 加固

为机密数据运行本地 LLM server 会产生不同于云端 API 的攻击面：inference/debug endpoints 可能泄露 prompt，serving stack 通常会暴露 reverse proxy，而 GPU device nodes 则提供对大型 `ioctl()` surfaces 的访问。如果你正在评估或部署 on-prem inference service，至少应检查以下事项。

### 通过 debug 和 monitoring endpoints 泄露 prompt

将 inference API 视为**多用户敏感服务**。Debug 或 monitoring routes 可能暴露 prompt 内容、slot 状态、model metadata 或内部 queue 信息。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它会暴露每个 slot 的状态，并且仅用于 slot 检查/管理。

- 在 inference server 前部署 reverse proxy，并采用**默认拒绝**策略。
- 仅 allowlist 客户端/UI 所需的确切 HTTP method + path 组合。
- 尽可能在 backend 自身禁用 introspection endpoints，例如 `llama-server --no-slots`。
- 将 reverse proxy 绑定到 `127.0.0.1`，并通过 SSH local port forwarding 等经过身份验证的 transport 暴露，而不是将其发布到 LAN。

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
### 无 root 权限容器、无网络和 UNIX sockets

如果 inference daemon 支持监听 UNIX socket，优先使用 UNIX socket 而不是 TCP，并以 **无网络栈** 模式运行容器：
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
- `--network none` removes inbound/outbound TCP/IP exposure and avoids user-mode helpers that rootless containers would otherwise need.
- A UNIX socket lets you use POSIX permissions/ACLs on the socket path as the first access-control layer.
- `--userns=keep-id` and rootless Podman reduce the impact of a container breakout because container root is not host root.
- Read-only model mounts reduce the chance of model tampering from inside the container.

### GPU 设备节点最小化

对于基于 GPU 的推理，`/dev/nvidia*` 文件属于高价值的本地攻击面，因为它们暴露了大型驱动 `ioctl()` 处理程序以及潜在的共享 GPU 内存管理路径。

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev 规则和 ACL，限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，确保只有映射的容器 UID 可以打开它们。
- 在无头推理主机上，将不必要的模块列入黑名单，例如 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem`。
- 在启动时仅预加载所需模块，而不是让 runtime 在推理启动期间伺机使用 `modprobe` 加载它们。

示例：
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使 workload 没有显式使用 `cudaMallocManaged()`，近期的 CUDA runtime 仍可能需要 `nvidia-uvm`。由于该 device 是共享的，并负责 GPU virtual memory management，应将其视为 cross-tenant data-exposure surface。如果 inference backend 支持，Vulkan backend 可能是一个值得考虑的 trade-off，因为它可能完全避免向 container 暴露 `nvidia-uvm`。

### inference workers 的 LSM confinement

应在 inference process 周围使用 AppArmor/SELinux/seccomp 作为 defense in depth：

- 仅允许实际需要的 shared libraries、model paths、socket directory 和 GPU device nodes。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等 high-risk capabilities。
- 将 model directory 保持为 read-only，并将可写 paths 限制在 runtime socket/cache directories。
- 监控 denial logs，因为当 model server 或 post-exploitation payload 试图逃离其预期 behaviour 时，这些日志可提供有用的 detection telemetry。

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

Phantom squatting 是 **slopsquatting 在域名/URL 层面的对应形式**。LLM 不再是幻觉生成一个不存在的软件包名称，而是为真实品牌幻觉生成一个看似合理的 **portal、API、webhook、billing、SSO、download 或 support 域名**，攻击者则在人员或 agent 使用该命名空间之前注册它。

这很重要，因为在许多 AI 辅助工作流中，模型输出会被视为 **受信任的依赖项**：
- 开发者会将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agent 会自动获取文档、schema、APK、ZIP 或 webhook 目标。
- 生成的 runbook 或文档可能会嵌入虚假 URL，并将其当作权威地址。

### Offensive workflow

1. **探测幻觉面**：针对品牌询问真实的工作流问题，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` portal。
2. **规范化候选项**：解析生成的 URL，将 NXDOMAIN 响应归并到父级可注册域名，并对 prompt 系列去重。Prompt 语料应保持多样化，例如使用 **Jaccard similarity** 去除近似重复项。
3. **优先处理可预测的幻觉**：
- **Thermal Hallucination Persistence (THP)**：同一个虚假域名会在不同 temperature 下出现，包括较低的 temperature，如 `T=0.1`。
- **Cross-model consensus**：多个 LLM 系列生成同一个虚假域名。
4. **注册并 weaponize** 父级域名，然后托管 phishing 页面、虚假 APK/ZIP 下载、credential harvester、恶意文档或用于收集 secrets/webhook payload 的 API endpoint。**纯域名级幻觉**最容易变现，因为攻击者控制整个命名空间；当规范化后的父级域名尚未注册时，子域名/路径幻觉同样可能被滥用。
5. **利用零信誉窗口**：新注册域名通常缺少 blocklist 历史、URL reputation 和成熟的 telemetry，因此在检测机制跟上之前可能绕过控制措施。攻击者还可以通过仅对 crawler 返回 benign 响应、redirect cloaking、CAPTCHA gate 或延迟 payload staging 来延长该窗口。

### Why it is dangerous for agents

对于 human victim，虚假域名通常仍然需要点击以及后续操作。对于 **agentic workflow**，LLM 同时可以充当 **lure** 和 **executor**：agent 接收幻觉生成的 URL，获取该 URL，解析响应，随后可能 leak tokens、执行 instructions、下载 dependency，或在没有任何 human review 的情况下将 poisoned data 推入 CI/CD。

### Practical attacker prompts

高价值 prompt 通常看起来像正常的 enterprise 任务，而不是明显的 phishing lure：
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

将其视为 proactive domain-monitoring 问题，而不仅仅是 prompt-injection 问题：
- 构建 **brand prompt corpus**，并定期探测用户/agent 所依赖的 LLM。
- 存储幻觉生成的 URL，并跟踪哪些 URL 在不同 temperature/model 下保持稳定。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次出现幻觉到攻击者注册域名之间的时间。AEW 为正意味着 defenders 可以在 weaponization 之前预注册、sinkhole 或预先 block。
- 监控父级域名从 **NXDOMAIN → registered** 的转换。
- 域名注册后，对 registrar、creation date、nameserver、privacy shielding、页面内容、截图、parked-page 状态以及 brand-asset similarity 进行 triage。
- 添加 policy gate，使 agent/developer **默认不信任 LLM 生成的域名**：在首次使用之前要求 allowlist、ownership validation、CT/RDAP 检查或 human approval。

这同时符合多个 AI 风险类别：**AI supply-chain attack**、**insecure model output**，以及 agent 自主使用幻觉 URL 时产生的 **rogue actions**。

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
