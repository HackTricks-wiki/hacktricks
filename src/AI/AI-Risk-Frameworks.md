# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP 已确定可能影响 AI 系统的十大 machine learning 漏洞。这些漏洞可能导致各种安全问题，包括 data poisoning、model inversion 和 adversarial attacks。了解这些漏洞对于构建安全的 AI 系统至关重要。

如需查看最新且详细的十大 machine learning 漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**：攻击者在**传入数据**中加入细微、通常不可见的变化，使模型做出错误判断。\
    *示例*：在停车标志上涂几处小斑点，就能骗过自动驾驶汽车，让它“看到”限速标志。

- **Data Poisoning Attack**：有人故意污染**训练集**，用有害规则训练模型。\
*示例*：在 antivirus 训练语料中，将恶意软件二进制文件标记为“良性”，使类似恶意软件之后得以逃过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**反向模型**，以重建原始输入中的敏感特征。\
*示例*：根据癌症检测模型的预测结果，重建患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过发现置信度差异，测试**特定记录**是否用于训练。\
*示例*：确认某人的银行交易是否出现在欺诈检测模型的训练数据中。

- **Model Theft**：通过反复查询，攻击者可以了解决策边界并**克隆模型的行为**（及知识产权）。\
*示例*：从 ML-as-a-Service API 中收集足够多的问答对，以构建一个近似等效的本地模型。

- **AI Supply‑Chain Attack**：入侵**ML pipeline**中的任意组件（数据、库、预训练权重、CI/CD），以污染下游模型。\
*示例*：model hub 中受污染的依赖项安装了带后门的情感分析模型，并影响众多应用。

- **Transfer Learning Attack**：在**预训练模型**中植入恶意逻辑，并使其在针对受害者任务进行微调后依然保留。\
*示例*：带有隐藏触发器的视觉 backbone，在适配用于医学影像后仍会翻转标签。

- **Model Skewing**：带有细微偏见或标签错误的数据会**改变模型输出**，使其偏向攻击者的目的。\
*示例*：注入标记为 ham 的“干净”垃圾邮件，使垃圾邮件过滤器放过之后的类似邮件。

- **Output Integrity Attack**：攻击者**在传输过程中篡改模型预测**，而非模型本身，以欺骗下游系统。\
*示例*：在文件隔离阶段读取结果前，将恶意软件分类器的“恶意”判定改为“良性”。

- **Model Poisoning** --- 直接、有针对性地修改**模型参数**本身，通常是在获得写入权限后实施，以改变模型行为。\
*示例*：在生产环境中调整欺诈检测模型的权重，使来自特定银行卡的交易总是获批。


## Google SAIF Risks

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了 AI 系统相关的各种风险：<sup>[[2]](#references)</sup>

- **Data Poisoning**：恶意行为者篡改或注入训练/调优数据，以降低准确性、植入后门或扭曲结果，从而损害整个数据生命周期中的模型完整性。

- **Unauthorized Training Data**：摄入受版权保护、敏感或未经许可的数据集会带来法律、伦理和性能方面的责任，因为模型使用了未经授权的数据进行学习。

- **Model Source Tampering**：在训练之前或期间，通过供应链攻击或内部人员篡改模型代码、依赖项或权重，可能植入即使经过重新训练仍会保留的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，从而增加数据暴露和合规风险。

- **Model Exfiltration**：攻击者窃取模型文件/权重，导致知识产权损失，并使仿冒服务或后续攻击成为可能。

- **Model Deployment Tampering**：攻击者修改模型工件或服务基础设施，使运行中的模型与经审核的版本不一致，可能改变模型行为。

- **Denial of ML Service**：通过 API 洪泛或发送“sponge”输入耗尽计算资源/能源，使模型离线，类似传统 DoS 攻击。

- **Model Reverse Engineering**：通过大量收集输入-输出对，攻击者可以克隆或蒸馏模型，进而制作仿冒产品和定制 adversarial attacks。

- **Insecure Integrated Component**：存在漏洞的插件、agent 或上游服务会使攻击者能够在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：通过直接或间接构造 prompt，夹带覆盖系统意图的指令，使模型执行非预期命令。

- **Model Evasion**：精心设计的输入会触发模型错误分类、产生幻觉或输出不允许的内容，损害安全性和信任度。

- **Sensitive Data Disclosure**：模型泄露训练数据或用户上下文中的私人或机密信息，违反隐私要求和法规。

- **Inferred Sensitive Data**：模型推断出从未提供过的个人属性，通过推断造成新的隐私危害。

- **Insecure Model Output**：未经清理的响应将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：自主集成的 agent 在缺乏充分用户监督的情况下，执行非预期的现实操作（写入文件、调用 API、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的框架，用于理解和缓解 AI 系统相关风险。它对攻击者可能针对 AI 模型使用的各种攻击技术和策略进行分类，也介绍了如何利用 AI 系统实施不同攻击。<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取有效的 session token 或 cloud API 凭据，未经授权调用付费的 cloud-hosted LLM。攻击者通常通过反向代理转售访问权限，由代理转发受害者账户的请求，例如“oai-reverse-proxy”部署。其后果包括经济损失、违反政策滥用模型，以及将活动归因于受害者租户。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- 从受感染的开发者机器或浏览器中收集 token；窃取 CI/CD secrets；购买 leaked cookies。<sup>[[5]](#references)</sup>
- 搭建反向代理，将请求转发给真实的服务提供商，以隐藏上游 key 并为多个客户复用连接。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 滥用直接的 base-model endpoint，以绕过企业防护措施和速率限制。<sup>[[4]](#references)</sup>

缓解措施：
- 将 token 绑定到设备指纹、IP 范围和客户端证明；设置较短的有效期，并通过 MFA 刷新。
- 将 key 的权限范围限制在最低限度（不授予 tool 访问权限；适用时设为只读）；发现异常时轮换 key。
- 让所有流量都经由服务器端的 policy gateway 处理，由其执行安全过滤、按路由配额和租户隔离。
- 监控异常使用模式（支出突然激增、区域异常、UA 字符串异常），并自动撤销可疑 session。
- 优先使用 mTLS 或由 IdP 签发的 signed JWT，而不是长期有效的静态 API key。

## Self-hosted LLM inference hardening

为机密数据运行本地 LLM server，与使用 cloud-hosted API 相比会带来不同的攻击面：inference/debug endpoint 可能泄露 prompt，服务栈通常会暴露反向代理，而 GPU 设备节点则提供了大量 `ioctl()` 攻击面。如果你正在评估或部署本地 inference 服务，至少应检查以下几点。<sup>[[8]](#references)</sup>

### 通过 debug 和 monitoring endpoint 导致 Prompt leak

将 inference API 视为**多用户敏感服务**。Debug 或 monitoring 路由可能暴露 prompt 内容、slot 状态、模型元数据或内部队列信息。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它会暴露每个 slot 的状态，且仅用于 slot 检查/管理。<sup>[[8]](#references)</sup>

如需对暴露的模型 runner 和相关 AI 服务进行黑盒指纹识别和测试，请查看 [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)。

- 在 inference server 前部署反向代理，并**默认拒绝**请求。
- 仅允许客户端/UI 所需的确切 HTTP 方法 + 路径组合。
- 尽可能在后端本身禁用 introspection endpoint，例如 `llama-server --no-slots`。<sup>[[9]](#references)</sup>
- 将反向代理绑定到 `127.0.0.1`，并通过经过身份验证的传输方式（例如 SSH 本地端口转发）访问，而不是将其暴露在 LAN 上。

使用 nginx 配置 allowlist 的示例：

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

### 无网络且使用 UNIX 套接字的无 root 容器

如果推理 daemon 支持监听 UNIX 套接字，优先使用它而不是 TCP，并在无网络堆栈的情况下运行容器：<sup>[[8]](#references)</sup>

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
- `--network none` 移除入站/出站 TCP/IP 暴露，并避免使用 rootless 容器原本需要的用户模式辅助程序。
- UNIX socket 允许你在 socket 路径上使用 POSIX 权限/ACL，作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可降低容器逃逸的影响，因为容器 root 并非主机 root。
- 只读模型挂载可降低从容器内部篡改模型的可能性。

对于持久化部署，可以使用 Podman Quadlet units 表达相同的限制。如果通过 Container Device Interface 委派 GPU 访问权限，应尽可能缩小 CDI 设备规范的范围，而不是暴露所有加速器节点。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU 设备节点最小化

对于 GPU 支持的推理，`/dev/nvidia*` 文件属于高价值本地攻击面，因为它们暴露了大型驱动程序 `ioctl()` 处理程序，以及可能共享的 GPU 内存管理路径。<sup>[[8]](#references)</sup>

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev rules 和 ACL 限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，确保只有映射后的容器 UID 才能打开这些设备。
- 在无头推理主机上，将 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem` 等不必要的模块加入黑名单。
- 在启动时仅预加载必需的模块，而不是让 runtime 在推理启动期间临时运行 `modprobe`。

示例：

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

一个重要的审查点是 **`/dev/nvidia-uvm`**。即使工作负载没有显式使用 `cudaMallocManaged()`，较新的 CUDA runtime 仍可能需要 `nvidia-uvm`。由于此设备由多个租户共享，且负责 GPU 虚拟内存管理，应将其视为跨租户数据暴露面。如果 inference backend 支持，Vulkan backend 可能是一个值得考虑的折衷方案，因为它或许能完全避免向容器暴露 `nvidia-uvm`。<sup>[[8]](#references)</sup>

### 对 inference worker 进行 LSM 限制

应使用 AppArmor/SELinux/seccomp 对 inference 进程实施纵深防御：<sup>[[8]](#references)</sup>

- 仅允许实际所需的共享库、模型路径、socket 目录和 GPU 设备节点。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险 capabilities。
- 将模型目录设为只读，并将可写路径限制为 runtime socket/cache 目录。
- 监控拒绝日志，因为当 model server 或 post-exploitation payload 试图逃逸预期行为时，这些日志可提供有用的检测遥测数据。

GPU 支持型 worker 的 AppArmor 规则示例：

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

Phantom squatting 是 **slopsquatting 在域名/URL 层面的对应形式**。LLM 不再是幻觉出一个不存在的 package 名称，而是为真实品牌幻觉出一个看似合理的**门户、API、webhook、billing、SSO、下载或支持域名**，攻击者则在人或 agent 使用它之前抢先注册该域名空间。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

这很重要，因为在许多 AI 辅助工作流中，模型输出会被视为**可信依赖项**：
- 开发者会将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agent 会自动获取文档、schemas、APK、ZIP 或 webhook 目标。
- 生成的 runbook 或文档可能会嵌入伪造 URL，并将其当作权威来源。

### Offensive workflow

1. **探测幻觉面**：针对品牌提出与真实工作流相关的问题，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` 门户。<sup>[[12]](#references)</sup>
2. **规范化候选项**：解析生成的 URL，将 NXDOMAIN 响应归并到可注册的父域名，并对 prompt 系列去重。Prompt 语料应保持多样性，例如使用 **Jaccard 相似度**去除近似重复项。
3. **优先处理可预测的幻觉**：
   - **Thermal Hallucination Persistence (THP)**：同一个伪造域名在不同 temperature 下反复出现，包括 `T=0.1` 这样的低 temperature。
   - **跨模型共识**：多个 LLM 系列生成相同的伪造域名。
4. **注册并武器化**父域名，然后托管 phishing 页面、伪造的 APK/ZIP 下载、凭据窃取程序、恶意文档，或用于收集 secrets/webhook payload 的 API endpoint。**纯域名级幻觉**最容易变现，因为攻击者控制整个域名空间；如果规范化后的父域名尚未注册，子域名/路径幻觉仍可被滥用。
5. **利用零信誉窗口**：新注册的域名通常没有 blocklist 历史、URL 信誉记录或成熟的 telemetry，因此在检测机制跟上之前可能绕过防护。攻击者可以通过仅向 crawler 返回良性响应、redirect cloaking、CAPTCHA 闸门或延迟部署 payload 来延长这个窗口。

### 为什么这对 agent 很危险

对于人类受害者，伪造域名通常仍需要一次点击和后续操作。对于 **agentic workflow**，LLM 既可以充当**诱饵**，也可以充当**执行者**：agent 收到幻觉出的 URL 后会获取该 URL、解析响应，随后可能 leak tokens、执行指令、下载依赖项，或在没有任何人工审核的情况下将投毒数据推送到 CI/CD。<sup>[[12]](#references)</sup>

### 实用的攻击者 prompts

高收益 prompts 通常看起来像普通的企业任务，而不是明确的 phishing 诱饵：<sup>[[12]](#references)</sup>
- “`<brand>` 集成的 payment sandbox URL 是什么？”
- “我应该使用哪个 webhook endpoint 来接收 `<brand>` 的 build 通知？”
- “`<brand>` 的员工 benefits / billing / SSO 门户在哪里？”
- “给我 `<brand>` 的 Android APK 或桌面客户端直链下载地址。”

### 防御性逆向措施

应将此问题视为主动域名监控问题，而不只是 prompt-injection 问题：<sup>[[12]](#references)</sup>
- 建立**品牌 prompt 语料**，并定期探测用户/agent 所依赖的 LLM。
- 保存幻觉出的 URL，并追踪哪些 URL 在不同 temperature/model 下保持稳定。
- 追踪 **Adversarial Exploitation Window (AEW)**：从首次出现幻觉到攻击者注册域名之间的时间。正值 AEW 表示防御者可以在域名被武器化前预先注册、sinkhole 或预先阻止它。
- 监控父域名从 **NXDOMAIN → 已注册**的变化。
- 域名注册后，检查 registrar、创建日期、nameserver、隐私保护、页面内容、截图、停放页面状态以及与品牌资产的相似度，并进行分类处置。
- 添加策略闸门，确保 agent/developer **不会默认信任 LLM 生成的域名**：首次使用前要求使用 allowlist、验证所有权、进行 CT/RDAP 检查，或取得人工批准。

这同时涉及多个 AI 风险类别：**AI 供应链攻击**、**不安全的模型输出**，以及 agent 自主使用幻觉 URL 时产生的**失控行为**。

## References

- [1] [OWASP 机器学习十大漏洞](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – 风险](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 威胁矩阵](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLM 的风险：有害内容、滥用与欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking：被盗的云凭据被用于新型 AI 攻击](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking 方案概述 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（转售被盗的 LLM 访问权限）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - 深入分析本地部署低权限 LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets：podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) 规范](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting：AI 幻觉域名作为软件供应链攻击向量](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting：AI 幻觉如何助长新型供应链攻击](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
