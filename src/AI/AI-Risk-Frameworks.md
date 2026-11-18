# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 机器学习漏洞

Owasp 已识别出可能影响 AI 系统的十大机器学习漏洞。这些漏洞可能引发各种安全问题，包括数据投毒、模型反演和对抗性攻击。了解这些漏洞对于构建安全的 AI 系统至关重要。

如需查看最新且详细的十大机器学习漏洞清单，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**：攻击者对**输入数据**进行细微且往往不可见的修改，使模型做出错误决策。\
    *示例*：在停车标志上喷几处小小的漆点，就能欺骗自动驾驶汽车将其“识别”为限速标志。

- **Data Poisoning Attack**：故意污染**训练集**，用有害规则误导模型。\
*示例*：在防病毒软件的训练语料中，将恶意软件二进制文件标记为“良性”，使类似恶意软件之后得以绕过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**逆向模型**，以重建原始输入中的敏感特征。\
*示例*：根据癌症检测模型的预测结果，重建患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过观察置信度差异，判断某条**特定记录**是否被用于训练。\
*示例*：确认某人的银行交易是否出现在欺诈检测模型的训练数据中。

- **Model Theft**：反复查询使攻击者能够学习决策边界，并**克隆模型的行为**（及其 IP）。\
*示例*：从 ML-as-a-Service API 收集足够多的问答对，构建一个几乎等效的本地模型。

- **AI Supply-Chain Attack**：入侵**ML pipeline**中的任意组件（数据、库、预训练权重、CI/CD），以破坏下游模型。\
*示例*：模型中心中的投毒依赖项安装了带后门的情感分析模型，并将其传播到许多应用中。

- **Transfer Learning Attack**：将恶意逻辑植入**预训练模型**，使其在针对受害者任务进行微调后仍然存在。\
*示例*：带有隐藏触发器的视觉骨干网络，在适配用于医学影像后仍会翻转标签。

- **Model Skewing**：有偏或标记错误的数据会悄然**改变模型输出**，使其有利于攻击者的目的。\
*示例*：注入标记为 ham 的“干净”垃圾邮件，使垃圾邮件过滤器放过之后出现的类似邮件。

- **Output Integrity Attack**：攻击者在传输过程中**篡改模型预测**，而不是修改模型本身，从而欺骗下游系统。\
*示例*：在文件隔离阶段接收到结果之前，将恶意软件分类器的“恶意”判定改为“良性”。

- **Model Poisoning** --- 直接、有针对性地更改**模型参数**本身，通常是在获得写入权限后实施，以改变模型行为。\
*示例*：在生产环境中调整欺诈检测模型的权重，使某些银行卡的交易始终获批。


## Google SAIF 风险

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：<sup>[[2]](#references)</sup>

- **Data Poisoning**：恶意行为者更改或注入训练/调优数据，以降低准确性、植入后门或扭曲结果，从而破坏整个数据生命周期中的模型完整性。

- **Unauthorized Training Data**：摄入受版权保护、敏感或未经许可的数据集会带来法律、伦理和性能方面的风险，因为模型会从未获准使用的数据中学习。

- **Model Source Tampering**：供应链或内部人员在训练之前或期间篡改模型代码、依赖项或权重，可能植入即使重新训练后仍会存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，增加数据暴露和合规风险。

- **Model Exfiltration**：攻击者窃取模型文件/权重，导致知识产权损失，并使仿制服务或后续攻击成为可能。

- **Model Deployment Tampering**：攻击者修改模型产物或服务基础设施，使运行中的模型与经过审查的版本不同，进而可能改变模型行为。

- **Denial of ML Service**：通过 API 洪泛或发送“sponge”输入耗尽计算资源/能源并使模型离线，类似于传统 DoS 攻击。

- **Model Reverse Engineering**：攻击者通过收集大量输入-输出对来克隆或蒸馏模型，助长仿制产品和定制化对抗性攻击。

- **Insecure Integrated Component**：存在漏洞的插件、代理或上游服务会使攻击者能够在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：通过直接或间接构造提示词来夹带指令，覆盖系统意图，使模型执行非预期命令。

- **Model Evasion**：精心设计的输入会触发模型错误分类、产生幻觉或输出不允许的内容，削弱安全性和信任度。

- **Sensitive Data Disclosure**：模型泄露训练数据或用户上下文中的私人或机密信息，违反隐私要求和法规。

- **Inferred Sensitive Data**：模型推断出用户从未提供的个人属性，因推理而造成新的隐私损害。

- **Insecure Model Output**：未经清理的响应将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：自主集成的代理在缺乏充分用户监督的情况下执行非预期的现实操作（写入文件、调用 API、进行购买等）。

## Mitre AI ATLAS 矩阵

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的框架，用于理解和缓解与 AI 系统相关的风险。该矩阵对攻击者可能针对 AI 模型使用的各种攻击技术和战术进行分类，也涵盖了如何利用 AI 系统执行不同的攻击。<sup>[[3]](#references)</sup>

## LLMJacking（窃取 Token 并转售云托管 LLM 的访问权限）

攻击者窃取有效的会话 Token 或云 API 凭据，未经授权调用付费的云托管 LLM。攻击者通常通过反向代理转售访问权限，由代理使用受害者的账户提供服务，例如部署“oai-reverse-proxy”。后果包括经济损失、违反政策使用模型，以及相关活动被归因于受害者租户。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs：
- 从受感染的开发人员计算机或浏览器中收集 Token；窃取 CI/CD 密钥；购买泄露的 cookie。<sup>[[5]](#references)</sup>
- 搭建反向代理，将请求转发给真正的服务提供商，隐藏上游密钥，并为多个客户复用该密钥。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 滥用直接的基础模型端点，以绕过企业防护措施和速率限制。<sup>[[4]](#references)</sup>

**在主机内复用 API key：**主机遭入侵后，植入程序可以直接从受害者主机发送模型 API 请求，并通过 C2 转发响应，而无需导出云 API key 或启动本地 AI CLI。在观察到的处理程序中，C2 提供的 key 优先级更高；只有在不存在该 key 时，植入程序才会从其自身进程环境中读取 `OPENAI_API_KEY`。因此，要使用受害者账户，必须有该进程可见的有效 key，并且能够访问模型 API。操作员的提示词会发送到 Chat Completions API，而模型输出和 Token 用量则通过 C2 返回。这样，即使不运行开发人员的 AI 工具，也可能消耗受害者付费的模型访问额度；这不同于 [本地 AI CLI 或 MCP 配置滥用](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md)。<sup>[[14]](#references)</sup>

缓解措施：
- 将 Token 绑定到设备指纹、IP 范围和客户端证明；设置较短的有效期，并通过 MFA 刷新。
- 将 key 的权限范围限制到最低（不授予工具访问权限；适用时设为只读）；出现异常时轮换 key。
- 将所有流量置于服务器端策略网关之后，由网关执行安全过滤、按路由配额控制和租户隔离。
- 监控异常使用模式（支出突然激增、区域异常、UA 字符串异常），并自动撤销可疑会话。
- 优先使用由 IdP 签发的 mTLS 或签名 JWT，而不是长期有效的静态 API key。

## 加固自托管 LLM 推理服务

为机密数据运行本地 LLM 服务器，其攻击面不同于云托管 API：推理/调试端点可能泄露提示词，服务堆栈通常会暴露反向代理，而 GPU 设备节点可访问大量 `ioctl()` 接口。如果你正在评估或部署本地推理服务，至少应检查以下事项。<sup>[[8]](#references)</sup>

### 通过调试和监控端点泄露提示词

将推理 API 视为**多用户敏感服务**。调试或监控路由可能暴露提示词内容、slot 状态、模型元数据或内部队列信息。在 `llama.cpp` 中，`/slots` 端点尤其敏感，因为它会暴露每个 slot 的状态，且仅用于 slot 检查/管理。<sup>[[8]](#references)</sup>

如需对暴露的模型运行器及相关 AI 服务进行黑盒指纹识别和测试，请参阅 [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)。

- 在推理服务器前部署反向代理，并**默认拒绝**访问。
- 仅将客户端/UI 所需的确切 HTTP 方法 + 路径组合列入允许列表。
- 尽可能在后端本身禁用内省端点，例如使用 `llama-server --no-slots`。<sup>[[9]](#references)</sup>
- 将反向代理绑定到 `127.0.0.1`，并通过 SSH 本地端口转发等经过身份验证的传输方式访问，而不是将其暴露在 LAN 上。

nginx 允许列表示例：

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

### 无网络和 UNIX 套接字的 Rootless 容器

如果推理守护进程支持监听 UNIX 套接字，请优先使用该方式而非 TCP，并在运行容器时**不启用网络栈**：<sup>[[8]](#references)</sup>

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
- `--network none` 会移除入站/出站 TCP/IP 暴露，并避免使用 rootless 容器原本需要的用户模式辅助程序。
- UNIX socket 允许你在 socket 路径上使用 POSIX 权限/ACL，作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可降低容器逃逸的影响，因为容器 root 并非主机 root。
- 只读模型挂载可降低从容器内部篡改模型的可能性。

对于持久化部署，可以通过 Podman Quadlet 单元表达相同的限制。如果通过 Container Device Interface 委派 GPU 访问，应尽可能缩小 CDI 设备规范的范围，而不是暴露所有加速器节点。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### 尽量减少 GPU 设备节点

对于 GPU 推理，`/dev/nvidia*` 文件是高价值的本地攻击面，因为它们暴露了大量驱动 `ioctl()` 处理程序，以及可能共享的 GPU 内存管理路径。<sup>[[8]](#references)</sup>

- 不要让 `/dev/nvidia*` 对所有用户开放写权限。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev 规则和 ACL 限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，确保只有映射后的容器 UID 可以打开这些设备。
- 在无头推理主机上，将 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem` 等不必要的模块列入黑名单。
- 在启动时仅预加载必需模块，而不是让运行时在推理启动期间临时执行 `modprobe`。

示例：

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

一个重要的审查点是 **`/dev/nvidia-uvm`**。即使工作负载没有显式使用 `cudaMallocManaged()`，较新的 CUDA 运行时仍可能需要 `nvidia-uvm`。由于此设备由多个租户共享，并负责 GPU 虚拟内存管理，应将其视为跨租户数据暴露面。如果推理后端支持，Vulkan 后端可能是一种值得考虑的权衡，因为它或许可以完全避免向容器暴露 `nvidia-uvm`。<sup>[[8]](#references)</sup>

### 推理工作进程的 LSM 限制

应使用 AppArmor/SELinux/seccomp 为推理进程提供纵深防御：<sup>[[8]](#references)</sup>

- 仅允许实际必需的共享库、模型路径、套接字目录和 GPU 设备节点。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险 capability。
- 将模型目录设为只读，并将可写路径限定为运行时套接字/缓存目录。
- 监控拒绝日志，因为当模型服务器或 post-exploitation payload 尝试逃逸预期行为时，这些日志可提供有用的检测遥测数据。

GPU 支持型工作进程的 AppArmor 规则示例：

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

Phantom squatting 是 **slopsquatting 的域名/URL 等价形式**。LLM 不再是幻觉生成不存在的软件包名称，而是为真实品牌幻觉生成看似合理的 **门户、API、webhook、计费、SSO、下载或支持域名**，攻击者则在人类或 agent 使用该域名前注册该命名空间。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

这很重要，因为在许多 AI 辅助工作流中，模型输出会被视为 **可信依赖项**：
- 开发人员会将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agents 会自动获取文档、schema、APK、ZIP 或 webhook 目标。
- 生成的运行手册或文档可能会嵌入伪造 URL，并将其当作权威来源。

### 攻击工作流

1. **探测幻觉面**：针对品牌提出与真实工作流相关的问题，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` 门户。<sup>[[12]](#references)</sup>
2. **规范化候选项**：解析生成的 URL，将 NXDOMAIN 响应归并到父级可注册域名，并对 prompt 类别去重。Prompt 语料应保持多样化，例如使用 **Jaccard 相似度**剔除近似重复项。
3. **优先处理可预测的幻觉**：
   - **Thermal Hallucination Persistence (THP)**：同一伪造域名会在不同温度下出现，包括 `T=0.1` 这样的低温度。
   - **跨模型共识**：多个 LLM 系列生成相同的伪造域名。
4. **注册并武器化**父域名，然后托管钓鱼页面、伪造 APK/ZIP 下载、凭据收集工具、恶意文档，或用于收集机密/webhook 负载的 API endpoint。**纯域名级幻觉**最容易变现，因为攻击者控制整个命名空间；若规范化后的父域名尚未注册，子域名/路径幻觉仍可能被滥用。
5. **利用零信誉窗口**：新注册域名通常没有封锁列表记录、URL 信誉数据和成熟的遥测信息，因此在检测机制跟上之前可能绕过安全控制。攻击者可通过仅向爬虫返回无害内容、重定向 cloaking、CAPTCHA 验证或延迟投放 payload 来延长这一窗口。

### 为什么这对 agents 很危险

对于人类受害者，伪造域名通常仍需要用户点击并执行后续操作。而在 **agentic 工作流**中，LLM 既可能是 **诱饵**，也可能是 **执行者**：agent 收到幻觉生成的 URL 后会获取该 URL、解析响应，随后可能在没有任何人工审核的情况下 leak tokens、执行指令、下载依赖项，或将投毒数据推送到 CI/CD 中。<sup>[[12]](#references)</sup>

### 实用攻击者 prompts

高收益 prompts 通常伪装成普通企业任务，而非明显的钓鱼诱饵：<sup>[[12]](#references)</sup>
- “`<brand>` 集成的支付 sandbox URL 是什么？”
- “`<brand>` 的构建通知应该使用哪个 webhook endpoint？”
- “`<brand>` 的员工福利 / 计费 / SSO 门户在哪里？”
- “提供 `<brand>` 的 Android APK 或桌面客户端直连下载地址。”

### 防御性反转

应将此问题视为主动域名监控问题，而不仅仅是 prompt injection 问题：<sup>[[12]](#references)</sup>
- 建立 **品牌 prompt 语料**，并定期探测用户/agents 依赖的 LLM。
- 保存幻觉生成的 URL，并跟踪它们在不同温度/模型下的稳定性。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次出现幻觉到攻击者注册域名之间的时间。AEW 为正值意味着防御者可在域名被武器化之前预先注册、sinkhole 或预先封锁。
- 监控父域名从 **NXDOMAIN → 已注册** 的状态变化。
- 注册后，检查注册商、创建日期、nameserver、隐私保护、页面内容、屏幕截图、停放页状态以及与品牌资产的相似度。
- 添加策略关卡，确保 agents/开发人员 **默认不信任 LLM 生成的域名**：首次使用前要求检查 allowlist、验证所有权、执行 CT/RDAP 检查，或获得人工批准。

这同时属于多个 AI 风险类别：**AI 供应链攻击**、**不安全的模型输出**，以及 agents 自主使用幻觉 URL 时产生的 **rogue actions**。

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP 机器学习十大漏洞](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF（安全 AI 框架）——风险](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 威胁矩阵](https://atlas.mitre.org/)
- [4] [Unit 42——代码助手 LLM 的风险：有害内容、滥用与欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig——LLMjacking：被盗云凭据被用于新型 AI 攻击](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMjacking 方案概述——The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（转售被盗的 LLM 访问权限）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv——深入解析低权限本地 LLM 服务器的部署](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets：podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) 规范](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42——Phantom Squatting：AI 幻觉域名作为软件供应链攻击向量](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket——Slopsquatting：AI 幻觉如何助长新型供应链攻击](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos——NIK C2：新型 AI 驱动的命令与控制框架](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
