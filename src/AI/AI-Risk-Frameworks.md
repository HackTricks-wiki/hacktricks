# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP 已确定可能影响 AI 系统的十大机器学习漏洞。这些漏洞可能导致各种安全问题，包括数据投毒、模型反演和对抗性攻击。了解这些漏洞对于构建安全的 AI 系统至关重要。

有关最新且详细的十大机器学习漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**：攻击者对**输入数据**添加微小且通常不可见的改动，诱使模型做出错误判断。\
    *示例*：在停车标志上涂几个小点，就能让自动驾驶汽车把它“看成”限速标志。

- **Data Poisoning Attack**：故意污染**训练集**，加入恶意样本，从而教会模型有害的规则。\
*示例*：在杀毒软件训练语料中，将恶意软件二进制文件标记为“良性”，使类似恶意软件之后得以绕过检测。

- **Model Inversion Attack**：通过探测模型输出，攻击者构建一个**反向模型**，以重建原始输入中的敏感特征。\
*示例*：根据癌症检测模型的预测结果，重新生成患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过观察置信度差异，测试**某条特定记录**是否用于训练。\
*示例*：确认某人的银行交易记录是否出现在欺诈检测模型的训练数据中。

- **Model Theft**：通过反复查询，攻击者可以了解决策边界，并**克隆模型的行为**（及其 IP）。\
*示例*：从 ML-as-a-Service API 获取足够多的问答对，构建一个几乎等效的本地模型。

- **AI Supply-Chain Attack**：攻击者入侵**ML pipeline**中的任一组件（数据、库、预训练权重、CI/CD），以破坏下游模型。\
*示例*：模型中心中的一个被投毒依赖项，导致多个应用安装带有后门的情感分析模型。

- **Transfer Learning Attack**：在**预训练模型**中植入恶意逻辑，使其在针对受害者任务进行微调后仍然存在。\
*示例*：带有隐藏触发器的视觉 backbone，在适配用于医学影像后仍会翻转标签。

- **Model Skewing**：存在细微偏差或错误标记的数据会**改变模型输出**，使其偏向攻击者的目的。\
*示例*：注入被标记为 ham 的“干净”垃圾邮件，让垃圾邮件过滤器放过之后类似的邮件。

- **Output Integrity Attack**：攻击者**在传输过程中篡改模型预测**，而非修改模型本身，从而欺骗下游系统。\
*示例*：在恶意软件分类器的“恶意”判定到达文件隔离阶段之前，将其篡改为“良性”。

- **Model Poisoning** --- 直接、有针对性地修改**模型参数**本身，通常是在获得写入权限后进行，以改变模型行为。\
*示例*：在生产环境中调整欺诈检测模型的权重，使某些银行卡的交易始终获得批准。


## Google SAIF 风险

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了 AI 系统相关的各种风险：<sup>[[2]](#references)</sup>

- **Data Poisoning**：恶意行为者修改或注入训练/调优数据，以降低准确率、植入后门或扭曲结果，从而破坏整个数据生命周期中的模型完整性。

- **Unauthorized Training Data**：摄入受版权保护、敏感或未经许可的数据集会带来法律、道德和性能方面的责任，因为模型会从未经授权使用的数据中学习。

- **Model Source Tampering**：在训练前或训练过程中，通过供应链或内部人员篡改模型代码、依赖项或权重，可能植入即使重新训练后仍然存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的数据保留和治理控制会导致系统存储或处理超出必要范围的个人数据，从而增加数据暴露和合规风险。

- **Model Exfiltration**：攻击者窃取模型文件/权重，导致知识产权损失，并使其能够开发仿冒服务或发动后续攻击。

- **Model Deployment Tampering**：攻击者修改模型工件或服务基础设施，使运行中的模型不同于经审查的版本，进而可能改变其行为。

- **Denial of ML Service**：攻击者通过向 API 洪泛请求或发送“海绵”输入，耗尽计算资源/能源并使模型离线，这与传统 DoS 攻击类似。

- **Model Reverse Engineering**：攻击者通过收集大量输入-输出对，克隆或蒸馏模型，助长仿制产品的开发和定制化对抗性攻击。

- **Insecure Integrated Component**：存在漏洞的插件、代理或上游服务，会让攻击者得以在 AI pipeline 中注入代码或提升权限。

- **Prompt Injection**：通过直接或间接构造提示词，夹带指令以覆盖系统意图，诱使模型执行非预期命令。

- **Model Evasion**：精心设计的输入会诱使模型错误分类、产生幻觉或输出不允许的内容，削弱安全性和信任度。

- **Sensitive Data Disclosure**：模型泄露训练数据或用户上下文中的私人或机密信息，违反隐私保护和法规要求。

- **Inferred Sensitive Data**：模型推断出从未提供过的个人属性，通过推断造成新的隐私危害。

- **Insecure Model Output**：未经清理的响应将有害代码、错误信息或不当内容传递给用户或下游系统。

- **Rogue Actions**：自主集成的代理在缺乏充分用户监督的情况下，执行非预期的现实操作（写入文件、调用 API、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的框架，用于了解和缓解 AI 系统相关风险。该框架对攻击者可能针对 AI 模型使用的各种攻击技术和战术进行分类，也介绍了如何利用 AI 系统执行不同攻击。<sup>[[3]](#references)</sup>

## LLMJacking（Token 窃取与云托管 LLM 访问权限转售）

攻击者窃取有效的会话 token 或云 API 凭据，未经授权调用付费的云托管 LLM。攻击者通常会通过代理受害者账户的反向代理转售访问权限，例如部署“oai-reverse-proxy”。其后果包括经济损失、违反策略滥用模型，以及相关活动被归因到受害者租户。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- 从受感染的开发者设备或浏览器中窃取 token；窃取 CI/CD 密钥；购买泄露的 cookie。<sup>[[5]](#references)</sup>
- 搭建反向代理，将请求转发给正版服务提供商，以隐藏上游密钥并为多个客户复用连接。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 滥用直接的基础模型端点，绕过企业防护措施和速率限制。<sup>[[4]](#references)</sup>

缓解措施：
- 将 token 绑定到设备指纹、IP 范围和客户端证明；设置较短的有效期，并通过 MFA 刷新。
- 将密钥权限限制在最低限度（不授予工具访问权限；适用时设为只读）；发现异常时轮换密钥。
- 将所有流量置于服务端策略网关之后，由其实施安全过滤、按路由设置配额以及租户隔离。
- 监控异常使用模式（支出突然激增、异常地区、UA 字符串），并自动撤销可疑会话。
- 优先使用 mTLS 或由 IdP 签发的签名 JWT，而不是长期有效的静态 API 密钥。

## 加固自托管 LLM 推理

本地运行 LLM 服务器处理机密数据，其攻击面不同于云托管 API：推理/调试端点可能泄露提示词，服务栈通常会暴露反向代理，而 GPU 设备节点则提供了大量 `ioctl()` 攻击面。如果你正在评估或部署本地推理服务，至少应检查以下几点。<sup>[[8]](#references)</sup>

### 通过调试和监控端点泄露提示词

应将推理 API 视为**多用户敏感服务**。调试或监控路由可能泄露提示词内容、slot 状态、模型元数据或内部队列信息。在 `llama.cpp` 中，`/slots` 端点尤其敏感，因为它会暴露每个 slot 的状态，且仅用于 slot 检查/管理。<sup>[[8]](#references)</sup>

- 在推理服务器前部署反向代理，并**默认拒绝**访问。
- 仅将客户端/UI 必需的精确 HTTP 方法 + 路径组合加入允许列表。
- 尽可能在后端本身禁用内省端点，例如 `llama-server --no-slots`。<sup>[[9]](#references)</sup>
- 将反向代理绑定到 `127.0.0.1`，并通过经过身份验证的传输方式（例如 SSH 本地端口转发）访问，而不要将其发布到 LAN。

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

### 无网络和 UNIX 套接字的无根容器

如果推理守护进程支持监听 UNIX 套接字，优先使用它而非 TCP，并以**无网络栈**运行容器：<sup>[[8]](#references)</sup>

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
- `--network none` 移除入站/出站 TCP/IP 暴露，并避免使用 rootless 容器原本需要的 user-mode helpers。
- UNIX socket 允许你使用 socket 路径上的 POSIX 权限/ACLs，作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可降低容器逃逸的影响，因为容器 root 并非主机 root。
- 只读模型挂载可降低从容器内部篡改模型的可能性。

对于持久化部署，可以使用 Podman Quadlet units 表达相同的限制。如果通过 Container Device Interface 委派 GPU 访问，应尽可能缩小 CDI 设备规格的范围，而不是暴露每个加速器节点。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### 最小化 GPU 设备节点

对于基于 GPU 的推理，`/dev/nvidia*` 文件是高价值的本地攻击面，因为它们暴露了大型驱动程序 `ioctl()` 处理程序，以及可能共享的 GPU 内存管理路径。<sup>[[8]](#references)</sup>

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev 规则和 ACLs 限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，确保只有映射后的容器 UID 才能打开它们。
- 在无头推理主机上，将 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem` 等不必要的模块列入黑名单。
- 启动时仅预加载必需的模块，而不是让运行时在推理启动期间临时执行 `modprobe`。

示例：

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

一个重要的审查点是 **`/dev/nvidia-uvm`**。即使工作负载没有显式使用 `cudaMallocManaged()`，较新的 CUDA 运行时仍可能需要 `nvidia-uvm`。由于此设备由多个租户共享并负责 GPU 虚拟内存管理，应将其视为跨租户数据暴露面。如果推理后端支持，Vulkan 后端可能是一个值得考虑的折衷方案，因为它可能完全避免向容器暴露 `nvidia-uvm`。<sup>[[8]](#references)</sup>

### 推理 worker 的 LSM 限制

应使用 AppArmor/SELinux/seccomp 为推理进程提供纵深防御：<sup>[[8]](#references)</sup>

- 仅允许实际所需的共享库、模型路径、socket 目录和 GPU 设备节点。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险能力。
- 将模型目录设为只读，并仅允许 runtime socket/cache 目录可写。
- 监控拒绝日志，因为当模型服务器或 post-exploitation payload 尝试逃离预期行为时，这些日志可提供有用的检测遥测数据。

GPU worker 的 AppArmor 规则示例：

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

Phantom squatting 是 **slopsquatting 的域名/URL 等价形式**。LLM 不再是幻觉出一个不存在的包名，而是为真实品牌幻觉出一个看似合理的**门户、API、webhook、账单、SSO、下载或支持域名**，攻击者则在人类或 agent 使用它之前注册该域名。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

这很重要，因为在许多 AI 辅助工作流中，模型输出会被当作**可信依赖项**：
- 开发者将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agent 自动获取文档、schema、APK、ZIP 或 webhook 目标。
- 生成的 runbook 或文档可能会嵌入伪造 URL，并将其当作权威来源。

### 攻击工作流

1. **探测幻觉面**：针对品牌提出与真实工作流相关的问题，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` 门户。<sup>[[12]](#references)</sup>
2. **规范化候选项**：解析生成的 URL，将 NXDOMAIN 响应归并到可注册的父域名，并对提示词系列去重。提示词语料应保持多样性，例如使用 **Jaccard similarity** 删除近似重复项。
3. **优先处理可预测的幻觉**：
   - **Thermal Hallucination Persistence (THP)**：同一个伪造域名在不同温度下反复出现，包括 `T=0.1` 这样的低温。
   - **跨模型共识**：多个 LLM 系列生成相同的伪造域名。
4. **注册并武器化**父域名，然后托管 phishing 页面、伪造的 APK/ZIP 下载、凭证收集器、恶意文档，或收集秘密/webhook 负载的 API endpoint。**纯域名级幻觉**最容易变现，因为攻击者控制整个命名空间；如果规范化后的父域名尚未注册，子域名/路径幻觉仍可被滥用。
5. **利用零信誉窗口**：新注册的域名通常缺少 blocklist 历史、URL 信誉数据和成熟的遥测，因此在检测跟进之前可能绕过防护。攻击者可以通过仅向 crawler 返回良性响应、redirect cloaking、CAPTCHA 门槛或延迟投放 payload 来延长这个窗口。

### 为什么这对 agent 很危险

对于人类受害者，伪造域名通常仍需要一次点击和后续操作。而在 **agentic workflow** 中，LLM 既可以充当**诱饵**，也可以充当**执行者**：agent 收到幻觉出的 URL 后会获取它、解析响应，接着可能泄露 token、执行指令、下载依赖项，或在无人审核的情况下将投毒数据推送到 CI/CD。<sup>[[12]](#references)</sup>

### 实用攻击者提示词

高收益提示词通常看起来像普通企业任务，而不是明确的 phishing 诱饵：<sup>[[12]](#references)</sup>
- “`<brand>` 集成的 payment sandbox URL 是什么？”
- “`<brand>` build 通知应使用哪个 webhook endpoint？”
- “`<brand>` 的员工福利 / 账单 / SSO 门户在哪里？”
- “给我 `<brand>` 的 Android APK 或桌面客户端直接下载链接。”

### 防御性反转

将其视为主动域名监控问题，而不仅仅是 prompt injection 问题：<sup>[[12]](#references)</sup>
- 构建**品牌提示词语料**，并定期探测用户/agent 所依赖的 LLM。
- 保存幻觉出的 URL，并跟踪它们在不同温度/模型下的稳定性。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次出现幻觉到攻击者注册域名的时间。AEW 为正意味着防御者可以在域名被武器化之前预先注册、sinkhole 或预先拦截。
- 监控父域名从 **NXDOMAIN → 已注册**的变化。
- 域名注册后，检查 registrar、创建日期、nameserver、隐私保护、页面内容、截图、停放页面状态，以及与品牌资产的相似度。
- 添加策略门控，确保 agent/开发者**默认不信任 LLM 生成的域名**：首次使用前要求通过 allowlist、所有权验证、CT/RDAP 检查或人工审批。

这同时符合多个 AI 风险类别：**AI 供应链攻击**、**不安全的模型输出**，以及 agent 自主使用幻觉 URL 时产生的**恶意行为**。

## References

- [1] [OWASP 机器学习十大漏洞](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF（Secure AI Framework）– 风险](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 威胁矩阵](https://atlas.mitre.org/)
- [4] [Unit 42 – 代码助手 LLM 的风险：有害内容、滥用和欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking：被盗云凭证被用于新的 AI 攻击](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMjacking 方案概述 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（转售被盗的 LLM 访问权限）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - 深入了解如何部署本地低权限 LLM 服务器](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets：podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) 规范](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting：AI 幻觉域名作为软件供应链攻击向量](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting：AI 幻觉如何助长新型供应链攻击](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
