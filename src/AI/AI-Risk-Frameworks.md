# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp 已确定可能影响 AI 系统的十大 machine learning vulnerabilities。这些 vulnerabilities 可能导致各种 security issues，包括 data poisoning、model inversion 和 adversarial attacks。了解这些 vulnerabilities 对构建 secure AI systems 至关重要。

如需查看更新且详细的十大 machine learning vulnerabilities 列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**：攻击者对**传入数据**添加微小且通常不可见的更改，使模型做出错误决策。\
*示例*：在 stop sign 上点缀几处油漆，就能欺骗自动驾驶汽车将其“看成”限速标志。

- **Data Poisoning Attack**：恶意污染**training set**，通过有害样本教会模型错误规则。\
*示例*：在 antivirus training corpus 中将 malware binaries 错误标记为“benign”，使类似 malware 之后得以绕过检测。

- **Model Inversion Attack**：通过探测输出，攻击者构建一个**reverse model**，重建原始输入中的敏感特征。\
*示例*：根据 cancer-detection model 的预测结果，重新创建患者的 MRI 图像。

- **Membership Inference Attack**：攻击者通过观察置信度差异，测试某条**特定记录**是否曾用于训练。\
*示例*：确认某人的 bank transaction 是否出现在 fraud-detection model 的 training data 中。

- **Model Theft**：反复查询使攻击者能够了解决策边界，并**克隆模型的行为**（以及 IP）。\
*示例*：从 ML-as-a-Service API 中收集足够多的问答对，构建一个近似等效的本地模型。

- **AI Supply-Chain Attack**：入侵**ML pipeline** 中的任意组件（data、libraries、pre-trained weights、CI/CD），以破坏下游模型。\
*示例*：model-hub 中被污染的 dependency 安装了带 backdoor 的 sentiment-analysis model，并扩散到多个应用。

- **Transfer Learning Attack**：将恶意逻辑植入**pre-trained model**，使其在受害者任务上进行 fine-tuning 后仍然存活。\
*示例*：带有隐藏 trigger 的 vision backbone 在适配 medical imaging 后仍会翻转 labels。

- **Model Skewing**：带有细微偏差或错误标记的数据**改变模型的输出**，使其偏向攻击者的目的。\
*示例*：注入被标记为 ham 的“clean” spam emails，使 spam filter 放行之后类似的邮件。

- **Output Integrity Attack**：攻击者**在传输过程中修改 model predictions**，而不是修改模型本身，从而欺骗下游系统。\
*示例*：在 file-quarantine stage 看到结果之前，将 malware classifier 的“malicious”判定翻转为“benign”。

- **Model Poisoning** --- 直接、有针对性地修改**model parameters** 本身，通常是在取得写入权限后改变其行为。\
*示例*：在生产环境中调整 fraud-detection model 的 weights，使来自特定 cards 的 transactions 始终获得批准。


## Google SAIF 风险

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI systems 相关的各种 risks：<sup>[[2]](#references)</sup>

- **Data Poisoning**：恶意行为者修改或注入 training/tuning data，以降低准确率、植入 backdoors 或扭曲结果，从而破坏整个 data-lifecycle 中的 model integrity。

- **Unauthorized Training Data**：摄入受版权保护、敏感或未经许可的 datasets，会产生法律、伦理和性能方面的 liabilities，因为模型从不被允许使用的数据中学习。

- **Model Source Tampering**：在 training 之前或期间对 model code、dependencies 或 weights 进行 supply-chain 或内部人员篡改，可能嵌入即使 retraining 后仍会存在的隐藏逻辑。

- **Excessive Data Handling**：薄弱的 data-retention 和 governance controls 导致系统存储或处理超出必要范围的 personal data，增加 exposure 和 compliance risk。

- **Model Exfiltration**：攻击者窃取 model files/weights，导致 intellectual property 损失，并支持 copy-cat services 或后续 attacks。

- **Model Deployment Tampering**：攻击者修改 model artifacts 或 serving infrastructure，使运行中的模型不同于经过审查的版本，从而可能改变其 behaviour。

- **Denial of ML Service**：通过 flooding APIs 或发送“sponge” inputs 耗尽 compute/energy，使模型离线，类似于经典的 DoS attacks。

- **Model Reverse Engineering**：通过收集大量 input-output pairs，攻击者可以克隆或 distil 模型，推动 imitation products 和定制化 adversarial attacks 的发展。

- **Insecure Integrated Component**：存在 vulnerabilities 的 plugins、agents 或 upstream services 允许攻击者在 AI pipeline 中注入 code 或提升 privileges。

- **Prompt Injection**：直接或间接构造 prompts，夹带覆盖 system intent 的 instructions，使模型执行非预期 commands。

- **Model Evasion**：精心设计的 inputs 触发模型进行错误分类、hallucinate 或输出被禁止的内容，削弱 safety 和 trust。

- **Sensitive Data Disclosure**：模型从 training data 或 user context 中泄露 private 或 confidential information，违反 privacy 和 regulations。

- **Inferred Sensitive Data**：模型推断从未提供过的个人属性，通过 inference 造成新的 privacy harms。

- **Insecure Model Output**：未经 sanitization 的 responses 将 harmful code、misinformation 或 inappropriate content 传递给 users 或下游 systems。

- **Rogue Actions**：集成到系统中的 autonomous agents 在没有充分 user oversight 的情况下执行非预期的现实操作（file writes、API calls、purchases 等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的 framework，用于理解和缓解与 AI systems 相关的 risks。它对 adversaries 可能针对 AI models 使用的各种 attack techniques 和 tactics 进行分类，同时也说明如何利用 AI systems 执行不同的 attacks。<sup>[[3]](#references)</sup>

## LLMJacking（Token Theft & Resale of Cloud-hosted LLM Access）

攻击者窃取 active session tokens 或 cloud API credentials，未经授权调用付费的 cloud-hosted LLMs。Access 通常通过位于受害者 account 前端的 reverse proxies 进行转售，例如“oai-reverse-proxy” deployments。后果包括 financial loss、违反政策的 model misuse，以及将相关活动归因于受害者 tenant。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs：
- 从受感染的 developer machines 或 browsers 中收集 tokens；窃取 CI/CD secrets；购买 leaked cookies。<sup>[[5]](#references)</sup>
- 搭建 reverse proxy，将 requests 转发到 genuine provider，同时隐藏 upstream key，并为多个 customers 进行 multiplexing。<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 滥用 direct base-model endpoints，以绕过 enterprise guardrails 和 rate limits。<sup>[[4]](#references)</sup>

缓解措施：
- 将 tokens 绑定到 device fingerprint、IP ranges 和 client attestation；设置较短的 expirations，并通过 MFA 进行 refresh。
- 尽量缩小 keys 的权限范围（不授予 tool access；适用时使用 read-only）；检测到异常时进行 rotation。
- 在 server-side 将所有 traffic 置于 policy gateway 后方，由其执行 safety filters、per-route quotas 和 tenant isolation。
- 监控异常的 usage patterns（spend 突然激增、异常 regions、UA strings），并自动 revoke 可疑 sessions。
- 优先使用由 IdP 签发的 mTLS 或 signed JWTs，而不是长期有效的 static API keys。

## Self-hosted LLM inference hardening

为 confidential data 运行 local LLM server，会形成不同于 cloud-hosted APIs 的 attack surface：inference/debug endpoints 可能 leak prompts，serving stack 通常会暴露 reverse proxy，而 GPU device nodes 则提供对大型 `ioctl()` surfaces 的访问。如果你正在评估或部署 on-prem inference service，至少应检查以下要点。<sup>[[8]](#references)</sup>

### 通过 debug 和 monitoring endpoints 泄露 prompt

将 inference API 视为**多用户敏感 service**。Debug 或 monitoring routes 可能暴露 prompt contents、slot state、model metadata 或内部 queue information。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它会暴露 per-slot state，并且只用于 slot inspection/management。<sup>[[8]](#references)</sup>

- 在 inference server 前放置 reverse proxy，并**默认拒绝**。
- 仅 allowlist client/UI 所需的准确 HTTP method + path combinations。
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
### 无网络和 UNIX socket 的 Rootless 容器

如果 inference daemon 支持监听 UNIX socket，优先使用它而不是 TCP，并以 **无网络栈** 运行容器：<sup>[[8]](#references)</sup>
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
- `--network none` 移除入站/出站 TCP/IP 暴露，并避免 rootless containers 原本需要的用户态 helper。
- UNIX socket 允许你在 socket 路径上使用 POSIX 权限/ACL，作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可降低 container breakout 的影响，因为 container root 并非 host root。
- 只读 model mounts 可降低从 container 内部篡改 model 的可能性。

对于持久化部署，可以通过 Podman Quadlet units 表达相同的限制。如果通过 Container Device Interface 委托 GPU 访问，应尽可能缩小 CDI device specification，而不是暴露每个 accelerator node。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node 最小化

对于 GPU-backed inference，`/dev/nvidia*` 文件属于高价值的本地攻击面，因为它们暴露了大型 driver `ioctl()` handlers，以及可能共享的 GPU memory-management paths。<sup>[[8]](#references)</sup>

- 不要让 `/dev/nvidia*` 对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev rules 和 ACL，限制 `nvidia`、`nvidiactl` 及 `nvidia-uvm`，使其只有映射后的 container UID 才能打开。
- 在 headless inference hosts 上 blacklist 不必要的 modules，例如 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem`。
- 在 boot 时仅 preload 必需的 modules，而不要让 runtime 在 inference startup 期间 opportunistically `modprobe` 它们。

示例：
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使 workload 没有显式使用 `cudaMallocManaged()`，近期的 CUDA runtimes 仍可能需要 `nvidia-uvm`。由于该设备是共享的，并负责 GPU virtual memory management，应将其视为 cross-tenant data-exposure surface。如果 inference backend 支持，Vulkan backend 可能是一个值得考虑的 trade-off，因为它可能完全避免将 `nvidia-uvm` 暴露给 container。<sup>[[8]](#references)</sup>

### inference workers 的 LSM confinement

应在 inference process 周围使用 AppArmor/SELinux/seccomp 进行 defense in depth：<sup>[[8]](#references)</sup>

- 仅允许实际需要的 shared libraries、model paths、socket directory 和 GPU device nodes。
- 明确拒绝 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace` 等高风险 capabilities。
- 将 model directory 保持为 read-only，并将可写 paths 限制为 runtime socket/cache directories。
- 监控 denial logs，因为当 model server 或 post-exploitation payload 尝试逃逸其预期 behaviour 时，这些日志能提供有用的 detection telemetry。

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

Phantom squatting 是 **slopsquatting 在域名/URL 层面的对应形式**。LLM 不再臆造不存在的软件包名称，而是为真实品牌臆造一个看似合理的 **portal、API、webhook、billing、SSO、download 或 support 域名**，攻击者则在人类或 agent 使用该域名之前注册相应的命名空间。<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

这之所以重要，是因为在许多 AI 辅助工作流中，模型输出会被当作 **受信任的依赖项**：
- 开发者会将建议的 endpoint 粘贴到代码或 CI/CD 集成中。
- AI agents 会自动获取文档、schema、APK、ZIP 或 webhook 目标。
- 生成的 runbook 或文档可能会嵌入 fake URL，并将其视为权威来源。

### Offensive workflow

1. **探测幻觉面**：针对品牌提出与真实工作流相关的问题，例如 `admin`、`billing`、`sandbox`、`benefits`、`api`、`download`、`support`、`webhook` 或 `mobile app` portal。<sup>[[12]](#references)</sup>
2. **标准化候选项**：解析生成的 URL，将 NXDOMAIN 响应归并到父级可注册域名，并对 prompt 家族去重。Prompt 语料应保持多样化，例如使用 **Jaccard similarity** 删除近似重复项。
3. **优先处理可预测的幻觉**：
- **Thermal Hallucination Persistence (THP)**：同一个 fake domain 会在不同温度下出现，包括 `T=0.1` 这样的低温设置。
- **跨模型共识**：多个 LLM 家族生成同一个 fake domain。
4. **注册并 weaponize** 父域名，然后托管 phishing、fake APK/ZIP downloads、credential harvesters、malicious docs 或收集 secrets/webhook payloads 的 API endpoints。**纯域名级幻觉** 最容易变现，因为攻击者控制整个命名空间；当标准化后的父域名尚未注册时，subdomain/path 幻觉同样可以被滥用。
5. **利用零信誉窗口**：新注册域名通常没有 blocklist 历史、URL reputation 和成熟的 telemetry，因此在检测机制跟上之前可能绕过控制措施。攻击者可以通过仅向 crawler 返回 benign 响应、redirect cloaking、CAPTCHA gates 或延迟 payload staging 来延长该窗口。

### Why it is dangerous for agents

对于人类受害者，fake domain 通常仍需要一次点击和后续操作。而对于 **agentic workflow**，LLM 可以同时充当 **诱饵** 和 **执行者**：agent 接收 hallucinated URL，获取该 URL、解析响应，随后可能在没有任何人工审核的情况下 leak tokens、执行 instructions、下载 dependency，或将 poisoned data 推送到 CI/CD 中。<sup>[[12]](#references)</sup>

### Practical attacker prompts

高价值 prompts 通常看起来像普通的企业任务，而不是明确的 phishing lure：<sup>[[12]](#references)</sup>
- “`<brand>` integrations 使用的 payment sandbox URL 是什么？”
- “`<brand>` build notifications 应使用哪个 webhook endpoint？”
- “`<brand>` 的 employee benefits / billing / SSO portal 在哪里？”
- “给我 `<brand>` 的 direct Android APK 或 desktop client download。”

### Defensive inversion

应将其视为主动域名监控问题，而不只是 prompt-injection 问题：<sup>[[12]](#references)</sup>
- 建立 **brand prompt corpus**，并定期探测用户/agents 所依赖的 LLM。
- 保存 hallucinated URLs，并跟踪哪些 URL 在不同温度/模型下保持稳定。
- 跟踪 **Adversarial Exploitation Window (AEW)**：从首次出现幻觉到攻击者注册域名之间的时间。正 AEW 表示防御者可以在 weaponization 之前完成预注册、sinkhole 或预封锁。
- 监控父域名从 **NXDOMAIN → registered** 的转换。
- 注册后，对 registrar、creation date、nameservers、privacy shielding、page content、screenshots、parked-page status 和 brand-asset similarity 进行 triage。
- 添加 policy gates，使 agents/developers **默认不信任 LLM 生成的域名**：在首次使用前要求 allowlists、ownership validation、CT/RDAP checks 或人工批准。

这同时符合多个 AI 风险类别：**AI supply-chain attack**、**insecure model output**，以及 agent 自主使用 hallucinated URL 时产生的 **rogue actions**。

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF（Secure AI Framework）– 风险](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 威胁矩阵](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLMs 的风险：有害内容、滥用与欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking：被盗的 Cloud Credentials 被用于新的 AI 攻击](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking 方案概述 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy（转售被盗的 LLM 访问权限）](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv – 深入分析 on-premise 低权限 LLM server 的部署](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets：podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface（CDI）规范](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting：AI 幻觉域名作为软件供应链攻击向量](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting：AI 幻觉如何助推新型供应链攻击](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
