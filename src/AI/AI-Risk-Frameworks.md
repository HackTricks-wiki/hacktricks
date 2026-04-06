# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP 机器学习十大漏洞

OWASP 已识别出可能影响 AI 系统的十大机器学习漏洞。这些漏洞可能导致多种安全问题，包括 data poisoning、model inversion 和 adversarial attacks。理解这些漏洞对构建安全的 AI 系统至关重要。

有关更新和详细的十大机器学习漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。

- **Input Manipulation Attack**: 攻击者对 **incoming data** 添加微小、通常不可见的改动，使模型做出错误判断。\
*Example*: 在停车标志上涂几滴油漆，让自动驾驶汽车把它“看成”限速标志。

- **Data Poisoning Attack**: 故意在 **training set** 中注入有害样本，教会模型错误或危险的规则。\
*Example*: 在杀毒软件训练语料中将恶意二进制误标为“benign”，使得相似的恶意软件日后可绕过检测。

- **Model Inversion Attack**: 通过探测输出，攻击者构建一个 **reverse model**，重建原始输入的敏感特征。\
*Example*: 从癌症检测模型的预测结果重建患者的 MRI 图像。

- **Membership Inference Attack**: 对手通过观察置信度差异测试某个 **specific record** 是否被用于训练。\
*Example*: 确认某人的银行交易记录是否出现在反欺诈模型的训练数据中。

- **Model Theft**: 通过反复查询，攻击者学习决策边界并 **clone the model's behavior**（以及 IP）。\
*Example*: 从 ML‑as‑a‑Service API 收集足够的问答对以构建近似等效的本地模型。

- **AI Supply‑Chain Attack**: 在 **ML pipeline** 的任一组件（数据、库、预训练权重、CI/CD）被破坏，从而腐化下游模型。\
*Example*: model‑hub 上被投毒的依赖项安装了带后门的情感分析模型，进而传播到许多应用中。

- **Transfer Learning Attack**: 在 **pre‑trained model** 中植入恶意逻辑，经过 fine‑tuning 后仍然存活在受害者任务中。\
*Example*: 带隐藏触发器的视觉 backbone 在被用于医疗影像时仍然会翻转标签。

- **Model Skewing**: 通过微妙偏置或错误标注的数据 **shifts the model's outputs**，以偏向攻击者的目标。\
*Example*: 注入被标为“ham”的“clean”垃圾邮件，使垃圾邮件过滤器以后放行相似邮件。

- **Output Integrity Attack**: 攻击者在传输过程中 **alters model predictions**，而非修改模型本身，欺骗下游系统。\
*Example*: 在文件隔离阶段之前把恶意软件分类器的“malicious”结论改为“benign”。

- **Model Poisoning** --- 在获得写权限后直接、有针对性地修改 **model parameters** 本身，以改变行为。\
*Example*: 在生产环境中微调欺诈检测模型的权重，使得来自某些卡号的交易总是被批准。

## Google SAIF 风险

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：

- **Data Poisoning**: 恶意行为者修改或注入训练/调优数据以降低准确度、植入后门或扭曲结果，破坏整个数据生命周期中的模型完整性。

- **Unauthorized Training Data**: 摄取受版权保护、敏感或未经许可的数据集会带来法律、伦理和性能风险，因为模型从未被允许使用这些数据进行学习。

- **Model Source Tampering**: 在训练之前或期间，通过供应链或内部人员篡改模型代码、依赖项或权重，可能嵌入隐藏逻辑并在重新训练后仍然存在。

- **Excessive Data Handling**: 薄弱的数据保留和治理控制会导致系统存储或处理超过必要的个人数据，增加暴露和合规风险。

- **Model Exfiltration**: 攻击者窃取模型文件/权重，导致知识产权丧失并促成仿制服务或后续攻击。

- **Model Deployment Tampering**: 对模型工件或服务基础设施的篡改使运行中的模型与审计版本不一致，可能改变其行为。

- **Denial of ML Service**: 通过洪水式请求或发送“sponge”输入消耗计算/能量并使模型下线，类似传统的 DoS 攻击。

- **Model Reverse Engineering**: 通过收集大量输入-输出对，攻击者可以克隆或蒸馏模型，助长仿制产品和定制化的对抗性攻击。

- **Insecure Integrated Component**: 易受攻击的插件、agent 或上游服务允许攻击者注入代码或在 AI 管道中提升权限。

- **Prompt Injection**: 精心构造的 prompt（直接或间接）走私指令以覆盖系统意图，使模型执行非预期命令。

- **Model Evasion**: 精心设计的输入触发模型误分类、产生 hallucination 或输出被禁止内容，破坏安全性和信任。

- **Sensitive Data Disclosure**: 模型泄露其训练数据或用户上下文中的私人或机密信息，违反隐私和法规。

- **Inferred Sensitive Data**: 模型推断出从未提供的个人属性，通过推断造成新的隐私伤害。

- **Insecure Model Output**: 未经消毒的响应向用户或下游系统传递有害代码、错误信息或不当内容。

- **Rogue Actions**: 自主集成的 agents 在没有充分用户监督的情况下执行非预期的真实世界操作（写文件、调用 API、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的框架，用于理解和缓解与 AI 系统相关的风险。它对对抗者可能针对 AI 模型使用的各种攻击技术和战术进行了分类，也涵盖了如何利用 AI 系统执行不同攻击的方式。

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取活跃会话 tokens 或 cloud API credentials，并在未经授权的情况下调用付费的 cloud-hosted LLMs。访问经常通过前置受害者账户的 reverse proxies 转售，例如 “oai-reverse-proxy” 部署。后果包括财务损失、模型违规使用以及将可归因于受害租户的行为。

TTPs:
- 从被感染的开发者机器或浏览器中收集 tokens；窃取 CI/CD secrets；购买 leaked cookies。
- 部署一个将请求转发到真实提供方的 reverse proxy，隐藏上游 key 并复用多个客户。
- 滥用直接的 base-model endpoints 以绕过企业 guardrails 和速率限制。

Mitigations:
- 将 tokens 绑定到设备指纹、IP 范围和客户端证明；强制短期过期并通过 MFA 刷新。
- 对 keys 做最小化权限范围（无工具访问、可读优先）；在异常时旋转。
- 在服务器端通过 policy gateway 终止所有流量，该网关执行安全过滤、按路由配额和租户隔离。
- 监测异常使用模式（突增支出、非典型地域、异常 UA 字符串）并自动撤销可疑会话。
- 优先使用 mTLS 或由你的 IdP 签发的 signed JWTs，而非长期存在的静态 API keys。

## Self-hosted LLM inference hardening

在本地运行 LLM server 以处理机密数据会产生不同于云端 API 的攻击面：inference/debug endpoints 可能会 leak prompts，serving stack 通常暴露 reverse proxy，GPU 设备节点暴露大量 ioctl() 面向。如果你在评估或部署 on-prem inference service，请至少检查以下要点。

### Prompt 泄露通过调试和监控端点

将 inference API 视为一个 **multi-user sensitive service**。调试或监控路由可能暴露 prompt 内容、slot 状态、model metadata 或内部队列信息。在 `llama.cpp` 中，`/slots` endpoint 尤为敏感，因为它会暴露每个 slot 的状态，仅用于 slot inspection/management。

- 在 inference server 前放置一个 reverse proxy，并将 **deny by default** 作为策略。
- 仅允许确切的 HTTP method + path 组合被 client/UI 使用。
- 尽可能在后端禁用 introspection endpoints，例如使用 `llama-server --no-slots`。
- 将 reverse proxy 绑定到 `127.0.0.1`，并通过受认证的传输（如 SSH local port forwarding）暴露，而不是在 LAN 上公开。

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
### Rootless containers（无网络，使用 UNIX sockets）

如果 inference daemon 支持在 UNIX socket 上监听，优先使用它而不是 TCP，并以 **no network stack** 运行容器：
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

### GPU device-node minimization

For GPU-backed inference, `/dev/nvidia*` files are high-value local attack surfaces because they expose large driver `ioctl()` handlers and potentially shared GPU memory-management paths.

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- Blacklist unnecessary modules such as `nvidia_drm`, `nvidia_modeset`, and `nvidia_peermem` on headless inference hosts.
- Preload only required modules at boot instead of letting the runtime opportunistically `modprobe` them during inference startup.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使工作负载没有显式使用 `cudaMallocManaged()`，较新的 CUDA 运行时仍可能需要 `nvidia-uvm`。由于该设备是共享的并负责 GPU 虚拟内存管理，应将其视为跨租户的数据暴露面。如果推理后端支持，使用 Vulkan 后端 可能是一个有趣的折衷，因为它可能完全避免将 `nvidia-uvm` 暴露给容器。

### LSM 隔离（用于推理工作进程）

AppArmor/SELinux/seccomp 应作为对推理进程的纵深防御：

- 只允许实际需要的共享库、模型路径、socket 目录和 GPU 设备节点。
- 明确拒绝高风险能力，例如 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace`。
- 将模型目录保持为只读，并将可写路径限定为运行时的 socket/cache 目录。
- 监控拒绝日志，因为当模型服务器或 post-exploitation payload 试图逃逸其预期行为时，这些日志提供有用的检测遥测。

针对以 GPU 为后端的工作进程的 AppArmor 规则示例：
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
## 参考资料
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
