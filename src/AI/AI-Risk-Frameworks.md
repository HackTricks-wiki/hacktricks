# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp 已识别出可能影响 AI 系统的机器学习 Top 10 漏洞。这些漏洞可能导致多种安全问题，包括 data poisoning、model inversion 和 adversarial attacks。理解这些漏洞对于构建安全的 AI 系统至关重要。

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: 攻击者对**传入数据**添加微小、通常不可见的改动，使模型做出错误判定。\
*Example*: 在停车标志上涂几点油漆就能欺骗自动驾驶汽车，把停车标志“看成”限速标志。

- **Data Poisoning Attack**: 有意在**训练集**中污染恶意样本，教会模型有害规则。\
*Example*: 在杀毒训练语料中把 malware binaries 错标为“benign”，使类似的 malware 日后能够绕过检测。

- **Model Inversion Attack**: 通过探测输出，攻击者构建一个**逆向模型**来重建原始输入的敏感特征。\
*Example*: 从癌症检测模型的预测结果重建病人的 MRI 图像。

- **Membership Inference Attack**: 对手通过观察置信度差异来测试某条**特定记录**是否被用于训练。\
*Example*: 确认某人的银行交易是否出现在某个 fraud-detection 模型的训练数据中。

- **Model Theft**: 反复查询可以让攻击者学习决策边界并**克隆模型行为**（及其 IP）。\
*Example*: 从 ML‑as‑a‑Service API 收集足够多的问答对，以构建一个近似等效的本地模型。

- **AI Supply‑Chain Attack**: 在 **ML pipeline** 的任一组件（数据、库、预训练权重、CI/CD）上被攻破，从而污染下游模型。\
*Example*: model-hub 上的被投毒依赖安装了带后门的 sentiment‑analysis 模型，传播到多个应用中。

- **Transfer Learning Attack**: 在 **pre‑trained model** 中植入恶意逻辑，即便在受害者任务上微调后也能存活。\
*Example*: 带隐藏触发器的 vision backbone 在被用于医疗影像适配后仍会翻转标签。

- **Model Skewing**: 通过微妙偏置或错标数据使**模型输出发生偏移**，以偏向攻击者的议程。\
*Example*: 注入被标记为 ham 的“干净”垃圾邮件，使 spam filter 在未来放行类似邮件。

- **Output Integrity Attack**: 攻击者**篡改传输中的模型预测**（而不是模型本身），欺骗下游系统。\
*Example*: 在文件被隔离前把 malware classifier 的“mal意”判定篡改为“benign”。

- **Model Poisoning** --- 对**模型参数**本身进行直接、定向的修改，通常在获得写权限后实施，以改变行为。\
*Example*: 在生产环境中调整 fraud‑detection 模型的权重，使特定卡号的交易总是被批准。


## Google SAIF Risks

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：

- **Data Poisoning**: 恶意者更改或注入训练/调优数据以降低准确性、植入后门或偏斜结果，从而破坏模型在整个数据生命周期内的完整性。

- **Unauthorized Training Data**: 摄取受版权保护、敏感或未获授权的数据集会带来法律、伦理和性能风险，因为模型从未被允许使用这些数据进行学习。

- **Model Source Tampering**: 在训练前或训练期间通过供应链或内部人员篡改模型代码、依赖或权重，可能嵌入在重训练后仍然存在的隐蔽逻辑。

- **Excessive Data Handling**: 薄弱的数据保留与治理控制导致系统存储或处理超出必要范围的个人数据，增加曝光与合规风险。

- **Model Exfiltration**: 攻击者窃取模型文件/权重，导致知识产权流失并使仿制服务或后续攻击成为可能。

- **Model Deployment Tampering**: 对模型产物或服务基础设施的篡改会使运行中的模型与已审核版本不一致，可能改变其行为。

- **Denial of ML Service**: 通过泛洪 API 或发送“sponge”输入耗尽计算/能量，令模型离线，类似传统的 DoS 攻击。

- **Model Reverse Engineering**: 通过收集大量输入-输出对，攻击者可以克隆或蒸馏模型，从而推动模仿产品和针对性的 adversarial attacks。

- **Insecure Integrated Component**: 易受攻击的插件、agent 或上游服务允许攻击者注入代码或在 AI 管道中提升权限。

- **Prompt Injection**: 精心构造的 prompts（直接或间接）走私指令以覆盖系统意图，使模型执行非预期命令。

- **Model Evasion**: 精心设计的输入触发模型误分类、hallucinate 或输出被禁止内容，侵蚀安全性与信任。

- **Sensitive Data Disclosure**: 模型泄露训练数据或用户上下文中的私人或机密信息，违反隐私与法规。

- **Inferred Sensitive Data**: 模型推断出从未提供的个人属性，通过推断造成新的隐私伤害。

- **Insecure Model Output**: 未消毒的响应向用户或下游系统传递有害代码、错误信息或不当内容。

- **Rogue Actions**: 自主集成的 agents 在没有足够用户监管的情况下执行非预期的现实世界操作（写文件、API 调用、购买等）。


## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的框架，用于理解和缓解与 AI 系统相关的风险。它对攻击者可能针对 AI 模型使用的各种攻击技术和战术进行分类，也涵盖了如何使用 AI 系统执行不同攻击的方法。


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取活动会话 token 或云 API 凭证并未经授权调用付费的 cloud-hosted LLM。访问经常通过反向代理转售，反向代理替前端受害者的账户，例如 "oai-reverse-proxy" 部署。后果包括财务损失、模型被滥用（违反策略），以及将行为归因到受害租户。

TTPs:
- 从被感染的开发者机器或浏览器中 harvest tokens；窃取 CI/CD secrets；购买被泄露的 cookies。
- 搭建一个把请求转发到真实提供者的 reverse proxy，隐藏上游 key 并为多个客户复用。
- 滥用直接的 base-model endpoints 以绕过企业 guardrails 和速率限制。

Mitigations:
- 将 tokens 绑定到设备指纹、IP 范围和 client attestation；强制短期有效并结合 MFA 刷新。
- 将 keys 最小化权限（无工具访问、在适用时只读）；在异常时 rotate。
- 在 server-side 通过 policy gateway 终止所有流量，执行 safety filters、按路由限额和租户隔离。
- 监控异常使用模式（突发消费增长、非典型地区、UA 字符串）并自动撤销可疑会话。
- 优先使用 mTLS 或由你的 IdP 签发的 signed JWTs，而不是长期存在的静态 API keys。

## Self-hosted LLM inference hardening

为机密数据运行本地 LLM server 会产生与 cloud-hosted API 不同的攻击面：inference/debug endpoints 可能 leak prompts，serving stack 通常暴露一个 reverse proxy，GPU 设备节点暴露大量的 `ioctl()` 接口。如果你正在评估或部署 on-prem inference service，请至少检查以下要点。

### Prompt leakage via debug and monitoring endpoints

将 inference API 视为一个**多用户敏感服务**。Debug 或 monitoring 路由可能会暴露 prompt 内容、slot 状态、model metadata 或内部队列信息。在 `llama.cpp` 中，`/slots` endpoint 尤其敏感，因为它会暴露每个 slot 的状态且只用于 slot inspection/management。

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

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
### 无特权容器：无网络并使用 UNIX sockets

如果推理守护进程支持在 UNIX socket 上监听，请优先使用它而不是 TCP，并以 **无网络栈** 运行容器：
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
- `--network none` 可以移除入/出站 TCP/IP 的暴露，并避免 rootless 容器本可能需要的 user-mode helpers。
- UNIX 套接字允许你在 socket 路径上使用 POSIX 权限/ACLs 作为第一层访问控制。
- `--userns=keep-id` 和 rootless Podman 可以降低容器逃逸的影响，因为容器内的 root 并非宿主机的 root。
- 只读的模型挂载可减少容器内部对模型篡改的可能性。

### GPU device-node minimization

对于基于 GPU 的推理，`/dev/nvidia*` 文件是高价值的本地攻击面，因为它们暴露了大型驱动的 `ioctl()` 处理程序以及可能的共享 GPU 内存管理路径。

- 不要将 `/dev/nvidia*` 设置为对所有用户可写。
- 使用 `NVreg_DeviceFileUID/GID/Mode`、udev rules 和 ACLs 限制 `nvidia`、`nvidiactl` 和 `nvidia-uvm`，以便只有映射的容器 UID 能打开它们。
- 在无头推理主机上将不必要的模块（如 `nvidia_drm`、`nvidia_modeset` 和 `nvidia_peermem`）列入黑名单。
- 在启动时仅预加载所需的模块，而不是让运行时在推理启动期间机会性地使用 `modprobe` 加载它们。

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
一个重要的审查点是 **`/dev/nvidia-uvm`**。即使工作负载没有明确使用 `cudaMallocManaged()`，最近的 CUDA runtimes 仍可能需要 `nvidia-uvm`。由于该设备是共享的并负责 GPU 虚拟内存管理，应将其视为跨租户的数据暴露面。如果推理后端支持，Vulkan 后端可能是一个有趣的折衷，因为它可能完全避免向容器暴露 `nvidia-uvm`。

### 推理工作者的 LSM 隔离

AppArmor/SELinux/seccomp 应作为围绕推理进程的深度防御：

- 仅允许实际需要的共享库、模型路径、socket 目录和 GPU 设备节点。
- 显式拒绝高风险能力，如 `sys_admin`、`sys_module`、`sys_rawio` 和 `sys_ptrace`。
- 将模型目录设为只读，并将可写路径限定为运行时的 socket/cache 目录。
- 监控拒绝日志，因为当模型服务器或 post-exploitation payload 试图逃逸其预期行为时，这些日志提供有用的检测遥测。

Example AppArmor rules for a GPU-backed worker:
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
- [Unit 42 – Code Assistant LLMs 的风险：有害内容、滥用与欺骗](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking 方案概述 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (转售被盗的 LLM 访问权限)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - 深入解析在本地部署低权限 LLM 服务器](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) 规范](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
