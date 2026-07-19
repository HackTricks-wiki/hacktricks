# Image Security, Signing, And Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Container security 在 workload 启动之前就已经开始。image 决定哪些 binaries、interpreters、libraries、startup scripts 和 embedded configuration 会进入 production。如果 image 被植入 backdoor、过时，或在构建时将 secrets 直接 baked into image，后续的 runtime hardening 实际上已经是在一个被 compromise 的 artifact 上运行。

因此，image provenance、vulnerability scanning、signature verification 和 secret handling 应与 namespaces 和 seccomp 放在同一讨论中。它们保护 lifecycle 中的不同阶段，但这里的 failures 往往会定义 runtime 随后必须限制的 attack surface。

## Image Registries And Trust

Images 可能来自 Docker Hub 等 public registries，也可能来自组织运营的 private registries。安全问题并不只是 image 存放在哪里，而是团队能否确认其 provenance 和 integrity。从 public sources 拉取 unsigned 或 tracking 不完善的 images，会增加 malicious 或被 tamper 的 content 进入 production 的风险。即使是内部托管的 registries，也需要明确的 ownership、review 和 trust policy。

Docker Content Trust 历来使用 Notary 和 TUF concepts 来要求 signed images。具体 ecosystem 已经发生变化，但这一长期有效的经验仍然有用：image identity 和 integrity 应当能够被验证，而不是被默认信任。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
这个示例的重点并不是每个团队都必须继续使用相同的工具链，而是说明签名和密钥管理属于运维任务，而非抽象理论。

## Vulnerability Scanning

镜像扫描有助于回答两个不同的问题。第一，镜像是否包含已知存在漏洞的软件包或库？第二，镜像是否携带了会扩大 attack surface 的不必要软件？充满调试工具、shell、解释器和过时软件包的镜像不仅更容易被利用，也更难进行分析。

常用的扫描器示例包括：
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
应谨慎解读这些工具的结果。未使用 package 中的 vulnerability，其 risk 并不等同于暴露的 RCE 路径，但两者仍都与 hardening 决策相关。

## Build-Time Secrets

container build pipeline 中最常见、历史最久的错误之一，是将 secrets 直接嵌入 image，或通过 environment variables 传递，而这些 secrets 随后可能通过 `docker inspect`、build logs 或恢复的 layers 暴露出来。Build-time secrets 应在 build 期间以临时方式挂载，而不是复制到 image filesystem 中。

BuildKit 通过支持专用的 build-time secret 处理机制改进了这一模型。无需将 secret 写入 layer，build step 可以临时使用它：
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
这很重要，因为 image layers 是持久存在的 artifacts。一旦 secret 进入已提交的 layer，之后在另一个 layer 中删除该文件，并不能真正从 image history 中移除最初的 disclosure。

## Runtime Secrets

运行中的 workload 所需的 secrets 也应尽可能避免使用 plain environment variables 等临时做法。Volumes、专用的 secret-management integrations、Docker secrets 和 Kubernetes Secrets 都是常见机制。即使 attacker 已经在 workload 中获得了 code execution，这些机制也无法消除所有风险，但相比于将 credentials 永久存储在 image 中，或通过 inspection tooling 随意暴露它们，它们仍然是更好的选择。

一个简单的 Docker Compose 风格 secret 声明如下：
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
在 Kubernetes 中，Secret objects、projected volumes、service-account tokens 和 cloud workload identities 构成了更广泛、更强大的模型，但也通过 host mounts、宽泛的 RBAC 或设计薄弱的 Pod，带来了更多意外暴露的机会。

## Abuse

检查目标时，目的是确定 secrets 是否被 baked into image、leaked into layers，或被挂载到可预测的 runtime locations：
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
这些命令有助于区分三种不同的问题：application configuration leaks、image-layer leaks 和 runtime-injected secret files。如果某个 secret 出现在 `/run/secrets`、projected volume 或 cloud identity token path 下，下一步需要确定它是否仅授予对当前 workload 的访问权限，还是能够访问规模大得多的 control plane。

### Full Example: Embedded Secret In Image Filesystem

如果 build pipeline 将 `.env` 文件或 credentials 复制到最终 image 中，post-exploitation 就会变得很简单：
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影响取决于应用程序，但嵌入的签名密钥、JWT secrets 或云凭据很容易将 container compromise 变成 API compromise、横向移动，或伪造受信任的应用程序令牌。

### 完整示例：构建时 Secret leak 检查

如果担心镜像历史记录捕获了包含 secret 的层：
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
这种 review 很有用，因为某个 secret 可能已从最终 filesystem 视图中删除，但仍保留在较早的 layer 或 build metadata 中。

## Checks

这些检查旨在确定 image 和 secret-handling pipeline 是否可能在 runtime 前扩大了 attack surface。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
这里有哪些值得关注的地方：

- 可疑的构建历史可能会暴露被复制的凭据、SSH 材料或不安全的构建步骤。
- projected volume 路径下的 Secrets 可能导致获得 cluster 或 cloud 访问权限，而不仅仅是本地应用访问权限。
- 大量包含明文凭据的配置文件通常表明，该 image 或 deployment 模型携带了超出必要范围的信任材料。

## 运行时默认设置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker / BuildKit | 支持安全的构建时 secret mount，但不会自动启用 | Secrets 可以在 `build` 期间以临时方式挂载；image signing 和 scanning 需要显式选择工作流 | 将 secrets 复制到 image 中，通过 `ARG` 或 `ENV` 传递 secrets，禁用 provenance checks |
| Podman / Buildah | 支持 OCI-native builds 和具备 secret 感知能力的工作流 | 可以使用强安全性的构建工作流，但 operators 仍必须有意识地选择它们 | 将 secrets 嵌入 Containerfiles，在构建期间使用范围过宽的 build contexts 或宽松的 bind mounts |
| Kubernetes | 原生 Secret objects 和 projected volumes | Runtime secret delivery 是一等能力，但暴露风险取决于 RBAC、pod 设计和 host mounts | 过度开放的 Secret mounts、滥用 service-account token、通过 `hostPath` 访问 kubelet 管理的 volumes |
| Registries | 除非强制执行，否则完整性检查是可选的 | Public 和 private registries 都依赖 policy、signing 和 admission 决策 | 随意拉取 unsigned images、admission control 薄弱、key management 不完善 |
{{#include ../../../banners/hacktricks-training.md}}
