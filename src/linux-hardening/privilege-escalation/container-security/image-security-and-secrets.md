# 镜像安全、签名与机密

{{#include ../../../banners/hacktricks-training.md}}

## 概述

容器安全始于工作负载启动之前。镜像决定哪些二进制文件、解释器、库、启动脚本和嵌入式配置会进入生产环境。如果镜像被植入后门、已过时，或将机密直接烘焙在其中，那么后续的运行时加固已经在一个被破坏的制品上运行。

这就是为什么镜像来源、漏洞扫描、签名验证和机密处理应与 namespaces 和 seccomp 一并讨论。它们保护的是生命周期的不同阶段，但这里的失败常常决定了运行时随后必须遏制的攻击面。

## 镜像注册表与信任

镜像可能来自公共注册表（例如 Docker Hub），也可能来自组织自营的私有注册表。安全问题不仅在于镜像存放在哪里，而在于团队能否确立其来源与完整性。从公共来源拉取未签名或追踪不良的镜像，会增加恶意或被篡改内容进入生产环境的风险。即便是内部托管的注册表，也需要明确的所有权、审查和信任策略。

Docker Content Trust 过去使用 Notary 和 TUF 的概念来要求镜像签名。具体生态已经演进，但持久的教训仍然适用：镜像的身份与完整性应当可验证，而不是被假定。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
这个例子的重点不是要求每个团队都必须使用相同的工具，而是要说明签名和密钥管理是操作性任务，而不是抽象的理论。

## 漏洞扫描

镜像扫描有助于回答两个不同的问题。首先，该镜像是否包含已知存在漏洞的包或库？其次，该镜像是否携带会扩大攻击面的不必要软件？充满调试工具、shell、解释器和过时软件包的镜像既更容易被利用，也更难以理解和评估。

常用扫描器示例包括：
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
这些工具的结果需要谨慎解读。在未使用的包中发现的漏洞，其风险不同于暴露的 RCE 路径，但两者在加固决策中仍然相关。

## 构建时机密

容器构建流水线中最古老的错误之一是将机密直接嵌入到镜像或通过环境变量传递，随后这些信息可能通过 `docker inspect`、构建日志或恢复的层被看到。构建时的机密应在构建过程中以临时挂载的方式使用，而不是复制到镜像文件系统中。

BuildKit 通过支持专门的构建时机密处理改进了这一模型。构建步骤可以暂时使用机密，而不是将其写入某一层：
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
这很重要，因为镜像层是持久的工件。一旦机密进入已提交的层，之后在另一层删除该文件并不能真正从镜像历史中移除最初的泄露。

## 运行时 Secrets

运行中 workload 所需的机密也应尽量避免使用临时性的做法，例如直接使用普通环境变量。Volumes、专用的 secret-management 集成、Docker secrets 和 Kubernetes Secrets 是常见的机制。没有一种能完全消除所有风险，尤其是在攻击者已经在 workload 中获得代码执行权限时，但它们仍然比将凭证永久存储在镜像中或通过检查工具随意暴露要好。

一个简单的 Docker Compose 风格的 secret 声明示例如下：
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
In Kubernetes 中，Secret objects、projected volumes、service-account tokens 和 cloud workload identities 构建了更广泛且更强大的模型，但它们也通过 host mounts、过于宽泛的 RBAC 或薄弱的 Pod 设计增加了意外暴露的机会。

## Abuse

在审查目标时，目的是发现 secrets 是否被嵌入镜像中、leaked 到镜像层中，或挂载到可预测的运行时位置：
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
这些命令有助于区分三类不同的问题：application configuration leaks、image-layer leaks 和 runtime-injected secret files。如果一个 secret 出现在 `/run/secrets`、a projected volume 或 cloud identity token path 下，下一步是判断它是否只授予对当前 workload 的访问权限，还是对更大的 control plane 有访问权限。

### 完整示例：嵌入在镜像文件系统中的 secret

如果构建流水线将 `.env` 文件或凭证复制到最终镜像中，post-exploitation 就变得很简单：
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影响取决于应用，但嵌入的 signing keys、JWT secrets 或 cloud credentials 很容易将 container compromise 转变为 API compromise、lateral movement，或伪造受信任的应用 tokens。

### 完整示例: Build-Time Secret Leakage Check

如果担心 image history 捕获了包含 secret 的 layer：
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
这种审查很有用，因为一个 secret 可能已从最终文件系统视图中删除，但仍保留在较早的层或构建元数据中。

## 检查

这些检查旨在确定镜像和 secret 处理管道是否可能在运行前增加了攻击面。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
这里值得注意的是：

- 可疑的构建历史可能暴露被复制的凭证、SSH 材料或不安全的构建步骤。
- 位于 projected volume paths 下的 Secrets 可能导致对集群或云的访问，而不仅仅是对本地应用的访问。
- 大量包含明文凭证的配置文件通常表明镜像或部署模型承载了超过必要的信任凭据。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | 支持安全的构建时 secret 挂载，但不会自动启用 | Secrets 可以在 `build` 期间以临时方式挂载；镜像签名和扫描需要显式的工作流程选择 | 将 secrets 复制到镜像中、通过 `ARG` 或 `ENV` 传递 secrets、禁用来源检查 |
| Podman / Buildah | 支持 OCI 原生构建和对 secrets 感知的工作流程 | 可用强健的构建工作流，但操作者仍需有意选择它们 | 在 Containerfiles 中嵌入 secrets、使用过宽的 build context、在构建期间使用宽松的 bind mounts |
| Kubernetes | 原生 Secret 对象和 projected volumes | 运行时 Secrets 的交付是一级支持的，但暴露取决于 RBAC、pod 设计和主机挂载 | 过度宽泛的 Secret 挂载、service-account token 滥用、`hostPath` 访问 kubelet 管理的卷 |
| Registries | 除非强制，否则完整性是可选的 | 公有和私有注册表都依赖策略、签名和 admission 决策 | 自由拉取未签名镜像、薄弱的 admission 控制、糟糕的密钥管理 |
