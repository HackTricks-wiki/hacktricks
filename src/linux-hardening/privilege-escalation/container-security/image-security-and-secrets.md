# 镜像安全、签名与 Secrets

{{#include ../../../banners/hacktricks-training.md}}

## 概述

容器安全从工作负载启动之前就开始。镜像决定了哪些二进制文件、解释器、库、启动脚本和内嵌配置会进入生产环境。如果镜像被植入后门、陈旧，或在构建时把 secrets 烘焙进去，那么随后进行的运行时强化已经在一个被妥协的工件上进行。

这就是为什么 image provenance、vulnerability scanning、signature verification 和 secret handling 应该与 namespaces 和 seccomp 放在同一讨论中。它们保护生命周期的不同阶段，但这里的失败常常决定了运行时随后需要遏制的攻击面。

## 镜像注册表与信任

镜像可能来自公共 registry（比如 Docker Hub），也可能来自组织运维的私有 registry。安全问题不仅在于镜像存放在哪里，而在于团队能否建立起其 provenance 和完整性。从公共来源拉取未签名或跟踪不良的镜像会增加恶意或被篡改内容进入生产环境的风险。即便是内部托管的 registry 也需要明确的所有权、审查和信任策略。

Docker Content Trust 历史上使用 Notary 和 TUF 的概念来要求镜像签名。尽管具体生态已经演化，但持久的教训仍然有用：image identity 和 integrity 应该是可验证的，而不是被假定的。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
这个示例的重点不是要求每个团队都使用相同的工具，而是要说明签名和密钥管理是操作性任务，而非抽象的理论。

## 漏洞扫描

镜像扫描有助于回答两个不同的问题。首先，该镜像是否包含已知存在漏洞的包或库？其次，该镜像是否携带扩展攻击面的不必要软件？包含大量调试工具、shell、interpreters 和过时包的镜像既更容易被利用，也更难以分析。

常用扫描器示例包括：
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
这些工具的结果应谨慎解读。未使用软件包中的漏洞与暴露的 RCE 路径在风险上并不相同，但两者在加固决策时都仍然相关。

## 构建时凭证

容器构建流水线中最常见的错误之一是将凭证直接嵌入镜像，或通过环境变量传递，这些变量随后可能通过 `docker inspect`、构建日志或恢复出来的层被看到。构建时的凭证应在构建过程中以短暂挂载的方式提供，而不是复制到镜像文件系统中。

BuildKit 通过提供专门的构建时凭证处理改进了这一模型。构建步骤可以临时使用凭证，而不是将其写入镜像层：
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
这很重要，因为镜像层是持久的工件。一旦敏感信息进入了已提交的层，在后来的某一层删除该文件并不能真正从镜像历史中移除最初的泄露。

## 运行时 Secrets

运行中的工作负载所需的 Secrets 也应尽量避免使用临时的做法，例如明文环境变量。Volumes、专用的 secret-management 集成、Docker secrets 和 Kubernetes Secrets 是常见的机制。没有一种能完全消除风险，尤其是在攻击者已经在工作负载中获得代码执行的情况下，但它们仍然优于将凭据永久保存在镜像中或通过检查工具随意暴露。

一个简单的 Docker Compose 风格的 secret 声明如下：
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
在 Kubernetes 中，Secret objects、projected volumes、service-account tokens 和 cloud workload identities 构建了更广泛且更强大的模型，但它们也通过 host mounts、宽泛的 RBAC 或设计不佳的 Pod 带来更多意外暴露的机会。

## 滥用

审查目标时，目的在于发现 secrets 是否被内置到镜像中、leaked into layers，或挂载到可预测的运行时位置：
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
这些命令有助于区分三种不同的问题：application configuration leaks、image-layer leaks 和 runtime-injected secret files。如果在 `/run/secrets`、一个 projected volume，或一个 cloud identity token 路径下出现 secret，下一步是要判断它是否仅授予当前 workload 访问权限，还是对更大的 control plane 开放。

### 完整示例：嵌入在镜像文件系统中的 Secret

如果构建 pipeline 将 `.env` 文件或凭据复制到了最终镜像，post-exploitation 就变得简单：
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影响取决于应用，但嵌入的 signing keys、JWT secrets 或 cloud credentials 很容易将 container compromise 转变为 API compromise、lateral movement，或伪造受信任的 application tokens。

### 完整示例：Build-Time Secret Leakage Check

如果担心 image history 捕获了包含 secret 的 layer：
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
这种审查很有用，因为 secret 可能已经从最终的文件系统视图中被删除，但仍然保留在较早的层或构建元数据中。

## 检查

这些检查旨在确定镜像和 secret 处理流水线是否可能在运行前增加了攻击面。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
这里的要点：

- 可疑的构建历史可能暴露被复制的凭证、SSH 材料或不安全的构建步骤。
- 位于 projected volume paths 下的 Secrets 可能导致对 cluster 或 cloud 的访问，而不仅仅是本地应用的访问。
- 大量包含明文凭证的配置文件通常表示镜像或部署模型携带了超过必要的信任材料。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | 将 secrets 复制到镜像中、通过 `ARG` 或 `ENV` 传递 secrets、禁用溯源检查 |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | 在 Containerfiles 中嵌入 secrets、广泛的构建上下文、在构建期间使用宽松的 bind mounts |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | 过度宽泛的 Secret 挂载、service-account token 的滥用、对 kubelet 管理的卷的 `hostPath` 访问 |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | 随意拉取未签名镜像、薄弱的准入控制、糟糕的密钥管理 |
{{#include ../../../banners/hacktricks-training.md}}
