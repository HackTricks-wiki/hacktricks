# 镜像安全、签名与 Secrets

{{#include ../../../banners/hacktricks-training.md}}

## 镜像注册表与信任

容器安全在 workload 启动之前就已经开始。镜像决定了哪些二进制文件、解释器、库、启动脚本和嵌入式配置会进入 production。如果镜像被植入后门、过时，或在构建时将 Secrets 烘焙其中，那么后续的运行时加固实际上已经是在处理一个受 compromise 的 artifact。

因此，镜像来源、漏洞扫描、签名验证和 Secret 处理应当与 namespaces 和 seccomp 放在同一场讨论中。它们保护的是生命周期中的不同阶段，但这些环节中的失败往往会决定运行时之后必须遏制的攻击面。

## 镜像注册表与信任

镜像可能来自 Docker Hub 等公共注册表，也可能来自组织运营的私有注册表。安全问题不只是镜像存放在哪里，而是团队能否确认其来源和完整性。从公共来源拉取未签名或跟踪不完善的镜像，会增加恶意或被篡改内容进入 production 的风险。即使是内部托管的注册表，也需要明确的所有权、审查流程和信任策略。

Docker Content Trust 历史上使用 Notary 和 TUF 的概念来要求镜像经过签名。具体生态已经发生变化，但其长期有效的经验仍然值得借鉴：镜像的身份和完整性应当能够被验证，而不是被默认信任。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
这个示例的重点并不是每个团队都必须继续使用相同的 tooling，而是说明 signing 和 key management 属于运维任务，而不是抽象理论。

## Vulnerability Scanning

Image scanning 有助于回答两个不同的问题。第一，image 是否包含已知存在漏洞的软件包或 library？第二，image 是否携带了会扩大攻击面的不必要软件？充满 debugging tools、shell、interpreter 和过时软件包的 image，既更容易被 exploit，也更难进行分析。

常用 scanner 的示例包括：
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
应谨慎解读这些工具的结果。未使用 package 中的 vulnerability 与暴露的 RCE path，其 risk 并不相同，但二者仍都与 hardening 决策相关。

## Build-Time Secrets

container build pipeline 中最古老的错误之一，是直接将 secrets 嵌入 image，或通过之后可从 `docker inspect`、build logs 或恢复的 layers 中看到的 environment variables 传递 secrets。Build-time secrets 应在 build 期间以临时方式挂载，而不是复制到 image filesystem 中。

BuildKit 通过支持专用的 build-time secret 处理机制改进了这一模型。build step 无需将 secret 写入 layer，而是可以临时使用它：
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
这很重要，因为 image layers 是持久存在的 artifacts。一旦 secret 进入某个已提交的 layer，之后在另一个 layer 中删除该文件，并不能真正从 image history 中移除原始 disclosure。

## Runtime Secrets

运行中 workload 所需的 secrets 也应尽可能避免使用 plain environment variables 等临时做法。Volumes、专用的 secret-management integrations、Docker secrets 和 Kubernetes Secrets 都是常见机制。即使 attacker 已经在 workload 中取得 code execution，这些机制也无法消除所有 risk，但相比于将 credentials 永久存储在 image 中，或通过 inspection tooling 随意暴露它们，仍然更加可取。

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
在 Kubernetes 中，Secret objects、projected volumes、service-account tokens 和 cloud workload identities 构成了更广泛且更强大的模型，但也通过 host mounts、宽泛的 RBAC 或不安全的 Pod 设计，增加了意外暴露的机会。

## 滥用

审查目标时，目的是发现 secrets 是否被 baked into image、泄露到 layers 中，或被挂载到可预测的 runtime locations：
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
这些命令有助于区分三种不同的问题：application configuration leaks、image-layer leaks，以及 runtime-injected secret files。如果某个 secret 出现在 `/run/secrets`、projected volume 或 cloud identity token path 下，下一步就是确定它仅授予当前 workload 访问权限，还是授予对更大 control plane 的访问权限。

### Full Example: Embedded Secret In Image Filesystem

如果 build pipeline 将 `.env` 文件或 credentials 复制到了最终 image 中，post-exploitation 就会变得很简单：
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影响取决于应用，但嵌入式 signing keys、JWT secrets 或 cloud credentials 很容易将 container compromise 转变为 API compromise、lateral movement，或伪造受信任的应用 token。

### 完整示例：构建时 Secret leak 检查

如果担心 image history 捕获了包含 secret 的 layer：
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
这种审查很有用，因为某个 secret 可能已从最终的 filesystem 视图中删除，但仍保留在较早的 layer 或 build metadata 中。

## 检查

这些检查旨在确定 image 和 secret-handling pipeline 是否可能在运行时之前扩大了 attack surface。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
这里有哪些值得关注的内容：

- 可疑的 build history 可能暴露被复制的 credentials、SSH material 或不安全的 build steps。
- projected volume paths 下的 Secrets 可能导致 cluster 或 cloud access，而不仅仅是本地 application access。
- 大量包含 plaintext credentials 的 configuration files 通常表明该 image 或 deployment model 携带了超出必要范围的 trust material。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | 支持 secure build-time secret mounts，但不会自动启用 | Secrets 可以在 `build` 期间以临时方式挂载；image signing 和 scanning 需要显式的 workflow 选择 | 将 secrets 复制到 image 中，通过 `ARG` 或 `ENV` 传递 secrets，禁用 provenance checks |
| Podman / Buildah | 支持 OCI-native builds 和 secret-aware workflows | 可使用强安全性的 build workflows，但 operators 仍必须有意选择这些 workflows | 将 secrets 嵌入 Containerfiles，在 builds 期间使用范围过宽的 build contexts 和宽松的 bind mounts |
| Kubernetes | 原生 Secret objects 和 projected volumes | Runtime secret delivery 是一等功能，但暴露程度取决于 RBAC、pod design 和 host mounts | 过度开放的 Secret mounts、service-account token misuse、通过 `hostPath` 访问 kubelet-managed volumes |
| Registries | 除非强制执行，否则 integrity 是可选的 | Public 和 private registries 都依赖 policy、signing 和 admission decisions | 随意拉取 unsigned images、薄弱的 admission control、糟糕的 key management |

{{#include ../../../banners/hacktricks-training.md}}
