{{#include ../../banners/hacktricks-training.md}}

# 容器中的SELinux

[来自redhat文档的介绍和示例](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) 是一个 **标签** **系统**。每个 **进程** 和每个 **文件** 系统对象都有一个 **标签**。SELinux 策略定义了关于 **进程标签可以对系统上所有其他标签执行的操作** 的规则。

容器引擎以单个受限的 SELinux 标签启动 **容器进程**，通常为 `container_t`，然后将容器内部的容器设置为标签 `container_file_t`。SELinux 策略规则基本上表示 **`container_t` 进程只能读取/写入/执行标记为 `container_file_t` 的文件**。如果容器进程逃离容器并尝试写入主机上的内容，Linux 内核将拒绝访问，并仅允许容器进程写入标记为 `container_file_t` 的内容。
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux 用户

除了常规的 Linux 用户，还有 SELinux 用户。SELinux 用户是 SELinux 策略的一部分。每个 Linux 用户都映射到一个 SELinux 用户，作为策略的一部分。这允许 Linux 用户继承施加在 SELinux 用户上的限制和安全规则与机制。

{{#include ../../banners/hacktricks-training.md}}
