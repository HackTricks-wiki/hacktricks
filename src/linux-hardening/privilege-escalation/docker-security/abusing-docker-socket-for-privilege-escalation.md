# 利用 Docker Socket 提升权限

{{#include ../../../banners/hacktricks-training.md}}

有些情况下你只拥有 **docker socket 的访问权限**，并且想要利用它来 **提升权限**。某些操作可能会非常可疑，你可能想要避免它们，因此在这里你可以找到一些有用的标志来提升权限：

### 通过挂载

你可以在以 root 身份运行的容器中 **挂载** 文件系统的不同部分并 **访问** 它们。\
你也可以 **利用挂载来提升容器内的权限**。

- **`-v /:/host`** -> 在容器中挂载主机文件系统，以便你可以 **读取主机文件系统**。
- 如果你想要 **感觉像是在主机上**，但实际上在容器中，你可以使用以下标志禁用其他防御机制：
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> 这与前面的方法类似，但这里我们是 **挂载设备磁盘**。然后，在容器内运行 `mount /dev/sda1 /mnt`，你可以在 `/mnt` 中 **访问** **主机文件系统**。
- 在主机上运行 `fdisk -l` 找到要挂载的 `</dev/sda1>` 设备。
- **`-v /tmp:/host`** -> 如果由于某种原因你只能 **挂载主机的某个目录**，并且你可以在主机内访问它。挂载它并在挂载目录中创建一个 **`/bin/bash`** 具有 **suid** 权限，以便你可以 **从主机执行它并提升到 root**。

> [!NOTE]
> 请注意，也许你无法挂载 `/tmp` 文件夹，但你可以挂载一个 **不同的可写文件夹**。你可以使用以下命令找到可写目录：`find / -writable -type d 2>/dev/null`
>
> **请注意，并非所有 Linux 机器上的目录都支持 suid 位！** 要检查哪些目录支持 suid 位，请运行 `mount | grep -v "nosuid"`。例如，通常 `/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup` 和 `/var/lib/lxcfs` 不支持 suid 位。
>
> 还要注意，如果你可以 **挂载 `/etc`** 或任何其他 **包含配置文件** 的文件夹，你可以在 docker 容器中以 root 身份更改它们，以便 **在主机中利用它们** 并提升权限（可能修改 `/etc/shadow`）。

### 从容器中逃逸

- **`--privileged`** -> 使用此标志，你 [移除容器的所有隔离](docker-privileged.md#what-affects)。查看技术以 [以 root 身份从特权容器中逃逸](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)。
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> 为了 [通过能力提升权限](../linux-capabilities.md)，**将该能力授予容器** 并禁用可能阻止漏洞工作的其他保护方法。

### Curl

在本页中，我们讨论了使用 docker 标志提升权限的方法，你可以在页面中找到 **使用 curl 命令滥用这些方法的方式**：

{{#include ../../../banners/hacktricks-training.md}}
