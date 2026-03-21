# 屏蔽路径

{{#include ../../../../banners/hacktricks-training.md}}

屏蔽路径是一种运行时保护，通过对这些对内核敏感的文件系统位置进行 bind-mount 覆盖或以其他方式使其不可访问，从容器视角隐藏它们。其目的是防止工作负载直接与普通应用不需要的接口交互，尤其是 procfs 内的接口。

这很重要，因为许多 container escapes 和影响宿主机的技巧通常从读取或写入 `/proc` 或 `/sys` 下的特殊文件开始。如果这些位置被屏蔽，攻击者即使在容器内获得代码执行，也会失去对内核控制面有用部分的直接访问。

## 工作原理

运行时通常会屏蔽一些选定的路径，例如：

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

确切的列表取决于运行时和宿主机配置。重要的是，从容器的视角这些路径变得不可访问或被替换，尽管它们在宿主机上仍然存在。

## 实验

查看 Docker 暴露的 masked-path 配置：
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
检查工作负载内部的实际挂载行为：
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## 安全影响

掩蔽并不构成主要的隔离边界，但它移除了若干高价值的利用后目标。没有掩蔽，受损的容器可能能够检查内核状态，读取敏感的进程或密钥信息，或与不应该对应用可见的 procfs/sysfs 对象交互。

## 配置不当

主要错误是在为方便或调试而取消掩蔽大量路径。在 Podman 中，这可能表现为 `--security-opt unmask=ALL` 或有针对性的取消掩蔽。在 Kubernetes 中，过度广泛的 proc 暴露可能通过 `procMount: Unmasked` 出现。另一个严重问题是通过绑定挂载暴露主机的 `/proc` 或 `/sys`，这完全绕过了缩减容器视图的初衷。

## 滥用

如果掩蔽薄弱或不存在，首先识别哪些敏感的 procfs/sysfs 路径是可以直接访问的：
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
如果一个所谓被掩盖的路径可访问，请仔细检查：
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## Checks

The point of these checks is to determine which paths the runtime intentionally hid and whether the current workload still sees a reduced kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
有几点值得注意：

- 在经过加固的运行时中，较长的 masked-path 列表是正常的。
- 对敏感的 procfs 条目未被屏蔽应当进行更仔细的检查。
- 如果敏感路径可访问，且容器同时拥有强权限（capabilities）或广泛的挂载，则暴露风险更高。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker 定义了默认的 masked path 列表 | 暴露主机的 proc/sys 挂载，`--privileged` |
| Podman | Enabled by default | Podman 应用默认的 masked paths，除非被手动取消屏蔽 | `--security-opt unmask=ALL`，有针对性的取消屏蔽，`--privileged` |
| Kubernetes | Inherits runtime defaults | 使用底层 runtime 的 masking 行为，除非 Pod 设置削弱了 proc 的暴露 | `procMount: Unmasked`，特权工作负载模式，广泛的主机挂载 |
| containerd / CRI-O under Kubernetes | Runtime default | 通常应用 OCI/runtime 的 masked paths，除非被覆盖 | 直接修改运行时配置，相同的 Kubernetes 放宽路径 |

Masked paths 通常默认存在。主要的实际问题不是运行时缺少这些路径，而是故意取消屏蔽（unmasking）或主机绑定挂载，这些会抵消保护。
