# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths 是一种运行时保护机制，通过在特别敏感的、面向 kernel 的文件系统位置上进行 bind-mount，或以其他方式使其无法访问，从而对 container 隐藏这些位置。其目的是防止 workload 直接与普通应用不需要使用的接口交互，尤其是在 procfs 内部。

这一点很重要，因为许多 container escape 和影响 host 的技巧，都是从读取或写入 `/proc` 或 `/sys` 下的特殊文件开始的。如果这些位置被 masked，即使攻击者已经在 container 内获得了 code execution，也会失去对 kernel control surface 中一部分有用区域的直接访问权限。

## Operation

Runtimes 通常会 mask 某些路径，例如：

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

具体列表取决于 runtime 和 host 配置。重要的是，从 container 的角度来看，即使该路径仍存在于 host 上，它也会变得无法访问，或被替换。

## Lab

检查 Docker 暴露的 masked-path 配置：
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
检查 workload 内部的实际挂载行为：
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Masking 并不构成主要的 isolation boundary，但它会移除多个高价值的 post-exploitation 目标。如果没有 Masking，被攻陷的 container 可能可以检查 kernel state，读取敏感的 process 或 keying information，或与本不应对 application 可见的 procfs/sysfs objects 交互。

## Misconfigurations

最常见的错误是为了方便或 debugging 而取消对大范围 paths 的 Masking。在 Podman 中，这可能表现为 `--security-opt unmask=ALL` 或针对特定 paths 的 unmasking。在 Kubernetes 中，过于宽泛的 proc exposure 可能通过 `procMount: Unmasked` 出现。另一个严重问题是通过 bind mount 暴露 host `/proc` 或 `/sys`，这会完全绕过 reduced container view 的设计。

## Abuse

如果 Masking 较弱或不存在，应首先确定哪些敏感的 procfs/sysfs paths 可以直接访问：
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
如果一个据称已被 masked 的路径可以访问，请仔细检查它：
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
这些命令可以揭示的内容：

- `/proc/timer_list` 可以暴露主机的 timer 和 scheduler 数据。这主要是一种 reconnaissance primitive，但它可以确认 container 能够读取通常被隐藏的、面向 kernel 的信息。
- `/proc/keys` 的敏感性更高。根据主机配置，它可能会暴露 keyring entries、key descriptions，以及使用 kernel keyring subsystem 的主机服务之间的关系。
- `/sys/firmware` 有助于识别 boot mode、firmware interfaces 和 platform details，这些信息可用于 host fingerprinting，并帮助了解 workload 是否能够看到 host-level state。
- `/proc/config.gz` 可能会暴露正在运行的 kernel configuration，这对于匹配 public kernel exploit prerequisites，或了解某个特定 feature 为何可访问，非常有价值。
- `/proc/sched_debug` 会暴露 scheduler state，并且经常会打破一种直觉上的预期：PID namespace 应该能够完全隐藏无关的 process information。

有价值的结果包括直接读取这些文件、确认数据属于 host 而不是受限的 container view，或者访问其他通常默认会被 masked 的 procfs/sysfs 位置。

## Checks

这些检查的目的是确定 runtime 有意隐藏了哪些路径，以及当前 workload 是否仍然能够看到一个受限的、面向 kernel 的 filesystem。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
这里有什么值得关注的：

- 在 hardened runtimes 中，较长的 masked-path 列表是正常现象。
- 敏感 procfs 条目缺少 masking，值得进一步检查。
- 如果某个敏感路径可访问，同时 container 还具备强大的 capabilities 或 broad mounts，那么该暴露的影响会更大。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker 定义了默认的 masked path 列表 | 暴露 host proc/sys mounts、`--privileged` |
| Podman | Enabled by default | Podman 会应用默认的 masked paths，除非手动取消 masking | `--security-opt unmask=ALL`、针对性 unmasking、`--privileged` |
| Kubernetes | Inherits runtime defaults | 使用底层 runtime 的 masking 行为，除非 Pod 设置削弱了 proc 暴露保护 | `procMount: Unmasked`、privileged workload 模式、广泛的 host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | 通常会应用 OCI/runtime masked paths，除非被覆盖 | 直接修改 runtime 配置、相同的 Kubernetes weakening paths |

Masked paths 通常默认存在。主要的实际运行问题不是它们缺少于 runtime，而是有意进行 unmasking，或使用抵消该保护的 host bind mounts。

{{#include ../../../../banners/hacktricks-training.md}}
