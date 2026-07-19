# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths 是一种运行时保护机制，通过在特别敏感的、面向 kernel 的 filesystem 位置上进行 bind-mount 覆盖，或以其他方式使其无法访问，从而将这些位置隐藏于 container。其目的是阻止 workload 直接与普通 applications 不需要使用的 interfaces 交互，尤其是在 procfs 内部。

这很重要，因为许多 container escapes 和影响 host 的 tricks 都始于读取或写入 `/proc` 或 `/sys` 下的特殊文件。如果这些位置被 masked，即使 attacker 已经在 container 内获得了 code execution，也会失去对 kernel control surface 中有用部分的直接访问权限。

## Operation

Runtimes 通常会 mask 以下路径：

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

具体列表取决于 runtime 和 host configuration。重要特性是，从 container 的视角来看，该路径会变得无法访问或被替换，即使它仍然存在于 host 上。

## Lab

检查 Docker 暴露的 masked-path configuration：
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
检查 workload 内部的实际挂载行为：
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Masking 不会创建主要的 isolation boundary，但会移除多个高价值的 post-exploitation 目标。如果没有 masking，遭入侵的容器可能能够检查 kernel 状态，读取敏感的进程或 keying 信息，或与本不应对应用可见的 procfs/sysfs 对象交互。

## Misconfigurations

最常见的错误是为了方便或调试而取消对大类路径的 masking。在 Podman 中，这可能表现为 `--security-opt unmask=ALL` 或针对特定路径的 unmasking。在 Kubernetes 中，过于宽泛的 proc 暴露可能通过 `procMount: Unmasked` 出现。另一个严重问题是通过 bind mount 暴露 host 的 `/proc` 或 `/sys`，这会完全绕过 reduced container view 的概念。

## Abuse

如果 masking 薄弱或不存在，首先确定哪些敏感的 procfs/sysfs 路径可以直接访问：
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
如果一个 supposedly masked path 可以访问，请仔细检查它：
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
这些命令可以揭示：

- `/proc/timer_list` 可以暴露 host 的 timer 和 scheduler 数据。这主要是一个 reconnaissance primitive，但它可以确认 container 能够读取通常被隐藏的、面向 kernel 的信息。
- `/proc/keys` 的敏感性要高得多。根据 host 配置，它可能会暴露 keyring 条目、key 描述，以及使用 kernel keyring subsystem 的 host 服务之间的关系。
- `/sys/firmware` 有助于识别 boot mode、firmware interfaces 和 platform 详细信息，这些信息可用于 host fingerprinting，并帮助了解 workload 是否能看到 host-level state。
- `/proc/config.gz` 可能会暴露正在运行的 kernel configuration，这对于匹配公开的 kernel exploit prerequisites，或了解某个特定 feature 为什么可访问，非常有价值。
- `/proc/sched_debug` 会暴露 scheduler state，并且通常会打破这样一种直觉预期：PID namespace 应该完全隐藏无关的 process information。

有趣的结果包括直接读取这些文件、证明这些数据属于 host 而不是受限的 container view，或访问其他通常默认被 masked 的 procfs/sysfs 位置。

## 检查

这些检查的目的是确定 runtime 有意隐藏了哪些路径，以及当前 workload 是否仍能看到一个受限的、面向 kernel 的 filesystem。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
这里有哪些值得关注的内容：

- 在 hardened runtimes 中，较长的 masked-path 列表是正常现象。
- 敏感 procfs 条目缺少 masking，值得进一步检查。
- 如果某个敏感路径可访问，且 container 同时拥有强大的 capabilities 或范围广泛的 mounts，那么这种 exposure 更值得重视。

## Runtime 默认设置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Docker 定义默认的 masked path 列表 | 暴露 host proc/sys mounts、`--privileged` |
| Podman | 默认启用 | Podman 应用默认的 masked paths，除非手动取消 masking | `--security-opt unmask=ALL`、针对性 unmasking、`--privileged` |
| Kubernetes | 继承 runtime 默认设置 | 使用底层 runtime 的 masking 行为，除非 Pod 设置弱化 proc 暴露 | `procMount: Unmasked`、privileged workload 模式、范围广泛的 host mounts |
| containerd / CRI-O under Kubernetes | Runtime 默认设置 | 通常应用 OCI/runtime masked paths，除非被覆盖 | 直接修改 runtime 配置、相同的 Kubernetes 弱化路径 |

Masked paths 通常默认存在。主要的运行问题不是它们缺少于 runtime，而是有意 unmasking，或使用抵消该保护的 host bind mounts。
{{#include ../../../../banners/hacktricks-training.md}}
