# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths 是一种运行时保护机制，通过在特别敏感、面向内核的文件系统位置上进行 bind mount，或以其他方式使其无法访问，从而将其对容器隐藏。OCI runtime specification 将 `maskedPaths` 定义为容器内不可读取的绝对路径。 <sup>[[1]](#references)</sup>

这很重要，因为许多容器逃逸和影响主机的技巧，都是从读取或写入 `/proc` 或 `/sys` 下的特殊文件开始的。如果这些位置被屏蔽，即使攻击者已在容器内获得代码执行权限，也无法直接访问内核控制面中的一部分有用接口。

## Operation

运行时通常会屏蔽以下选定路径：

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

具体列表取决于运行时和主机配置。关键在于，从容器的视角来看，这些路径变得无法访问或被替换，即使它们仍然存在于主机上。

## Lab

检查 Docker 暴露的 masked-path 配置：

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

检查工作负载内部的实际挂载行为：

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

列出的路径不一定可读：runc 可以用 `/dev/null` bind mount 屏蔽文件，并用只读的空 tmpfs 屏蔽目录。检查确切的挂载点，而不只是看 `ls` 是否成功。 <sup>[[4]](#references)</sup>

## Security Impact

屏蔽不会构成主要的隔离边界，但会移除多个高价值的 post-exploitation 目标。未进行屏蔽时，遭到入侵的容器可能能够检查内核状态、读取敏感的进程或密钥信息，或与本不应对应用程序可见的 procfs/sysfs 对象交互。

## Misconfigurations

主要错误是为了方便或调试而取消屏蔽大类路径。在 Podman 中，这可能表现为 `--security-opt unmask=ALL` 或针对特定路径取消屏蔽。 <sup>[[2]](#references)</sup> 在 Kubernetes 中，过度开放 proc 可能通过 `procMount: Unmasked` 实现；当前 Kubernetes 要求此设置同时使用 `spec.hostUsers: false`（即 user namespace），而 1.12–1.29 版本并未强制要求这一点。 <sup>[[3]](#references)</sup> 另一个严重问题是通过 bind mount 暴露宿主机的 `/proc` 或 `/sys`，这会完全绕过精简容器视图的设计。

## Abuse

如果屏蔽较弱或缺失，首先找出哪些敏感 procfs/sysfs 路径可以直接访问：

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

如果某个据称已被屏蔽的路径仍可访问，请仔细检查它：

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

这些命令可以揭示以下信息：

- `/proc/timer_list` 可能暴露主机计时器和调度器数据。这主要是一种侦察手段，但可以确认容器能够读取通常被隐藏的内核相关信息。
- `/proc/keys` 仅列出读取者具有 **view** 权限的密钥元数据，并受 LSM 检查约束。它可以揭示密钥类型和描述，但不会转储密钥负载。 <sup>[[6]](#references)</sup>
- `/sys/firmware` 有助于识别启动模式、固件接口和平台详情，可用于主机指纹识别，也有助于了解工作负载是否能看到主机级状态。
- `/proc/config.gz` 可能会暴露正在运行的内核配置，这对匹配公开内核漏洞利用的前置条件，或了解为何某项特定功能可被访问，很有价值。
- `/proc/sched_debug` 会暴露调度器状态，而且常常会打破一种直觉预期：PID namespace 应能完全隐藏无关进程信息。

值得关注的结果包括：能够直接读取这些文件、数据显然属于主机而非受限的容器视图，或能够访问其他默认情况下通常会被屏蔽的 procfs/sysfs 位置。

### 容器启动期间的屏蔽源竞争条件

在存在漏洞的 runc 实现中，文件屏蔽依赖容器的 `/dev/null` inode。能够安排共享挂载的并发容器（包括并行 BuildKit 步骤）的攻击者，可以在启动时进行竞争，在 runc 将 `/dev/null` 绑定到被屏蔽的 procfs 文件之前将其移除。随后，运行时会将缺失的**源**误认为屏蔽目标不存在，并静默跳过这些文件屏蔽。此故障取决于运行时设置期间发生的竞争；启动后移除 `/dev/null` 不会撤销已安装的屏蔽。 <sup>[[4]](#references)</sup>

完成受控测试后，将请求的屏蔽列表与新容器内的精确挂载点进行比较。 <sup>[[4]](#references)</sup> `findmnt -M` 会检查指定的挂载点，而不会回退到父挂载；如果没有 `findmnt`，请检查 `/proc/self/mountinfo`。 <sup>[[5]](#references)</sup> `ls` 成功或 `cat` 输出为空，都不能证明屏蔽不存在。 <sup>[[4]](#references)</sup>

使用[以下检查](#checks)，将请求的屏蔽与新容器中的精确挂载进行比较。

如果常规权限和 LSM 策略允许，跳过文件屏蔽可能会暴露 procfs 数据。它本身**不会**使 `/proc/sys` 可写：那是单独的 [read-only-path](read-only-paths.md) 控制。可将 bind mount 重定向到可写 procfs 目标的另一种 `/dev/null` 符号链接替换问题，详见 [PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs)。 <sup>[[4]](#references)</sup>

## Checks

这些检查旨在确定运行时有意隐藏了哪些路径，以及当前工作负载是否仍能看到受限的内核相关文件系统。

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

使用精确的 mount 检查，因为被屏蔽的文件仍可能存在，而从 `/dev/null` 读取时可能返回空结果。挂载点缺失是需要调查的发现，但本身并不能证明主机数据可读。 <sup>[[4]](#references)[[5]](#references)</sup>

这里值得关注的是：

- 在经过加固的运行时中，屏蔽路径列表很长是正常的。
- 对敏感 procfs 条目缺少屏蔽措施，值得进一步检查。
- 如果敏感路径可访问，且容器同时拥有强大的 capabilities 或范围广泛的挂载，那么这种暴露就更值得重视。

## 运行时默认设置

| 运行时 / 平台 | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Docker 定义了默认的屏蔽路径列表 | 暴露主机 proc/sys 挂载、`--privileged` |
| Podman | 默认启用 | Podman 会应用默认屏蔽路径，除非手动取消屏蔽 | `--security-opt unmask=ALL`、针对特定路径取消屏蔽、`--privileged` |
| Kubernetes | 继承运行时默认设置 | 使用底层运行时的屏蔽行为，除非 Pod 设置削弱了 proc 的暴露限制 | `procMount: Unmasked`（当前版本要求 `hostUsers: false`）、特权工作负载模式、范围广泛的主机挂载 |
| Kubernetes 下的 containerd / CRI-O | 运行时默认设置 | 通常会应用 OCI/运行时的屏蔽路径，除非被覆盖 | 直接修改运行时配置、采用相同的 Kubernetes 弱化方式 |

屏蔽路径通常默认存在。主要的运维问题并非运行时缺少这些路径，而是有人刻意取消屏蔽，或使用主机 bind mount 抵消了这项保护。

## References

- [1] [Open Container Initiative - Linux 容器配置：屏蔽路径](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman 文档 - `podman run` 安全选项](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes 文档 - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc 安全公告：masked-path 挂载源竞争条件](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8) 手册](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7) 手册](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
