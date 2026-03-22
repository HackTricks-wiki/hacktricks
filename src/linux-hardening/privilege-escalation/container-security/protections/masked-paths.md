# 屏蔽路径

{{#include ../../../../banners/hacktricks-training.md}}

屏蔽路径是一种运行时保护，通过在这些位置上进行 bind-mount 或以其他方式使其不可访问，来对容器隐藏那些特别敏感的面向内核的文件系统位置。其目的是阻止工作负载直接与普通应用不需要的接口交互，尤其是在 procfs 中。

之所以重要，是因为许多 container escapes 和影响主机的技巧都是通过读取或写入 `/proc` 或 `/sys` 下的特殊文件开始的。如果这些位置被屏蔽，攻击者即使在容器内获得代码执行，也会失去对内核控制面某些有用部分的直接访问。

## 工作原理

运行时通常会屏蔽一些选定的路径，例如：

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

具体列表取决于运行时和主机配置。重要的特性是，从容器的视角这些路径会变得不可访问或被替换，即便它们在主机上仍然存在。

## 实验

检查 Docker 暴露的 masked-path 配置：
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
检查工作负载内部的实际挂载行为：
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

掩蔽并不构成主要的隔离边界，但它会移除若干高价值的 post-exploitation 目标。如果没有掩蔽，被攻破的容器可能能够检查内核状态、读取敏感的进程或密钥信息，或与应用程序不应可见的 procfs/sysfs 对象交互。

## Misconfigurations

主要错误是为了方便或调试而对大量路径进行取消掩蔽。在 Podman 中，这可能表现为 `--security-opt unmask=ALL` 或有针对性的 unmask。在 Kubernetes 中，过度宽泛的 proc 暴露可能表现为 `procMount: Unmasked`。另一个严重问题是通过 bind mount 暴露宿主机的 `/proc` 或 `/sys`，这完全绕过了容器视图被裁减的初衷。

## Abuse

如果掩蔽薄弱或不存在，应首先识别哪些敏感的 procfs/sysfs 路径是直接可访问的：
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
如果一个看似被掩盖的路径可访问，请仔细检查它：
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
这些命令可能揭示的信息：

- `/proc/timer_list` 可以暴露主机的计时器和调度器数据。这主要是一个侦察原语，但它确认容器可以读取通常被隐藏的面向内核的信息。
- `/proc/keys` 更加敏感。取决于主机配置，它可能揭示 keyring 条目、密钥描述，以及使用 kernel keyring 子系统的主机服务之间的关系。
- `/sys/firmware` 有助于识别启动模式、固件接口和平台细节，这些对于主机指纹识别以及判断工作负载是否看到主机级状态非常有用。
- `/proc/config.gz` 可能揭示正在运行的内核配置，这对于匹配公开的内核 exploit 先决条件或理解为什么某个特性可达非常有价值。
- `/proc/sched_debug` 会暴露调度器状态，并且常常绕过直觉上认为 PID namespace 应该完全隐藏无关进程信息的期望。

有趣的结果包括直接读取这些文件、证明数据属于主机而不是受限容器视图，或者访问其他通常默认被屏蔽的 procfs/sysfs 位置。

## 检查

这些检查的目的是确定运行时故意隐藏了哪些路径，以及当前工作负载是否仍然看到一个被减少的面向内核的文件系统。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
值得注意的是：

- 在强化的 runtimes 中，较长的屏蔽路径列表是正常的。
- 对敏感的 procfs 条目缺少屏蔽值得进一步检查。
- 如果敏感路径可访问，且容器还具有较高的权限或广泛的挂载，暴露的风险会更大。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Docker 定义了默认的屏蔽路径列表 | 暴露主机的 proc/sys 挂载， `--privileged` |
| Podman | 默认启用 | Podman 应用默认的屏蔽路径，除非手动取消屏蔽 | `--security-opt unmask=ALL`、有针对性的取消屏蔽、 `--privileged` |
| Kubernetes | 继承运行时默认设置 | 使用底层 runtime 的屏蔽行为，除非 Pod 设置削弱了 proc 暴露 | `procMount: Unmasked`、特权工作负载模式、广泛的主机挂载 |
| containerd / CRI-O under Kubernetes | 运行时默认 | 通常应用 OCI/runtime 的屏蔽路径，除非被覆盖 | 直接修改运行时配置，与 Kubernetes 相同的弱化路径 |

屏蔽路径通常默认存在。主要的操作问题并不是运行时缺少这些路径，而是故意取消屏蔽或主机的绑定挂载抵消了该保护措施。
{{#include ../../../../banners/hacktricks-training.md}}
