# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

The PID (Process IDentifier) namespace is a feature in the Linux kernel that provides process isolation by enabling a group of processes to have their own set of unique PIDs, separate from the PIDs in other namespaces. This is particularly useful in containerization, where process isolation is essential for security and resource management.

When a new PID namespace is created, the first process in that namespace is assigned PID 1. This process becomes the "init" process of the new namespace and is responsible for managing other processes within the namespace. Each subsequent process created within the namespace will have a unique PID within that namespace, and these PIDs will be independent of PIDs in other namespaces.

From the perspective of a process within a PID namespace, it can only see other processes in the same namespace. It is not aware of processes in other namespaces, and it cannot interact with them using traditional process management tools (e.g., `kill`, `wait`, etc.). This provides a level of isolation that helps prevent processes from interfering with one another.

### How it works:

1. When a new process is created (e.g., by using the `clone()` system call), the process can be assigned to a new or existing PID namespace. **If a new namespace is created, the process becomes the "init" process of that namespace**.
2. The **kernel** maintains a **mapping between the PIDs in the new namespace and the corresponding PIDs** in the parent namespace (i.e., the namespace from which the new namespace was created). This mapping **allows the kernel to translate PIDs when necessary**, such as when sending signals between processes in different namespaces.
3. **Processes within a PID namespace can only see and interact with other processes in the same namespace**. They are not aware of processes in other namespaces, and their PIDs are unique within their namespace.
4. When a **PID namespace is destroyed** (e.g., when the "init" process of the namespace exits), **all processes within that namespace are terminated**. This ensures that all resources associated with the namespace are properly cleaned up.

## Lab:

### Create different Namespaces

#### CLI

```bash
sudo unshare -pf --mount-proc /bin/bash
```

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

   - The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
   - Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
   - The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

   - The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
   - The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
   - Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

#### Docker

```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```

### Check which namespace are your process in

```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```

### Find all PID namespaces

```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```

Note that the root use from the initial (default) PID namespace can see all the processes, even the ones in new PID names paces, thats why we can see all the PID namespaces.

### Enter inside a PID namespace

```bash
nsenter -t TARGET_PID --pid /bin/bash
```

When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **enter in another process PID namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Recent Exploitation Notes

### CVE-2025-31133: abusing `maskedPaths` to reach host PIDs

runc ≤1.2.7 allowed attackers that control container images or `runc exec` workloads to replace the container-side `/dev/null` just before the runtime masked sensitive procfs entries. When the race succeeds, `/dev/null` can be turned into a symlink pointing at any host path (for example `/proc/sys/kernel/core_pattern`), so the new container PID namespace suddenly inherits read/write access to host-global procfs knobs even though it never left its own namespace. Once `core_pattern` or `/proc/sysrq-trigger` is writable, generating a coredump or triggering SysRq yields code execution or denial of service in the host PID namespace.

Practical workflow:

1. Build an OCI bundle whose rootfs replaces `/dev/null` with a link to the host path you want (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Start the container before the fix so runc bind-mounts the host procfs target over the link.
3. Inside the container namespace, write to the now-exposed procfs file (e.g., point `core_pattern` to a reverse shell helper) and crash any process to force the host kernel to execute your helper as PID 1 context.

You can quickly audit whether a bundle is masking the right files before starting it:

```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```

If the runtime is missing a masking entry you expect (or skips it because `/dev/null` vanished), treat the container as having potential host PID visibility.

### Namespace injection with `insject`

NCC Group’s `insject` loads as an LD_PRELOAD payload that hooks a late stage in the target program (default `main`) and issues a sequence of `setns()` calls after `execve()`. That lets you attach from the host (or another container) into a victim’s PID namespace *after* its runtime initialized, preserving its `/proc/<pid>` view without having to copy binaries into the container filesystem. Because `insject` can defer joining the PID namespace until it forks, you can keep one thread in the host namespace (with CAP_SYS_PTRACE) while another thread executes in the target PID namespace, creating powerful debugging or offensive primitives.

Example usage:

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Key takeaways when abusing or defending against namespace injection:

- Use `-S/--strict` to force `insject` to abort if threads already exist or namespace joins fail, otherwise you may leave partly-migrated threads straddling host and container PID spaces.
- Never attach tools that still hold writable host file descriptors unless you also join the mount namespace—otherwise any process inside the PID namespace can ptrace your helper and reuse those descriptors to tamper with host resources.

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
