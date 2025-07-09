# Network Namespace
{{#include /banners/hacktricks-training.md}}


{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

A network namespace is a Linux kernel feature that provides isolation of the network stack, allowing **each network namespace to have its own independent network configuration**, interfaces, IP addresses, routing tables, and firewall rules. This isolation is useful in various scenarios, such as containerization, where each container should have its own network configuration, independent of other containers and the host system.

### How it works:

1. When a new network namespace is created, it starts with a **completely isolated network stack**, with **no network interfaces** except for the loopback interface (lo). This means that processes running in the new network namespace cannot communicate with processes in other namespaces or the host system by default.
2. **Virtual network interfaces**, such as veth pairs, can be created and moved between network namespaces. This allows for establishing network connectivity between namespaces or between a namespace and the host system. For example, one end of a veth pair can be placed in a container's network namespace, and the other end can be connected to a **bridge** or another network interface in the host namespace, providing network connectivity to the container.
3. Network interfaces within a namespace can have their **own IP addresses, routing tables, and firewall rules**, independent of other namespaces. This allows processes in different network namespaces to have different network configurations and operate as if they are running on separate networked systems.
4. Processes can move between namespaces using the `setns()` system call, or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWNET` flag. When a process moves to a new namespace or creates one, it will start using the network configuration and interfaces associated with that namespace.

## Lab:

### Create different Namespaces

#### CLI

```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

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

#### Docker

```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```

### Check which namespace is your process in

```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```

### Find all Network namespaces

```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

### Enter inside a Network namespace

```bash
nsenter -n TARGET_PID --pid /bin/bash
```

Also, you can only **enter in another process namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/net`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
