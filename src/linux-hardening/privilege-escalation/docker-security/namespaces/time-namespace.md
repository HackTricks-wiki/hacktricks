# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

The time namespace in Linux allows for per-namespace offsets to the system monotonic and boot-time clocks. It is commonly used in Linux containers to change the date/time within a container and adjust clocks after restoring from a checkpoint or snapshot.

## Lab:

### Create different Namespaces

#### CLI

```bash
sudo unshare -T [--mount-proc] /bin/bash
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
```

### Check which namespace is your process in

```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```

### Find all Time namespaces

```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

### Enter inside a Time namespace

```bash
nsenter -T TARGET_PID --pid /bin/bash
```


## Manipulating Time Offsets

Starting with Linux 5.6, two clocks can be virtualised per time namespace:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Their per-namespace deltas are exposed (and can be modified) through the file `/proc/<PID>/timens_offsets`:

```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```

The file contains two lines – one per clock – with the offset in **nanoseconds**.  Processes that hold **CAP_SYS_TIME** _in the time namespace_ can change the value:

```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```

If you need the wall clock (`CLOCK_REALTIME`) to change as well you still have to rely on classic mechanisms (`date`, `hwclock`, `chronyd`, …); it is **not** namespaced.


### `unshare(1)` helper flags (util-linux ≥ 2.38)

```
sudo unshare -T \
            --monotonic="+24h"  \
            --boottime="+7d"    \
            --mount-proc         \
            bash
```

The long options automatically write the chosen deltas to `timens_offsets` right after the namespace is created, saving a manual `echo`.

---

## OCI & Runtime support

* The **OCI Runtime Specification v1.1** (Nov 2023) added a dedicated `time` namespace type and the `linux.timeOffsets` field so that container engines can request time virtualisation in a portable way.
* **runc >= 1.2.0** implements that part of the spec.  A minimal `config.json` fragment looks like:
  ```json
  {
    "linux": {
      "namespaces": [
        {"type": "time"}
      ],
      "timeOffsets": {
        "monotonic": 86400,
        "boottime": 600
      }
    }
  }
  ```
  Then run the container with `runc run <id>`.

>  NOTE: runc **1.2.6** (Feb 2025) fixed an "exec into container with private timens" bug that could lead to a hang and potential DoS.  Make sure you are on ≥ 1.2.6 in production.

---

## Security considerations

1. **Required capability** – A process needs **CAP_SYS_TIME** inside its user/time namespace to change the offsets.  Dropping that capability in the container (default in Docker & Kubernetes) prevents tampering.
2. **No wall-clock changes** – Because `CLOCK_REALTIME` is shared with the host, attackers cannot spoof certificate lifetimes, JWT expiry, etc. via timens alone.
3. **Log / detection evasion** – Software that relies on `CLOCK_MONOTONIC` (e.g. rate-limiters based on uptime) can be confused if the namespace user adjusts the offset.  Prefer `CLOCK_REALTIME` for security-relevant timestamps.
4. **Kernel attack surface** – Even with `CAP_SYS_TIME` removed, the kernel code remains accessible; keep the host patched. Linux 5.6 → 5.12 received multiple timens bug-fixes (NULL-deref, signedness issues).

### Hardening checklist

* Drop `CAP_SYS_TIME` in your container runtime default profile.
* Keep runtimes updated (runc ≥ 1.2.6, crun ≥ 1.12).
* Pin util-linux ≥ 2.38 if you rely on the `--monotonic/--boottime` helpers.
* Audit in-container software that reads **uptime** or **CLOCK_MONOTONIC** for security-critical logic.

## References

* man7.org – Time namespaces manual page: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: new time and RDT namespaces" (Nov 15 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}



