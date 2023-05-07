# Mount Namespace

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

A mount namespace is a Linux kernel feature that provides isolation of the file system mount points seen by a group of processes. Each mount namespace has its own set of file system mount points, and **changes to the mount points in one namespace do not affect other namespaces**. This means that processes running in different mount namespaces can have different views of the file system hierarchy.

Mount namespaces are particularly useful in containerization, where each container should have its own file system and configuration, isolated from other containers and the host system.

### How it works:

1. When a new mount namespace is created, it is initialized with a **copy of the mount points from its parent namespace**. This means that, at creation, the new namespace shares the same view of the file system as its parent. However, any subsequent changes to the mount points within the namespace will not affect the parent or other namespaces.
2. When a process modifies a mount point within its namespace, such as mounting or unmounting a file system, the **change is local to that namespace** and does not affect other namespaces. This allows each namespace to have its own independent file system hierarchy.
3. Processes can move between namespaces using the `setns()` system call, or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWNS` flag. When a process moves to a new namespace or creates one, it will start using the mount points associated with that namespace.
4. **File descriptors and inodes are shared across namespaces**, meaning that if a process in one namespace has an open file descriptor pointing to a file, it can **pass that file descriptor** to a process in another namespace, and **both processes will access the same file**. However, the file's path may not be the same in both namespaces due to differences in mount points.

## Lab:

### Create different Namespaces

#### CLI

```bash
sudo unshare -m [--mount-proc] /bin/bash
```

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

If you run the previous line without `-f` you will get that error.\
The error is caused by the PID 1 process exits in the new namespace.

After bash start to run, bash will fork several new sub-processes to do somethings. If you run unshare without -f, bash will have the same pid as the current "unshare" process. The current "unshare" process call the unshare systemcall, create a new pid namespace, but the current "unshare" process is not in the new pid namespace. It is the desired behavior of linux kernel: process A creates a new namespace, the process A itself won't be put into the new namespace, only the sub-processes of process A will be put into the new namespace. So when you run:

```
unshare -p /bin/bash
```

The unshare process will exec /bin/bash, and /bin/bash forks several sub-processes, the first sub-process of bash will become PID 1 of the new namespace, and the subprocess will exit after it completes its job. So the PID 1 of the new namespace exits.

The PID 1 process has a special function: it should become all the orphan processes' parent process. If PID 1 process in the root namespace exits, kernel will panic. If PID 1 process in a sub namespace exits, linux kernel will call the disable\_pid\_allocation function, which will clean the PIDNS\_HASH\_ADDING flag in that namespace. When linux kernel create a new process, kernel will call alloc\_pid function to allocate a PID in a namespace, and if the PIDNS\_HASH\_ADDING flag is not set, alloc\_pid function will return a -ENOMEM error. That's why you got the "Cannot allocate memory" error.

You can resolve this issue by use the '-f' option:

```
unshare -fp /bin/bash
```

If you run unshare with '-f' option, unshare will fork a new process after it create the new pid namespace. And run /bin/bash in the new process. The new process will be the pid 1 of the new pid namespace. Then bash will also fork several sub-processes to do some jobs. As bash itself is the pid 1 of the new pid namespace, its sub-processes can exit without any problem.

Copied from [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker

```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```

### &#x20;Check which namespace is your process in

```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```

### Find all Mount namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Enter inside a Mount namespace

```bash
nsenter -m TARGET_PID --pid /bin/bash
```

Also, you can only **enter in another process namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/mnt`).

Because new mounts are only accessible within the namespace it's possible that a namespace contains sensitive information that can only be accessible from it.

### Mount something

```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
