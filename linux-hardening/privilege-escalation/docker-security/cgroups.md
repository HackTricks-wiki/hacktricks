# CGroups

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

**Linux control groups**, also known as cgroups, are a Linux kernel feature that allows you to **limit**, police, and prioritize **system resources** for a collection of processes. Cgroups provide a way to **manage and isolate the resource usage** (CPU, memory, disk I/O, network, etc.) of groups of processes in a system. This can be useful for many purposes, such as limiting the resources available to a particular group of processes, isolating certain types of workloads from others, or prioritizing the use of system resources between different groups of processes.

There are **two versions of cgroups**, 1 and 2, and both are currently in use and can be configured simultaneously on a system. The most **significant difference** between cgroups version 1 and **version 2** is that the latter introduced a new hierarchical organization for cgroups, where groups can be arranged in a **tree-like structure** with parent-child relationships. This allows for a more flexible and fine-grained control over the allocation of resources between different groups of processes.

In addition to the new hierarchical organization, cgroups version 2 also introduced **several other changes and improvements**, such as support for **new resource controllers**, better support for legacy applications, and improved performance.

Overall, cgroups **version 2 offers more features and better performance** than version 1, but the latter may still be used in certain scenarios where compatibility with older systems is a concern.

You can list the v1 and v2 cgroups for any process by looking at its cgroup file in /proc/\<pid>. You can start by looking at your shell’s cgroups with this command:

```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```

Don’t be alarmed if the **output is significantly shorter** on your system; this just means that you probably **have only cgroups v2**. Every line of output here starts with a number and is a different cgroup. Here are some pointers on how to read it:

* **Numbers 2–12 are for cgroups v1**. The **controllers** for those are listed next to the number.
* **Number 1** is also for **version 1**, but it does not have a controller. This cgroup is for **management purposes** only (in this case, systemd configured it).
* The last line, **number 0**, is for **cgroups v2**. No controllers are visible here. On a system that doesn’t have cgroups v1, this will be the only line of output.
* **Names are hierarchical and look like parts of file paths**. You can see in this example that some of the cgroups are named /user.slice and others /user.slice/user-1000.slice/session-2.scope.
* The name /testcgroup was created to show that in cgroups v1, the cgroups for a process can be completely independent.
* **Names under user.slice** that include session are login sessions, assigned by systemd. You’ll see them when you’re looking at a shell’s cgroups. The **cgroups** for your **system services** will be **under system.slice**.

### Viewing cgroups

Cgroups are typically **accessed through the filesystem**. This is in contrast to the traditional Unix system call interface for interacting with the kernel.\
To explore the cgroup setup of a shell, you can look in the `/proc/self/cgroup` file to find the shell's cgroup, and then navigate to the `/sys/fs/cgroup` (or `/sys/fs/cgroup/unified`) directory and look for a **directory with the same name as the cgroup**. Changing to this directory and looking around will allow you to see the various **settings and resource usage information for the cgroup**.

<figure><img src="../../../.gitbook/assets/image (10) (2).png" alt=""><figcaption></figcaption></figure>

Among the many files that can be here, **the primary cgroup interface files begin with `cgroup`**. Start by looking at `cgroup.procs` (using cat is fine), which lists the processes in the cgroup. A similar file, `cgroup.threads`, also includes threads.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

Most cgroups used for shells have these two controllers, which can control the **amount of memory** used and the **total number of processes in the cgroup**. To interact with a controller, look for the **files that match the controller prefix**. For example, if you want to see the number of threads running in the cgroup, consult pids.current:

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

A value of **max means that this cgroup has no specific limit**, but because cgroups are hierarchical, a cgroup back down the subdirectory chain might limit it.

### Manipulating and Creating cgroups

To put a process into a cgroup, **write its PID to its `cgroup.procs` file as root:**

```shell-session
# echo pid > cgroup.procs
```

This is how many changes to cgroups work. For example, if you want to **limit the maximum number of PIDs of a cgroup** (to, say, 3,000 PIDs), do it as follows:

```shell-session
# echo 3000 > pids.max
```

**Creating cgroups is trickier**. Technically, it’s as easy as creating a subdirectory somewhere in the cgroup tree; when you do so, the kernel automatically creates the interface files. If a cgroup has no processes, you can remove the cgroup with rmdir even with the interface files present. What can trip you up are the rules governing cgroups, including:

* You can put **processes only in outer-level (“leaf”) cgroups**. For example, if you have cgroups named /my-cgroup and /my-cgroup/my-subgroup, you can’t put processes in /my-cgroup, but /my-cgroup/my-subgroup is okay. (An exception is if the cgroups have no controllers, but let’s not dig further.)
* A cgroup **can’t have a controller that isn’t in its parent cgroup**.
* You must explicitly **specify controllers for child cgroups**. You do this through the `cgroup.subtree_control` file; for example, if you want a child cgroup to have the cpu and pids controllers, write +cpu +pids to this file.

An exception to these rules is the **root cgroup** found at the bottom of the hierarchy. You can **place processes in this cgroup**. One reason you might want to do this is to detach a process from systemd’s control.

Even with no controllers enabled, you can see the CPU usage of a cgroup by looking at its cpu.stat file:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Because this is the accumulated CPU usage over the entire lifespan of the cgroup, you can see how a service consumes processor time even if it spawns many subprocesses that eventually terminate.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
