# CGroups

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

**Linux Control Groups**, or **cgroups**, are a feature of the Linux kernel that allows the allocation, limitation, and prioritization of system resources like CPU, memory, and disk I/O among process groups. They offer a mechanism for **managing and isolating the resource usage** of process collections, beneficial for purposes such as resource limitation, workload isolation, and resource prioritization among different process groups.

There are **two versions of cgroups**: version 1 and version 2. Both can be used concurrently on a system. The primary distinction is that **cgroups version 2** introduces a **hierarchical, tree-like structure**, enabling more nuanced and detailed resource distribution among process groups. Additionally, version 2 brings various enhancements, including:

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

The output structure is as follows:

* **Numbers 2–12**: cgroups v1, with each line representing a different cgroup. Controllers for these are specified adjacent to the number.
* **Number 1**: Also cgroups v1, but solely for management purposes (set by, e.g., systemd), and lacks a controller.
* **Number 0**: Represents cgroups v2. No controllers are listed, and this line is exclusive on systems only running cgroups v2.
* The **names are hierarchical**, resembling file paths, indicating the structure and relationship between different cgroups.
* **Names like /user.slice or /system.slice** specify the categorization of cgroups, with user.slice typically for login sessions managed by systemd and system.slice for system services.

### Viewing cgroups

The filesystem is typically utilized for accessing **cgroups**, diverging from the Unix system call interface traditionally used for kernel interactions. To investigate a shell's cgroup configuration, one should examine the **/proc/self/cgroup** file, which reveals the shell's cgroup. Then, by navigating to the **/sys/fs/cgroup** (or **`/sys/fs/cgroup/unified`**) directory and locating a directory that shares the cgroup's name, one can observe various settings and resource usage information pertinent to the cgroup.

![Cgroup Filesystem](<../../../.gitbook/assets/image (1128).png>)

The key interface files for cgroups are prefixed with **cgroup**. The **cgroup.procs** file, which can be viewed with standard commands like cat, lists the processes within the cgroup. Another file, **cgroup.threads**, includes thread information.

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

Cgroups managing shells typically encompass two controllers that regulate memory usage and process count. To interact with a controller, files bearing the controller's prefix should be consulted. For instance, **pids.current** would be referenced to ascertain the count of threads in the cgroup.

![Cgroup Memory](<../../../.gitbook/assets/image (677).png>)

The indication of **max** in a value suggests the absence of a specific limit for the cgroup. However, due to the hierarchical nature of cgroups, limits might be imposed by a cgroup at a lower level in the directory hierarchy.

### Manipulating and Creating cgroups

Processes are assigned to cgroups by **writing their Process ID (PID) to the `cgroup.procs` file**. This requires root privileges. For instance, to add a process:

```bash
echo [pid] > cgroup.procs
```

Similarly, **modifying cgroup attributes, like setting a PID limit**, is done by writing the desired value to the relevant file. To set a maximum of 3,000 PIDs for a cgroup:

```bash
echo 3000 > pids.max
```

**Creating new cgroups** involves making a new subdirectory within the cgroup hierarchy, which prompts the kernel to automatically generate necessary interface files. Though cgroups without active processes can be removed with `rmdir`, be aware of certain constraints:

* **Processes can only be placed in leaf cgroups** (i.e., the most nested ones in a hierarchy).
* **A cgroup cannot possess a controller absent in its parent**.
* **Controllers for child cgroups must be explicitly declared** in the `cgroup.subtree_control` file. For example, to enable CPU and PID controllers in a child cgroup:

```bash
echo "+cpu +pids" > cgroup.subtree_control
```

The **root cgroup** is an exception to these rules, allowing direct process placement. This can be used to remove processes from systemd management.

**Monitoring CPU usage** within a cgroup is possible through the `cpu.stat` file, displaying total CPU time consumed, helpful for tracking usage across a service's subprocesses:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>CPU usage statistics as shown in the cpu.stat file</p></figcaption></figure>

## References

* **Book: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

