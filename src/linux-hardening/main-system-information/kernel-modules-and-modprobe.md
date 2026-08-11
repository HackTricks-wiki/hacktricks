# Kernel Modules 和 modprobe 滥用

{{#include ../../banners/hacktricks-training.md}}

## Kernel module 和 module-loading 配置错误

在 Linux privilege escalation review 期间，Kernel module 支持是一个高影响区域。不要仅凭每条 unsigned-module 消息就认为存在可利用漏洞，而应利用这些信息回答实际问题。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 当前用户能否通过 `sudo`、capabilities 或可写的 helper 路径加载 modules？
- module loading 是否仍处于启用状态？
- module signature enforcement 是否已禁用？
- module directories 或 module files 是否可写？
- 能否读取 kernel logs 以确认发生了什么？

快速 triage 从以下 module-status、signature、logging 和 module-tree 检查开始。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
解释：

- `modules_disabled=1` 表示模块既不能被加载，也不能被卸载，并且在重启前无法将该值重置为 `0`。<sup>[[1]](#references)</sup>
- 内核命令行中的 `module.sig_enforce=1` 或 `CONFIG_MODULE_SIG_FORCE=y` 要求模块具有有效签名；否则，未签名模块可能被加载并使内核 taint。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` 不对 `dmesg` 施加任何限制；当其值为 `1` 时，访问需要 `CAP_SYSLOG`。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 下可写的路径很危险，因为 `modprobe` 加载模块时会搜索该目录树及其依赖数据。<sup>[[8]](#references)</sup>

### 加载模块并读取内核输出

如果你获得了加载本地模块的合法许可，`insmod` 会插入你提供的确切 `.ko` 文件。模块的 init 函数会作为加载过程的一部分运行，而使用 `printk()` 写入的消息会进入内核日志缓冲区，通常使用 `dmesg` 读取。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

最小化的审查流程使用 `modinfo` 检查元数据，使用 `insmod` 和 `rmmod` 加载及移除模块，使用 `lsmod` 确认加载状态，并使用 `dmesg` 检查内核日志。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
如果 `sudo -l` 允许使用 `insmod`、`modprobe` 或它们的 wrapper，应将其视为 critical：`sudo -l` 会列出调用用户的权限，而加载 kernel module 需要 `CAP_SYS_MODULE`。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

允许用户通过 sudo 运行 `insmod` 的规则，不能与允许运行普通管理辅助工具相提并论。模块的初始化代码会作为插入过程的一部分运行，因此实际的审查问题是：该用户是否能够选择或修改要加载的模块。<sup>[[3]](#references)</sup>

以下通用审查流程会针对候选模块，重复执行检查、加载、状态、日志和移除检查。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
如果用户能够提供任意 `.ko`，在授权评估中，该规则应被视为完整的系统 compromise。更安全的操作方式是避免通过 sudo 委托加载模块；如果无法避免，则应限制确切路径、所有权、权限、签名策略和移除流程。<sup>[[3]](#references)[[10]](#references)</sup>

对于受控实验室中无害的模块构建模式，下面给出了最小的源代码和 Makefile；`make -C /lib/modules/$(uname -r)/build M=$PWD` 形式遵循 kernel 针对外部模块记录的 kbuild 工作流程。<sup>[[5]](#references)[[7]](#references)</sup>
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
仅在经授权的实验室中构建和加载；kbuild 构建外部模块，而加载/移除命令调用内核模块接口。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` 滥用检查

`kernel.modprobe` 指定了内核在模块自动加载请求时执行的 userspace helper；此 sysctl 影响自动加载，不影响显式模块插入。如果攻击者能够将其修改为可写的可执行路径，并触发模块请求，该 helper 就会成为特权代码执行路径。<sup>[[1]](#references)</sup>

通过内核 sysctl 接口检查当前 helper 路径，并检查目标的所有权和模式。<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
检查 sysctl、委派的 sudo 规则或文件 capabilities 是否可以被操控。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
以下仅限实验室使用的模式会更改 helper 路径，并触发一个有文档记录的 module-autoload 请求；只能在隔离且经过授权的系统上使用。<sup>[[1]](#references)</sup>

在当前 Linux 内核中，不要使用未知 executable 作为通用触发器：传统的自定义 binary-format module autoloading 已在 Linux 6.14 中移除，而内核文档将未知 filesystem type 标识为 module-autoload 请求路径。<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
在经过加固的系统上，当权限阻止非特权用户写入 `kernel.modprobe`、helper 路径不可写，或模块自动加载被禁用时，此操作应失败。<sup>[[1]](#references)</sup>

### 可写 `/lib/modules` 审查

可写的模块目录可能导致模块替换、恶意模块植入或自动加载滥用，具体取决于之后调用 `modprobe` 的方式；`modprobe` 会搜索 `/lib/modules/$(uname -r)`，并在解析模块时使用其中的依赖数据。<sup>[[8]](#references)</sup>

审查活动内核版本模块树下可写的模块文件以及依赖项/别名元数据。<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
如果发现可写的模块内容，请检查 `modprobe` 如何解析依赖关系，以及 `modinfo` 如何报告模块元数据。<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御性说明：

- 保持 `/lib/modules` 的所有者为 `root:root`，并确保用户不可写入。<sup>[[8]](#references)</sup>
- 在操作上可行的情况下，在启动后设置 `kernel.modules_disabled=1`。<sup>[[1]](#references)</sup>
- 在需要可加载 modules 的系统上强制执行 module signing。<sup>[[2]](#references)</sup>
- 监控对 `/proc/sys/kernel/modprobe`、`/lib/modules` 的写入，以及非预期的 `insmod`/`modprobe` 执行。<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [关于 /proc/sys/kernel/ 的文档 — Linux Kernel 文档](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — Linux Kernel 文档](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Linux Kernel 文档](https://docs.kernel.org/driver-api/basics.html)
- [6] [使用 printk 记录消息 — Linux Kernel 文档](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [构建 External Modules — Linux Kernel 文档](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [合并标签 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
