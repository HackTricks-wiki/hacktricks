# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

AppArmor 是一个 **内核增强，旨在通过每个程序的配置文件限制程序可用的资源**，有效地通过将访问控制属性直接与程序而非用户绑定来实现强制访问控制 (MAC)。该系统通过 **将配置文件加载到内核中** 来运行，通常在启动时，这些配置文件规定了程序可以访问的资源，例如网络连接、原始套接字访问和文件权限。

AppArmor 配置文件有两种操作模式：

- **强制模式**：此模式积极执行配置文件中定义的策略，阻止违反这些政策的操作，并通过 syslog 或 auditd 等系统记录任何试图违反的行为。
- **投诉模式**：与强制模式不同，投诉模式不会阻止违反配置文件政策的操作。相反，它将这些尝试记录为政策违规，而不执行限制。

### AppArmor 的组件

- **内核模块**：负责政策的执行。
- **政策**：指定程序行为和资源访问的规则和限制。
- **解析器**：将政策加载到内核中以进行执行或报告。
- **实用程序**：这些是用户模式程序，提供与 AppArmor 交互和管理的接口。

### 配置文件路径

Apparmor 配置文件通常保存在 _**/etc/apparmor.d/**_\
使用 `sudo aa-status`，您将能够列出受某些配置文件限制的二进制文件。如果您将每个列出二进制文件路径中的字符 "/" 更改为点，您将获得提到的文件夹内的 apparmor 配置文件名称。

例如，**apparmor** 配置文件对于 _/usr/bin/man_ 将位于 _/etc/apparmor.d/usr.bin.man_

### 命令
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## 创建配置文件

- 为了指示受影响的可执行文件，**绝对路径和通配符**被允许用于指定文件。
- 要指示二进制文件对**文件**的访问，可以使用以下**访问控制**：
- **r**（读取）
- **w**（写入）
- **m**（将内存映射为可执行）
- **k**（文件锁定）
- **l**（创建硬链接）
- **ix**（执行另一个程序，新程序继承策略）
- **Px**（在另一个配置文件下执行，清理环境后）
- **Cx**（在子配置文件下执行，清理环境后）
- **Ux**（在无约束下执行，清理环境后）
- **变量**可以在配置文件中定义，并可以从配置文件外部进行操作。例如：@{PROC} 和 @{HOME}（将 #include \<tunables/global> 添加到配置文件中）
- **支持拒绝规则以覆盖允许规则**。

### aa-genprof

为了轻松开始创建配置文件，apparmor 可以帮助你。可以让**apparmor 检查二进制文件执行的操作，然后让你决定要允许或拒绝哪些操作**。\
你只需运行：
```bash
sudo aa-genprof /path/to/binary
```
然后，在另一个控制台中执行二进制文件通常会执行的所有操作：
```bash
/path/to/binary -a dosomething
```
然后，在第一个控制台中按“**s**”，然后在记录的操作中指示您想要忽略、允许或其他。当您完成后按“**f**”，新配置文件将创建在 _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> 使用箭头键可以选择您想要允许/拒绝/其他的内容

### aa-easyprof

您还可以使用以下命令创建二进制文件的 apparmor 配置文件模板：
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> 请注意，默认情况下，在创建的配置文件中没有任何内容被允许，因此所有内容都被拒绝。您需要添加类似 `/etc/passwd r,` 的行，以允许二进制文件读取 `/etc/passwd`，例如。

您可以然后 **enforce** 新的配置文件，使用
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### 从日志修改配置文件

以下工具将读取日志并询问用户是否希望允许某些检测到的禁止操作：
```bash
sudo aa-logprof
```
> [!NOTE]
> 使用箭头键可以选择您想要允许/拒绝/其他的内容

### 管理配置文件
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## 日志

来自 _/var/log/audit/audit.log_ 的可执行文件 **`service_bin`** 的 **AUDIT** 和 **DENIED** 日志示例：
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
您还可以使用以下方法获取此信息：
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

注意 **docker-profile** 的配置文件是默认加载的：
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
默认情况下，**Apparmor docker-default 配置文件**是从 [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) 生成的。

**docker-default 配置文件摘要**：

- **访问**所有**网络**
- **未定义能力**（但是，一些能力将来自包含基本基础规则，即 #include \<abstractions/base>）
- **写入**任何**/proc** 文件**不允许**
- 其他/**proc** 和/**sys** 的**子目录**/**文件**被**拒绝**读/写/锁/链接/执行访问
- **挂载****不允许**
- **Ptrace** 只能在被**相同 apparmor 配置文件**限制的进程上运行

一旦你**运行一个 docker 容器**，你应该看到以下输出：
```bash
1 processes are in enforce mode.
docker-default (825)
```
注意，**apparmor 甚至会阻止默认情况下授予容器的能力特权**。例如，它将能够**阻止写入 /proc 的权限，即使授予了 SYS_ADMIN 能力**，因为默认情况下 docker apparmor 配置文件拒绝此访问：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
您需要**禁用 apparmor**以绕过其限制：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
请注意，默认情况下，**AppArmor** 还会 **禁止容器从内部挂载** 文件夹，即使具有 SYS_ADMIN 能力。

请注意，您可以 **添加/删除** **能力** 到 docker 容器（这仍然会受到 **AppArmor** 和 **Seccomp** 等保护方法的限制）：

- `--cap-add=SYS_ADMIN` 给予 `SYS_ADMIN` 能力
- `--cap-add=ALL` 给予所有能力
- `--cap-drop=ALL --cap-add=SYS_PTRACE` 删除所有能力，仅给予 `SYS_PTRACE`

> [!NOTE]
> 通常，当您 **发现** 在 **docker** 容器 **内部** 有一个 **特权能力** 可用 **但** 某些部分的 **利用没有工作** 时，这将是因为 docker **apparmor 会阻止它**。

### 示例

（示例来自 [**这里**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

为了说明 AppArmor 的功能，我创建了一个新的 Docker 配置文件 “mydocker”，并添加了以下行：
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
要激活配置文件，我们需要执行以下操作：
```
sudo apparmor_parser -r -W mydocker
```
要列出配置文件，我们可以执行以下命令。下面的命令列出了我的新 AppArmor 配置文件。
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
如下面所示，当尝试更改“/etc/”时，我们会遇到错误，因为 AppArmor 配置文件阻止对“/etc”的写入访问。
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

您可以使用以下命令找到**正在运行容器的 apparmor 配置文件**：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
然后，您可以运行以下命令来**查找正在使用的确切配置文件**：
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
在奇怪的情况下，你可以**修改 apparmor docker 配置文件并重新加载它。** 你可以删除限制并“绕过”它们。

### AppArmor Docker Bypass2

**AppArmor 是基于路径的，** 这意味着即使它可能在保护像 **`/proc`** 这样的目录中的文件，如果你可以**配置容器的运行方式，** 你可以**挂载**主机的 proc 目录到 **`/host/proc`**，并且它**将不再受到 AppArmor 的保护**。

### AppArmor Shebang Bypass

在 [**这个漏洞**](https://bugs.launchpad.net/apparmor/+bug/1911431) 中，你可以看到一个例子，说明**即使你正在防止 perl 使用某些资源运行，** 如果你只需创建一个 shell 脚本**在第一行指定** **`#!/usr/bin/perl`** 并且你**直接执行该文件，** 你将能够执行你想要的任何内容。例如：
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
