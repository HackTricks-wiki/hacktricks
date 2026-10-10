# 进程枚举与服务路径

{{#include ../../banners/hacktricks-training.md}}

关键问题是：哪个特权进程会读取低权限用户能够影响的数据或代码？检查进程树、运行时环境、打开的文件，以及启动每个候选进程的 unit 或脚本。

## 映射进程与所有权

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

跨用户的父子进程关系可能是正常的，但遇到意外的用户身份切换时，应检查父进程命令、参数、可执行文件、工作目录和引用的文件。使用 [users and sessions](../user-information/user-and-session-triage.md) 判断进程所有者和登录上下文。

### 本地虚拟机控制台

检查 QEMU 进程的 `-spice` 选项及其监听地址。[QEMU 文档](https://www.qemu.org/docs/master/system/qemu-manpage.html)说明，`disable-ticketing` 允许 SPICE 客户端无需认证即可连接。即使监听器绑定到环回地址，其他本地主机用户仍可能访问。将命令行视为暴露的控制台之前，应确认实际监听器、认证选项和本地访问权限。控制台操作影响的是**虚拟机**；要获取虚拟机账户或更改其启动状态，需要满足单独的虚拟机内部条件，且不会因此获得虚拟化主机的 root 权限。在被动枚举期间，应读取进程参数和套接字元数据，不要连接虚拟机或重启它。

即使最初的 shell 无法访问某个服务账户的文件，本地可访问的 Web 界面仍可能以该服务账户的身份执行代码。例如，CVE-2023-0297 影响 pyLoad 的 `/flash/addcrypted2` 处理逻辑：不可信 JavaScript 在启用 Python imports 的情况下进入 Js2Py；[上游修复](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)禁用了 `pyimport`。在将 pyLoad 进程视为提权路径之前，应结合运行中进程的所有者、监听地址、端点暴露情况以及已安装的补丁或供应商回移补丁进行判断。仅凭进程名称、开放端口或软件包版本，无法证明存在暴露；被动枚举不应发送执行 payload。

### 共享终端的特权登录 shell

如果特权交互式 shell 运行 `su --login <user>`，但没有独立的伪终端，终端可能会与低权限登录 shell 共享。如果该用户的启动文件可被控制，且其中的代码能够使用 `TIOCSTI` 注入终端输入，那么特权 shell 恢复运行时可能会收到这些输入。[util-linux 的 `su` 手册](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)说明了共享终端的风险，并建议交互使用 `su --pty`/`-P`；`su -c` 则会启动一个没有控制终端的独立会话。此风险是否存在，取决于实际的父 shell、终端关系、目标启动文件和内核策略。仅凭进程名称或 `su -l` 参数，只能作为进一步检查的线索。

检查观察到的进程树和 TTY 列，然后检查可读取的启动器以及启动文件的所有权和权限。在 Linux 上，如果存在，`/proc/sys/dev/tty/legacy_tiocsti` 可帮助判断策略；该文件不存在并不能证明安全。[Linux `TIOCSTI` 手册](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)指出，自 Linux 6.2 起，当此 sysctl 为 false 时，该操作可能需要 `CAP_SYS_ADMIN`。不要仅为枚举主机而调用此 ioctl。

数据库账户有时可以修改目标用户的启动文件，即使它本身无法直接写入文件系统。PostgreSQL 服务端的 `COPY ... TO 'filename'` 会以数据库服务器的 OS 账户身份写入文件，但[PostgreSQL 的限制](https://www.postgresql.org/docs/current/sql-copy.html)规定，只有数据库超级用户或具有 `pg_write_server_files` 等权限的角色才能使用这种文件形式。应同时确认数据库角色权限和服务器 OS 文件权限；仅有应用程序连接字符串并不代表拥有写文件权限。评估此攻击链时，应分别看待特权启动器和数据库账户的能力。

## 检查运行时工件

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

已删除的可执行文件和已删除但仍打开的文件会一直保留引用，直到其最后一个文件描述符关闭。它们可能保留证据或可访问的机密信息。进程环境和内存中可能包含凭据，但读取其他进程会受到所有权、`/proc` 挂载选项、Yama ptrace 策略及其他安全控制的限制。相关技术请参阅[文件描述符](../main-system-information/filesystem-links-and-file-descriptors.md)和[后渗透凭据搜寻](../post-exploitation/README.md)。

保存的 syscall 跟踪记录也是一道文件权限边界。[`strace` 会将 syscall 参数记录到输出文件](https://man7.org/linux/man-pages/man1/strace.1.html)，因此，可读取的 [`execve` 参数](https://man7.org/linux/man-pages/man2/execve.2.html)跟踪记录可能会暴露特权任务在命令行中传递的密码。首先确认当前用户能够读取特定跟踪记录，并确认参数中确实包含凭据；之后若要切换到 Unix 账户，还需单独证明该账户接受此凭据。在常规枚举中，文件元数据可作为有用的被动线索，无需扫描每个跟踪记录或打印其内容。

## 特权办公自动化套接字

LibreOffice 和 OpenOffice 可以通过 `--accept=socket,host=<host>,port=<port>;urp;` 参数公开其 UNO API。拥有可访问端点的 root 所有办公进程，可能允许权限较低的本地用户在该进程的安全上下文中调用 API 服务。`SystemShellExecute` 服务包含用于启动系统命令的操作。绑定到 loopback 会限制远程访问，但除非有其他控制阻止访问，本地用户仍可连接该套接字。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

关联进程所有者、精确的 `--accept` 参数，以及当前监听地址和端口。配置了 acceptor 但绑定失败只能作为线索；被动枚举期间不要连接或调用 API。不要仅为测试此情况而启动特权 office 实例。

## 特权进程使用的 System V 共享内存

root 所有的 helper 可以创建其他用户可写的 System V 共享内存段。如果该 helper 随后在 shell 命令或其他敏感操作中信任该共享内存段中的数据，那么即使可执行文件及其文件受到保护，该共享内存段仍跨越了权限边界。`shmget()` 根据其 flags 的低九位设置访问权限；模式 `0666` 允许其他用户写入，而 `IPC_CREAT` 标志不会缩小这些权限。使用 `ipcs -m` 被动检查活动的共享内存段，并将其所有者、模式和生命周期与特权进程及其输入处理方式进行关联。仅有一个全局可写的共享内存段，并不能证明存在命令执行。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments 与 `/dev/shm` 下的 POSIX shared-memory files 不同。仅存在片刻的 segment 可能不会出现在单次 `ipcs` 快照中，因此输出为空并不能排除某个 helper 使用 shared memory。检查其 source 或 binary 行为，以及任何用于启动它的 `sudo` 规则；不要仅为了在枚举时让 segment 出现而调用该 privileged helper。[IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) 说明了 namespaces 如何影响可见性。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent 脚本检查

Consul 可以使用其 agent 的操作系统身份运行脚本健康检查。如果 agent 以 root 身份运行、启用了 `enable_script_checks`，并允许低权限用户通过本地 HTTP API 注册带有脚本检查的 service，该用户就可能触发以 root 身份运行的命令。即使 API 仅绑定到 `127.0.0.1`，本地用户仍可访问它。`enable_local_script_checks` 设置的范围更窄：它会排除通过 HTTP API 注册提交的脚本检查。启用 Consul ACL 后，service 注册需要 `service:write`；仅有 `acl.default_policy=allow` 这一行，并不能证明匿名调用者可以注册。应结合检查 agent 的实际身份、已加载的设置、API 绑定地址和授权配置。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

根据运行中 agent 的 `-config-dir` 和 `-config-file` 参数，找到相关配置，并且只检查 script-check 和 ACL 字段名称及设置。配置文件也可能包含 gossip 密钥或令牌；避免将它们粘贴到共享日志中。不要仅为枚举此情况而注册服务或运行健康检查。

如果低权限用户可以**写入并搜索**由以 root 身份运行的 agent 的 `-config-dir` 指定的目录，则存在另一条本地文件路径：该目录中新增的 `.hcl` 或 `.json` 服务定义可能会被加载。即使禁止列出目录，目录搜索和写入权限也可能允许添加文件。若要执行 root 命令，请确认 agent 确实会加载该目录、其**有效的** script-check 设置允许本地定义、该定义已加载，并且 agent 保持 root 权限。[Consul 文档](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)说明了哪些设置和健康检查定义可以重新加载；启用 script checks 本身可能需要重启，因此请核实已安装版本的行为。如果 ACL 保护了 agent，[`consul reload` 需要 `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)；仅有 KV 写入权限并不具备该权限。将可写目录元数据视为审查线索，而非已获授权重新加载、重启或执行命令的证明。检查路径、权限和策略，但不要写入配置或调用 API。

## 跟踪服务执行链路

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

检查 unit、drop-in、`EnvironmentFile=`、辅助脚本、相对命令、可写目录和 socket activation。即使 unit 归 root 所有，如果它读取用户可写的配置或脚本，仍可能不安全。[arbitrary file write](../interesting-files-permissions/write-to-root.md) 页面介绍了常见的 service 和 unit 滥用路径。如果一次性的 `ps` 列表遗漏了短暂运行的任务，可使用 [pspy](https://github.com/DominicBreuker/pspy) 或 audit/进程遥测进行监控。

对于自定义的 **xinetd** service，应将已启用 stanza 中的 `server`、`user` 和访问控制与实时 listener 及确切的可执行文件对应起来。[`user` 设置](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) 决定生成进程的身份，而可执行文件上的 set-user-ID 位也可能单独改变其有效身份，前提是 [`execve` 允许这种转换](https://man7.org/linux/man-pages/man2/execve.2.html)。如果可访问的高权限二进制接受不可信输入，应离线检查源代码或反汇编，排查内存安全漏洞，例如将无界 [`scanf` 字符串转换](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)写入固定大小的 buffer。service 映射和 set-user-ID 元数据只是线索，不能证明存在此类漏洞；被动枚举期间不要发送会导致崩溃的输入，也不要调试正在运行的高权限 service。

对于源代码可读的自定义高权限 listener，应检查每个由调用方控制、用于 [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) 等复制操作的长度。仅检查当前写入索引是否位于固定 buffer 范围内，并不能证明**复制长度**适合剩余空间；确认索引在有效范围内后，还要验证 `copy_length <= capacity - index`，并检查有符号性和算术溢出。只有当输入会到达该操作、低权限用户可访问 listener，且进程保留更高的有效身份时，这才是值得审查的线索。离线检查源代码和进程元数据；枚举期间不要向运行中的 service 发送会导致崩溃的输入。

在使用 **Upstart** 的系统上，系统 job 定义可能位于 `/etc/init/*.conf`。当活动 init daemon 会加载该确切 job、其 `script` 或 `exec` stanza 以更高权限身份运行，且用户可通过允许的 `initctl` 命令或其他真实触发机制启动它时，当前用户可写的 job 文件才值得关注。仅有 sudo `initctl` 授权，并不能证明任何 job 文件可写，也不能证明修改后的 job 会运行。检查确切 job 文件的权限、有效的运行身份设置、活动 daemon 和触发机制；枚举期间不要编辑或启动该 job。参见 [Upstart job 配置](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)和 [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) 手册。

如果用户可读取 autologin 密码文件，例如在[启动 job 会读取该确切路径](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)的系统上的 `/etc/autologin/passwd`，这就是凭据暴露线索。确认已安装启动 job 且它会使用该文件，然后另行验证密码是否对其他本地账户或 service 有效。仅凭文件名无法确定密码是否重复使用；记录路径和访问元数据，不要将密码写入共享的枚举输出。

unit 的 `ExecStart=` 或计划任务命令可能会显示不可列出目录中脚本的确切路径。[目录搜索权限](https://man7.org/linux/man-pages/man7/path_resolution.7.html)仍可能允许当前身份遍历这个已知路径；应确认每个父目录上的搜索权限以及文件的读取权限，不要假设目录列表失败就能保护文件。可读脚本可能包含传输凭据，但只有该凭据仍然有效且在另一账户上被独立接受，才能进一步访问该账户。记录路径和权限证据，不要将秘密值写入共享日志。

对于计划运行的 CommonJS Node.js 脚本，即使脚本本身是只读的，也要检查 `require('package')` 等裸导入。[Node 会先在导入文件旁边及其祖先目录中搜索 `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)，之后才回退到配置的全局路径。能够对其中某个祖先目录进行**写入和搜索**的低权限用户，可能可以创建一个优先匹配的 package。确认确切的导入会被执行、所选 package 不是内置模块、相关路径可以创建或修改、已安装的 runtime 会在该路径解析模块，以及高权限 job 会在之后的某次运行中加载它。父目录可写的元数据只是审查线索；应被动检查脚本和 scheduler，不要植入模块或触发 job。

当自动化 job 以不同的 OS 身份安装 package 时，私有 Python package index 也是一个信任边界。将确切的 job 和运行账户与其配置的 index、选定的 package 名称，以及低权限用户能否发布或替换 job 实际会安装的 package 对应起来。构建 source distribution 时，可能会以安装程序的身份运行其 build backend 或旧式 `setup.py`；导入已安装的 package 则是另一条执行路径。index listener、可读取的上传密码 hash 或 package 文件名本身都不足以证明这条链路。检查 job、index 授权和 package 来源；枚举期间不要上传或安装任何内容。参见 [pip 的 build-system 接口](https://pip.pypa.io/en/stable/reference/build-system/)和[安全安装指南](https://pip.pypa.io/en/stable/topics/secure-installs/)。

高权限 agent 可能会轮询由独立 web service 或 container 管理的 task queue。如果低信任身份可以写入该 service 的 task database，应确认这些行是否会实际发送给该 agent，以及 command task 是否以 agent 的 OS 身份运行。分别确认 database 写入权限、目标 session 或 routing key、活动轮询、task 授权以及 agent 的有效用户。在 container 内的 root 本身并不意味着拥有 host-root 权限；只有当拥有 host 特权的 consumer 执行攻击者控制的 task 数据时，才会跨越此边界。检查进程、database 文件和 service 元数据；枚举期间不要修改 queue 或发送 task。

计划任务也可能从 application database 配置行中读取命令。确认低权限 database role 是否可以更改该确切行、活动 job 是否会在更改后读取它，以及该值是否会在更高 OS 身份下传递给 shell 或等效的命令运行器。拥有 database 写入权限或看到一个看似命令的值，都不能证明会执行；被动枚举期间应检查 job 和权限，不要更改该行。

排队的消息也可能包含 URL，而不是代码。如果高权限 consumer 会获取该 URL 并将响应作为 Lua 或其他可执行 plugin 加载，应验证发布者对确切 exchange 和 routing key 的权限、与被消费 queue 的 binding、获取和加载 plugin 的路径，以及 worker 的有效身份。[RabbitMQ 通过 exchanges 路由已发布的消息](https://www.rabbitmq.com/docs/exchanges)；broker listener 或有效登录凭据本身都不能证明消息会送达该 worker。捕获到的明文 broker 凭据是另一条线索，需要实际具备 packet-capture 权限且能够读取流量；它们不能证明拥有发布授权。只有当 runtime 提供 [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) API 时，Lua plugin 才能通过它调用 shell 命令。被动枚举期间应检查配置和代码，不要捕获流量、发布消息或获取 plugin。

当高权限 Python service 暴露本地 HTTP 或 socket endpoint 时，即使文件权限阻止修改，可读脚本仍可能揭示输入到代码的路径。将活动进程和 unit 身份与确切脚本、listener、route 授权及调用方可控字段对应起来。然后跟踪这些字段经过解析和验证到达动态 `eval()` 或 `exec()` sink 的过程。特别是，根据请求文本构造新的 f-string 并进行求值，可能会将攻击者提供的替换字段解释为 Python 表达式（[Python `eval` 警告](https://docs.python.org/3/library/functions.html#eval)；[f-string 语义](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。仅仅匹配到 `eval` 或发现绑定到 loopback，并不能证明不可信调用方可以到达该 sink；应检查实际数据流和访问控制，枚举期间不要发送测试 payload。

该 route 上的签名请求 gate 也需要单独审查。如果可读源代码显示签名密钥是从一个明显较小或可预测的输出空间推导出来，且 service 暴露了有效的签名样本，那么该签名可能无法再保护高权限 `eval()` sink。验证确切的密钥推导和验证器、活动 service 的身份及本地调用方访问权限，以及签名字段是否会到达 sink；仅仅导入 Python 的 [`random` 模块](https://docs.python.org/3/library/random.html)或看到签名样本，都不能证明这些条件成立。Python 还警告，限制 `__builtins__` [并不能为不可信的 `eval()` 输入提供安全边界](https://docs.python.org/3/library/functions.html#eval)。离线分析密钥；被动枚举期间不要提交伪造请求。

即使 unit 文件和所有现有 drop-in 都受到保护，一个为空但可写的 `/etc/systemd/system/<unit>.service.d` 目录仍值得关注：用户可能创建新的 `.conf` override。检查当前身份是否具有该目录的写入和搜索权限、unit 是否已加载并以 root 身份运行，以及是否会发生 daemon reload 后重启。允许 reload 或重启的权限、timer 或之后的系统启动都可能使更改生效；仅有目录写入权限不会立即执行更改。

对于正在运行的 service，应从 unit 的 `[Service]` section 中检查字面形式的 `EnvironmentFile=` 路径，包括名称不以 `.env` 开头的文件。如果低权限用户可以读取某个文件，可列出 `API_TOKEN` 或 `APP_SECRET_KEY` 等类似凭据的键名，但不要将值写入共享日志。评估有效 unit 时，应检查 drop-in override 和可选的 `-` 前缀。可读性只是凭据暴露线索；只有该值对高权限操作仍然有效，才可能导致权限提升。

### 对不可信上传内容的高权限处理

以 root 身份运行的 file watcher 可能会将用户可写上传目录中的文件交给短暂运行的 parser 或 extractor。沿着运行中的 watcher 检查其父脚本或 service，并确认确切目录、谁可以在其中放置文件、子进程命令及其参数，以及子进程运行时的身份。进程快照可能会显示 watcher，却漏掉两次上传之间运行的 extractor。被动枚举期间不要放置测试 payload 或触发 watcher。

一个具体示例是 Binwalk 的提取模式（`-e`）处理攻击者控制的 PFS 数据。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617)允许 PFS extractor 写入预期目录之外的位置，包括 Binwalk 之后可能加载的 plugin 路径。上游已在 [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) 中修复，但发行版 backport 可能仍显示较旧版本；判断是否适用前，应检查已安装 package 的安全状态，例如查看 [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)。仅仅安装了某个版本的 Binwalk，并不能证明存在权限提升路径：必须确实有更高权限的进程在低权限用户可控的输入上调用提取功能。

### 使用本地依赖的计划构建

计划执行的 `cargo run` 会以 job 的运行用户身份重新编译源代码。检查 manifest 中的本地 `{ path = "..." }` 依赖，以及每个依赖的源文件和父目录权限，不要只检查主 crate。如果低权限用户可以修改 Cargo 会编译的依赖，且计划 job 会运行编译结果，那么代码就能以该运行用户的身份执行。确认有效的 scheduler 命令、工作目录、依赖解析方式，以及是否会发生重新构建；其他位置存在可写的 Rust 源文件只能作为线索。被动初步排查只需读取 manifest 和路径元数据。参见 [Cargo 的 path dependency 文档](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)。

## Xvfb framebuffer 文件

`Xvfb -fbdir <directory>` 使用名为 `Xvfb_screen<n>` 的 memory-mapped 文件来存放虚拟屏幕。如果其他用户正在运行的 Xvfb 进程指定了一个目录，且当前用户可以读取其中的屏幕文件，那么 framebuffer 可能会暴露该用户桌面的内容。应一并确认进程、文件所有权和权限；仅凭文件可读，并不能证明屏幕上有有用内容。先检查路径和元数据，不要将图像数据复制到共享的枚举输出中。[Xvfb 手册](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)说明了 `-fbdir` 的行为。

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` 手册](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` 手册](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` 手册](https://man.openbsd.org/ipcs.1)
4. [Consul agent 配置：脚本检查](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent 服务注册 API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL 配置](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice 帮助：为外部 API 客户端打开套接字](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK：`XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
