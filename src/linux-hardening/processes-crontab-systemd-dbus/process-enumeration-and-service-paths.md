# 进程枚举与服务路径

{{#include ../../banners/hacktricks-training.md}}

关键问题是：哪个特权进程会使用低权限用户能够影响的数据或代码？检查进程树、实时环境、打开的文件，以及启动每个候选进程的单元或脚本。

## 映射进程与所有权

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

跨用户的父子进程关系可能是正常的，但如果出现意外的用户身份切换，应检查父进程命令、参数、可执行文件、工作目录和引用的文件。使用[用户和会话](../user-information/user-and-session-triage.md)来判断所有者和登录上下文。

### 本地虚拟机控制台

结合 QEMU 进程的 `-spice` 选项及其监听地址进行检查。[QEMU 文档](https://www.qemu.org/docs/master/system/qemu-manpage.html)指出，`disable-ticketing` 允许 SPICE 客户端无需身份验证即可连接。即使监听地址绑定到 loopback，其他本地主机用户仍可能访问。在将命令行视为暴露了控制台之前，应确认实际监听器、身份验证选项和本地访问权限。控制台操作影响的是**guest**；获取 guest 账户或更改其启动状态需要满足独立的 guest 端条件，并不会因此获得虚拟化主机上的 root 权限。在被动枚举期间，应读取进程参数和 socket 元数据，不要连接 guest 或重启它。

即使初始 shell 无法访问服务账户的文件，本地可访问的 Web 界面仍可能以其服务账户身份执行代码。例如，CVE-2023-0297 影响了 pyLoad 的 `/flash/addcrypted2` 处理逻辑：不可信的 JavaScript 在启用 Python import 的情况下传入 Js2Py；[上游修复](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)禁用了 `pyimport`。在将 pyLoad 进程视为提权路径之前，应关联检查运行进程的所有者、监听地址、端点暴露情况，以及已安装的补丁或供应商回移补丁。仅凭进程名称、开放端口或软件包版本无法证明存在暴露；被动枚举不应发送执行 payload。

### 共享终端的特权登录 shell

如果特权交互式 shell 运行 `su --login <user>` 时没有独立的伪终端，它可能会与低权限登录 shell 共用终端。如果该用户的启动文件可被控制，且其中的代码能够使用 `TIOCSTI` 注入终端输入，那么特权 shell 恢复运行时可能会收到这些输入。[util-linux 的 `su` 手册](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)说明了共享终端的风险，并建议交互使用时采用 `su --pty`/`-P`；`su -c` 会启动一个没有控制终端的独立会话。要确认风险，必须检查实际的父 shell、终端关系、目标启动文件和内核策略。仅凭进程名称或 `su -l` 参数只能作为进一步检查的线索。

检查观察到的进程树和 TTY 列，然后检查可读取的启动器，以及启动文件的所有权和权限。在 Linux 上，如果存在，`/proc/sys/dev/tty/legacy_tiocsti` 有助于判断策略；该文件不存在并不能证明系统安全。[Linux `TIOCSTI` 手册](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)指出，自 Linux 6.2 起，当此 sysctl 为 false 时，该操作可能需要 `CAP_SYS_ADMIN`。不要仅为枚举主机而调用该 ioctl。

数据库账户有时可以修改目标用户的启动文件，即使它没有直接的文件系统写入权限。PostgreSQL 服务端的 `COPY ... TO 'filename'` 会以数据库服务器的 OS 账户身份写入文件，但 [PostgreSQL 的限制](https://www.postgresql.org/docs/current/sql-copy.html)规定，这种文件写入形式仅限数据库超级用户或 `pg_write_server_files` 等角色。应确认数据库角色和服务器 OS 文件权限；仅有应用的连接字符串并不代表拥有文件写入权限。评估这条链时，应分别考虑特权启动器和数据库账户的能力。

## 检查运行时产物

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

已删除的可执行文件和已删除但仍处于打开状态的文件，在最后一个文件描述符关闭前仍会被引用。它们可能保留证据或可访问的机密信息。进程环境和内存中可能包含凭据，但读取其他进程会受到所有权、`/proc` 挂载选项、Yama ptrace 策略及其他安全控制的限制。相关技术请参阅[文件描述符](../main-system-information/filesystem-links-and-file-descriptors.md)和[post-exploitation 凭据搜寻](../post-exploitation/README.md)。

保存的 syscall 跟踪记录也是一道文件权限边界。[`strace` 会将 syscall 参数记录到输出文件](https://man7.org/linux/man-pages/man1/strace.1.html)，因此，可读取的 [`execve` 参数](https://man7.org/linux/man-pages/man2/execve.2.html)跟踪记录可能会暴露特权任务在命令行中传递的密码。首先确认当前用户能够读取特定跟踪记录，并确认参数中确实包含凭据；之后若要切换 Unix 账户，还需单独验证该凭据是否被目标账户接受。在常规枚举过程中，文件元数据可作为有用的被动线索，无需扫描所有跟踪记录或打印其内容。

## 特权办公自动化套接字

LibreOffice 和 OpenOffice 可以通过 `--accept=socket,host=<host>,port=<port>;urp;` 参数公开其 UNO API。拥有可访问端点的 root 所有办公进程，可能允许权限较低的本地用户在该进程的安全上下文中调用 API 服务。`SystemShellExecute` 服务包含启动系统命令的操作。绑定到 loopback 可以限制远程访问，但除非有其他控制措施阻止访问，否则本地用户仍可连接该套接字。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

关联进程所有者、准确的 `--accept` 参数，以及当前监听的地址和端口。配置了但绑定失败的 acceptor 只能作为线索；被动枚举期间不要连接或调用 API。不要仅为测试这一情况而启动特权 office 实例。

## 特权进程使用的 System V 共享内存

root 所有的辅助程序可能会创建一个其他用户可以写入的 System V 共享内存段。如果该辅助程序随后在 shell 命令或其他敏感操作中信任该段中的数据，那么即使可执行文件及其文件都受到保护，该共享内存段仍跨越了权限边界。`shmget()` 从其标志的低九位获取访问权限；模式 `0666` 允许其他用户写入，而 `IPC_CREAT` 标志不会缩小这些权限。使用 `ipcs -m` 被动检查活动段，并将其所有者、模式和生命周期与特权进程及其输入处理方式关联起来。仅有一个所有用户可写的共享内存段，并不能证明存在命令执行。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments 与 `/dev/shm` 下的 POSIX shared-memory files 不同。仅存在片刻的 segment 可能不会出现在单次 `ipcs` 快照中，因此输出为空并不能排除某个使用 shared memory 的 helper。检查其 source 或 binary 行为，以及任何用于启动它的 `sudo` 规则；不要仅仅为了在枚举时让 segment 出现而调用该 privileged helper。[IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) 说明了 namespaces 如何影响可见性。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul 可以使用其 agent 的操作系统身份运行 script health checks。如果 agent 以 root 身份运行、启用了 `enable_script_checks`，并且允许低权限用户通过本地 HTTP API 注册带有 script check 的 service，该用户就可能触发以 root 身份运行的命令。即使 API 仅绑定到 `127.0.0.1`，本地用户仍然可以访问它。`enable_local_script_checks` 的限制更严格：它会排除通过 HTTP API 注册提交的 script checks。启用 Consul ACL 后，注册 service 需要 `service:write`；仅有 `acl.default_policy=allow` 这一行，并不能证明匿名调用方可以注册。应结合检查 agent 的实际身份、已加载的设置、API 绑定地址和授权配置。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

根据运行中的 agent 的 `-config-dir` 和 `-config-file` 参数，找到相关配置，并且只检查 script-check 和 ACL 字段名称及设置。配置文件也可能包含 gossip keys 或 tokens；避免将它们粘贴到共享日志中。不要仅为了枚举此情况而注册服务或运行健康检查。

如果低权限用户能够**写入并搜索**由以 root 身份运行的 agent 的 `-config-dir` 指定的目录，则存在另一条本地文件路径：该目录可能会加载新增的 `.hcl` 或 `.json` 服务定义。即使禁止列出目录，目录的搜索和写入权限仍可能允许添加文件。若要以 root 身份执行命令，请确认 agent 确实会加载该目录、其**有效的** script-check 设置允许本地定义、该定义已加载，且 agent 保留 root 权限。[Consul 文档](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)说明了哪些设置和健康检查定义可以重新加载；启用 script checks 本身可能需要重启，因此请核实已安装版本的行为。如果 ACL 保护了 agent，[`consul reload` 需要 `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)；仅有 KV 写入权限并不包含此权限。将可写的目录元数据视为审查线索，而非已获授权进行重新加载、重启或执行命令的证明。检查路径、权限和策略，不要写入配置或调用 API。

## 跟踪服务执行链路

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

检查 unit、drop-in、`EnvironmentFile=`、helper scripts、相对命令、可写目录和 socket activation。即使 unit 由 root 所有，如果它读取用户可写的配置或脚本，仍可能不安全。[arbitrary file write](../interesting-files-permissions/write-to-root.md) 页面介绍了常见的 service 和 unit 滥用路径。如果一次性的 `ps` 列表漏掉短时运行的 job，可用 [pspy](https://github.com/DominicBreuker/pspy) 或 audit/process telemetry 进行监控。

对于自定义 **xinetd** service，将已启用 stanza 中的 `server`、`user` 和访问控制与正在运行的 listener 及确切的可执行文件关联起来。[`user` 设置](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)决定启动的进程使用哪个身份；如果 [`execve` 允许身份转换](https://man7.org/linux/man-pages/man2/execve.2.html)，可执行文件上的 set-user-ID 位也可以独立改变其 effective identity。可访问且具有特权的二进制文件如果接受不可信输入，就值得离线审查其源码或反汇编，检查内存安全漏洞，例如将不受限的 [`scanf` 字符串转换](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)写入固定缓冲区。service 映射和 set-user-ID 元数据只是线索，并不能证明存在此类漏洞；被动枚举期间，不要发送会导致崩溃的输入，也不要调试正在运行的特权 service。

对于可读取源码的自定义特权 listener，检查每个由调用方控制、用于 [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) 等复制操作的长度。仅检查当前写入索引是否在固定缓冲区范围内，并不能证明**复制长度**适合剩余空间；确认索引在有效范围内后，验证 `copy_length <= capacity - index`，并检查有符号性和算术溢出。只有当输入能到达该操作、低权限用户可以访问 listener，且进程保留了更高的 effective identity 时，这才是值得审查的线索。离线检查源码和进程元数据；枚举期间不要向正在运行的 service 发送会导致崩溃的输入。

在使用 **Upstart** 的系统上，system job 定义可能位于 `/etc/init/*.conf`。只有当活动的 init daemon 会加载该确切 job、其 `script` 或 `exec` stanza 以更高权限身份运行，并且用户能通过获准的 `initctl` 命令或其他实际触发机制启动它时，当前用户可写的 job 文件才值得关注。仅有 sudo `initctl` 授权，并不能证明任何 job 文件可写，也不能证明修改后的 job 会运行。枚举期间不要编辑或启动 job；应检查确切 job 文件的权限、有效的 run-as 设置、活动 daemon 和触发机制。参见 [Upstart job 配置](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)和 [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html)手册。

可读的自动登录密码文件，例如使用[启动 job 确实读取该路径](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)的系统上的 `/etc/autologin/passwd`，是凭据泄露线索。确认启动 job 已安装且会使用该文件，然后单独验证该密码是否对其他本地账户或 service 有效。仅凭文件名无法证明密码被重复使用；记录路径和访问元数据，不要将密码写入共享的枚举输出。

unit 的 `ExecStart=` 或计划任务命令可能会透露一个无法列出目录中的脚本确切路径。[目录搜索权限](https://man7.org/linux/man-pages/man7/path_resolution.7.html)仍可能允许当前身份遍历已知路径；应确认每个父目录都具有搜索权限，且文件具有读取权限，不要认为目录列表失败就能保护文件。可读脚本可能包含传输凭据，但要转到另一个账户，仍需该凭据有效且能在该账户处独立通过验证。记录路径和权限证据，不要将秘密值打印到共享日志中。

对于计划运行的 CommonJS Node.js 脚本，即使脚本本身是只读的，也要检查 `require('package')` 这类裸导入。[Node 会先在导入文件旁边及其祖先目录中搜索 `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)，然后才会回退到已配置的全局路径。能够**写入并搜索**这些祖先目录之一的低权限用户，可能可以创建一个优先匹配的 package。确认确切的导入会被执行、选中的 package 不是内置模块、相关路径可以创建或修改、该模块能在已安装的 runtime 中解析到该路径，并且更高权限的 job 会在未来某次运行时加载它。父目录可写的元数据仅是审查线索；应被动检查脚本和 scheduler，不要植入模块或触发 job。

当自动化 job 以不同的 OS 身份安装 package 时，私有 Python package index 是另一条信任边界。将确切的 job 和 run-as 账户与其配置的 index、选定的 package 名称关联起来，并确认低权限用户能否发布或替换 job 实际会安装的 package。构建 source distribution 时，可能会以安装程序的身份运行其 build backend 或旧式 `setup.py`；导入已安装 package 则是另一条执行路径。index listener、可读的上传密码哈希或 package 文件名本身，都不能证明这条链路成立。枚举期间不要上传或安装任何内容；应审查 job、index 授权和 package 来源。参见 [pip 的 build-system 接口](https://pip.pypa.io/en/stable/reference/build-system/)和 [安全安装指南](https://pip.pypa.io/en/stable/topics/secure-installs/)。

特权 agent 可能会轮询由独立 web service 或 container 管理的 task queue。如果较低信任级别的身份可以写入该 service 的 task database，应确认这些行是否确实会提供给该 agent，以及 command task 是否以 agent 的 OS 身份运行。分别确认 database 写入权限、目标 session 或 routing key、是否正在轮询、task 授权，以及 agent 的 effective user。container 内的 root 本身并不意味着拥有 host-root 访问权限；只有当具有 host 特权的 consumer 执行攻击者控制的 task 数据时，才跨越了该边界。枚举期间不要修改 queue 或发送 task；应检查进程、database 文件和 service 元数据。

周期性 job 也可能从 application database 的配置行中读取命令。确认低权限 database role 能否修改该确切行、活动 job 是否会在修改后读取它，以及该值是否会在更高 OS 身份下传递给 shell 或同等的命令执行器。database 写入权限或看起来像命令的值本身都不能证明会执行；被动枚举期间应检查 job 和权限，不要修改该行。

排队消息也可能包含 URL 而非代码。如果特权 consumer 会获取该 URL 并将响应作为 Lua 或其他可执行 plugin 加载，应验证发布者对确切 exchange 和 routing key 的权限、到被消费 queue 的 binding、获取和加载 plugin 的路径，以及 worker 的 effective identity。[RabbitMQ 会通过 exchanges 路由已发布的消息](https://www.rabbitmq.com/docs/exchanges)；broker listener 或有效登录本身并不能证明消息会送达该 worker。捕获到的明文 broker 凭据是另一条线索，需要实际的 packet-capture 访问权限和可读取的流量；它们不能证明拥有发布授权。只有在 runtime 中可用 [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) API 时，Lua plugin 才能通过它调用 shell 命令。被动枚举期间应检查配置和代码，不要捕获流量、发布消息或获取 plugin。

当特权 Python service 暴露本地 HTTP 或 socket endpoint 时，即使文件权限不允许修改，可读脚本仍可能揭示从输入到代码执行的路径。将活动进程和 unit 身份与确切脚本、listener、route 授权及由调用方控制的字段关联起来。然后追踪这些字段经过解析和验证后是否到达动态 `eval()` 或 `exec()` sink。尤其是从 request 文本构造新的 f-string 并对其求值时，攻击者提供的替换字段可能会被解释为 Python 表达式（[Python `eval` 警告](https://docs.python.org/3/library/functions.html#eval)；[f-string 语义](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。仅匹配到 `eval` 或绑定到 loopback，并不能证明不可信调用方能到达该 sink；应审查实际的数据流和访问控制，枚举期间不要发送测试 payload。

该 route 上的签名请求门控也需要单独审查。如果可读源码能证明签名密钥的输出空间很小或可预测，且 service 暴露了有效的签名样本，那么签名可能不再能保护特权 `eval()` sink。应验证确切的密钥派生和 verifier、正在运行的 service 身份及本地调用方访问权限，以及签名字段是否会到达 sink；导入 Python 的 [`random` 模块](https://docs.python.org/3/library/random.html)或仅有一个签名样本，都不能证明这些条件成立。Python 还警告说，限制 `__builtins__` [并不能为不可信的 `eval()` 输入提供安全边界](https://docs.python.org/3/library/functions.html#eval)。离线分析密钥；被动枚举期间不要提交伪造请求。

即使 unit 文件和所有现有 drop-in 都受到保护，一个空的但可写的 `/etc/systemd/system/<unit>.service.d` 目录仍值得关注：用户可能会创建新的 `.conf` override。检查当前身份是否有权写入和搜索该目录、unit 是否已加载并以 root 身份运行，以及之后是否会执行 daemon reload 并重启。允许 reload 或 restart 的权限、timer 或之后的系统启动都可能使修改生效；仅有目录写入权限不会立即执行修改。

对于正在运行的 service，应从 unit 的 `[Service]` 部分跟踪字面量 `EnvironmentFile=` 路径，包括文件名不以 `.env` 开头的文件。如果低权限用户可以读取其中的文件，可列出 `API_TOKEN` 或 `APP_SECRET_KEY` 等疑似凭据的键名，但不要将值打印到共享日志中。评估有效 unit 时，应检查 drop-in override 和可选的 `-` 前缀。文件可读是凭据泄露线索；要实现提权，该值仍必须对某项特权操作有效。

### 特权进程处理不可信上传文件

以 root 身份运行的 file watcher 可能会将用户可写上传目录中的文件交给短时运行的 parser 或 extractor。跟踪正在运行的 watcher 的父脚本或 service，并确认确切目录、谁可以向其中放置文件、子命令及其参数，以及子进程运行时使用的身份。进程快照可能显示 watcher，却漏掉两次上传之间运行的 extractor。被动枚举期间不要放置测试 payload，也不要触发 watcher。

一个具体示例是 Binwalk 的提取模式（`-e`）处理攻击者控制的 PFS 数据。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) 允许 PFS extractor 写入其预期目录之外的位置，包括 Binwalk 之后可能加载的 plugin 路径。上游在 [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) 中加入了修复，但发行版的 backport 可能导致显示的版本较旧；判断是否适用前，应检查已安装 package 的安全状态，例如查看 [Debian 跟踪页面](https://security-tracker.debian.org/tracker/CVE-2022-4510)。仅安装了某个版本的 Binwalk，并不能证明存在提权路径：必须确实由更高权限的进程对低权限用户可控制的输入调用提取功能。

### 使用本地依赖的计划构建任务

计划任务中的 `cargo run` 会以 job 的 run-as 用户身份重新编译源码。检查 manifest 中本地 `{ path = "..." }` 依赖项，以及每个依赖项的源码和父目录权限，而不仅仅检查主 crate。如果低权限用户可以修改 Cargo 会编译的依赖项，且计划 job 会运行编译结果，代码就能以该 run-as 用户身份执行。确认实际的 scheduler 命令、工作目录、依赖项解析情况，以及是否会重新构建；其他位置可写的 Rust 源文件仅是线索。被动分诊只需读取 manifest 和路径元数据。参见 [Cargo 路径依赖文档](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)。

## Xvfb 帧缓冲文件

`Xvfb -fbdir <directory>` 会为其虚拟屏幕使用名为 `Xvfb_screen<n>` 的内存映射文件。如果其他用户正在运行的 Xvfb 进程指定了一个目录，且当前用户可以读取该目录中的屏幕文件，那么帧缓冲可能会暴露该用户的桌面内容。应同时确认进程、文件所有权和权限；仅有可读文件并不能证明屏幕上存在有用内容。先检查路径和元数据，不要将图像数据复制到共享的枚举输出中。[Xvfb 手册](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)介绍了 `-fbdir` 的行为。

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` 手册](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` 手册](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` 手册](https://man.openbsd.org/ipcs.1)
4. [Consul agent 配置：script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent 服务注册 API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL 配置](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice 帮助：为外部 API 客户端打开 socket](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK：`XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
