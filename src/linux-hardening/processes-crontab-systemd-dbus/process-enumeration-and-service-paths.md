# 进程枚举与服务路径

{{#include ../../banners/hacktricks-training.md}}

关键问题是：哪些特权进程会使用低权限用户能够影响的数据或代码？检查进程树、实时环境变量、打开的文件，以及启动每个候选进程的 unit 或脚本。

## 映射进程与所有权

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

跨用户的父子进程关系可能是正常的，但出现意外的身份切换时，应检查父进程命令、参数、可执行文件、工作目录和引用的文件。使用[用户和会话](../user-information/user-and-session-triage.md)解读进程所有者和登录上下文。

### 本地虚拟机控制台

检查 QEMU 进程的 `-spice` 选项及其监听地址。[QEMU 文档](https://www.qemu.org/docs/master/system/qemu-manpage.html)说明，`disable-ticketing` 允许 SPICE 客户端无需认证即可连接。绑定到 loopback 的监听器仍可能被其他本地主机用户访问。在将命令行视为暴露了控制台之前，应确认实际监听器、认证选项和本地访问情况。控制台操作影响的是**guest**；获取 guest 账户或更改其启动状态需要满足单独的 guest 端条件，而且不会因此获得虚拟化主机上的 root 权限。在被动枚举期间，只读取进程参数和套接字元数据，不要连接 guest 或重启 guest。

即使最初的 shell 无法访问某个服务账户的文件，本地可访问的 Web 界面仍可能以该服务账户的身份执行代码。例如，CVE-2023-0297 影响了 pyLoad 的 `/flash/addcrypted2` 处理逻辑：不可信 JavaScript 在启用 Python imports 的情况下被传递给 Js2Py；[上游修复](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)禁用了 `pyimport`。在将 pyLoad 进程视为提权路径之前，应结合运行进程的所有者、监听地址、端点暴露情况以及已安装的补丁或供应商回移补丁进行判断。仅凭进程名称、开放端口或软件包版本，无法证明存在暴露；被动枚举不应发送代码执行 payload。

### 共享终端的特权登录 shell

如果特权交互式 shell 运行 `su --login <user>` 时没有使用独立的伪终端，它的终端可能会与低权限登录 shell 共享。如果该用户可控制其启动文件，且其中的代码能够使用 `TIOCSTI` 注入终端输入，那么特权 shell 恢复运行时可能会收到这些输入。[util-linux `su` 手册](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)介绍了共享终端的风险，并建议交互式使用时采用 `su --pty`/`-P`；`su -c` 会启动一个没有控制终端的独立会话。该风险取决于实际的父 shell、终端关系、目标启动文件和内核策略。仅凭进程名称或 `su -l` 参数，只能作为进一步检查的线索。

检查观察到的进程树和 TTY 列，然后检查可读取的启动器以及启动文件的所有权和权限。在 Linux 上，如果存在，`/proc/sys/dev/tty/legacy_tiocsti` 有助于判断相关策略；该文件不存在并不能证明系统安全。[Linux `TIOCSTI` 手册](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)指出，自 Linux 6.2 起，当此 sysctl 为 false 时，执行该操作可能需要 `CAP_SYS_ADMIN`。不要仅为枚举主机而调用该 ioctl。

数据库账户有时可以修改目标用户的启动文件，即使它无法直接写入该文件系统路径。PostgreSQL 服务端的 `COPY ... TO 'filename'` 会以数据库服务器的 OS 账户身份写入文件，但[PostgreSQL 的限制](https://www.postgresql.org/docs/current/sql-copy.html)规定，只有数据库超级用户或 `pg_write_server_files` 等角色才能使用这种文件形式。应确认数据库角色和服务器 OS 文件权限；仅有应用连接字符串并不代表拥有文件写入权限。评估攻击链时，应分别考量特权启动器和数据库账户的能力。

## 检查运行时制品

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

已删除的可执行文件和已删除但仍处于打开状态的文件，在最后一个文件描述符关闭前仍会被引用。它们可能保留证据或可访问的机密。进程环境和内存中可能包含凭据，但读取其他进程会受到所有权、`/proc` 挂载选项、Yama ptrace 策略及其他安全控制的限制。有关相关技术，请参阅 [文件描述符](../main-system-information/filesystem-links-and-file-descriptors.md) 和 [post-exploitation 凭据搜寻](../post-exploitation/README.md)。

保存的 syscall 跟踪记录也是一道文件权限边界。[`strace` 会将 syscall 参数记录到输出文件](https://man7.org/linux/man-pages/man1/strace.1.html)，因此，可读取的 [`execve` 参数](https://man7.org/linux/man-pages/man2/execve.2.html)跟踪记录可能会暴露特权任务在命令行中传递的密码。首先确认当前用户可以读取特定跟踪记录，并确认参数确实包含凭据；之后要切换 Unix 账户，还需单独证明该凭据在目标账户下有效。文件元数据可作为有用的被动线索，无需在常规枚举期间扫描所有跟踪记录或输出其内容。

## 特权办公自动化套接字

LibreOffice 和 OpenOffice 可以通过 `--accept=socket,host=<host>,port=<port>;urp;` 参数公开其 UNO API。拥有可访问端点的 root 所有办公进程，可能允许低权限本地用户在该进程的安全上下文中调用 API 服务。`SystemShellExecute` 服务包含用于启动系统命令的操作。绑定到 loopback 可限制远程访问，但除非有其他控制措施阻止访问，否则本地用户仍可连接该套接字。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

关联进程所有者、精确的 `--accept` 参数，以及当前监听地址和端口。配置了但绑定失败的 acceptor 只能作为线索；被动枚举期间不要连接或调用 API。不要仅为测试此情况而启动特权 office 实例。

## 特权进程使用的 System V 共享内存

root 所有的 helper 可以创建一个其他用户可写的 System V 共享内存段。如果 helper 随后在 shell 命令或其他敏感操作中信任该共享内存段中的数据，那么即使可执行文件及其文件受到保护，该共享内存段仍然跨越了权限边界。`shmget()` 从其标志的低九位获取访问权限；模式 `0666` 允许其他用户写入，而 `IPC_CREAT` 标志不会收窄这些权限。使用 `ipcs -m` 被动检查活动段，并将其所有者、模式和生命周期与特权进程及其输入处理方式关联起来。仅有一个全局可写的共享内存段，并不能证明可以执行命令。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V 段与 `/dev/shm` 下的 POSIX 共享内存文件不同。只存在片刻的段可能不会出现在单次 `ipcs` 快照中，因此输出为空并不能排除某个使用共享内存的辅助程序。检查其源代码或二进制行为，以及任何用于启动它的 `sudo` 规则；不要为了在枚举时让段出现而调用特权辅助程序。[IPC namespace 指南](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) 解释了 namespace 如何影响可见性。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul 可以使用其 agent 的操作系统身份运行脚本健康检查。如果 agent 以 root 身份运行、启用了 `enable_script_checks`，并允许低权限用户通过本地 HTTP API 注册带有脚本检查的服务，那么该用户可能导致以 root 身份运行命令。即使 API 只绑定到 `127.0.0.1`，本地用户仍可访问它。`enable_local_script_checks` 设置的范围更窄：它会排除通过 HTTP API 注册提交的脚本检查。启用 Consul ACL 后，服务注册需要 `service:write`；单独一行 `acl.default_policy=allow` 并不能证明匿名调用者可以注册。应一并检查实际 agent 身份、已加载的设置、API 绑定和授权配置。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

根据运行中 agent 的 `-config-dir` 和 `-config-file` 参数，找到相关配置，并且只检查脚本检查和 ACL 字段名称及设置。配置文件也可能包含 gossip 密钥或 token；避免将其粘贴到共享日志中。不要仅为枚举此情况而注册服务或运行健康检查。

如果权限较低的用户可以**写入并搜索**由 root 运行的 agent 的 `-config-dir` 指定目录，则存在另一条本地文件路径：该目录可能会加载新的 `.hcl` 或 `.json` 服务定义。即使禁止列出目录，目录搜索和写入权限仍可能允许添加文件。要实现 root 命令执行，需确认 agent 确实会加载该目录、其**有效的**脚本检查设置允许本地定义、该定义已加载，并且 agent 保留 root 权限。[Consul 文档](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)说明了哪些设置和健康检查定义可以重新加载；启用脚本检查本身可能需要重启，因此请验证已安装版本的行为。如果 ACL 保护了 agent，[`consul reload` 需要 `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)；仅有 KV 写入权限并不能提供此权限。将可写目录元数据视为审查线索，而非已授权重新加载、重启或命令执行的证明。检查路径、权限和策略，不要写入配置或调用 API。

## 跟踪服务执行链

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

检查 unit、drop-in、`EnvironmentFile=`、helper scripts、相对命令、可写目录和 socket activation。即使 unit 归 root 所有，如果它读取用户可写的配置或 script，也仍可能不安全。[arbitrary file write](../interesting-files-permissions/write-to-root.md) 页面介绍了常见的 service 和 unit 滥用路径。如果一次性的 `ps` 列表遗漏了短暂运行的任务，可使用 [pspy](https://github.com/DominicBreuker/pspy) 或 audit/process telemetry 进行监控。

对于自定义的 **xinetd** service，将已启用 stanza 中的 `server`、`user` 和访问控制与实际 listener 及确切 executable 对照起来。 [`user` 设置](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)决定生成的 process 身份，而 executable 上的 set-user-ID bit 则可能在 [`execve` 允许该转换时](https://man7.org/linux/man-pages/man2/execve.2.html)单独改变其 effective identity。一个可访问且有特权的 binary 如果接受不可信输入，就值得离线检查其 source 或反汇编结果，寻找内存安全漏洞，例如将无界的 [`scanf` 字符串转换](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)写入固定大小的 buffer。service 映射和 set-user-ID metadata 只是调查线索，并不能证明存在此类漏洞；被动枚举期间不要发送会导致崩溃的输入，也不要调试正在运行的特权 service。

对于 source 可读的自定义特权 listener，检查每个由调用方控制、用于 [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html) 等复制操作的长度。仅检查当前写入索引是否位于固定 buffer 范围内，并不能证明**复制长度**适合剩余空间；确认索引在范围内后，还要验证 `copy_length <= capacity - index`，并检查 signedness 和算术溢出。只有当输入会到达该操作、低权限用户可访问该 listener，且 process 保留了更高的 effective identity 时，这才是值得跟进的审查线索。离线检查 source 和 process metadata；枚举期间不要向正在运行的 service 发送会导致崩溃的输入。

使用 **Upstart** 的系统可能会将 system job 定义放在 `/etc/init/*.conf` 下。如果当前用户可写某个 job file，且 active init daemon 会加载该确切 job、其 `script` 或 `exec` stanza 以更高权限身份运行，并且用户能通过允许的 `initctl` 命令或其他真实触发机制启动它，那么该文件就值得关注。仅有 sudo `initctl` 授权，并不能证明任何 job file 可写，也不能证明修改后的 job 会运行。枚举时检查确切 job file 的权限、有效的 run-as 设置、active daemon 和触发机制，不要编辑或启动该 job。参见 [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) 和 [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) 手册。

可读的 autologin 密码文件（例如某些系统上的 `/etc/autologin/passwd`，其 [boot job 会读取该确切路径](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)）是凭据暴露线索。确认已安装该 boot job，且它会使用此文件，然后单独验证密码是否对其他本地账户或 service 有效。仅凭文件名不能证明密码被重复使用；记录路径和访问 metadata，不要将密码写入共享的枚举输出。

unit 的 `ExecStart=` 或计划任务命令可能会暴露无法列出目录中的 script 确切路径。[目录 search permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html) 仍可能允许当前身份遍历该已知路径；应确认每个父目录都具有 search 权限，并确认文件具有 read 权限，而不要想当然地认为目录列表失败就能保护文件。可读 script 可能包含传输凭据，但要访问另一个账户，还需要该凭据仍然有效且能在该账户处独立通过验证。记录路径和权限证据，不要将秘密值打印到共享日志中。

对于计划执行的 CommonJS Node.js script，即使 script 本身是只读的，也要检查 `require('package')` 这类裸导入。[Node 会先在导入文件旁边以及其祖先目录中搜索 `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)，然后才回退到配置的全局路径。若低权限用户能**写入并搜索**其中一个祖先目录，就可能创建一个更早匹配到的 package。确认确切导入会被执行、所选 package 不是内置 module、相关路径可创建或修改、已安装的 runtime 会从该路径解析 module，并且更高权限的 job 会在未来某次运行时加载它。父目录可写的 metadata 只是审查线索；被动检查 script 和 scheduler，不要植入 module 或触发 job。

当自动化 job 以不同的 OS 身份安装 package 时，私有 Python package index 也是一个信任边界。将确切 job 和 run-as 账户与其配置的 index、所选 package 名称进行关联，并确认低权限用户能否发布或替换 job 实际会安装的 package。构建 source distribution 时，可能会以安装程序的身份运行其 build backend 或旧式 `setup.py`；导入已安装 package 则是另一条执行路径。仅凭 index listener、可读的上传密码 hash 或 package 文件名，不能证明这条链路成立。检查 job、index 授权和 package 来源；枚举期间不要上传或安装任何内容。参见 [pip 的 build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) 和 [secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/)。

特权 agent 可能会轮询由独立 web service 或 container 管理的 task queue。如果低信任身份能写入该 service 的 task database，应确认这些记录确实会提供给该 agent，且 command task 会以 agent 的 OS 身份运行。分别确认 database 写入权限、目标 session 或 routing key、轮询是否 active、task 授权，以及 agent 的 effective user。container 内的 root 本身并不意味着拥有 host-root 权限；只有当具有 host 特权的 consumer 执行了攻击者控制的 task 数据时，才跨越了该边界。检查 process、database file 和 service metadata，不要在枚举期间修改 queue 或发送 task。

计划任务也可能从 application database 的配置记录中读取命令。确认低权限 database role 能否修改该确切记录、active job 是否会在更改后读取它，以及该值是否会以更高 OS 身份传递给 shell 或等效的 command runner。database 写入权限或看起来像命令的值本身都不能证明会执行；被动枚举期间检查 job 和权限，不要修改该记录。

排队消息也可能包含 URL 而非代码。如果特权 consumer 会获取该 URL，并将响应作为 Lua 或其他可执行 plugin 加载，应验证发布者对确切 exchange 和 routing key 的权限、与被消费 queue 的 binding、fetch 和 plugin-load 路径，以及 worker 的 effective identity。[RabbitMQ 会通过 exchanges 路由已发布的消息](https://www.rabbitmq.com/docs/exchanges)；仅有 broker listener 或有效登录凭据，并不能证明消息会送达该 worker。捕获到的明文 broker 凭据是另一条线索，需要实际具备 packet-capture 访问权限且流量可读；它们不能证明发布授权。只有在 runtime 提供该 API 时，Lua plugin 才能通过 [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) 调用 shell 命令。被动枚举期间检查配置和代码，不要捕获流量、发布消息或获取 plugin。

当特权 Python service 暴露本地 HTTP 或 socket endpoint 时，即使文件权限不允许修改，可读 script 也可能揭示从输入到代码的执行路径。将 active process 和 unit 身份与确切 script、listener、route 授权及调用方控制的字段对应起来，然后沿着这些字段经过解析和验证的流程，追踪到动态 `eval()` 或 `exec()` sink。尤其是从请求文本构造新的 f-string 并对其求值，可能会将攻击者提供的替换字段解释为 Python 表达式（[Python `eval` warning](https://docs.python.org/3/library/functions.html#eval)；[f-string semantics](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。仅仅发现 `eval`，或发现服务绑定到 loopback，都不能证明不可信调用方能到达该 sink；应检查实际数据流和访问控制，枚举期间不要发送测试 payload。

该 route 上的 signed-request gate 也需要单独审查。如果可读 source 显示 signing key 来自一个明确很小或可预测的输出空间，而且 service 暴露了一个有效签名样本，那么该签名可能无法保护特权 `eval()` sink。验证确切的 key derivation 和 verifier、运行中 service 的身份和本地调用方访问权限，以及签名字段是否会到达该 sink；仅仅导入 Python 的 [`random` module](https://docs.python.org/3/library/random.html) 或拥有一个签名样本，都不能证明这些条件成立。Python 也警告，限制 `__builtins__` [并不能为不可信的 `eval()` 输入提供安全边界](https://docs.python.org/3/library/functions.html#eval)。离线分析 key；被动枚举期间不要提交伪造请求。

即使 unit file 和所有现有 drop-in 都受到保护，只要 `/etc/systemd/system/<unit>.service.d` 目录为空但可写，仍然值得关注：用户可以创建新的 `.conf` override。检查当前身份是否能写入并搜索该目录、unit 是否已加载并以 root 身份运行，以及之后是否会执行 daemon reload 和 restart。reload 或 restart 权限、timer 或后续启动都可能使更改生效；仅有目录写入权限并不会立即执行更改。

对于正在运行的 service，沿着 unit 的 `[Service]` 段中 `EnvironmentFile=` 指定的字面路径检查文件，包括名称不以 `.env` 开头的文件。如果低权限用户可读取某个文件，可列出 `API_TOKEN` 或 `APP_SECRET_KEY` 等类似凭据的键名，但不要将值打印到共享日志中。评估有效 unit 时，也要检查 drop-in override 和可选的 `-` 前缀。文件可读是凭据暴露线索；只有该值仍然有效且能用于特权操作时，才可能导致权限提升。

### 特权处理不可信上传文件

以 root 身份运行的 file watcher 可能会将用户可写上传目录中的文件交给短暂运行的 parser 或 extractor。沿着运行中的 watcher 找到其父 script 或 service，并确认确切目录、谁能在其中放置文件、子命令及其参数，以及子进程运行时使用的身份。process snapshot 可能会显示 watcher，却遗漏两次上传之间运行的 extractor。被动枚举期间不要放置测试 payload 或触发 watcher。

一个具体例子是 Binwalk 的 extraction mode（`-e`）处理攻击者控制的 PFS 数据。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) 使 PFS extractor 能够写入预期目录之外的位置，包括 Binwalk 之后可能加载的 plugin 路径。上游在 [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4) 中包含了修复，但发行版 backport 可能保留较旧的显示版本；判断是否适用前，请检查已安装 package 的安全状态，例如查看 [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)。仅安装了某个版本的 Binwalk，并不能证明存在权限提升路径：更高权限的 process 必须实际对低权限用户可控的输入调用 extraction。

### 使用本地依赖的计划构建

计划执行的 `cargo run` 会以 job 的 run-as 用户身份重新编译 source。检查 manifest 中 `{ path = "..." }` 形式的本地依赖，并检查每个依赖的 source 和父目录权限，而不只是主 crate。如果低权限用户能修改 Cargo 会编译的依赖，且计划任务会运行编译结果，那么编译后的代码就能以该 run-as 用户身份执行。确认 scheduler 的有效命令、working directory、依赖解析情况，以及是否会重新构建；其他位置的可写 Rust source file 只是线索。被动排查只需读取 manifest 和路径 metadata。参见 [Cargo path-dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)。

## Xvfb framebuffer 文件

`Xvfb -fbdir <directory>` 会使用名为 `Xvfb_screen<n>` 的 memory-mapped 文件存储其虚拟屏幕。如果另一个用户正在运行的 Xvfb process 指定了一个目录，且当前用户能读取其中的 screen file，那么 framebuffer 可能会暴露该用户桌面上的内容。应结合检查 process、文件所有权和权限；仅仅文件可读，并不能证明屏幕上有有用内容。先检查路径和 metadata，不要将图像数据复制到共享枚举输出中。[Xvfb 手册](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)介绍了 `-fbdir` 的行为。

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
7. [LibreOffice 帮助：为外部 API 客户端打开 socket](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK：`XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
