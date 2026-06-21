# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic 是什么？

Mythic 是一个开源、模块化、协作式的 command and control (C2) 框架，专为 red teaming 设计。它允许操作员在不同操作系统上管理和部署 agents（payloads），包括 Windows、Linux 和 macOS。Mythic 提供了一个浏览器 UI，用于多操作员任务分配、文件处理、SOCKS/rpfwd 管理以及 payload 生成。

与单体框架不同，Mythic 仓库本身**不**直接提供 payload 类型或 C2 profiles。Agents、wrappers 和 C2 profiles 通常作为外部组件安装，并且可以独立于 Mythic core 更新。

### 安装

要安装 Mythic，请按照官方 **[Mythic repo](https://github.com/its-a-feature/Mythic)** 中的说明进行操作。从 Mythic 目录进行的常见 bootstrap 是：
```bash
sudo make
sudo ./mythic-cli start
```
如果 Mythic 已经在运行，通常你可以通过 `./mythic-cli install github ...` 添加一个新的 agent 或 profile，然后重启 Mythic，或者直接启动新的组件。

### Agents

Mythic 支持多个 agents，它们是**在被入侵系统上执行任务的 payloads**。每个 agent 都可以针对特定需求进行定制，并且可以运行在不同的操作系统上。

默认情况下 Mythic 没有安装任何 agents。开源社区的 agents 位于 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)，而 [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) 可用于快速检查支持的操作系统、payload formats、wrappers 和 C2 profiles。

要从该组织安装一个 agent，你可以运行：
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 形式在你从非 root 环境进行安装时很有用。即使 Mythic 已经在运行，你也可以用前面的命令添加新的 agents。

### C2 Profiles

Mythic 中的 C2 profiles 定义了 **agents 如何与 Mythic server 通信**。它们指定通信协议、加密方法以及其他设置。你可以通过 Mythic web interface 创建和管理 C2 profiles。

默认情况下，Mythic 安装时不包含任何 profiles，不过，可以通过运行从仓库 [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) 下载一些 profiles：
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
当前需要牢记的 operator 相关 profiles：

- [`http`](https://github.com/MythicC2Profiles/http)：基础的异步 GET/POST traffic。
- [`httpx`](https://github.com/MythicC2Profiles/httpx)：更灵活的 HTTP traffic，支持多个 callback domains、fail-over/round-robin 轮换、自定义 headers/query parameters，以及消息 transforms（`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`），可放在 cookies、headers、query parameters 或 body 中。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp)：当静态 `http` profile 太容易被识别时，使用 JSON/TOML 驱动的 HTTP message shaping。

### 当前 platform 说明

- 许多公开的 agents 和 profiles 现在安装时会使用预构建的远程容器镜像。  
如果你 fork 了某个组件，或者在本地打了补丁，但 Mythic 仍然使用旧行为，请检查生成的 `.env` 条目里的 `*_REMOTE_IMAGE`、`*_USE_BUILD_CONTEXT` 和 `*_USE_VOLUME`；启用 `*_USE_BUILD_CONTEXT="true"` 通常会让 Mythic 重新从你的本地 Docker context 构建，而不是悄悄复用远程镜像。
- Browser scripts 是 Mythic 对 operator 来说最有价值的提升体验功能之一：它们可以把原始命令输出转换成表格、截图查看器、下载链接，以及直接从 UI 发起后续 tasking 的按钮。这对重复性的 `ls`、`ps`、triage 和 file-browser 工作流尤其有用。
- 更新版 Mythic 还支持交互式 tasking 和 Push C2 模式，这能减少在 PTY/SOCKS/rpfwd 密集操作时对 `sleep 0` 轮询的需求。当 agent/profile 支持时，这通常比不断轰击服务器仅仅为了保持交互通道可用，开销更低。

### Wrapper payloads

Wrapper payloads 让你在保持相同 agent logic 的同时，改变交付或持久化到磁盘上的表示形式。

- `service_wrapper`：把另一个 payload 转成 Windows service executable，这在执行路径需要有效的 service binary 时很有用。
- `scarecrow_wrapper`：使用 ScareCrow loader 包装兼容的 shellcode，生成基于 loader 的输出，如 EXE/DLL/CPL。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo 是一个用 C# 编写的 Windows agent，使用 4.0 .NET Framework，专为 SpecterOps training offerings 设计。

安装它：
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### 当前 build/profile 说明

- Apollo 目前可以输出 `WinExe`、`Shellcode`、`Service` 和 `Source` payloads。
- 常用的 Apollo profiles 是 `http`、`httpx`、`smb`、`tcp` 和 `websocket`。
- 当你需要域名轮换、proxy 支持、自定义消息放置和消息变换，而不是旧的静态 `http` profile 时，`httpx` 通常是更灵活的选项。
- Apollo 支持诸如 `service_wrapper` 和 `scarecrow_wrapper` 之类的 wrapper payloads。
- `register_file` 和 `register_assembly` 是 `execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import` 和 `powerpick` 的 staging primitives。 在当前 Apollo builds 中，这些 staged artifacts 会在 client-side 以 DPAPI-protected AES256 blobs 缓存。
- `ls` 和 `ps` 的结果与 Mythic 的 browser scripts 以及 file/process browser 配合得特别好，这会让 operator triage 在协作操作中明显更快。
- Apollo 的 fork-and-run jobs 会从 `spawnto_x86` / `spawnto_x64` 继承 sacrificial process 设置，从 `ppid` 继承 parent selection，然后使用当前选定的 injection primitive。 实际上，这意味着你对某个命令做的 OPSEC 调整，往往会同时影响 `execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe` 和 `spawn`。
- 当前文档中的 Apollo injection backends 包括 `CreateRemoteThread`、`QueueUserAPC`（early-bird 风格）以及通过 syscalls 的 `NtCreateThreadEx`。 在噪声较大的 post-exploitation 之前先用 `get_injection_techniques` 查看可用项；如果你需要切换离开某个与目标或要运行的命令冲突的 primitive，就用 `set_injection_technique`。
- `blockdlls` 只会影响为 post-exploitation jobs 创建的 sacrificial processes。 再配合一个比默认裸 `rundll32.exe` 更不显眼的 `spawnto_x64` target，这是在运行大量 assembly/PowerShell 任务前，最容易做的 Apollo 侧改动之一。

这个 agent 有很多 commands，因此它和 Cobalt Strike 的 Beacon 非常相似，但又多了一些功能。 其中，它支持：

### 常用操作

- `cat`: 打印文件内容
- `cd`: 更改当前工作目录
- `cp`: 将文件从一个位置复制到另一个位置
- `ls`: 列出当前目录或指定路径中的文件和目录
- `ifconfig`: 获取网络适配器和 interfaces
- `netstat`: 获取 TCP 和 UDP connection 信息
- `pwd`: 打印当前工作目录
- `ps`: 列出目标系统上正在运行的 processes（附加信息）
- `jobs`: 列出与长时间运行 tasking 相关的所有运行中 jobs
- `download`: 将文件从目标系统下载到本地机器
- `upload`: 将文件从本地机器上传到目标系统
- `reg_query`: 查询目标系统上的 registry keys 和 values
- `reg_write_value`: 向指定的 registry key 写入新 value
- `sleep`: 更改 agent 的 sleep interval，它决定它多久向 Mythic server 检查一次
- 还有很多其他命令，使用 `help` 查看可用命令完整列表。

### Privilege escalation

- `getprivs`: 在当前 thread token 上尽可能启用更多 privileges
- `getsystem`: 打开 winlogon 的 handle 并复制 token，实际上将 privileges 提升到 SYSTEM level
- `make_token`: 创建一个新的 logon session 并将其应用到 agent，允许 impersonation 另一个用户
- `steal_token`: 从另一个 process 盗取 primary token，允许 agent impersonate 该 process 的用户
- `pth`: Pass-the-Hash attack，允许 agent 使用用户的 NTLM hash 进行认证，而不需要明文 password
- `mimikatz`: 运行 Mimikatz commands，从 memory 或 SAM database 中提取 credentials、hashes 和其他敏感信息
- `rev2self`: 将 agent 的 token 恢复为其 primary token，实际上把 privileges 降回原始 level
- `ppid`: 通过指定新的 parent process ID 来更改 post-exploitation jobs 的 parent process，从而更好地控制 job execution context
- `printspoofer`: 执行 PrintSpoofer commands 绕过 print spooler security measures，从而实现 privilege escalation 或 code execution
- `dcsync`: 将用户的 Kerberos keys 同步到本地机器，允许 offline password cracking 或进一步 attacks
- `ticket_cache_add`: 将一个 Kerberos ticket 添加到当前 logon session 或指定 session，允许 ticket reuse 或 impersonation

### Process execution

- `assembly_inject`: 允许将一个 .NET assembly loader 注入到远程 process
- `blockdlls`: 阻止非 Microsoft 签名的 DLL 被加载到 post-exploitation jobs 中
- `execute_assembly`: 在 agent 的上下文中执行一个 .NET assembly
- `execute_coff`: 在内存中执行一个 COFF file，允许 in-memory execution 已编译代码
- `execute_pe`: 执行一个 unmanaged executable（PE）
- `keylog_inject`: 向另一个 process 注入 keylogger，并将按键流回传到 Mythic 的 keylog view
- `screenshot` / `screenshot_inject`: 直接捕获当前桌面，或者通过向目标 process/session 注入 screenshot assembly 来捕获
- `get_injection_techniques`: 显示可用的 injection techniques 以及当前选中的那个
- `inline_assembly`: 在一个可丢弃的 AppDomain 中执行一个 .NET assembly，允许临时执行 code 而不影响 agent 的主 process
- `register_assembly`: 注册一个 .NET assembly 供后续执行
- `register_file`: 在 agent cache 中注册一个 file，供后续 `execute_*` 或 PowerShell tasking 使用
- `run`: 使用系统的 PATH 来查找 executable，在目标系统上执行一个 binary
- `set_injection_technique`: 更改 post-exploitation jobs 使用的 injection primitive
- `shinject`: 将 shellcode 注入到远程 process，允许在内存中执行任意 code
- `inject`: 将 agent shellcode 注入到远程 process，允许在内存中执行 agent 的 code
- `spawn`: 在指定 executable 中生成一个新的 agent session，允许在新 process 中执行 shellcode
- `spawnto_x64` 和 `spawnto_x86`: 将 post-exploitation jobs 使用的默认 binary 改为指定 path，而不是使用没有参数、非常显眼的 `rundll32.exe`。

### Mythic Forge

这允许从 Mythic Forge 中 **load COFF/BOF** files，Mythic Forge 是一个预编译 payloads 和 tools 的仓库，这些内容可以在目标系统上执行。 对于所有可加载的 commands，可以把它们作为 BOFs 在当前 agent process 中执行常见操作（通常比单独启动一个 process 具有更好的 OPSEC）。

开始安装它们：
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` to show the COFF/BOF modules from the Mythic Forge to be able to select and load them into the agent's memory for execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

For BOFs, remember that Forge does **not** just pass one flat argument string
to Apollo. It maps BOF parameters into Mythic's typed-array format and then
forwards them into Apollo's `execute_coff` flow. If a Forge-loaded BOF behaves
strangely, check the expected BOF argument types / entrypoint rather than only
the command line you typed.

### PowerShell & scripting execution

- `powershell_import`: 导入新的 PowerShell 脚本 (.ps1) 到 agent 缓存中，以便后续执行
- `powershell`: 在 agent 的上下文中执行 PowerShell 命令，支持高级脚本和自动化
- `powerpick`: 将 PowerShell loader assembly 注入到一个牺牲进程中并执行 PowerShell 命令（不记录 powershell 日志）。
- `psinject`: 在指定进程中执行 PowerShell，允许在另一个进程的上下文中有针对性地执行脚本
- `shell`: 在 agent 的上下文中执行 shell 命令，类似于在 cmd.exe 中运行命令

### Lateral Movement

- `jump_psexec`: 使用 PsExec 技术通过先复制 Apollo agent 可执行文件（apollo.exe）并执行它，横向移动到新主机。
- `jump_wmi`: 使用 WMI 技术通过先复制 Apollo agent 可执行文件（apollo.exe）并执行它，横向移动到新主机。
- `link` and `unlink`: 在 callbacks 之间创建和拆除 P2P 链接（例如通过 SMB/TCP）。
- `wmiexecute`: 使用 WMI 在本地或指定的远程系统上执行命令，可选使用凭据进行冒充。
- `net_dclist`: 获取指定域的域控制器列表，适用于识别横向移动的潜在目标。
- `net_localgroup`: 列出指定计算机上的本地组；如果未指定计算机，则默认为 localhost。
- `net_localgroup_member`: 获取指定本地或远程计算机上某个组的本地组成员信息，可用于枚举特定组中的用户。
- `net_shares`: 列出指定计算机上的远程共享及其可访问性，适用于识别横向移动的潜在目标。
- `socks`: 在目标网络上启用符合 SOCKS 5 的代理，允许通过被入侵主机中转流量。与 proxychains 等工具兼容。
- `rpfwd`: 在目标主机上监听指定端口，并通过 Mythic 将流量转发到远程 IP 和端口，从而允许远程访问目标网络上的服务。
- `listpipes`: 列出本地系统上的所有命名管道，可通过与 IPC 机制交互用于横向移动或提权。

For the lower-level WMI execution primitives used underneath `jump_wmi` or `wmiexecute`, check [WmiExec](lateral-movement/wmiexec.md). For broader pivoting patterns, check [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: 显示 agent 中特定命令的详细信息，或显示所有可用命令的一般信息。
- `clear`: 将任务标记为 'cleared'，这样 agents 就不会再拾取它们。你可以指定 `all` 来清除所有任务，或指定 `task Num` 来清除特定任务。


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is a Golang agent that compiles into **Linux and macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.
- `pty` is one of the most useful newer-quality-of-life commands for Linux/macOS
operations because it opens an interactive PTY and can expose a Mythic-side
port for fuller terminal interaction without resorting to the older `sleep 0`
+ SOCKS workaround.
- Poseidon's current docs are especially interesting for macOS-heavy
tradecraft: `jxa` executes JavaScript for Automation in-memory,
`screencapture` grabs the logged-in desktop, `clipboard_monitor` streams
pasteboard changes, `execute_library` loads a local dylib and calls a
function from it, and `libinject` forces a remote process to load an on-disk
dylib.
- For long-running jobs, remember that Poseidon executes post-exploitation work
in goroutines/threads that are cooperative rather than hard-killable. The
docs also explicitly note that there is currently no built-in agent
obfuscation, so build/profile-level tradecraft matters more than with heavily
obfuscated commercial implants.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: 打印文件内容
- `cd`: 更改当前工作目录
- `chmod`: 更改文件权限
- `config`: 查看当前配置和主机信息
- `cp`: 将文件从一个位置复制到另一个位置
- `curl`: 执行单个 Web 请求，可选携带头部和 method
- `upload`: 将文件上传到目标
- `download`: 从目标系统下载文件到本地机器
- And many more

### Search Sensitive Information

- `triagedirectory`: 在主机上的目录中查找有价值的文件，例如敏感文件或凭据。
- `getenv`: 获取当前所有环境变量。

### macOS-specific tradecraft

- `jxa`: 通过 `OSAScript` 在内存中执行 JavaScript for Automation，这在不落地单独脚本文件的情况下进行原生 macOS post-exploitation 很有用。
- `clipboard_monitor`: 轮询 pasteboard 并将变化回传给 Mythic，这对依赖复制/粘贴的凭据/token 窃取流程很方便。
- `screencapture`: 捕获 macOS 上用户的桌面。
- `execute_library`: 从磁盘加载一个 dylib，并调用其中指定的导出函数。
- `libinject`: 注入一个 shellcode stub，强制另一个 macOS 进程从磁盘加载一个 dylib。
- `persist_launchd`: 直接从 agent 创建 LaunchAgent / LaunchDaemon 持久化。

### Move laterally

- `ssh`: 使用指定凭据通过 SSH 连接到主机，并打开一个 PTY，而不需要启动 ssh。
- `sshauth`: 使用指定凭据连接到指定主机。你也可以用它通过 SSH 在远程主机上执行特定命令，或者用它通过 SCP 传输文件。
- `link_tcp`: 通过 TCP 连接到另一个 agent，允许 agent 之间直接通信。
- `link_webshell`: 使用 webshell P2P profile 连接到一个 agent，允许远程访问该 agent 的 Web 界面。
- `rpfwd`: 启动或停止 Reverse Port Forward，允许远程访问目标网络上的服务。
- `socks`: 在目标网络上启动或停止 SOCKS5 proxy，允许通过被攻陷主机隧道转发流量。与 `proxychains` 等工具兼容。
- `portscan`: 扫描主机上的开放端口，有助于识别横向移动或进一步攻击的潜在目标。

### Process execution

- `shell`: 通过 /bin/sh 执行单个 shell 命令，允许直接在目标系统上执行命令。
- `run`: 使用参数从磁盘执行一个命令，允许在目标系统上执行二进制文件或脚本。
- `pty`: 打开一个交互式 PTY，允许直接与目标系统上的 shell 交互。




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
