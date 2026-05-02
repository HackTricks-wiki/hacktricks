# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic 是什么？

Mythic 是一个开源、模块化、协作式的 command and control (C2) 框架，专为 red teaming 设计。它允许操作者在不同 operating systems 上管理和部署 agents（payloads），包括 Windows、Linux 和 macOS。Mythic 提供浏览器 UI，用于多操作者 tasking、文件处理、SOCKS/rpfwd 管理以及 payload 生成。

与单体框架不同，Mythic 仓库本身**不**自带 payload types 或 C2 profiles。Agents、wrappers 和 C2 profiles 通常作为外部组件安装，并且可以独立于 Mythic core 更新。

### 安装

要安装 Mythic，请按照官方 **[Mythic repo](https://github.com/its-a-feature/Mythic)** 中的说明进行。从 Mythic 目录进行常见的 bootstrap 方法是：
```bash
sudo make
sudo ./mythic-cli start
```
如果 Mythic 已经在运行，你通常可以使用 `./mythic-cli install github ...` 添加一个新的 agent 或 profile，然后重启 Mythic，或者直接启动新的组件。

### Agents

Mythic 支持多个 agent，这些 agent 是**在被攻陷系统上执行任务的 payload**。每个 agent 都可以针对特定需求进行定制，并且可以运行在不同的操作系统上。

默认情况下，Mythic 没有安装任何 agent。开源社区的 agent 位于 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)，而 [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) 可用于快速查看支持的操作系统、payload 格式、wrappers 和 C2 profiles。

要从该 org 安装一个 agent，你可以运行：
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 形式在你从非 root 环境进行安装时很有用。即使 Mythic 已经在运行，你也可以使用前面的命令添加新的 agents。

### C2 Profiles

Mythic 中的 C2 profiles 定义了 **agents 如何与 Mythic server 通信**。它们指定通信协议、加密方法以及其他设置。你可以通过 Mythic web interface 创建和管理 C2 profiles。

默认情况下，Mythic 安装时没有任何 profiles，不过，你可以从 repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) 下载一些 profiles，运行：
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): 基本的异步 GET/POST 流量。
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 更灵活的 HTTP 流量，支持多个 callback domains、fail-over/round-robin rotation、自定义 headers/query parameters，以及消息变换（`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`），这些内容可放在 cookies、headers、query parameters 或 body 中。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): 当静态 `http` profile 太容易被识别时，可使用 JSON/TOML 驱动的 HTTP 消息塑形。

### Wrapper payloads

Wrapper payloads 让你在保持相同 agent logic 的同时，改变交付或持久化时的磁盘表示形式。

- `service_wrapper`: 将另一个 payload 变成 Windows service executable，这在执行路径需要一个有效的 service binary 时很有用。
- `scarecrow_wrapper`: 使用 ScareCrow loader 封装兼容的 shellcode，生成带 loader 的输出，例如 EXE/DLL/CPL。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo 是一个用 C# 编写的 Windows agent，使用 4.0 .NET Framework，设计用于 SpecterOps training offerings。

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo 目前可以输出 `WinExe`、`Shellcode`、`Service` 和 `Source` payloads。
- Apollo 常用的 profiles 有 `http`、`httpx`、`smb`、`tcp` 和 `websocket`。
- 当你需要 domain rotation、proxy support、custom message placement，以及 message transforms，而不是旧的静态 `http` profile 时，`httpx` 通常是更灵活的选择。
- Apollo 支持 `service_wrapper` 和 `scarecrow_wrapper` 这类 wrapper payloads。
- `register_file` 和 `register_assembly` 是 `execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import` 和 `powerpick` 的 staging primitives。当前的 Apollo builds 会把这些 staged artifacts 缓存在 client-side，形式为受 DPAPI 保护的 AES256 blobs。
- `ls` 和 `ps` 结果与 Mythic 的 browser scripts 和 file/process browser 配合尤其好，这会让 operator triage 在协作操作中明显更快。

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: 打印文件内容
- `cd`: 更改当前工作目录
- `cp`: 将文件从一个位置复制到另一个位置
- `ls`: 列出当前目录或指定路径中的文件和目录
- `ifconfig`: 获取网络适配器和接口
- `netstat`: 获取 TCP 和 UDP 连接信息
- `pwd`: 打印当前工作目录
- `ps`: 列出目标系统上正在运行的进程（附加信息）
- `jobs`: 列出所有与长时间运行 tasking 关联的运行中 jobs
- `download`: 将文件从目标系统下载到本地机器
- `upload`: 将文件从本地机器上传到目标系统
- `reg_query`: 查询目标系统上的 registry keys 和 values
- `reg_write_value`: 向指定的 registry key 写入新值
- `sleep`: 更改 agent 的 sleep interval，这决定了它多久向 Mythic server 检查一次
- 还有很多其他命令，使用 `help` 查看可用命令的完整列表。

### Privilege escalation

- `getprivs`: 尽可能为当前 thread token 启用更多 privileges
- `getsystem`: 打开 winlogon 的 handle 并复制 token，从而有效提升权限到 SYSTEM level
- `make_token`: 创建新的 logon session 并将其应用到 agent，从而允许 impersonation 另一个用户
- `steal_token`: 从另一个 process 盗取 primary token，从而允许 agent impersonate 该 process 的用户
- `pth`: Pass-the-Hash attack，允许 agent 使用用户的 NTLM hash 进行认证，而无需明文 password
- `mimikatz`: 运行 Mimikatz commands，以从 memory 或 SAM database 中提取 credentials、hashes 和其他敏感信息
- `rev2self`: 将 agent 的 token 恢复为其 primary token，有效地把 privileges 降回原始 level
- `ppid`: 通过指定新的 parent process ID 来更改 post-exploitation jobs 的 parent process，从而更好地控制 job execution context
- `printspoofer`: 执行 PrintSpoofer commands 以绕过 print spooler security measures，从而实现 privilege escalation 或 code execution
- `dcsync`: 将用户的 Kerberos keys 同步到本地机器，从而允许 offline password cracking 或进一步攻击
- `ticket_cache_add`: 向当前 logon session 或指定 session 添加 Kerberos ticket，从而允许 ticket reuse 或 impersonation

### Process execution

- `assembly_inject`: 允许将 .NET assembly loader 注入到远程 process
- `blockdlls`: 阻止非 Microsoft 签名的 DLLs 加载到 post-exploitation jobs 中
- `execute_assembly`: 在 agent 的上下文中执行 .NET assembly
- `execute_coff`: 在 memory 中执行 COFF file，从而允许在 memory 中执行已编译代码
- `execute_pe`: 执行一个 unmanaged executable (PE)
- `get_injection_techniques`: 显示可用的 injection techniques 以及当前选中的一个
- `inline_assembly`: 在一个可丢弃的 AppDomain 中执行 .NET assembly，从而允许临时执行 code 而不影响 agent 的主 process
- `register_assembly`: 注册一个 .NET assembly 以便之后执行
- `register_file`: 在 agent cache 中注册一个文件，以便之后进行 `execute_*` 或 PowerShell tasking
- `run`: 使用系统的 PATH 来查找 executable，在目标系统上执行 binary
- `set_injection_technique`: 更改 post-exploitation jobs 使用的 injection primitive
- `shinject`: 将 shellcode 注入远程 process，从而允许在 memory 中执行任意 code
- `inject`: 将 agent shellcode 注入远程 process，从而允许在 memory 中执行 agent 的 code
- `spawn`: 在指定 executable 中生成一个新的 agent session，从而允许在一个新 process 中执行 shellcode
- `spawnto_x64` 和 `spawnto_x86`: 将 post-exploitation jobs 使用的默认 binary 更改为指定路径，而不是使用没有参数、且非常显眼的 `rundll32.exe`。

### Mythic Forge

这允许从 Mythic Forge 加载 `COFF/BOF` files，Mythic Forge 是一个预编译 payloads 和 tools 的 repository，这些内容可以在目标系统上执行。借助所有可加载的 commands，就可以把它们作为 BOFs 在当前 agent process 中执行，从而完成常见操作（通常比单独启动一个 process 具有更好的 OPSEC）。

Start installing them with:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
然后，使用 `forge_collections` 来显示 Mythic Forge 中的 COFF/BOF modules，以便选择它们并将它们加载到 agent 的内存中执行。默认情况下，Apollo 中会添加以下 2 个 collections：

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

加载一个 module 之后，它会以另一个 command 的形式出现在列表中，例如 `forge_bof_sa-whoami` 或 `forge_bof_sa-netuser`。

### PowerShell & scripting execution

- `powershell_import`: 导入一个新的 PowerShell script (.ps1) 到 agent cache 中，以便后续执行
- `powershell`: 在 agent 的上下文中执行一个 PowerShell command，支持高级 scripting 和 automation
- `powerpick`: 将一个 PowerShell loader assembly 注入到一个 sacrificial process 中，并执行一个 PowerShell command（不记录 powershell logging）。
- `psinject`: 在指定 process 中执行 PowerShell，允许在另一个 process 的上下文中有针对性地执行 scripts
- `shell`: 在 agent 的上下文中执行一个 shell command，类似于在 cmd.exe 中运行命令

### Lateral Movement

- `jump_psexec`: 使用 PsExec technique 通过先复制 Apollo agent executable（apollo.exe）并执行它，横向移动到新的 host。
- `jump_wmi`: 使用 WMI technique 通过先复制 Apollo agent executable（apollo.exe）并执行它，横向移动到新的 host。
- `link` and `unlink`: 在 callbacks 之间创建和拆除 P2P links（例如通过 SMB/TCP）。
- `wmiexecute`: 使用 WMI 在本地或指定的 remote system 上执行 command，并可选择凭据进行 impersonation。
- `net_dclist`: 获取指定 domain 的 domain controllers 列表，有助于识别横向移动的潜在 targets。
- `net_localgroup`: 列出指定 computer 上的 local groups；如果未指定 computer，则默认使用 localhost。
- `net_localgroup_member`: 获取本地或远程 computer 上指定 group 的 local group membership，便于枚举特定 groups 中的 users。
- `net_shares`: 列出指定 computer 上的 remote shares 及其可访问性，有助于识别横向移动的潜在 targets。
- `socks`: 在目标 network 上启用一个符合 SOCKS 5 的 proxy，允许通过被入侵的 host 隧道化 traffic。兼容 proxychains 等 tools。
- `rpfwd`: 在目标 host 上监听指定 port，并通过 Mythic 将 traffic 转发到一个远程 IP 和 port，允许远程访问目标 network 上的 services。
- `listpipes`: 列出本地系统上的所有 named pipes，这对于通过与 IPC mechanisms 交互来进行横向移动或 privilege escalation 可能很有用。

关于 `jump_wmi` 或 `wmiexecute` 底层使用的更低层级 WMI execution primitives，请查看 [WmiExec](lateral-movement/wmiexec.md)。关于更广泛的 pivoting patterns，请查看 [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md)。

### Miscellaneous Commands
- `help`: 显示关于 agent 中所有可用 commands 的详细信息，或关于特定 command 的一般信息。
- `clear`: 将 tasks 标记为 'cleared'，这样 agents 就无法再拾取它们。你可以指定 `all` 来清除所有 tasks，或指定 `task Num` 来清除某个特定 task。


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon 是一个 Golang agent，可编译为 **Linux and macOS** executables。
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### 当前 build/profile 说明

- 当前 Poseidon builds 目标为 Linux 和 macOS，支持 `x86_64` 和 `arm64`。
- 支持的输出格式包括原生可执行文件，以及 `dylib` 和 `so` 等 shared-library 风格输出。
- Poseidon 支持 `http`、`websocket`、`tcp` 和 `dynamichttp`，当前 builders 还提供 `egress_order` 和 failover thresholds 等 multi-egress 设置。
- 当你需要更干净的网络行为或额外的 Go binary 混淆时，值得检查 `proxy_bypass` 和 `garble` 之类的 build-time options。

关于基于 Mythic 的 macOS-specific tradecraft、JAMF abuse，或 MDM-as-C2 ideas，请查看 [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md)。

当在 Linux 或 macOS 上使用时，它有一些有趣的 commands：

### 常见 actions

- `cat`: 打印文件内容
- `cd`: 更改当前工作目录
- `chmod`: 更改文件权限
- `config`: 查看当前 config 和主机信息
- `cp`: 将文件从一个位置复制到另一个位置
- `curl`: 执行单个 web request，可选 headers 和 method
- `upload`: 上传文件到目标
- `download`: 从目标系统下载文件到本地机器
- 以及更多

### 搜索敏感信息

- `triagedirectory`: 在主机上的目录中查找有价值的文件，例如敏感文件或 credentials。
- `getenv`: 获取当前所有环境变量。

### 横向移动

- `ssh`: 使用指定的 credentials 通过 SSH 连接到主机，并在不启动 ssh 的情况下打开一个 PTY。
- `sshauth`: 使用指定的 credentials 连接到指定主机。你也可以用它通过 SSH 在远程主机上执行特定 command，或者用它来通过 SCP 传输文件。
- `link_tcp`: 通过 TCP 连接到另一个 agent，允许 agents 之间直接通信。
- `link_webshell`: 使用 webshell P2P profile 连接到一个 agent，从而远程访问该 agent 的 web 界面。
- `rpfwd`: 启动或停止 Reverse Port Forward，允许远程访问目标网络中的 services。
- `socks`: 在目标网络上启动或停止 SOCKS5 proxy，用于通过已被 compromise 的主机转发 traffic。兼容 proxychains 等工具。
- `portscan`: 扫描主机上的 open ports，适用于识别潜在目标以进行 lateral movement 或进一步攻击。

### 进程执行

- `shell`: 通过 /bin/sh 执行单个 shell command，允许在目标系统上直接执行 commands。
- `run`: 从磁盘执行带 arguments 的 command，允许在目标系统上执行 binaries 或 scripts。
- `pty`: 打开一个交互式 PTY，允许直接与目标系统上的 shell 交互。




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
