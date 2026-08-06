# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic 是什么？

Mythic 是一个为 red teaming 设计的开源、模块化、协作式 command and control (C2) framework。它允许 operators 跨不同操作系统（包括 Windows、Linux 和 macOS）管理和部署 agents（payloads）。Mythic 提供了一个 browser UI，用于 multi-operator tasking、文件处理、SOCKS/rpfwd 管理和 payload 生成。

与单体式 frameworks 不同，Mythic repository 本身**不**包含 payload types 或 C2 profiles。Agents、wrappers 和 C2 profiles 通常作为 external components 安装，并且可以独立于 Mythic core 进行更新。

### 安装

要安装 Mythic，请按照官方 **[Mythic repo](https://github.com/its-a-feature/Mythic)** 中的说明操作。从 Mythic 目录执行的常见 bootstrap 命令如下：
```bash
sudo make
sudo ./mythic-cli start
```
如果 Mythic 已在运行，通常可以使用 `./mythic-cli install github ...` 添加新的 agent 或 profile，然后重启 Mythic，或者直接启动新的组件。

### Agents

Mythic 支持多个 agent，它们是**在被入侵系统上执行任务的 payloads**。每个 agent 都可以针对特定需求进行定制，并且可以在不同的操作系统上运行。

默认情况下，Mythic 未安装任何 agent。开源社区的 agent 位于 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)，而 [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) 可用于快速检查支持的操作系统、payload 格式、wrappers 和 C2 profiles。<sup>[[1]](#references)</sup>

要从该组织安装 agent，可以运行：
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 形式在从非 root 环境进行安装时非常有用。即使 Mythic 已经在运行，你仍然可以使用之前的命令添加新 agents。

### C2 Profiles

Mythic 中的 C2 profiles 定义了 **agents 如何与 Mythic server 通信**。它们指定通信协议、加密方法和其他设置。你可以通过 Mythic web interface 创建和管理 C2 profiles。

默认情况下，Mythic 安装时不包含任何 profiles，但你可以从 repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) 下载一些 profiles，运行：
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
当前 operator 需要注意的 profiles：

- [`http`](https://github.com/MythicC2Profiles/http)：基础的异步 GET/POST 流量。
- [`httpx`](https://github.com/MythicC2Profiles/httpx)：更灵活的 HTTP 流量，支持多个 callback domains、故障转移/round-robin 轮换、自定义 headers/query parameters，以及放置在 cookies、headers、query parameters 或 body 中的 message transforms（`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`）。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp)：当静态的 `http` profile 过于容易被识别时，通过 JSON/TOML 驱动的 HTTP message shaping。

### 当前平台说明

- 许多 public agents 和 profiles 现在会通过预构建的 remote container images 安装。
如果你 fork 了某个组件或在本地进行了 patch，而 Mythic 仍然使用旧行为，请检查生成的 `.env` 条目中的 `*_REMOTE_IMAGE`、
`*_USE_BUILD_CONTEXT` 和 `*_USE_VOLUME`；启用
`*_USE_BUILD_CONTEXT="true"` 通常可以让 Mythic 从你本地的 Docker context 重新构建，而不是悄悄复用 remote image。
- Browser scripts 是 Mythic 为 operators 提供的最高价值的 quality-of-life 功能之一：
它们可以将原始 command output 转换为表格、截图查看器、下载链接、搜索链接和按钮，并直接从 UI 发起后续 tasking。当前的 Mythic builds 允许每个 operator 保留自己的 scripts，并全局或按 task 启用这些 scripts；当 agents 返回结构化 JSON 而不是 plaintext 时，效果最佳。对于重复性的 `ls`、`ps`、triage 和 file-browser 工作流，这尤其有用。<sup>[[4]](#references)[[6]](#references)</sup>
- 较新的 Mythic builds 还支持 interactive tasking 和 Push C2 模式，从而减少在 PTY/SOCKS/rpfwd 密集型操作中对 `sleep 0` polling 的需求。当 agent/profile 支持这些功能时，相比持续向 server 发送 check-ins、仅仅为了保持 interactive channel 可用，这通常具有更低的开销。<sup>[[3]](#references)</sup>
- 当前 3.4-era 的 Mythic builders 比旧 writeups 所描述的更加 context-aware：build parameters 现在可以根据所选 OS 或其他 build options 进行分组或隐藏；payload types 可以声明是否支持在一次 build 中使用多个 C2 profiles，或同一 C2 的多个实例；C2 parameter deviations 允许 agent 隐藏其实际并未实现的字段。当你在 `http`、`httpx`、`smb`、`tcp` 和 `websocket` 之间切换时，这一点很重要，因为安全/有效的 build surface 已不再是扁平的静态表单。<sup>[[5]](#references)</sup>
- 如果你正在构建自定义的 agent/profile 组合，并且不希望 Mythic 在 wire 上使用其 JSON message format 或默认 crypto，请使用
`translation_container`：Mythic 会移除 UUID，通过 gRPC 将加密 blob 和 key material 交给 translator，并接收 agent-native bytes。对于支持 binary protocols、custom framing 或 agent-side encryption，而不必重写整个 server，这是最简洁的方式。
- 请记住，linked/P2P callbacks 不只是传递 tasking。Mythic 的
`get_tasking` flow 还可以携带 responses 以及 `delegates`、
`socks`、`rpfwd` 和 `interactive` data。实际上，一个 egress callback 可以在同一 polling loop 中为 inner callbacks 和 pivot channels 提供服务；如果 child agents 执行自己的 periodic check-ins，设置 `get_delegate_tasks=false` 可以防止 parent 意外取走 inner callback 队列中的 jobs。

### Wrapper payloads

Wrapper payloads 让你能够保留相同的 agent logic，同时改变交付或持久化时的 on-disk representation。

- `service_wrapper`：将另一个 payload 转换为 Windows service executable，适用于 execution path 要求有效 service binary 的情况。
- `scarecrow_wrapper`：使用 ScareCrow loader 包装兼容的 shellcode，以生成由 loader 支持的 EXE/DLL/CPL 等 outputs。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo 是一个使用 4.0 .NET Framework 编写的 Windows agent，设计用于 SpecterOps 的 training offerings。<sup>[[2]](#references)</sup>

使用以下命令安装：
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### 当前 build/profile notes

- Apollo 当前可以生成 `WinExe`、`Shellcode`、`Service` 和 `Source` payload。
- 常用的 Apollo profiles 是 `http`、`httpx`、`smb`、`tcp` 和 `websocket`。
- 当需要 domain rotation、proxy support、custom message placement 和 message transforms 时，`httpx` 通常是更灵活的选项，而不是较旧的 static `http` profile。
- Apollo 是功能较完整的 community agent 之一，目前提供 Mythic-side integrations，例如 browser scripts、file/process browser views、screenshots、keylogging、SOCKS、rpfwd、Push C2 和 P2P routing。
- Apollo 支持 `service_wrapper` 和 `scarecrow_wrapper` 等 wrapper payload。
- Apollo 支持 dynamic command loading，因此可以保持 initial payload 精简，并在之后加载额外 commands 或 Forge modules，而不必将所有 post-ex capabilities 都编译进第一次 build。
- 生成 shellcode output 时，Apollo 当前的 builder 还提供 Donut format 选项（`Binary`、`Base64`、`C`、`Ruby`、`Python`、`Powershell`、`C#`、`Hex`）以及 Donut bypass 行为（`None`、`Abort on fail`、`Continue on fail`）。如果最终目标是使用 `service_wrapper`、`scarecrow_wrapper` 或 custom loader 重新包装 shellcode，这会很有用。
- `register_file` 和 `register_assembly` 是 `execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import` 和 `powerpick` 使用的 staging primitives。在当前 Apollo builds 中，这些 staged artifacts 会在 client-side 缓存为受 DPAPI 保护的 AES256 blobs。
- `ls` 和 `ps` 的结果与 Mythic 的 browser scripts 以及 file/process browser 集成得尤其良好，能够显著加快 collaborative operations 中的 operator triage。
- Apollo 的 fork-and-run jobs 从 `spawnto_x86` / `spawnto_x64` 继承 sacrificial process settings，从 `ppid` 继承 parent selection，然后使用当前选中的 injection primitive。实际上，这意味着你对某个 command 的 OPSEC tuning，通常会同时影响 `execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe` 和 `spawn`。
- 当前文档记录的 Apollo injection backends 包括 `CreateRemoteThread`、`QueueUserAPC`（early-bird style）以及通过 syscalls 实现的 `NtCreateThreadEx`。在执行 noisy post-exploitation 前使用 `get_injection_techniques`；如果需要切换，避开与目标或要运行的 command 冲突的 primitive，则使用 `set_injection_technique`。
- `blockdlls` 只影响为 post-exploitation jobs 创建的 sacrificial processes。将其与比默认裸 `rundll32.exe` 更不 suspicious 的 `spawnto_x64` target 结合，是运行 assembly/PowerShell-heavy tasking 前最容易进行的 Apollo-side 调整之一。

这个 agent 拥有大量 commands，功能上与 Cobalt Strike 的 Beacon 非常相似，同时还增加了一些 extras。它支持：

### Common actions

- `cat`：打印文件内容
- `cd`：更改当前 working directory
- `cp`：将文件从一个位置复制到另一个位置
- `ls`：列出当前 directory 或指定 path 中的 files 和 directories
- `ifconfig`：获取 network adapters 和 interfaces
- `netstat`：获取 TCP 和 UDP connection information
- `pwd`：打印当前 working directory
- `ps`：列出 target system 上正在运行的 processes（包含额外信息）
- `jobs`：列出与 long-running tasking 相关的所有 running jobs
- `download`：将文件从 target system 下载到本地 machine
- `upload`：将文件从本地 machine 上传到 target system
- `reg_query`：查询 target system 上的 registry keys 和 values
- `reg_write_value`：向指定 registry key 写入新 value
- `sleep`：更改 agent 的 sleep interval，该 interval 决定 agent 多久向 Mythic server check in 一次
- 以及许多其他 commands，使用 `help` 查看完整的可用 commands 列表。

### Privilege escalation

- `getprivs`：在当前 thread token 上启用尽可能多的 privileges
- `getsystem`：打开指向 winlogon 的 handle 并 duplicate 其 token，从而将 privileges effectively 提升到 SYSTEM level
- `make_token`：创建新的 logon session 并将其应用到 agent，从而允许 impersonation 其他 user
- `steal_token`：从另一个 process 窃取 primary token，从而允许 agent impersonate 该 process 的 user
- `pth`：Pass-the-Hash attack，允许 agent 使用 user 的 NTLM hash 进行 authentication，而不需要 plaintext password
- `mimikatz`：运行 Mimikatz commands，从 memory 或 SAM database 中提取 credentials、hashes 和其他 sensitive information
- `rev2self`：将 agent 的 token 恢复为其 primary token，从而有效地将 privileges 降回原始 level
- `ppid`：通过指定新的 parent process ID，更改 post-exploitation jobs 的 parent process，从而更好地控制 job execution context
- `printspoofer`：执行 PrintSpoofer commands，以绕过 print spooler security measures，从而实现 privilege escalation 或 code execution
- `dcsync`：将 user 的 Kerberos keys 同步到 local machine，从而允许 offline password cracking 或进一步的 attacks
- `ticket_cache_add`：向当前 logon session 或指定的 session 添加 Kerberos ticket，从而允许 ticket reuse 或 impersonation

### Process execution

- `assembly_inject`：将 .NET assembly loader 注入 remote process
- `blockdlls`：阻止 non-Microsoft signed DLLs 加载到 post-exploitation jobs 中
- `execute_assembly`：在 agent 的 context 中执行 .NET assembly
- `execute_coff`：在 memory 中执行 COFF file，从而允许 in-memory execution of compiled code
- `execute_pe`：执行 unmanaged executable（PE）
- `keylog_inject`：将 keylogger 注入另一个 process，并将 keystrokes stream 回 Mythic 的 keylog view
- `screenshot` / `screenshot_inject`：直接 capture 当前 desktop，或通过将 screenshot assembly 注入 target process/session 来 capture
- `get_injection_techniques`：显示可用的 injection techniques 以及当前选中的 technique
- `inline_assembly`：在 disposable AppDomain 中执行 .NET assembly，从而可以临时执行 code，而不影响 agent 的 main process
- `register_assembly`：注册 .NET assembly，供之后执行
- `register_file`：将 file 注册到 agent cache，供之后的 `execute_*` 或 PowerShell tasking 使用
- `run`：在 target system 上执行 binary，并使用 system 的 PATH 查找 executable
- `set_injection_technique`：更改 post-exploitation jobs 使用的 injection primitive
- `shinject`：将 shellcode 注入 remote process，从而允许 in-memory execution 任意 code
- `inject`：将 agent shellcode 注入 remote process，从而允许 in-memory execution agent code
- `spawn`：在指定 executable 中 spawn 新的 agent session，从而允许在新 process 中执行 shellcode
- `spawnto_x64` 和 `spawnto_x86`：将 post-exploitation jobs 使用的 default binary 更改为指定 path，而不是使用不带 params 且非常 noisy 的 `rundll32.exe`。

### Mythic Forge

这允许从 Mythic Forge 加载 **COFF/BOF** files。Mythic Forge 是一个 pre-compiled payloads 和 tools 的 repository，这些 payloads 和 tools 可以在 target system 上执行。使用所有可加载的 commands，可以将它们作为 BOFs 在当前 agent process 中执行，从而完成常见 actions（通常比 spawn separate process 具有更好的 OPSEC）。

开始安装：
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
然后，使用 `forge_collections` 显示 Mythic Forge 中的 COFF/BOF modules，以便选择并将其加载到 agent 的内存中执行。默认情况下，Apollo 中会添加以下 2 个 collections：

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

加载 module 后，它会作为另一个 command 出现在列表中，例如 `forge_bof_sa-whoami` 或 `forge_bof_sa-netuser`。

对于 BOF，请记住，Forge **不会**只是将一个扁平的参数字符串传递给 Apollo。它会将 BOF 参数映射为 Mythic 的 typed-array 格式，然后将其转发到 Apollo 的 `execute_coff` flow 中。如果通过 Forge 加载的 BOF 行为异常，请检查预期的 BOF 参数类型 / entrypoint，而不只是检查你输入的 command line。还需注意，Apollo 较新的 BOF loader 相较于更早的 2.3.1-era builds 更改了参数处理方式，因此 stale BOFs 或 old collections 可能会单纯因为 marshaling 预期发生变化而失败。

### PowerShell 和 scripting 执行

- `powershell_import`：将新的 PowerShell script (.ps1) 导入 agent cache，以便之后执行
- `powershell`：在 agent context 中执行 PowerShell command，支持 advanced scripting 和 automation
- `powerpick`：将 PowerShell loader assembly 注入 sacrificial process，并执行 PowerShell command（不进行 powershell logging）。
- `psinject`：在指定 process 中执行 PowerShell，从而能够在另一个 process 的 context 中定向执行 scripts
- `shell`：在 agent context 中执行 shell command，类似于在 cmd.exe 中运行 command

### Lateral Movement

- `jump_psexec`：使用 PsExec technique 进行 lateral movement 到新 host，首先复制 Apollo agent executable (apollo.exe)，然后执行它。
- `jump_wmi`：使用 WMI technique 进行 lateral movement 到新 host，首先复制 Apollo agent executable (apollo.exe)，然后执行它。
- `link` 和 `unlink`：在 callbacks 之间创建和拆除 P2P links（例如通过 SMB/TCP）。
- `wmiexecute`：使用 WMI 在本地或指定的 remote system 上执行 command，并可选用 credentials 进行 impersonation。
- `net_dclist`：获取指定 domain 的 domain controllers 列表，可用于识别 lateral movement 的潜在 targets。
- `net_localgroup`：列出指定 computer 上的 local groups；如果未指定 computer，则默认使用 localhost。
- `net_localgroup_member`：获取 local 或 remote computer 上指定 group 的 local group membership，从而枚举特定 groups 中的 users。
- `net_shares`：列出指定 computer 上的 remote shares 及其 accessibility，可用于识别 lateral movement 的潜在 targets。
- `socks`：在 target network 上启用符合 SOCKS 5 的 proxy，从而允许通过 compromised host 对 traffic 进行 tunneling。兼容 proxychains 等 tools。
- `rpfwd`：开始在 target host 的指定 port 上监听，并通过 Mythic 将 traffic 转发到 remote IP 和 port，从而实现对 target network 上 services 的 remote access。
- `listpipes`：列出 local system 上的所有 named pipes，可通过与 IPC mechanisms 交互用于 lateral movement 或 privilege escalation。

有关 `jump_wmi` 或 `wmiexecute` 底层使用的 lower-level WMI execution primitives，请参阅 [WmiExec](lateral-movement/wmiexec.md)。有关更广泛的 pivoting patterns，请参阅 [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md)。

### Miscellaneous Commands
- `help`：显示有关特定 commands 的详细信息，或显示 agent 中所有可用 commands 的 general information。
- `clear`：将 tasks 标记为 'cleared'，使其无法被 agents 获取。可以指定 `all` 清除所有 tasks，或指定 `task Num` 清除特定 task。


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon 是一个编译为 **Linux 和 macOS** executables 的 Golang agent。
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### 当前 build/profile 说明

- 当前 Poseidon builds 面向 Linux 和 macOS，支持 `x86_64` 和 `arm64`。
- 支持的输出格式包括 native executables，以及 `dylib` 和 `so` 等 shared-library style outputs。
- Poseidon 支持 `http`、`websocket`、`tcp` 和 `dynamichttp`，当前 builders 提供包括 `egress_order` 和 failover thresholds 在内的 multi-egress settings。
- Poseidon 当前的 capability metadata 还包括 browser scripts、file/process browser integration、interactive tasking、keylogging、screenshots、Push C2、SOCKS、rpfwd 和 P2P，因此它可以作为真正的 Linux/macOS pivot node，而不仅仅是简单的 remote shell。
- 当你需要更干净的 network behavior 或额外的 Go binary obfuscation 时，值得检查 `proxy_bypass` 和 `garble` 等 build-time options。
- 对 Linux/macOS operations 而言，`pty` 是较新的 quality-of-life commands 中最有用的一个，因为它可以打开 interactive PTY，并在 Mythic 侧暴露一个 port，从而实现更完整的 terminal interaction，而无需使用旧的 `sleep 0` + SOCKS workaround。
- Poseidon 当前的 docs 对 macOS-heavy tradecraft 尤其值得关注：`jxa` 可通过 `OSAScript` 在内存中执行 JavaScript for Automation，`screencapture` 可抓取已登录用户的 desktop，`clipboard_monitor` 可传输 pasteboard changes，`execute_library` 可加载本地 dylib 并调用其中的 function，而 `libinject` 可强制 remote process 加载磁盘上的 dylib。
- 对于长期运行的 jobs，请记住 Poseidon 会在 goroutines/threads 中执行 post-exploitation work，这些 goroutines/threads 是 cooperative 的，无法被 hard-kill。docs 还明确指出，目前没有内置的 agent obfuscation，因此与高度 obfuscated 的 commercial implants 相比，build/profile-level tradecraft 更为重要。

如需了解 Mythic-backed operations、JAMF abuse 或 MDM-as-C2 ideas 相关的 macOS-specific tradecraft，请查看 [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md)。

在 Linux 或 macOS 上使用时，它包含一些有趣的 commands：

### 常见 actions

- `cat`：打印文件内容
- `cd`：更改当前 working directory
- `chmod`：更改文件权限
- `config`：查看当前 config 和 host information
- `cp`：将文件从一个位置复制到另一个位置
- `curl`：使用可选 headers 和 method 执行单个 web request
- `upload`：将文件上传到 target
- `download`：将文件从 target system 下载到 local machine
- 以及更多

### 搜索敏感信息

- `triagedirectory`：在 host 的 directory 中查找有价值的文件，例如 sensitive files 或 credentials。
- `getenv`：获取当前所有 environment variables。

### macOS-specific tradecraft

- `jxa`：通过 `OSAScript` 在内存中执行 JavaScript for Automation，
可用于 macOS native post-exploitation，而无需写入单独的 script
files。
- `clipboard_monitor`：轮询 pasteboard 并将 changes 报告回 Mythic，
适用于依赖 copy/paste 的 credential/token theft workflows。
- `screencapture`：捕获用户在 macOS 上的 desktop。
- `execute_library`：从磁盘加载 dylib 并调用特定的 exported function。
- `libinject`：注入一个 shellcode stub，强制另一个 macOS process 从磁盘加载 dylib。
- `persist_launchd`：直接通过 agent 创建 LaunchAgent / LaunchDaemon persistence。

### 横向移动

- `ssh`：使用指定 credentials 通过 SSH 连接 host，并打开 PTY，而无需生成 ssh。
- `sshauth`：使用指定 credentials 连接指定的 host(s)。也可以使用它通过 SSH 在 remote hosts 上执行特定 command，或使用它通过 SCP 传输 files。
- `link_tcp`：通过 TCP 连接到另一个 agent，从而实现 agents 之间的 direct communication。
- `link_webshell`：使用 webshell P2P profile 连接到 agent，从而远程访问该 agent 的 web interface。
- `rpfwd`：启动或停止 Reverse Port Forward，从而远程访问 target network 上的 services。
- `socks`：在 target network 上启动或停止 SOCKS5 proxy，从而通过 compromised host 对 traffic 进行 tunneling。兼容 proxychains 等 tools。
- `portscan`：扫描 host(s) 的 open ports，可用于识别潜在的 lateral movement targets 或进一步 attacks 的目标。

### Process execution

- `shell`：通过 /bin/sh 执行单个 shell command，从而直接在 target system 上执行 commands。
- `run`：使用 arguments 执行磁盘上的 command，从而在 target system 上执行 binaries 或 scripts。
- `pty`：打开 interactive PTY，从而直接与 target system 上的 shell 交互。

## 参考资料

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
