# Mythic

{{#include ../banners/hacktricks-training.md}}

## 什么是 Mythic？

Mythic 是一个开源的、模块化的命令与控制 (C2) 框架，旨在用于红队测试。它允许安全专业人员在不同操作系统（包括 Windows、Linux 和 macOS）上管理和部署各种代理（有效载荷）。Mythic 提供了一个用户友好的网页界面，用于管理代理、执行命令和收集结果，使其成为在受控环境中模拟真实攻击的强大工具。

### 安装

要安装 Mythic，请按照官方 **[Mythic repo](https://github.com/its-a-feature/Mythic)** 上的说明进行操作。

### 代理

Mythic 支持多个代理，这些代理是 **在被攻陷系统上执行任务的有效载荷**。每个代理可以根据特定需求进行定制，并可以在不同操作系统上运行。

默认情况下，Mythic 没有安装任何代理。然而，它在 [**https://github.com/MythicAgents**](https://github.com/MythicAgents) 提供了一些开源代理。

要从该仓库安装代理，您只需运行：
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
您可以使用之前的命令添加新代理，即使 Mythic 已经在运行。

### C2 配置文件

Mythic 中的 C2 配置文件定义了 **代理与 Mythic 服务器之间的通信方式**。它们指定了通信协议、加密方法和其他设置。您可以通过 Mythic 网络界面创建和管理 C2 配置文件。

默认情况下，Mythic 安装时没有配置文件，但可以通过运行从仓库下载一些配置文件 [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)：
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo 是一个用 C# 编写的 Windows 代理，使用 4.0 .NET Framework，旨在用于 SpecterOps 培训课程。

使用以下命令安装：
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
这个代理有很多命令，使其与Cobalt Strike的Beacon非常相似，并且有一些额外功能。其中，它支持：

### 常见操作

- `cat`: 打印文件内容
- `cd`: 更改当前工作目录
- `cp`: 从一个位置复制文件到另一个位置
- `ls`: 列出当前目录或指定路径中的文件和目录
- `pwd`: 打印当前工作目录
- `ps`: 列出目标系统上运行的进程（附加信息）
- `download`: 从目标系统下载文件到本地机器
- `upload`: 从本地机器上传文件到目标系统
- `reg_query`: 查询目标系统上的注册表键和值
- `reg_write_value`: 向指定注册表键写入新值
- `sleep`: 更改代理的睡眠间隔，决定其多频繁与Mythic服务器检查
- 还有其他更多，使用`help`查看可用命令的完整列表。

### 权限提升

- `getprivs`: 在当前线程令牌上启用尽可能多的权限
- `getsystem`: 打开winlogon的句柄并复制令牌，有效地将权限提升到SYSTEM级别
- `make_token`: 创建一个新的登录会话并将其应用于代理，允许模拟另一个用户
- `steal_token`: 从另一个进程窃取主令牌，允许代理模拟该进程的用户
- `pth`: Pass-the-Hash攻击，允许代理使用用户的NTLM哈希进行身份验证，而无需明文密码
- `mimikatz`: 运行Mimikatz命令以从内存或SAM数据库中提取凭据、哈希和其他敏感信息
- `rev2self`: 将代理的令牌恢复为其主令牌，有效地将权限降回原始级别
- `ppid`: 通过指定新的父进程ID更改后渗透作业的父进程，允许更好地控制作业执行上下文
- `printspoofer`: 执行PrintSpoofer命令以绕过打印后台处理程序的安全措施，允许权限提升或代码执行
- `dcsync`: 将用户的Kerberos密钥同步到本地机器，允许离线密码破解或进一步攻击
- `ticket_cache_add`: 将Kerberos票证添加到当前登录会话或指定会话，允许票证重用或模拟

### 进程执行

- `assembly_inject`: 允许将.NET程序集加载器注入远程进程
- `execute_assembly`: 在代理的上下文中执行.NET程序集
- `execute_coff`: 在内存中执行COFF文件，允许编译代码的内存执行
- `execute_pe`: 执行非托管可执行文件（PE）
- `inline_assembly`: 在一次性AppDomain中执行.NET程序集，允许临时执行代码而不影响代理的主进程
- `run`: 在目标系统上执行二进制文件，使用系统的PATH查找可执行文件
- `shinject`: 将shellcode注入远程进程，允许任意代码的内存执行
- `inject`: 将代理的shellcode注入远程进程，允许代理代码的内存执行
- `spawn`: 在指定的可执行文件中生成新的代理会话，允许在新进程中执行shellcode
- `spawnto_x64`和`spawnto_x86`: 将后渗透作业中使用的默认二进制文件更改为指定路径，而不是使用没有参数的`rundll32.exe`，这会产生很多噪音。

### Mithic Forge

这允许从Mythic Forge加载**COFF/BOF**文件，Mythic Forge是一个预编译有效载荷和工具的存储库，可以在目标系统上执行。通过可以加载的所有命令，将能够以BOFs的形式在当前代理进程中执行常见操作（通常更隐蔽）。

开始安装它们：
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
然后，使用 `forge_collections` 显示 Mythic Forge 中的 COFF/BOF 模块，以便能够选择并将它们加载到代理的内存中以执行。默认情况下，以下 2 个集合在 Apollo 中添加：

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

加载一个模块后，它将作为另一个命令出现在列表中，例如 `forge_bof_sa-whoami` 或 `forge_bof_sa-netuser`。

### Powershell & 脚本执行

- `powershell_import`: 将新的 PowerShell 脚本 (.ps1) 导入代理缓存以供后续执行
- `powershell`: 在代理的上下文中执行 PowerShell 命令，允许进行高级脚本编写和自动化
- `powerpick`: 将 PowerShell 加载程序程序集注入到一个牺牲进程中并执行 PowerShell 命令（不记录 PowerShell 日志）。
- `psinject`: 在指定进程中执行 PowerShell，允许在另一个进程的上下文中有针对性地执行脚本
- `shell`: 在代理的上下文中执行 shell 命令，类似于在 cmd.exe 中运行命令

### 横向移动

- `jump_psexec`: 使用 PsExec 技术通过首先复制 Apollo 代理可执行文件 (apollo.exe) 并执行它来横向移动到新主机。
- `jump_wmi`: 使用 WMI 技术通过首先复制 Apollo 代理可执行文件 (apollo.exe) 并执行它来横向移动到新主机。
- `wmiexecute`: 使用 WMI 在本地或指定的远程系统上执行命令，提供可选的凭据进行模拟。
- `net_dclist`: 检索指定域的域控制器列表，有助于识别潜在的横向移动目标。
- `net_localgroup`: 列出指定计算机上的本地组，如果未指定计算机，则默认为 localhost。
- `net_localgroup_member`: 检索本地或远程计算机上指定组的本地组成员资格，允许枚举特定组中的用户。
- `net_shares`: 列出指定计算机上的远程共享及其可访问性，有助于识别潜在的横向移动目标。
- `socks`: 在目标网络上启用 SOCKS 5 兼容代理，允许通过被攻陷的主机隧道流量。与 proxychains 等工具兼容。
- `rpfwd`: 在目标主机上指定端口开始监听，并通过 Mythic 将流量转发到远程 IP 和端口，允许远程访问目标网络上的服务。
- `listpipes`: 列出本地系统上的所有命名管道，这对于通过与 IPC 机制交互进行横向移动或权限提升可能很有用。

### 其他命令
- `help`: 显示有关特定命令的详细信息或代理中所有可用命令的一般信息。
- `clear`: 将任务标记为“已清除”，以便代理无法接收。您可以指定 `all` 来清除所有任务或 `task Num` 来清除特定任务。

## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon 是一个用 Golang 编写的代理，编译为 **Linux 和 macOS** 可执行文件。
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
当用户在 Linux 上时，有一些有趣的命令：

### 常见操作

- `cat`: 打印文件的内容
- `cd`: 更改当前工作目录
- `chmod`: 更改文件的权限
- `config`: 查看当前配置和主机信息
- `cp`: 从一个位置复制文件到另一个位置
- `curl`: 执行单个网络请求，带可选的头和方法
- `upload`: 将文件上传到目标
- `download`: 从目标系统下载文件到本地机器
- 还有更多

### 搜索敏感信息

- `triagedirectory`: 在主机的目录中查找有趣的文件，例如敏感文件或凭据。
- `getenv`: 获取所有当前环境变量。

### 横向移动

- `ssh`: 使用指定凭据 SSH 到主机，并在不生成 ssh 的情况下打开 PTY。
- `sshauth`: 使用指定凭据 SSH 到指定主机。您还可以使用此命令通过 SSH 在远程主机上执行特定命令或使用它来 SCP 文件。
- `link_tcp`: 通过 TCP 链接到另一个代理，允许代理之间的直接通信。
- `link_webshell`: 使用 webshell P2P 配置文件链接到代理，允许远程访问代理的 Web 界面。
- `rpfwd`: 启动或停止反向端口转发，允许远程访问目标网络上的服务。
- `socks`: 在目标网络上启动或停止 SOCKS5 代理，允许通过被攻陷的主机隧道流量。与 proxychains 等工具兼容。
- `portscan`: 扫描主机以查找开放端口，有助于识别潜在的横向移动或进一步攻击的目标。

### 进程执行

- `shell`: 通过 /bin/sh 执行单个 shell 命令，允许在目标系统上直接执行命令。
- `run`: 从磁盘执行带参数的命令，允许在目标系统上执行二进制文件或脚本。
- `pty`: 打开一个交互式 PTY，允许与目标系统上的 shell 直接交互。


{{#include ../banners/hacktricks-training.md}}
