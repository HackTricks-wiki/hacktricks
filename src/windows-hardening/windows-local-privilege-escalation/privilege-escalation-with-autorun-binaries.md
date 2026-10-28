# Autoruns ile Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**, programları **başlangıçta** çalıştırmak için kullanılabilir. Başlangıçta çalışacak şekilde ayarlanmış binary’leri görmek için:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Zamanlanmış Görevler

**Görevler**, **belirli bir sıklıkta** çalışacak şekilde zamanlanabilir. Hangi ikili dosyaların çalıştırılmak üzere zamanlandığını görmek için aşağıdaki komutları kullanın:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

`/sc ONLOGON /rl HIGHEST` ile oluşturulan bir görev, kayıtlı sorumlusu için **kullanılabilir** en yüksek çalışma düzeyini ister; bu anahtar tek başına sorumluyu değiştirmez veya UAC'yi atlatmaz. Düşük ayrıcalıklı bir işlem, en yüksek çalışma düzeyinde bir görev kaydedemez veya görev kimliği olarak SYSTEM'ı seçemez. Yukarıdaki örneği, standart kullanıcıdan SYSTEM'a geçiş yolu olarak değil, zaten yükseltilmiş bir çağıranın gerçekleştirebileceği bir işlem olarak değerlendirin.<sup>[[8]](#references)</sup>

SYSTEM olarak çalışan etkin bir görev, görev tanımı ve eylem dosyası korumalı olsa bile incelenmelidir. [Task Scheduler requires execute permission on the task to run it on demand](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Düşük ayrıcalıklı bir kullanıcının bu izni varsa, tam eylemi inceleyin; özellikle Active Directory ACL'lerini değiştiren veya hesap koruma ayarlarını sıfırlayan PowerShell script'lerini. Görevin `AllowDemandStart` ayarını kontrol edin ve script'in girdilerini ve etkilerini doğrulayın; sabit bir görevi başlatma izni tek başına rastgele kod çalıştırılabileceği anlamına gelmez.

## Klasörler

**Başlangıç klasörlerinde** bulunan tüm binary'ler başlangıçta çalıştırılır. Yaygın başlangıç klasörleri aşağıda listelenmiştir; ancak başlangıç klasörü registry'de belirtilir. [Konumunu öğrenmek için burayı okuyun.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Daha yüksek ayrıcalıklı bir kullanıcının Startup girdisi, başka bir kullanıcının yazabildiği bir dizindeki dosyaları tekrar tekrar açan korumalı bir script'i başlatıyor olabilir. Bu dizini bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce girdinin **gerçek oturum açma kimliğini**, script'in girdi dizinini ve ACL'lerini, ayrıca yapılan işlemin tam olarak ne olduğunu inceleyin. Özellikle [`hh.exe`, derlenmiş HTML Help (`.chm`) dosyalarını açar](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); kullanıcı tarafından sağlanan dosyaları bu programa aktaran bir script, dosya adını veya ilk baytları kontrol etse bile bir içerik güven sınırını aşar. [HTML Help ilkeleri, yürütülebilir kısayolları kısıtlayabilir](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands); bu nedenle kurulu ilkeyi ve erişilebilir içeriğin davranışını doğrulayın. Tek başına `.chm` uzantısı veya sihirli baytlar, daha yüksek ayrıcalıklı kod yürütüldüğünü kanıtlamaz. Sayım sırasında güvenilmeyen dosyayı açmadan autorun girdisini, süreç komut satırını ve yol izinlerini inceleyin.

Aynı içerik güven sınırı, daha yüksek ayrıcalıklı bir kişinin başka bir kullanıcının değiştirebildiği bir documentation klasöründeki `.chm` dosyasını **manuel olarak açması** durumunda da söz konusudur. Dosyanın kendisi ve üst dizini için tam yazma izinlerini, görüntüleyicinin gerçek kimliğini ve açma olayını, ayrıca geçerli HTML Help ilkesini doğrulayın. Bir klasörün yazılabilir olması veya documentation dosyalarının incelenmesinin istenmesi, daha yüksek ayrıcalıklı kimliğin saldırganın denetimindeki içeriği açtığını kanıtlamaz.

> **BİLGİ**: Arşiv çıkarma işlemindeki *path traversal* güvenlik açıkları (WinRAR'da 7.13 öncesinde kötüye kullanılan CVE-2025-8088 gibi), **payload'ları doğrudan bu Startup klasörlerine çıkartma sırasında yerleştirmek** ve böylece sonraki kullanıcı oturum açışında kod yürütmek için kullanılabilir. Bu tekniğe daha yakından bakmak için:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Buradaki not](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry girdisi, 64-bit Windows sürümü çalıştırdığınızı gösterir. İşletim sistemi bu anahtarı, 64-bit Windows sürümlerinde çalışan 32-bit uygulamalar için HKEY_LOCAL_MACHINE\SOFTWARE'nin ayrı bir görünümünü sunmak amacıyla kullanır.

### Çalıştırmalar

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

**Run** ve **RunOnce** olarak bilinen registry anahtarları, kullanıcı sisteme her oturum açtığında programları otomatik olarak çalıştırmak üzere tasarlanmıştır. Anahtarın veri değeri olarak atanan komut satırı en fazla 260 karakter olabilir.<sup>[[2]](#references)</sup>

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
> **Exploit 1**: **HKLM** içindeki belirtilen registry'lerden herhangi birine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında ayrıcalıklarınızı yükseltebilirsiniz.

> [!TIP]
> **Exploit 2**: **HKLM** içindeki herhangi bir registry'de belirtilen binary'lerden birinin üzerine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında bu binary'yi backdoor içerecek şekilde değiştirip ayrıcalıklarınızı yükseltebilirsiniz.

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

### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** klasörüne yerleştirilen kısayollar, kullanıcı oturum açtığında veya sistem yeniden başlatıldığında hizmetlerin ya da uygulamaların otomatik olarak başlatılmasını sağlar. **Startup** klasörünün konumu, hem **Local Machine** hem de **Current User** kapsamları için kayıt defterinde tanımlanır. Bu nedenle belirtilen **Startup** konumlarına eklenen tüm kısayollar, bağlantılı hizmetin veya programın oturum açma ya da yeniden başlatma işleminin ardından başlamasını sağlar ve programları otomatik olarak çalışacak şekilde zamanlamanın kolay bir yolunu sunar.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** altındaki herhangi bir \[User] Shell Folder'ı üzerine yazabiliyorsanız, onu sizin denetiminizdeki bir klasöre yönlendirebilir ve bir kullanıcı sistemde her oturum açtığında çalıştırılarak ayrıcalıkları yükseltecek bir backdoor yerleştirebilirsiniz.

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

Bu kullanıcıya özel registry değeri, kullanıcı oturum açtığında çalıştırılacak bir script veya komuta işaret edebilir. Yalnızca etkilenen kullanıcının bağlamında çalıştığı için başlıca bir **persistence** tekniğidir; ancak post-exploitation ve autoruns incelemeleri sırasında yine de kontrol edilmeye değerdir.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Geçerli kullanıcı için bu değere yazabiliyorsanız, admin haklarına ihtiyaç duymadan bir sonraki etkileşimli oturum açmada çalıştırmayı yeniden tetikleyebilirsiniz. Başka bir kullanıcının hive'ı için bu değere yazabiliyorsanız, o kullanıcı oturum açtığında kod çalıştırma olanağı elde edebilirsiniz.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notlar:

- Hedef kullanıcının zaten okuyabildiği `.bat`, `.cmd`, `.ps1` veya diğer launcher dosyaları için tam yolları tercih edin.
- Değer kaldırılana kadar bu, oturum kapatıp yeniden başlatma sonrasında da kalıcılığını korur.
- `HKLM\...\Run` anahtarından farklı olarak, bu tek başına **elevation** sağlamaz; kullanıcı kapsamlı bir kalıcılık yöntemidir.

### Winlogon Anahtarları

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle **Userinit** anahtarı **userinit.exe** olarak ayarlanır. Ancak bu anahtar değiştirilirse, belirtilen yürütülebilir dosya da kullanıcı oturum açtığında **Winlogon** tarafından başlatılır. Benzer şekilde, **Shell** anahtarının **explorer.exe**'yi göstermesi amaçlanmıştır; bu, Windows'un varsayılan shell'idir.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Registry değerinin veya binary'nin üzerine yazabiliyorsanız yetkilerinizi yükseltebilirsiniz.

### Policy Settings

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

Windows Kayıt Defteri'nde `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında, varsayılan olarak `cmd.exe` değerine ayarlanmış bir **`AlternateShell`** değeri bulunur. Bu, başlangıç sırasında F8 tuşuna basıp "Komut İstemi ile Güvenli Mod"u seçtiğinizde `cmd.exe`'nin kullanılacağı anlamına gelir. Ancak F8'e basıp bu seçeneği elle belirlemeniz gerekmeden bilgisayarınızı otomatik olarak bu modda başlatacak şekilde ayarlamak mümkündür.

"Komut İstemi ile Güvenli Mod"u otomatik başlatmak için bir önyükleme seçeneği oluşturma adımları:<sup>[[5]](#references)</sup>

1. Salt okunur, sistem ve gizli bayraklarını kaldırmak için `boot.ini` dosyasının özniteliklerini değiştirin: `attrib c:\boot.ini -r -s -h`
2. Düzenlemek için `boot.ini` dosyasını açın.
3. Şuna benzer bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Değişiklikleri `boot.ini` dosyasına kaydedin.
5. Dosyanın özgün özniteliklerini yeniden uygulayın: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** kayıt defteri anahtarını değiştirmek, yetkisiz erişim için kullanılabilecek özel bir komut kabuğu kurulumuna olanak tanır.
- **Exploit 2 (PATH Yazma İzinleri):** Sistem **PATH** değişkeninin herhangi bir kısmına, özellikle `C:\Windows\system32` öncesindeki bir konuma yazma iznine sahip olmak, özel bir `cmd.exe` çalıştırmanızı sağlar. Sistem Güvenli Mod'da başlatılırsa bu dosya bir arka kapı olabilir.
- **Exploit 3 (PATH ve boot.ini Yazma İzinleri):** `boot.ini` dosyasına yazma erişimi, Güvenli Mod'un otomatik olarak başlatılmasını sağlayarak bir sonraki yeniden başlatmada yetkisiz erişimi kolaylaştırır.

Geçerli **AlternateShell** ayarını denetlemek için şu komutları kullanın:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Yüklü Bileşen

Active Setup, Windows'ta **masaüstü ortamı tamamen yüklenmeden önce başlayan** bir özelliktir. Kullanıcı oturumu açma işlemi devam etmeden önce tamamlanması gereken belirli komutların yürütülmesine öncelik verir. Bu işlem, Run veya RunOnce kayıt defteri bölümlerindekiler gibi diğer başlangıç girdileri tetiklenmeden önce gerçekleşir.

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

**Güvenlik İçgörüleri:**

- **`IsInstalled`** değeri `"1"` olarak ayarlanmış ve belirli bir **`StubPath`** içeren bir anahtarı değiştirmek veya bu anahtara yazmak, yetkisiz komut yürütülmesine ve potansiyel olarak ayrıcalık yükseltmeye yol açabilir.
- Yeterli izinlere sahip olunduğunda, herhangi bir **`StubPath`** değerinde belirtilen ikili dosyayı değiştirmek de ayrıcalık yükseltme sağlayabilir.

Active Setup bileşenlerindeki **`StubPath`** yapılandırmalarını incelemek için şu komutlar kullanılabilir:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Browser Helper Objects (BHOs) Genel Bakış

Browser Helper Objects (BHOs), Microsoft Internet Explorer'a ek özellikler kazandıran DLL modülleridir. Her başlatıldığında Internet Explorer ve Windows Explorer'a yüklenirler. Ancak **NoExplorer** anahtarı 1 olarak ayarlanarak çalışmaları engellenebilir; bu, Windows Explorer örnekleriyle birlikte yüklenmelerini önler.<sup>[[1]](#references)</sup>

BHO'lar, Internet Explorer 11 aracılığıyla Windows 10 ile uyumludur ancak Windows'un daha yeni sürümlerindeki varsayılan tarayıcı olan Microsoft Edge'de desteklenmez.

Bir sistemde kayıtlı BHO'ları incelemek için aşağıdaki kayıt defteri anahtarlarına bakabilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, kayıt defterinde benzersiz bir tanımlayıcı görevi gören **CLSID** ile temsil edilir. Her CLSID hakkındaki ayrıntılı bilgiler `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Kayıt defterindeki BHO'ları sorgulamak için şu komutlar kullanılabilir:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer Eklentileri

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kayıt defterinde her DLL için 1 yeni kayıt bulunacağını ve bunun **CLSID** ile temsil edileceğini unutmayın. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` konumunda bulabilirsiniz.

### Font Sürücüleri

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

### Context menu COM handlers

Explorer context menu handler'ları, `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` ve `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` gibi anahtarlar altında kayıtlı shell extension'lardır. Bir handler'ın varsayılan değeri veya bazen anahtar adı bir CLSID'dir. Bu CLSID'yi `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` anahtarına kadar izleyin; buradaki varsayılan değer, handler çağrıldığında yüklenen DLL'yi belirtir.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Hem 32-bit hem de 64-bit registry görünümlerini kontrol edin. `HKCR`, kullanıcıya özel ve makine genelindeki class kayıtlarını birleştirir; bu nedenle bir sürecin hangi temel anahtarı kullanacağını doğrulayın. Makine genelindeki bir `InprocServer32` değerini değiştirebilen düşük ayrıcalıklı bir kimlik, daha yüksek ayrıcalıklı bir süreci başka bir DLL'e yönlendirebilir; ancak bu yükseltme için söz konusu sürecin handler'ı çağırması gerekir. Registry değeri korumalı olsa bile yazılabilir bir DLL yolu benzer bir risk oluşturabilir.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Autorun'ları bulabileceğiniz tüm konumların [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) tarafından **zaten tarandığını** unutmayın. Ancak otomatik çalıştırılan dosyaların daha **kapsamlı bir listesini** görmek için systinternals'ın [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) aracını kullanabilirsiniz:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Daha Fazla

**Daha fazla Autoruns benzeri kayıt defteri girdisini şu adreste bulabilirsiniz:** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Yaygın malware kalıcılık mekanizmaları](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Önyükleme veya Oturum Açma Otomatik Başlatma Yürütmesi: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Önyükleme veya Oturum Açma Başlatma Betikleri: Oturum Açma Betiği (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Otomatik başlatma kategorileri (Windows Sysinternals Araçlarıyla Sorun Giderme, 2. Baskı)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Alternatif bir kabuk başlatan önyükleme seçeneğini nasıl ekleyebilirim?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Özeti 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Görevler için Güvenlik Bağlamları](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
