# Autoruns ile Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**, programları **startup** sırasında çalıştırmak için kullanılabilir. **startup** sırasında çalışacak şekilde programlanmış binary'leri görmek için:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zamanlanmış Görevler

**Görevler**, **belirli bir sıklıkta** çalışacak şekilde zamanlanabilir. Hangi binary dosyaların çalışacak şekilde zamanlandığını görmek için aşağıdaki komutları kullanın:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Klasörler

**Başlangıç klasörlerinde** bulunan tüm binary'ler **başlangıçta çalıştırılır**. Yaygın başlangıç klasörleri aşağıda listelenenlerdir, ancak başlangıç klasörü registry'de belirtilir. [Konumunu öğrenmek için bunu okuyun.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **BİLGİ**: Arşiv çıkarma *path traversal* güvenlik açıklarından (WinRAR 7.13 öncesinde kötüye kullanılan CVE-2025-8088 gibi) yararlanılarak, sıkıştırma sırasında payload'lar doğrudan bu Startup klasörlerine bırakılabilir ve bir sonraki kullanıcı oturum açışında code execution gerçekleştirilebilir. Bu tekniğin ayrıntılı açıklaması için bkz.:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Kayıt Defteri

> [!TIP]
> [Buradan not](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry girdisi, 64-bit Windows sürümü kullandığınızı gösterir. İşletim sistemi, 64-bit Windows sürümlerinde çalışan 32-bit uygulamalar için HKEY_LOCAL_MACHINE\SOFTWARE görünümünün ayrı bir görünümünü sunmak amacıyla bu anahtarı kullanır.

### Runs

Yaygın olarak bilinen **AutoRun** registry girdileri:

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

**Run** ve **RunOnce** olarak bilinen registry anahtarları, bir kullanıcı sisteme her oturum açtığında programları otomatik olarak çalıştırmak üzere tasarlanmıştır. Bir anahtarın data value'su olarak atanan command line, 260 karakter veya daha kısa olmakla sınırlıdır.<sup>[[2]](#references)</sup>

**Service runs** (boot sırasında servislerin automatic startup işlemini kontrol edebilir):

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

Windows Vista ve sonraki sürümlerde **Run** ve **RunOnce** registry anahtarları otomatik olarak oluşturulmaz. Bu anahtarlardaki girdiler programları doğrudan başlatabilir veya bunları dependency olarak belirtebilir. Örneğin, oturum açma sırasında bir DLL dosyasını yüklemek için **RunOnceEx** registry anahtarı ve bir "Depend" anahtarı kullanılabilir. Bu, sistem start-up'ı sırasında "C:\temp\evil.dll" dosyasını çalıştırmak üzere bir registry girdisi eklenerek gösterilmiştir:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: **HKLM** içindeki belirtilen kayıt defterlerinden herhangi birine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında ayrıcalıkları yükseltebilirsiniz.

> [!TIP]
> **Exploit 2**: **HKLM** içindeki kayıt defterlerinden herhangi birinde belirtilen binary'lerden herhangi birinin üzerine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında bu binary'yi bir backdoor ile değiştirerek ayrıcalıkları yükseltebilirsiniz.
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
### Startup Yolu

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** klasörüne yerleştirilen kısayollar, kullanıcı logon olduğunda veya sistem yeniden başlatıldığında services ya da applications başlatılmasını otomatik olarak tetikler. **Startup** klasörünün konumu, hem **Local Machine** hem de **Current User** kapsamları için registry'de tanımlanır. Bu, belirtilen **Startup** konumlarına eklenen herhangi bir kısayolun, bağlantılı service veya programın logon ya da reboot işleminin ardından başlatılmasını sağlar ve programların otomatik olarak çalışmasını planlamak için basit bir yöntem sunar.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** altındaki herhangi bir \[User] Shell Folder'ı overwrite edebiliyorsanız, bunu sizin kontrolünüzdeki bir klasöre yönlendirebilir ve bir kullanıcı system'e log in yaptığında her seferinde çalıştırılacak bir backdoor yerleştirerek privileges escalation gerçekleştirebilirsiniz.
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

Bu kullanıcıya özel registry değeri, ilgili kullanıcı oturum açtığında çalıştırılan bir script veya komuta işaret edebilir. Yalnızca etkilenen kullanıcının bağlamında çalıştığı için temel olarak bir **persistence** primitive'idir, ancak post-exploitation ve autoruns incelemeleri sırasında yine de kontrol edilmeye değerdir.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Mevcut kullanıcı için bu değere yazabiliyorsanız, admin haklarına ihtiyaç duymadan bir sonraki interaktif oturum açma sırasında çalıştırmayı yeniden tetikleyebilirsiniz. Başka bir kullanıcının hive'ına yazabiliyorsanız, o kullanıcı oturum açtığında code execution elde edebilirsiniz.
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
- Bu, değer kaldırılana kadar logoff/reboot sonrasında da kalıcı olur.
- `HKLM\...\Run` öğesinin aksine bu, tek başına elevation sağlamaz; user-scope persistence sağlar.

### Winlogon Anahtarları

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle **Userinit** anahtarı **userinit.exe** olarak ayarlanır. Ancak bu anahtar değiştirilirse belirtilen executable, kullanıcı logon yaptığında **Winlogon** tarafından da çalıştırılır. Benzer şekilde **Shell** anahtarının, Windows için varsayılan shell olan **explorer.exe** dosyasını göstermesi amaçlanır.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Kayıt defteri değerinin veya binary'nin üzerine yazabiliyorsanız privilege escalation gerçekleştirebilirsiniz.

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

### Safe Mode Command Prompt'u Değiştirme

Windows Registry'de `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında varsayılan olarak `cmd.exe` değerine ayarlanmış bir **`AlternateShell`** değeri bulunur. Bu, başlangıç sırasında (F8'e basarak) "Safe Mode with Command Prompt" seçeneğini belirlediğinizde `cmd.exe` dosyasının kullanılacağı anlamına gelir. Ancak bilgisayarınızı F8'e basıp bu seçeneği manuel olarak belirlemeniz gerekmeksizin otomatik olarak bu modda başlayacak şekilde yapılandırmak mümkündür.

"Safe Mode with Command Prompt" modunda otomatik olarak başlamak için bir boot seçeneği oluşturma adımları:<sup>[[5]](#references)</sup>

1. Salt okunur, sistem ve gizli bayraklarını kaldırmak için `boot.ini` dosyasının özniteliklerini değiştirin: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` dosyasını düzenlemek üzere açın.
3. Şuna benzer bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Değişiklikleri `boot.ini` dosyasına kaydedin.
5. Dosyanın özgün özniteliklerini yeniden uygulayın: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** Registry anahtarını değiştirmek, yetkisiz erişim amacıyla kullanılabilecek özel bir command shell yapılandırmasına olanak tanır.
- **Exploit 2 (PATH Write Permissions):** Sistem **PATH** değişkeninin herhangi bir bölümünde, özellikle `C:\Windows\system32` yolundan önce yazma izinlerine sahip olmak, özel bir `cmd.exe` dosyasını çalıştırmanıza olanak tanır. Sistem Safe Mode'da başlatılırsa bu bir backdoor olabilir.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` dosyasına yazma erişimine sahip olmak, otomatik Safe Mode başlatmayı etkinleştirerek bir sonraki yeniden başlatmada yetkisiz erişimi kolaylaştırır.

Mevcut **AlternateShell** ayarını kontrol etmek için şu komutları kullanın:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Yüklü Bileşen

Active Setup, **masaüstü ortamı tamamen yüklenmeden önce başlatılan** bir Windows özelliğidir. Kullanıcı oturum açma işlemi devam etmeden önce tamamlanması gereken belirli komutların yürütülmesine öncelik verir. Bu işlem, Run veya RunOnce registry bölümlerindeki girişler gibi diğer startup girdileri tetiklenmeden önce gerçekleşir.

Active Setup aşağıdaki registry keys üzerinden yönetilir:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu keys içinde, her biri belirli bir bileşene karşılık gelen çeşitli subkeys bulunur. Özellikle ilgi çekici key values şunlardır:

- **IsInstalled:**
- `0`, bileşenin komutunun yürütülmeyeceğini belirtir.
- `1`, komutun her kullanıcı için bir kez yürütüleceği anlamına gelir; `IsInstalled` değeri eksikse varsayılan davranış budur.
- **StubPath:** Active Setup tarafından yürütülecek komutu tanımlar. `notepad` başlatmak gibi geçerli herhangi bir command line olabilir.

**Security Insights:**

- Belirli bir **`StubPath`** ile **`IsInstalled`** değeri `"1"` olarak ayarlanmış bir key'i değiştirmek veya bu key'e yazmak, yetkisiz komut yürütülmesine ve potansiyel olarak privilege escalation gerçekleştirilmesine yol açabilir.
- Herhangi bir **`StubPath`** değerinde referans verilen binary file'ı değiştirmek de yeterli permissions olması koşuluyla privilege escalation sağlayabilir.

Active Setup bileşenleri genelindeki **`StubPath`** yapılandırmalarını incelemek için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) Genel Bakış

Browser Helper Objects (BHOs), Microsoft's Internet Explorer'ına ek özellikler ekleyen DLL modülleridir. Her başlatıldığında Internet Explorer ve Windows Explorer'a yüklenirler. Ancak **NoExplorer** anahtarı 1 olarak ayarlanarak çalışmaları engellenebilir; bu da Windows Explorer örnekleriyle birlikte yüklenmelerini önler.<sup>[[1]](#references)</sup>

BHOs, Internet Explorer 11 aracılığıyla Windows 10 ile uyumludur ancak Windows'un daha yeni sürümlerindeki varsayılan tarayıcı olan Microsoft Edge'de desteklenmez.

Bir sistemde kayıtlı BHOs'ları incelemek için aşağıdaki registry key'lerini kontrol edebilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, registry'de benzersiz bir identifier görevi gören **CLSID** ile temsil edilir. Her CLSID hakkında ayrıntılı bilgiler `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Registry'de BHO'ları sorgulamak için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kayıt defterinin her DLL için 1 yeni kayıt içereceğini ve bunun **CLSID** ile temsil edileceğini unutmayın. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` konumunda bulabilirsiniz.

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Komutu

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

autoruns bulabileceğiniz tüm sitelerin **zaten** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **tarafından tarandığını** unutmayın. Ancak, **otomatik olarak çalıştırılan** dosyaların daha **kapsamlı bir listesini** elde etmek için systinternals tarafından sağlanan [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) aracını kullanabilirsiniz:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Daha Fazla

**Daha fazla Autoruns benzeri registry girdisini** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Yaygın malware persistence mekanizmaları](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart kategorileri (Windows Sysinternals Tools ile Sorun Giderme, 2. Baskı)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Alternatif bir shell başlatan bir boot seçeneğini nasıl ekleyebilirim?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Özeti 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
