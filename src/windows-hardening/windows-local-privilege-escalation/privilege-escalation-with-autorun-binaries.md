# Autorun'lar ile Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**, programları **startup** sırasında çalıştırmak için kullanılabilir. Startup sırasında çalışması planlanan binary'leri görmek için:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zamanlanmış Görevler

**Görevler**, **belirli bir sıklıkta** çalışacak şekilde zamanlanabilir. Şu komutla hangi ikili dosyaların çalışacak şekilde zamanlandığını görün:
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

**Başlangıç klasörlerinde bulunan tüm binary'ler başlangıçta çalıştırılır**. Yaygın başlangıç klasörleri aşağıda listelenmiştir, ancak başlangıç klasörü registry'de belirtilir. [Konumunu öğrenmek için bunu okuyun.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **BİLGİ**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposition payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon. For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry entry, 64-bit Windows version kullandığınızı gösterir. İşletim sistemi, 64-bit Windows sürümlerinde çalışan 32-bit uygulamalar için HKEY_LOCAL_MACHINE\SOFTWARE anahtarının ayrı bir görünümünü sunmak üzere bu anahtarı kullanır.

### Runs

**Yaygın olarak bilinen** AutoRun registry:

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

**Run** ve **RunOnce** olarak bilinen registry anahtarları, bir kullanıcı system'e her logon olduğunda programları otomatik olarak çalıştırmak üzere tasarlanmıştır. Bir anahtarın data value'su olarak atanan command line, 260 karakter veya daha kısa olmakla sınırlıdır.<sup>[[2]](#references)</sup>

**Service runs** (boot sırasında services'in automatic startup'ını kontrol edebilir):

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

Windows Vista ve sonraki sürümlerde **Run** ve **RunOnce** registry anahtarları otomatik olarak oluşturulmaz. Bu anahtarlardaki entries, programları doğrudan başlatabilir veya bunları dependencies olarak belirtebilir. Örneğin, logon sırasında bir DLL file yüklemek için **RunOnceEx** registry anahtarı, bir "Depend" anahtarıyla birlikte kullanılabilir. Bu, system start-up sırasında "C:\temp\evil.dll" dosyasını çalıştıracak bir registry entry eklenerek gösterilmiştir:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: **HKLM** içindeki belirtilen registry girdilerinden herhangi birine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında ayrıcalıkları yükseltebilirsiniz.

> [!TIP]
> **Exploit 2**: **HKLM** içindeki registry girdilerinde belirtilen binary dosyalardan herhangi birinin üzerine yazabiliyorsanız, farklı bir kullanıcı oturum açtığında bu binary dosyayı bir backdoor ile değiştirerek ayrıcalıkları yükseltebilirsiniz.
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

**Startup** klasörüne yerleştirilen kısayollar, kullanıcı logon olduğunda veya sistem yeniden başlatıldığında services ya da applications öğelerinin otomatik olarak başlatılmasını tetikler. **Startup** klasörünün konumu, hem **Local Machine** hem de **Current User** kapsamları için registry'de tanımlanır. Bu, belirtilen **Startup** konumlarına eklenen herhangi bir kısayolun, logon veya yeniden başlatma işleminin ardından bağlantılı service ya da programın başlatılmasını sağlar ve programların otomatik olarak çalışmasını zamanlamak için basit bir yöntem sunar.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** altındaki herhangi bir \[User] Shell Folder'ı overwrite edebiliyorsanız, bunu sizin kontrolünüzdeki bir klasöre yönlendirebilir ve bir user system'e her logon olduğunda çalıştırılacak bir backdoor yerleştirerek privileges yükseltebilirsiniz.
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

Bu kullanıcıya özel registry değeri, kullanıcı oturum açtığında çalıştırılan bir script veya komuta işaret edebilir. Yalnızca etkilenen kullanıcının context'inde çalıştığı için esas olarak bir **persistence** primitive'idir; ancak post-exploitation ve autoruns incelemeleri sırasında yine de kontrol edilmeye değerdir.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Mevcut kullanıcı için bu değere yazabiliyorsanız, admin rights gerektirmeden bir sonraki interactive logon sırasında execution'ı yeniden tetikleyebilirsiniz. Başka bir kullanıcının hive'ına yazabiliyorsanız, o kullanıcı oturum açtığında code execution elde edebilirsiniz.
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
- Bu, değer kaldırılana kadar oturum kapatma/yeniden başlatma sonrasında da kalıcılığını sürdürür.
- `HKLM\...\Run` öğesinin aksine, bu yöntem tek başına yetki yükseltme sağlamaz; user-scope persistence sağlar.

### Winlogon Anahtarları

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Genellikle **Userinit** anahtarı **userinit.exe** olarak ayarlanır. Ancak bu anahtar değiştirilirse belirtilen executable, kullanıcı oturum açtığında **Winlogon** tarafından da başlatılır. Benzer şekilde **Shell** anahtarının, Windows için varsayılan shell olan **explorer.exe** dosyasını göstermesi amaçlanır.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Kayıt defteri değerinin veya binary'nin üzerine yazabiliyorsanız yetkilerinizi yükseltebilirsiniz.

### İlke Ayarları

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

Windows Registry'de `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` altında, varsayılan olarak `cmd.exe` değerine ayarlanmış bir **`AlternateShell`** değeri bulunur. Bu, başlangıç sırasında (F8'e basarak) "Safe Mode with Command Prompt" seçeneğini belirlediğinizde `cmd.exe` kullanıldığı anlamına gelir. Ancak bilgisayarınızı F8'e basıp bu seçeneği manuel olarak belirlemeniz gerekmeksizin otomatik olarak bu modda başlayacak şekilde yapılandırmak mümkündür.

"Safe Mode with Command Prompt" modunda otomatik olarak başlamak için bir boot seçeneği oluşturma adımları:<sup>[[5]](#references)</sup>

1. Salt okunur, sistem ve gizli bayraklarını kaldırmak için `boot.ini` dosyasının özniteliklerini değiştirin: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` dosyasını düzenlemek üzere açın.
3. Şuna benzer bir satır ekleyin: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Değişiklikleri `boot.ini` dosyasına kaydedin.
5. Özgün dosya özniteliklerini yeniden uygulayın: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key'ini değiştirmek, yetkisiz erişim amacıyla kullanılabilecek özel bir command shell yapılandırmasına olanak tanır.
- **Exploit 2 (PATH Write Permissions):** Sistem **PATH** değişkeninin herhangi bir bölümünde, özellikle `C:\Windows\system32` yolundan önce, write permissions bulunması özel bir `cmd.exe` dosyasını çalıştırmanıza olanak tanır. Sistem Safe Mode'da başlatılırsa bu bir backdoor olabilir.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` dosyasına write access olması, otomatik Safe Mode başlangıcını etkinleştirerek bir sonraki reboot işleminde yetkisiz erişimi kolaylaştırır.

Mevcut **AlternateShell** ayarını kontrol etmek için şu commands'leri kullanın:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup, **masaüstü ortamı tamamen yüklenmeden önce başlatılan** bir Windows özelliğidir. Belirli komutların çalıştırılmasına öncelik verir; bu komutların kullanıcı oturumu açma işlemi devam etmeden önce tamamlanması gerekir. Bu işlem, Run veya RunOnce registry bölümlerindeki girişler gibi diğer startup girişleri tetiklenmeden önce gerçekleşir.

Active Setup aşağıdaki registry key'leri üzerinden yönetilir:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Bu key'lerin içinde, her biri belirli bir component'e karşılık gelen çeşitli subkey'ler bulunur. Özellikle ilgi çeken key değerleri şunlardır:

- **IsInstalled:**
- `0`, component'in komutunun çalıştırılmayacağını belirtir.
- `1`, komutun her kullanıcı için bir kez çalıştırılacağı anlamına gelir; `IsInstalled` değeri eksikse varsayılan davranış budur.
- **StubPath:** Active Setup tarafından çalıştırılacak komutu tanımlar. `notepad` başlatmak gibi geçerli herhangi bir command line olabilir.

**Security Insights:**

- **`IsInstalled`** değerinin `"1"` olarak ayarlandığı ve belirli bir **`StubPath`** içeren bir key'i değiştirmek veya key'e yazmak, yetkisiz command execution'a ve potansiyel olarak privilege escalation'a yol açabilir.
- Yeterli permission olması koşuluyla, herhangi bir **`StubPath`** değerinde referans verilen binary file'ı değiştirmek de privilege escalation sağlayabilir.

Active Setup component'leri genelindeki **`StubPath`** yapılandırmalarını incelemek için şu command'ler kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHO'lar) Genel Bakış

Browser Helper Objects (BHO'lar), Microsoft's Internet Explorer'a ek özellikler kazandıran DLL modülleridir. Her başlatıldığında Internet Explorer ve Windows Explorer'a yüklenirler. Ancak **NoExplorer** anahtarı 1 olarak ayarlanarak çalıştırılmaları engellenebilir; bu, Windows Explorer örnekleriyle birlikte yüklenmelerini önler.<sup>[[1]](#references)</sup>

BHO'lar, Internet Explorer 11 aracılığıyla Windows 10 ile uyumludur; ancak Windows'un daha yeni sürümlerindeki varsayılan tarayıcı olan Microsoft Edge'de desteklenmezler.

Bir sistemde kayıtlı BHO'ları incelemek için aşağıdaki registry key'lerini kontrol edebilirsiniz:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Her BHO, registry'de benzersiz bir identifier görevi gören **CLSID**'si ile temsil edilir. Her CLSID hakkında ayrıntılı bilgiler `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` altında bulunabilir.

Registry'de BHO'ları sorgulamak için şu komutlar kullanılabilir:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Eklentileri

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kayıt defterinde her DLL için 1 yeni registry bulunacağını ve bunun **CLSID** ile temsil edileceğini unutmayın. CLSID bilgilerini `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` konumunda bulabilirsiniz.

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
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Autoruns bulabileceğiniz tüm sitelerin [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) tarafından **zaten arandığını** unutmayın. Ancak, **otomatik olarak çalıştırılan** dosyaların daha kapsamlı bir listesi için systinternals'ın [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) aracını kullanabilirsiniz:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Daha Fazla

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) adresinde registry benzeri daha fazla Autoruns bulun**<sup>[[4]](#references)</sup>

## Referanslar

- [1] [Yaygın malware persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Alternatif bir shell başlatan bir boot option nasıl eklenir?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
