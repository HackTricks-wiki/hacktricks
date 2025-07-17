# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) yazılım güncelleyicisini tehlikeye atan çekirdek zafiyetleri açıklanmaktadır.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Doğada Kernel 0-günler (CVE-2024-23225 & CVE-2024-23296)

Apple, Mart 2024'te iOS ve macOS'a karşı aktif olarak istismar edilen iki bellek bozulma hatasını yamanladı (macOS 14.4/13.6.5/12.7.4'te düzeltildi).

* **CVE-2024-23225 – Kernel**
• XNU sanal bellek alt sisteminde sınır dışı yazma, ayrıcalıksız bir işlemin çekirdek adres alanında keyfi okuma/yazma elde etmesine olanak tanır ve PAC/KTRR'yi atlatır.
• Mesaj ayrıştırıldığında `libxpc` içindeki bir tamponu aşan bir XPC mesajı aracılığıyla kullanıcı alanından tetiklenir ve ardından çekirdeğe geçiş yapar.
* **CVE-2024-23296 – RTKit**
• Apple Silicon RTKit (gerçek zamanlı yardımcı işlemci) içindeki bellek bozulması.
• Gözlemlenen istismar zincirleri, çekirdek R/W için CVE-2024-23225 ve güvenli yardımcı işlemci kumandasından çıkmak ve PAC'yi devre dışı bırakmak için CVE-2024-23296 kullanmıştır.

Yaman düzeyi tespiti:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Eğer yükseltme mümkün değilse, savunmasız hizmetleri devre dışı bırakarak azaltın:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Tür Karışıklığı – CVE-2023-41075

`mach_msg()` istekleri, ayrıcalıksız bir IOKit kullanıcı istemcisine gönderildiğinde, MIG tarafından üretilen yapıştırıcı kodda bir **tip karışıklığına** yol açar. Yanıt mesajı, başlangıçta tahsis edilenden daha büyük bir dıştan tanımlayıcı ile yeniden yorumlandığında, bir saldırgan kontrol edilen bir **OOB yazma** işlemi gerçekleştirebilir ve nihayetinde `root` yetkisine yükselebilir.

Temel taslak (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits, hatayı silahlandırarak:
1. Aktif port işaretçileri ile `ipc_kmsg` tamponlarını doldurmak.
2. Bir sarkan portun `ip_kobject`'ını üzerine yazmak.
3. `mprotect()` kullanarak PAC-taklit adresinde haritalanmış shellcode'a atlamak.

---

## 2024-2025: Üçüncü Taraf Kext'ler Üzerinden SIP Bypass – CVE-2024-44243 (aka “Sigma”)

Microsoft'tan güvenlik araştırmacıları, yüksek ayrıcalıklı daemon `storagekitd`'nin **imzasız bir çekirdek uzantısını** yüklemeye zorlanabileceğini ve böylece tamamen yamanmış macOS'ta (**15.2'den önce**) **Sistem Bütünlüğü Koruması (SIP)**'nı tamamen devre dışı bırakabileceğini gösterdi. Saldırı akışı:

1. Saldırgan kontrolündeki bir yardımcıyı başlatmak için özel yetki `com.apple.storagekitd.kernel-management`'i kötüye kullanmak.
2. Yardımcı, kötü niyetli bir kext paketi işaret eden hazırlanmış bir bilgi sözlüğü ile `IOService::AddPersonalitiesFromKernelModule`'u çağırır.
3. SIP güven kontrolü, `storagekitd` tarafından kext sahneye konduktan *sonra* gerçekleştirildiğinden, kod ring-0'da doğrulama öncesinde çalışır ve SIP `csr_set_allow_all(1)` ile kapatılabilir.

Tespit ipuçları:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Acil düzeltme, macOS Sequoia 15.2 veya daha yenisine güncellemektir.

---

### Hızlı Sayım Kılavuzu
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach mesaj fuzzer'ı, MIG alt sistemlerini hedef alır (`github.com/preshing/luftrauser`).
* **oob-executor** – CVE-2024-23225 araştırmasında kullanılan IPC out-of-bounds ilke üreticisi.
* **kmutil inspect** – Yüklemeden önce kext'leri statik olarak analiz etmek için yerleşik Apple aracı (macOS 11+): `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
