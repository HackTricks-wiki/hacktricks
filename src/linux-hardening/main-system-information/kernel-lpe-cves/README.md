# Kernel, LPE ve CVE İçeriği

{{#include ../../../banners/hacktricks-training.md}}

Bu vaka incelemeleri, birbirinden farklı yerel ayrıcalık yükseltme primitive’lerini ele alır. Bir tekniği uygulamadan önce her makalede etkilenen ürünü veya kernel’i, yapılandırmayı ve ön koşulları kontrol edin. Daha kapsamlı host keşfi için [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md) listesini kullanın.

Dirty Pipe (CVE-2022-0847) için [orijinal araştırma](https://dirtypipe.cm4all.com/), upstream stable düzeltmelerini 5.10.102, 5.15.25 ve 5.16.11 sürümlerinde belirtir. Eski ve etkilenen bir sürüm aralığındaki kernel sürümü, yalnızca inceleme için bir ipucudur: dağıtım kernel’lerine farklı sürüm adları altında düzeltmeler backport edilebilir ve page-cache yazma primitive’inin kullanılabilmesi için hedef dosyanın okunabilir olması gerekir. Set-ID geçişi hâlâ etkiliyse, okunabilir bir SUID executable’ın üzerine yazmak olası bir ayrıcalık yükseltme yoludur; `/etc/passwd` dosyasını değiştirdikten sonra kimlik doğrulaması yapmak da yerel PAM stack’ine bağlı olabilir. Erişilebilirliği değerlendirirken kurulu vendor kernel paketini, yeniden başlatma sonrasında çalışan kernel’i, hedef izinlerini, `nosuid` mount seçeneğini ve `no_new_privs` ayarını kontrol edin. Pasif keşif sırasında yazma testi çalıştırmayın. Bkz. [Ubuntu'nun sürüme özgü durumu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): güvenilmeyen process-path discovery üzerinden ayrıcalıklı kod yürütme.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel page-cache üzerine yazma yolu.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer işlemede bir yarış durumu.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): process çıkış yarışı sırasında file descriptor erişimi.

## İlgili binary exploitation vaka incelemeleri

Binary Exploitation bölümü, bu Linux kernel hedeflerine yönelik exploit primitive’lerini, bellek düzenini ve mitigation atlatma tekniklerini daha ayrıntılı ele alır:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket bug’ının kernel read ve write primitive’lerine dönüştürülmesi.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pipe buffer’ları ve workqueue’ler üzerinden genişletilen bir pointer-write primitive’i.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation ve mitigation atlatma teknikleri.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): yukarıda da özetlenen timer race durumunun binary exploitation açısından incelenmesi.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation için adres keşfi.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel belleğine erişim sağlayan bir Android GPU yolu.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel belleğine yazmak için kullanılan bir Android accelerator bug’ı.
{{#include ../../../banners/hacktricks-training.md}}
