# Kernel, LPE ve CVE İçeriği

{{#include ../../../banners/hacktricks-training.md}}

Bu vaka incelemeleri, birbirinden farklı yerel ayrıcalık yükseltme primitive'lerini ele alır. Bir tekniği uygulamadan önce her makaledeki etkilenen ürünü veya kernel'i, yapılandırmayı ve ön koşulları kontrol edin. Daha kapsamlı host keşfi için [Linux ayrıcalık yükseltme kontrol listesini](../linux-privilege-escalation-checklist.md) kullanın.

Dirty Pipe (CVE-2022-0847) için [orijinal araştırma](https://dirtypipe.cm4all.com/), upstream stable düzeltmelerinin 5.10.102, 5.15.25 ve 5.16.11 sürümlerinde bulunduğunu belirtir. Eski ve etkilenen aralıkta yer alan bir kernel sürümü yalnızca inceleme için ipucu niteliğindedir: dağıtım kernel'leri düzeltmeleri farklı sürüm adlarıyla backport edebilir ve page-cache write primitive'i için ilgili hedef dosyanın okunabilir olması gerekir. Set-ID geçişi hâlâ etkiliyse, okunabilir bir SUID executable'ın üzerine yazmak ayrıcalık elde etmenin olası yollarından biridir; `/etc/passwd` dosyasını değiştirmek ve ardından kimlik doğrulaması yapmak da yerel PAM stack'ine bağlı olabilir. Erişilebilirliği değerlendirirken kurulu vendor kernel paketini, yeniden başlatma sonrasındaki çalışan kernel'i, hedef izinlerini, mount üzerindeki `nosuid` seçeneğini ve `no_new_privs` değerini kontrol edin. Pasif keşif sırasında write probe çalıştırmayın. Bkz. [Ubuntu'nun sürüme özgü durumu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): güvenilmeyen process-path keşfi üzerinden ayrıcalıklı çalıştırma.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel page-cache üzerine yazma yolu.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer işleme sırasında oluşan bir race.
- [Linux ptrace exit race ve `pidfd_getfd` file descriptor hırsızlığı](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): bir process exit race'i sırasında descriptor erişimi.

## İlgili binary exploitation vaka incelemeleri

Binary Exploitation bölümü, bu Linux kernel hedeflerine yönelik exploit primitive'lerini, bellek yerleşimini ve mitigation bypass'larını daha ayrıntılı ele alır:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): kernel read ve write primitive'lerine dönüştürülen bir socket hatası.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pipe buffer'ları ve workqueue'ler üzerinden genişletilen bir pointer-write primitive'i.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation ve mitigation bypass'ları.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): yukarıda da özetlenen timer race'inin binary exploitation incelemesi.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation için adres keşfi.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel belleğine erişim sağlayan bir Android GPU yolu.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel write işlemleri için kullanılan bir Android hızlandırıcı hatası.
{{#include ../../../banners/hacktricks-training.md}}
