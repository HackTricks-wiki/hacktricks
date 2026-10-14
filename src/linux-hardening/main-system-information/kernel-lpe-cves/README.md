# Kernel, LPE ve CVE Materyalleri

{{#include ../../../banners/hacktricks-training.md}}

Bu vaka çalışmaları, farklı yerel yetki yükseltme (LPE) ilkelerini ele alır. Bir tekniği uygulamadan önce her makaledeki etkilenen ürünü veya kernel’i, yapılandırmayı ve ön koşulları kontrol edin. Daha kapsamlı host keşfi için [Linux yetki yükseltme kontrol listesini](../linux-privilege-escalation-checklist.md) kullanın.

Dirty Pipe (CVE-2022-0847) için [orijinal araştırma](https://dirtypipe.cm4all.com/), upstream stable düzeltmelerinin 5.10.102, 5.15.25 ve 5.16.11 sürümlerinde yer aldığını belirtir. Etkilenen daha eski bir aralıktaki kernel sürümü, yalnızca inceleme için bir ipucudur: dağıtım kernel’leri, düzeltmeleri farklı sürüm adlarıyla backport edebilir ve page-cache yazma primitive’i için ilgili hedef dosyanın okunabilir olması gerekir. Set-ID geçişi hâlâ etkiliyse, okunabilir bir SUID executable’ı üzerine yazmak olası bir yetki yoludur; `/etc/passwd` dosyasını değiştirmek ve ardından kimlik doğrulamak da yerel PAM stack’ine bağlı olabilir. Erişilebilirliği değerlendirirken kurulu vendor kernel paketini, yeniden başlatma sonrasında çalışan kernel’i, hedef izinlerini, `nosuid` mount seçeneğini ve `no_new_privs` ayarını kontrol edin. Pasif keşif sırasında yazma testi çalıştırmayın. [Ubuntu’nun sürüme özel durumuna](https://ubuntu.com/security/CVE-2022-0847) bakın.

- [VMware Tools hizmet keşfi, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): güvenilmeyen process-path keşfi üzerinden ayrıcalıklı yürütme.
- [AF_ALG splice page-cache üzerine yazma, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel page-cache üzerine yazma yolu.
- [POSIX CPU timer’larında TOCTOU race ve exploitation, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): task çıkışı sırasında timer süresinin dolması/silinmesi; IRQ-path ön koşulları ve exploit araştırması dahil.
- [Linux ptrace çıkış yarışı ve `pidfd_getfd` file descriptor hırsızlığı](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): process çıkış yarışı sırasında descriptor erişimi.

## İlgili binary exploitation vaka çalışmaları

Binary Exploitation bölümü, bu Linux kernel hedefleri için exploit primitive’lerini, bellek düzenini ve mitigation atlatma yöntemlerini daha ayrıntılı ele alır:

- [AF_UNIX bant dışı SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket bug’ının kernel okuma ve yazma primitive’lerine dönüştürülmesi.
- [AF_ALG eşzamanlı writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): skcipher writer race’inin kernel yazımına dönüştürülmesi.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pipe buffer’ları ve workqueue’ler üzerinden genişletilen pointer-write primitive’i.
- [ksmbd streams sınır dışı yazma, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation ve mitigation atlatma yöntemleri.
- [Arm64 statik linear-map KASLR atlatması](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation için adres keşfi.
- [Adreno A7xx GPU/SMMU yetki atlatması](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel belleğine erişim sağlayan bir Android GPU yolu.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel yazımları için kullanılan bir Android hızlandırıcı bug’ı.
{{#include ../../../banners/hacktricks-training.md}}
