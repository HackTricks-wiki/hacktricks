# Kernel, LPE ve CVE Materyali

{{#include ../../../banners/hacktricks-training.md}}

Bu vaka çalışmaları, birbirinden farklı local privilege escalation primitive’lerini ele alır. Bir tekniği uygulamadan önce her makaledeki etkilenen ürünü veya kernel’i, yapılandırmayı ve ön koşulları kontrol edin. Daha kapsamlı host enumeration için [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md) sayfasını kullanın.

Dirty Pipe (CVE-2022-0847) için [orijinal araştırma](https://dirtypipe.cm4all.com/), upstream stable düzeltmelerinin 5.10.102, 5.15.25 ve 5.16.11 sürümlerinde bulunduğunu belirtir. Eski ve etkilenen bir aralıktaki kernel sürümü yalnızca inceleme için bir ipucudur: dağıtım kernel’leri düzeltmeleri farklı sürüm adları altında backport edebilir ve page-cache write primitive’i için ilgili hedef dosyanın okunabilir olması gerekir. Okunabilir bir SUID executable dosyasının üzerine yazmak, set-ID geçişi hâlâ etkiliyse olası bir privilege escalation yoludur; `/etc/passwd` dosyasını değiştirmek ve ardından kimlik doğrulamak da yerel PAM stack’ine bağlı olabilir. Erişilebilirliği değerlendirirken yüklü vendor kernel package’ını, yeniden başlatma sonrasında çalışan kernel’i, hedef izinlerini, `nosuid` mount seçeneğini ve `no_new_privs` değerini kontrol edin. Pasif enumeration sırasında yazma testi yapmayın. Bkz. [Ubuntu’nun sürüme özgü durumu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): güvenilmeyen process-path discovery üzerinden ayrıcalıklı çalıştırma.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel page-cache üzerine yazma yolu.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer işleme sırasında ortaya çıkan bir race.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): process exit race sırasında descriptor erişimi.

## İlgili binary exploitation vaka çalışmaları

Binary Exploitation bölümü, bu Linux kernel hedefleri için exploit primitive’lerini, memory layout’u ve mitigation bypass’larını daha ayrıntılı ele alır:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket bug’ının kernel read ve write primitive’lerine dönüştürülmesi.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pipe buffer’ları ve workqueue’ler üzerinden genişletilen bir pointer-write primitive’i.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation ve mitigation bypass’ları.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): yukarıda da özetlenen timer race’in binary exploitation kapsamında ele alınışı.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation için adres keşfi.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel memory erişimi sağlayan bir Android GPU yolu.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel write işlemleri için kullanılan bir Android accelerator bug’ı.
{{#include ../../../banners/hacktricks-training.md}}
