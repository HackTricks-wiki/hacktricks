# Kernel, LPE i CVE materijali

{{#include ../../../banners/hacktricks-training.md}}

Ove studije slučaja obrađuju različite primitive za lokalno podizanje privilegija. Pre primene tehnike, proverite pogođeni proizvod ili kernel, konfiguraciju i preduslove navedene u svakom članku. Za šire enumerisanje hosta koristite [Linux kontrolnu listu za podizanje privilegija](../linux-privilege-escalation-checklist.md).

Za Dirty Pipe (CVE-2022-0847), [originalno istraživanje](https://dirtypipe.cm4all.com/) navodi upstream stabilne ispravke u verzijama 5.10.102, 5.15.25 i 5.16.11. Verzija kernela iz starijeg pogođenog opsega samo je povod za dodatnu proveru: distribucije mogu da prenesu ispravke u pakete kernela pod drugim nazivima izdanja, a ciljna datoteka mora biti čitljiva da bi primitiva za upis u page cache bila moguća. Prepisivanje čitljivog SUID izvršnog fajla jedan je od mogućih puteva za podizanje privilegija, ako njegov set-ID prelaz i dalje funkcioniše; izmena datoteke `/etc/passwd` i zatim autentifikacija mogu zavisiti i od lokalnog PAM steka. Pre procene dostupnosti, proverite instalirani paket kernela dobavljača, kernel koji se pokreće nakon reboot-a, dozvole ciljne datoteke, opciju mount-a `nosuid` i `no_new_privs`. Nemojte izvršavati probni upis tokom pasivnog enumerisanja. Pogledajte [status za konkretno izdanje Ubuntua](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegovano izvršavanje kroz otkrivanje putanja procesa kojima se ne veruje.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): putanja za prepisivanje page cache-a u kernelu.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race uslov u obradi tajmera.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): pristup deskriptorima tokom race uslova pri izlasku procesa.

## Povezane studije slučaja iz oblasti Binary Exploitation

Odeljak Binary Exploitation detaljnije obrađuje exploit primitive, raspored memorije i zaobilaženje mitigacija za ove Linux kernel ciljeve:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): greška u socket-u razvijena u primitive za čitanje i upis u kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitiva za upis pokazivača proširena pomoću pipe bafera i workqueue-ova.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): eksploatacija kernel heap-a i zaobilaženje mitigacija.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): obrada timer race uslova u okviru Binary Exploitation, koja je takođe ukratko opisana iznad.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): otkrivanje adresa za eksploataciju arm64 kernela.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Android GPU putanja do pristupa memoriji kernela.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): greška Android akceleratora iskorišćena za upis u kernel.
{{#include ../../../banners/hacktricks-training.md}}
