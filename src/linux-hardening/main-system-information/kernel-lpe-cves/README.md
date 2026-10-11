# Materijal o kernelu, LPE-u i CVE-ovima

{{#include ../../../banners/hacktricks-training.md}}

Ove studije slučaja obrađuju različite primitive za lokalno podizanje privilegija. Pre primene tehnike, u svakom članku proverite pogođeni proizvod ili kernel, konfiguraciju i preduslove. Za šire popisivanje hosta koristite [Linux kontrolnu listu za podizanje privilegija](../linux-privilege-escalation-checklist.md).

Za Dirty Pipe (CVE-2022-0847), [originalno istraživanje](https://dirtypipe.cm4all.com/) navodi ispravke u uzvodnim stabilnim verzijama 5.10.102, 5.15.25 i 5.16.11. Verzija kernela u starijem pogođenom rasponu samo je razlog za dodatnu proveru: distribucioni kerneli mogu imati prenete ispravke pod drugačijim oznakama izdanja, a ciljni fajl mora biti čitljiv da bi primitiva za upis u page cache mogla da se iskoristi. Prepisivanje čitljive SUID izvršne datoteke jedan je od mogućih načina za sticanje privilegija ako njen prelaz set-ID i dalje funkcioniše; izmena `/etc/passwd` i naknadna autentifikacija takođe mogu zavisiti od lokalnog PAM steka. Pre procene mogućnosti iskorišćavanja proverite instalirani paket kernela dobavljača, pokrenuti kernel nakon ponovnog pokretanja, dozvole ciljne datoteke, opciju montiranja `nosuid` i `no_new_privs`. Tokom pasivnog popisivanja nemojte pokretati probni upis. Pogledajte [status za pojedinačna izdanja Ubuntua](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): izvršavanje sa privilegijama kroz otkrivanje putanje procesa kojoj se ne veruje.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): putanja za prepisivanje kernel page cache-a.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): utrka u obradi tajmera.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): pristup deskriptorima tokom utrke pri izlasku procesa.

## Povezane studije slučaja binarnog iskorišćavanja

Odeljak Binary Exploitation detaljnije obrađuje primitive za iskorišćavanje, raspored memorije i zaobilaženje zaštita za ove Linux kernel ciljeve:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): greška u soketu iskorišćena za dobijanje primitiva za čitanje i upis u kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitiva za upisivanje pokazivača proširena preko bafera cevi i workqueue-a.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): iskorišćavanje kernel heap-a i zaobilaženje zaštita.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): obrada utrke tajmera iz ugla binarnog iskorišćavanja, takođe ukratko opisana iznad.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): otkrivanje adresa za iskorišćavanje arm64 kernela.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): putanja preko Android GPU-a do pristupa memoriji kernela.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): greška u Android akceleratoru iskorišćena za upis u kernel.
{{#include ../../../banners/hacktricks-training.md}}
