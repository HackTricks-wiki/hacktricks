# Materijal o kernelu, LPE-u i CVE-ovima

{{#include ../../../banners/hacktricks-training.md}}

Ove studije slučaja obrađuju različite primitive za lokalno podizanje privilegija. Pre primene tehnike, proverite pogođeni proizvod ili kernel, konfiguraciju i preduslove navedene u svakom članku. Za šire popisivanje hosta koristite [kontrolnu listu za podizanje privilegija na Linuxu](../linux-privilege-escalation-checklist.md).

Za Dirty Pipe (CVE-2022-0847), [originalno istraživanje](https://dirtypipe.cm4all.com/) navodi upstream stabilne ispravke u verzijama 5.10.102, 5.15.25 i 5.16.11. Verzija kernela u starijem pogođenom opsegu samo je povod za proveru: distribucije mogu da prenesu ispravke u svoje kernele pod drugačijim oznakama izdanja, a ciljna datoteka mora biti čitljiva da bi primitiv za upis u page-cache bio moguć. Prepisivanje čitljivog SUID izvršnog fajla jedan je od mogućih puteva do privilegija, ako prelaz set-ID i dalje funkcioniše; izmena datoteke `/etc/passwd`, a zatim autentifikacija, takođe može da zavisi od lokalnog PAM steka. Pre procene mogućnosti iskorišćavanja, proverite instalirani kernel paket proizvođača, kernel koji je pokrenut nakon ponovnog pokretanja, dozvole cilja, opciju montiranja `nosuid` i `no_new_privs`. Nemojte izvoditi probni upis tokom pasivnog popisivanja. Pogledajte [status za određena izdanja Ubuntua](https://ubuntu.com/security/CVE-2022-0847).

- [Otkrivanje VMware Tools servisa, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): izvršavanje s privilegijama putem otkrivanja putanje procesa kojoj se ne može verovati.
- [Prepisivanje page-cache-a pomoću AF_ALG splice-a, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): putanja za prepisivanje kernel page-cache-a.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race uslov u obradi tajmera.
- [Linux ptrace race pri izlasku procesa i krađa deskriptora datoteka pomoću `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): pristup deskriptoru tokom race uslova pri izlasku procesa.

## Povezane studije slučaja Binary Exploitation

Odeljak Binary Exploitation detaljnije obrađuje primitive za exploit, raspored memorije i zaobilaženje mitigacija za ove Linux kernel ciljeve:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): greška u socket-u razvijena u primitive za čitanje i upis u kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitiv za upis pokazivača proširen pomoću pipe bafera i workqueue-ova.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): iskorišćavanje kernel heap-a i zaobilaženje mitigacija.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): obrada race uslova tajmera u kontekstu binary exploitation-a, koja je takođe sažeta iznad.
- [Zaobilaženje KASLR-a za statičku linear mapu na Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): otkrivanje adresa za iskorišćavanje arm64 kernela.
- [Zaobilaženje privilegija Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Android GPU putanja do pristupa memoriji kernela.
- [Pixel Bigwave use-after-free zbog isteka vremena posla](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): greška u Android akceleratoru iskorišćena za upis u kernel.
{{#include ../../../banners/hacktricks-training.md}}
