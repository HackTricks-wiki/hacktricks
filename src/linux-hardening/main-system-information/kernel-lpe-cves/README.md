# Materijali o kernelu, LPE-u i CVE-ovima

{{#include ../../../banners/hacktricks-training.md}}

Ove studije slučaja obrađuju različite primitive za lokalnu eskalaciju privilegija. Pre primene tehnike proverite pogođeni proizvod ili kernel, konfiguraciju i preduslove navedene u svakom članku. Za šire prikupljanje informacija o hostu koristite [kontrolnu listu za eskalaciju privilegija u Linuxu](../linux-privilege-escalation-checklist.md).

Za Dirty Pipe (CVE-2022-0847), [originalno istraživanje](https://dirtypipe.cm4all.com/) navodi da su ispravke za upstream stable objavljene u verzijama 5.10.102, 5.15.25 i 5.16.11. Verzija kernela iz starijeg pogođenog raspona samo je povod za proveru: distribucije mogu da prenesu ispravke u pakete pod drugim nazivima verzija, a ciljna datoteka mora biti čitljiva da bi primitiv za upis u page-cache bio upotrebljiv. Prepisivanje čitljivog SUID izvršnog fajla jedan je od mogućih puteva za sticanje privilegija ako je njegov set-ID prelaz i dalje delotvoran; izmena fajla `/etc/passwd`, a zatim autentifikacija, takođe može zavisiti od lokalnog PAM steka. Pre procene dostupnosti proverite instalirani paket kernela dobavljača, kernel koji je покренут након рестартовања, dozvole ciljne datoteke, opciju montiranja `nosuid` i `no_new_privs`. Nemojte izvoditi probni upis tokom pasivnog prikupljanja informacija. Pogledajte [status za pojedina izdanja Ubuntua](https://ubuntu.com/security/CVE-2022-0847).

- [Otkrivanje VMware Tools servisa, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): izvršavanje s privilegijama kroz nepouzdano otkrivanje putanje procesa.
- [Prepisivanje page-cache putem AF_ALG splice-a, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): putanja za prepisivanje page-cache-a u kernelu.
- [TOCTOU trka POSIX CPU tajmera i eksploatacija, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): istek/brisanje tajmera tokom gašenja taska, uključujući preduslove za IRQ putanju i istraživanje eksploatacije.
- [Linux ptrace trka pri izlasku procesa i krađa deskriptora fajla putem `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): pristup deskriptoru tokom trke pri izlasku procesa.

## Povezane studije slučaja binarne eksploatacije

Odeljak Binary Exploitation detaljnije obrađuje primitive eksploatacije, raspored memorije i zaobilaženje mitigacija za ove Linux kernel mete:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): greška u soketu razvijena u primitive za čitanje i upis u kernel.
- [AF_ALG underflow scatterlist-a usled konkurentnog pisanja](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): trka pri upisu skcipher-a razvijena u upis u kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitiv za upis pokazivača proširen pomoću pipe bafera i workqueue-ova.
- [Out-of-bounds upis u ksmbd streams, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): eksploatacija kernel heap-a i zaobilaženje mitigacija.
- [Zaobilaženje KASLR-a za statičku linearnu mapu na Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): otkrivanje adresa za eksploataciju arm64 kernela.
- [Zaobilaženje privilegija Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): putanja kroz Android GPU do pristupa memoriji kernela.
- [Pixel Bigwave use-after-free usled isteka vremena posla](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): greška u Android akceleratoru iskorišćena za upis u kernel.
{{#include ../../../banners/hacktricks-training.md}}
