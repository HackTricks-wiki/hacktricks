# Materijal o kernelu, LPE-u i CVE-ovima

{{#include ../../../banners/hacktricks-training.md}}

Ove studije slučaja obrađuju različite primitive za lokalnu eskalaciju privilegija. Pre primene tehnike proverite pogođeni proizvod ili kernel, konfiguraciju i preduslove navedene u svakom članku. Za šire popisivanje hosta koristite [kontrolnu listu za eskalaciju privilegija u Linuxu](../linux-privilege-escalation-checklist.md).

Za Dirty Pipe (CVE-2022-0847), [originalno istraživanje](https://dirtypipe.cm4all.com/) navodi upstream stable ispravke u verzijama 5.10.102, 5.15.25 i 5.16.11. Verzija kernela iz starijeg pogođenog raspona samo je povod za proveru: distribucioni kerneli mogu da prenesu ispravke u druge verzije, a ciljna datoteka mora biti čitljiva da bi primitiva za upis u page-cache mogla da se iskoristi. Prepisivanje čitljive SUID izvršne datoteke jedan je od mogućih puteva do privilegija ako je njen set-ID prelaz i dalje delotvoran; izmena datoteke `/etc/passwd`, a zatim autentifikacija, takođe može zavisiti od lokalnog PAM steka. Pre procene mogućnosti iskorišćavanja proverite instalirani paket kernel-a dobavljača, pokrenuti kernel nakon ponovnog pokretanja, dozvole ciljne datoteke, opciju montiranja `nosuid` i `no_new_privs`. Nemojte pokretati probni upis tokom pasivnog popisivanja. Pogledajte [status za konkretna izdanja Ubuntua](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): izvršavanje sa povišenim privilegijama putem otkrivanja putanje procesa iz nepouzdanog izvora.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): putanja za prepisivanje kernel page-cache-a.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): utrka u obradi tajmera.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): pristup deskriptoru tokom utrke pri izlasku procesa.

## Povezane studije slučaja binarne eksploatacije

Odeljak Binary Exploitation detaljnije obrađuje primitive za eksploataciju, raspored memorije i zaobilaženje mera zaštite za ove ciljeve u Linux kernelu:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): greška u socketu iskorišćena za dobijanje primitiva za čitanje i upis u kernel.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): utrka pri upisu pomoću skcipher-a iskorišćena za upis u kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitiva za upis pokazivača proširena korišćenjem pipe bafera i workqueue-a.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): eksploatacija kernel heap-a i zaobilaženje mera zaštite.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): obrada utrke tajmera iz perspektive binarne eksploatacije, takođe ukratko opisana iznad.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): otkrivanje adresa za eksploataciju arm64 kernela.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): putanja preko Android GPU-a do pristupa memoriji kernela.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): greška u Android akceleratoru iskorišćena za upis u kernel.
{{#include ../../../banners/hacktricks-training.md}}
