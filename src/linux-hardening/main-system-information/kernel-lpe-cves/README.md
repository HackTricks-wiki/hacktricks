# Materijal o kernelu, LPE-u i CVE-ovima

{{#include ../../../banners/hacktricks-training.md}}

Ove studije slučaja obrađuju različite primitive za lokalnu eskalaciju privilegija. Pre primene tehnike proverite pogođeni proizvod ili kernel, konfiguraciju i preduslove navedene u svakom članku. Za šire enumerisanje hosta koristite [kontrolnu listu za eskalaciju privilegija na Linuxu](../linux-privilege-escalation-checklist.md).

Za Dirty Pipe (CVE-2022-0847), [originalno istraživanje](https://dirtypipe.cm4all.com/) navodi ispravke u upstream stabilnim verzijama 5.10.102, 5.15.25 i 5.16.11. Verzija kernela u starijem pogođenom rasponu samo je povod za proveru: distribucije mogu preneti ispravke u pakete kernela pod drugim nazivima izdanja, a relevantna ciljna datoteka mora biti čitljiva da bi primitiva za upis u page-cache mogla da se iskoristi. Prepisivanje čitljivog SUID izvršnog fajla jedan je od mogućih puteva do privilegija ako njegov set-ID prelaz i dalje funkcioniše; menjanje `/etc/passwd` i naknadna autentifikacija takođe mogu zavisiti od lokalnog PAM sklopa. Pre procene mogućnosti iskorišćavanja proverite instalirani vendorski paket kernela, kernel koji radi nakon ponovnog pokretanja, dozvole ciljnog fajla, opciju montiranja `nosuid` и `no_new_privs`. Tokом пасивног enumerisanja немојте покретати пробу уписа. Погледајте [статус специфичан за издање Ubuntu-а](https://ubuntu.com/security/CVE-2022-0847).

- [Откривање VMware Tools сервиса, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): привилеговано извршавање кроз откривање путање процеса којој се не верује.
- [Преписивање page-cache помоћу AF_ALG splice-а, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): путања за преписивање kernel page-cache-а.
- [TOCTOU у POSIX CPU тајмерима, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): трка у обради тајмера.
- [Linux ptrace трка при изласку процеса и крађа дескриптора датотека помоћу `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): приступ дескриптору током трке при изласку процеса.

## Повезане студије случаја бинарне експлоатације

Одељак Binary Exploitation детаљније обрађује примитиве за експлоатацију, распоред меморије и заобилажење мера заштите за ове Linux kernel мете:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): грешка у socket-у искоришћена за добијање примитива за читање и упис у kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): примитива за упис показивача проширена преко pipe buffer-а и workqueue-а.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): експлоатација kernel heap-а и заобилажење мера заштите.
- [TOCTOU у POSIX CPU тајмерима, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): обрада трке тајмера у контексту бинарне експлоатације, сажета и изнад.
- [Заобилажење KASLR-а за статичку линеарну мапу на Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): откривање адреса за експлоатацију Arm64 kernel-а.
- [Заобилажење привилегија Adreno A7xx GPU/SMMU-а](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Android GPU путања до приступа kernel меморији.
- [Pixel Bigwave use-after-free услед истека времена job-а](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): грешка у Android акцелератору искоришћена за упис у kernel.
{{#include ../../../banners/hacktricks-training.md}}
