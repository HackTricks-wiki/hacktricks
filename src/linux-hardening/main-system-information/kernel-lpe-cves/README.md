# Materiały dotyczące kernela, LPE i CVE

{{#include ../../../banners/hacktricks-training.md}}

Te analizy przypadków obejmują różne prymitywy lokalnej eskalacji uprawnień. Przed zastosowaniem techniki sprawdź w każdym artykule podatny produkt lub kernel, konfigurację i wymagania wstępne. Aby szerzej rozpoznawać hosta, skorzystaj z [listy kontrolnej eskalacji uprawnień w systemie Linux](../linux-privilege-escalation-checklist.md).

W przypadku Dirty Pipe (CVE-2022-0847) w [oryginalnym opracowaniu](https://dirtypipe.cm4all.com/) wskazano poprawki w upstreamowych stabilnych wersjach 5.10.102, 5.15.25 i 5.16.11. Wersja kernela mieszcząca się w starszym podatnym zakresie to jedynie wskazówka do dalszej analizy: dystrybucje mogą backportować poprawki, używając innych oznaczeń wersji, a plik docelowy musi być czytelny, by można było wykorzystać prymityw zapisu do page cache. Nadpisanie czytelnego pliku wykonywalnego SUID to jedna z możliwych ścieżek uzyskania uprawnień, jeśli przejście set-ID nadal działa; modyfikacja `/etc/passwd`, a następnie uwierzytelnienie również może zależeć od lokalnego stosu PAM. Przed oceną możliwości wykorzystania sprawdź zainstalowany pakiet kernela dostawcy, działający kernel po ponownym uruchomieniu, uprawnienia do pliku docelowego, opcję montowania `nosuid` oraz `no_new_privs`. Nie wykonuj sondy zapisu podczas pasywnego rozpoznania. Zobacz [stan dla poszczególnych wersji Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Wykrywanie usługi VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): wykonanie z podwyższonymi uprawnieniami przez wykrywanie ścieżki procesu z niezaufanego źródła.
- [Nadpisanie page cache przez AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ścieżka nadpisania page cache kernela.
- [TOCTOU w timerach CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): wyścig w obsłudze timerów.
- [Wyścig przy kończeniu procesu w Linux ptrace i kradzież deskryptora pliku przez `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): dostęp do deskryptora podczas wyścigu przy kończeniu procesu.

## Powiązane analizy przypadków binary exploitation

Sekcja Binary Exploitation dokładniej omawia prymitywy exploita, układ pamięci i obejścia mechanizmów ochronnych dla tych celów w kernelu Linux:

- [Use-after-free SKB poza pasmem w AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): błąd gniazda wykorzystany do uzyskania prymitywów odczytu i zapisu w kernelu.
- [Niedomiar scatterlist przy równoczesnym zapisie w AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): wyścig zapisu skcipher wykorzystany do uzyskania zapisu w kernelu.
- [Use-after-free Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): prymityw zapisu wskaźnika rozszerzony przez bufory pipe i workqueue.
- [Zapis poza zakresem w strumieniach ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): wykorzystanie sterty kernela i obejścia mechanizmów ochronnych.
- [TOCTOU w timerach CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): omówienie wyścigu timerów z perspektywy binary exploitation, podsumowanego również powyżej.
- [Obejście KASLR w statycznej mapie liniowej Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ustalanie adresów na potrzeby wykorzystania kernela arm64.
- [Obejście uprawnień GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ścieżka przez GPU w Androidzie umożliwiająca dostęp do pamięci kernela.
- [Use-after-free po przekroczeniu limitu czasu zadania Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): błąd akceleratora w Androidzie wykorzystany do zapisu w kernelu.
{{#include ../../../banners/hacktricks-training.md}}
