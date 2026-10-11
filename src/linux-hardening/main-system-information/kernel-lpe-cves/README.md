# Materiały dotyczące kernela, LPE i CVE

{{#include ../../../banners/hacktricks-training.md}}

Te studia przypadków opisują różne prymitywy lokalnej eskalacji uprawnień. Przed zastosowaniem techniki sprawdź w każdym artykule, jakiego produktu lub kernela dotyczy problem, jaka jest konfiguracja i jakie są wymagania wstępne. Do szerszego rozpoznania hosta użyj [listy kontrolnej eskalacji uprawnień w systemie Linux](../linux-privilege-escalation-checklist.md).

W przypadku Dirty Pipe (CVE-2022-0847) w [oryginalnym opracowaniu](https://dirtypipe.cm4all.com/) wskazano poprawki dla upstreamowych wersji stabilnych: 5.10.102, 5.15.25 i 5.16.11. Wersja kernela z wcześniejszego, podatnego zakresu jest jedynie wskazówką do dalszej weryfikacji: dystrybucje mogą backportować poprawki, nadając im inne oznaczenia wersji, a plik docelowy musi być czytelny, aby można było użyć prymitywu zapisu do page cache. Nadpisanie czytelnego pliku wykonywalnego SUID to jedna z możliwych ścieżek uzyskania uprawnień, jeśli przejście set-ID nadal działa; modyfikacja `/etc/passwd`, a następnie uwierzytelnienie również może zależeć od lokalnego stosu PAM. Przed oceną możliwości wykorzystania sprawdź zainstalowany pakiet kernela dostawcy, działający kernel po ponownym uruchomieniu, uprawnienia do pliku docelowego, opcję montowania `nosuid` oraz `no_new_privs`. Podczas pasywnego rozpoznania nie wykonuj próby zapisu. Zobacz [status dla poszczególnych wydań Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Wykrywanie usługi VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): wykonanie kodu z podwyższonymi uprawnieniami poprzez wyszukiwanie ścieżek procesów niezaufanych źródeł.
- [Nadpisanie page cache przez AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ścieżka prowadząca do nadpisania page cache kernela.
- [TOCTOU w timerach CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): wyścig w obsłudze timerów.
- [Wyścig wyjścia ptrace w systemie Linux i kradzież deskryptora pliku przez `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): dostęp do deskryptora podczas wyścigu związanego z zakończeniem procesu.

## Powiązane studia przypadków dotyczące binary exploitation

Sekcja Binary Exploitation dokładniej omawia prymitywy exploitów, układ pamięci i omijanie zabezpieczeń dla tych celów w kernelu Linux:

- [Użycie po zwolnieniu SKB w AF_UNIX out-of-band](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): błąd gniazda rozwinięty w prymitywy odczytu i zapisu w kernelu.
- [Użycie po zwolnieniu Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): prymityw zapisu wskaźnika rozszerzony z użyciem buforów pipe i workqueue.
- [Zapis poza zakresem w strumieniach ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): eksploatacja sterty kernela i omijanie zabezpieczeń.
- [TOCTOU w timerach CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): ujęcie wyścigu timerów z perspektywy binary exploitation, również podsumowanego powyżej.
- [Obejście KASLR dla statycznej mapy liniowej Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ustalanie adresów na potrzeby eksploatacji kernela arm64.
- [Obejście uprawnień Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ścieżka przez GPU Androida umożliwiająca dostęp do pamięci kernela.
- [Użycie po zwolnieniu w wyniku limitu czasu zadania Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): błąd akceleratora Androida wykorzystany do zapisu w kernelu.
{{#include ../../../banners/hacktricks-training.md}}
