# Materiały dotyczące kernela, LPE i CVE

{{#include ../../../banners/hacktricks-training.md}}

Te analizy przypadków obejmują różne prymitywy lokalnej eskalacji uprawnień. Przed zastosowaniem techniki sprawdź w każdym artykule, jaki produkt lub kernel jest podatny oraz jakie są wymagane konfiguracja i warunki wstępne. Aby przeprowadzić szerszą enumerację hosta, skorzystaj z [listy kontrolnej eskalacji uprawnień w systemie Linux](../linux-privilege-escalation-checklist.md).

W przypadku Dirty Pipe (CVE-2022-0847) w [oryginalnym opracowaniu](https://dirtypipe.cm4all.com/) wskazano, że poprawki dla upstream stable wprowadzono w wersjach 5.10.102, 5.15.25 i 5.16.11. Wersja kernela należąca do starszego, podatnego zakresu to jedynie wskazówka wymagająca sprawdzenia: dystrybucje mogą backportować poprawki, nadając im inne oznaczenia wydań, a plik docelowy musi być czytelny, aby można było użyć prymitywu zapisu do page-cache. Nadpisanie czytelnego pliku wykonywalnego SUID to jedna z możliwych dróg uzyskania uprawnień, jeśli przejście set-ID nadal działa; modyfikacja `/etc/passwd`, a następnie uwierzytelnienie, również może zależeć od lokalnego stosu PAM. Przed oceną możliwości wykorzystania sprawdź zainstalowany pakiet kernela dostawcy, kernel uruchomiony po restarcie, uprawnienia do pliku docelowego, opcję montowania `nosuid` oraz `no_new_privs`. Nie wykonuj próby zapisu podczas pasywnej enumeracji. Zobacz [stan dla poszczególnych wydań Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Wykrywanie usługi VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): wykonanie z uprawnieniami uprzywilejowanymi przez wyszukiwanie ścieżek procesów niezaufanego pochodzenia.
- [Nadpisanie page-cache przez AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ścieżka nadpisania page-cache kernela.
- [TOCTOU w timerach CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): wyścig w obsłudze timerów.
- [Wyścig ptrace podczas kończenia procesu w systemie Linux i kradzież deskryptora pliku przez `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): dostęp do deskryptora podczas wyścigu związanego z kończeniem procesu.

## Powiązane analizy przypadków Binary Exploitation

Sekcja Binary Exploitation dokładniej omawia prymitywy exploita, układ pamięci i obchodzenie zabezpieczeń w przypadku tych celów opartych na kernelu Linux:

- [Use-after-free SKB dla danych poza pasmem AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): błąd gniazda wykorzystany do uzyskania prymitywów odczytu i zapisu w kernelu.
- [Use-after-free Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): prymityw zapisu wskaźnika rozszerzony za pomocą buforów potoków i workqueue.
- [Zapis poza zakresem w strumieniach ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): wykorzystanie sterty kernela i obchodzenie zabezpieczeń.
- [TOCTOU w timerach CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): omówienie wyścigu w timerach z perspektywy Binary Exploitation, podsumowanego również powyżej.
- [Obejście KASLR dla statycznej mapy liniowej Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ustalanie adresów na potrzeby exploitacji kernela arm64.
- [Obejście uprawnień GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ścieżka przez GPU Androida umożliwiająca dostęp do pamięci kernela.
- [Use-after-free po przekroczeniu limitu czasu zadania Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): błąd akceleratora Androida wykorzystany do zapisu w kernelu.
{{#include ../../../banners/hacktricks-training.md}}
