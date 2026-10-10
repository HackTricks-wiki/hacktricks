# Materiały dotyczące kernela, LPE i CVE

{{#include ../../../banners/hacktricks-training.md}}

Te studia przypadków dotyczą różnych mechanizmów lokalnego podnoszenia uprawnień. Zanim zastosujesz daną technikę, sprawdź w artykule, jakiego produktu lub kernela dotyczy, jaka konfiguracja jest wymagana i jakie są warunki wstępne. Szersze rozpoznanie hosta umożliwia [lista kontrolna podnoszenia uprawnień w systemie Linux](../linux-privilege-escalation-checklist.md).

W przypadku Dirty Pipe (CVE-2022-0847) w [oryginalnym opracowaniu](https://dirtypipe.cm4all.com/) wskazano poprawki w upstreamowych wydaniach stabilnych: 5.10.102, 5.15.25 i 5.16.11. Wersja kernela należąca do starszego, podatnego zakresu to jedynie wskazówka do dalszej weryfikacji: dystrybucje mogą przenosić poprawki do swoich kerneli pod innymi nazwami wydań, a odpowiedni plik docelowy musi być czytelny, aby można było użyć mechanizmu zapisu do page-cache. Nadpisanie czytelnego pliku wykonywalnego SUID to jedna z możliwych dróg uzyskania uprawnień, jeśli przejście na identyfikator set-ID nadal działa; modyfikacja `/etc/passwd`, a następnie uwierzytelnienie może też zależeć od lokalnego stosu PAM. Przed oceną, czy atak jest możliwy, sprawdź zainstalowany pakiet kernela od dostawcy, kernel uruchomiony po restarcie, uprawnienia do pliku docelowego, opcję montowania `nosuid` oraz `no_new_privs`. Podczas pasywnego rozpoznania nie wykonuj testu zapisu. Zobacz [status dla poszczególnych wydań Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): wykonanie z podwyższonymi uprawnieniami wskutek odnajdywania ścieżek procesów w niezaufany sposób.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): mechanizm nadpisania page-cache kernela.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): wyścig podczas obsługi timerów.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): dostęp do deskryptora podczas wyścigu z zakończeniem procesu.

## Powiązane studia przypadków z zakresu Binary Exploitation

Sekcja Binary Exploitation szczegółowo omawia prymitywy exploita, układ pamięci i obejścia mechanizmów ochronnych w tych celach opartych na kernelu Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): błąd gniazda przekształcony w prymitywy odczytu i zapisu w kernelu.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): prymityw zapisu wskaźnika rozszerzony o bufory potoków i kolejki zadań.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): wykorzystanie sterty kernela i obejścia mechanizmów ochronnych.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): omówienie wyścigu timerów z perspektywy Binary Exploitation, podsumowanego również powyżej.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ustalanie adresów na potrzeby exploitacji kernela arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ścieżka wykorzystująca GPU w Androidzie do uzyskania dostępu do pamięci kernela.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): błąd akceleratora w Androidzie wykorzystany do zapisu w kernelu.
{{#include ../../../banners/hacktricks-training.md}}
