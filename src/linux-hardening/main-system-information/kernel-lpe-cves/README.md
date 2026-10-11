# Materiały dotyczące jądra, LPE i CVE

{{#include ../../../banners/hacktricks-training.md}}

Te studia przypadków opisują różne mechanizmy lokalnej eskalacji uprawnień. Przed zastosowaniem techniki sprawdź, jakiego produktu lub jądra dotyczy artykuł, a także konfigurację i wymagania wstępne. Do szerszego rozpoznania hosta użyj [listy kontrolnej eskalacji uprawnień w systemie Linux](../linux-privilege-escalation-checklist.md).

W przypadku Dirty Pipe (CVE-2022-0847) [oryginalne badania](https://dirtypipe.cm4all.com/) wskazują, że poprawki dla stabilnych wersji upstream pojawiły się w wersjach 5.10.102, 5.15.25 i 5.16.11. Wersja jądra mieszcząca się w starszym, podatnym zakresie jest jedynie wskazówką do dalszej weryfikacji: dystrybucje mogą backportować poprawki i udostępniać je pod innymi oznaczeniami wersji, a odpowiedni plik docelowy musi być czytelny, aby można było wykorzystać prymityw zapisu do page-cache. Nadpisanie czytelnego pliku wykonywalnego SUID to jedna z możliwych dróg uzyskania uprawnień, jeśli przejście set-ID nadal działa; modyfikacja `/etc/passwd`, a następnie uwierzytelnienie, również może zależeć od lokalnego stosu PAM. Przed oceną możliwości wykorzystania sprawdź zainstalowany pakiet jądra dostawcy, działające jądro po ponownym uruchomieniu, uprawnienia do pliku docelowego, opcję montowania `nosuid` oraz `no_new_privs`. Nie wykonuj próby zapisu podczas pasywnego rozpoznania. Zobacz [status dla poszczególnych wydań Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): uprzywilejowane wykonanie kodu z użyciem niezaufanego wyszukiwania ścieżki procesu.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ścieżka nadpisania page-cache w jądrze.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): wyścig w obsłudze timerów.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): dostęp do deskryptora podczas wyścigu związanego z zakończeniem procesu.

## Powiązane studia przypadków binary exploitation

Sekcja Binary Exploitation dokładniej omawia prymitywy exploitów, układ pamięci i omijanie mechanizmów ochronnych w przypadku tych celów w jądrze Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): błąd gniazda rozwinięty w prymitywy odczytu i zapisu w jądrze.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): prymityw zapisu wskaźnika rozszerzony z użyciem buforów pipe i workqueue.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): eksploatacja sterty jądra i omijanie mechanizmów ochronnych.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): omówienie wyścigu timerów z perspektywy binary exploitation, podsumowanego również powyżej.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ustalanie adresów na potrzeby eksploatacji jądra arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ścieżka wykorzystująca GPU w Androidzie do uzyskania dostępu do pamięci jądra.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): błąd akceleratora w Androidzie wykorzystany do zapisu w jądrze.
{{#include ../../../banners/hacktricks-training.md}}
