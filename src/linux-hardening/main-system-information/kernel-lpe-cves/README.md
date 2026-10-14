# Materiały dotyczące kernela, LPE i CVE

{{#include ../../../banners/hacktricks-training.md}}

Te studia przypadków przedstawiają różne mechanizmy lokalnego podniesienia uprawnień. Przed zastosowaniem techniki sprawdź w każdym artykule, jakiego produktu lub kernela dotyczy, jaka konfiguracja jest wymagana i jakie są warunki wstępne. Aby przeprowadzić szersze rozpoznanie hosta, skorzystaj z [listy kontrolnej podnoszenia uprawnień w systemie Linux](../linux-privilege-escalation-checklist.md).

W przypadku Dirty Pipe (CVE-2022-0847) w [oryginalnym opracowaniu](https://dirtypipe.cm4all.com/) wskazano poprawki w stabilnych wersjach upstream: 5.10.102, 5.15.25 i 5.16.11. Wersja kernela należąca do starszego zakresu podatnych wersji to jedynie wskazówka do dalszej weryfikacji: kernele dystrybucji mogą zawierać poprawki przeniesione wstecz i używać innych nazw wydań, a plik docelowy musi być możliwy do odczytu, aby zadziałał mechanizm zapisu do page cache. Nadpisanie czytelnego pliku wykonywalnego SUID to jedna z możliwych dróg uzyskania uprawnień, jeśli przejście z użyciem set-ID nadal działa; modyfikacja `/etc/passwd`, a następnie uwierzytelnienie, również może zależeć od lokalnego stosu PAM. Przed oceną możliwości wykorzystania sprawdź zainstalowany pakiet kernela dostawcy, działający kernel po ponownym uruchomieniu, uprawnienia do pliku docelowego, opcję montowania `nosuid` oraz `no_new_privs`. Podczas pasywnego rozpoznania nie wykonuj prób zapisu. Zobacz [status dla poszczególnych wydań Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Wykrywanie usługi VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): uprzywilejowane wykonanie kodu przez wyszukiwanie ścieżki procesu w niezaufanych lokalizacjach.
- [Nadpisanie page cache przez splice w AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ścieżka prowadząca do nadpisania page cache kernela.
- [Wyścig TOCTOU timerów CPU POSIX i jego wykorzystanie, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): wygaśnięcie/usunięcie timera podczas kończenia zadania, w tym wymagania dotyczące ścieżki IRQ i badania nad exploitem.
- [Wyścig przy kończeniu procesu w Linux ptrace i kradzież deskryptora pliku przez `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): dostęp do deskryptora podczas wyścigu przy kończeniu procesu.

## Powiązane studia przypadków z zakresu binary exploitation

Sekcja Binary Exploitation dokładniej omawia mechanizmy exploitów, układ pamięci i omijanie zabezpieczeń dla tych celów w kernelu Linux:

- [Use-after-free SKB poza pasmem w AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): błąd gniazda rozwinięty w mechanizmy odczytu i zapisu w kernelu.
- [Przepełnienie scatterlist przy równoczesnym zapisie w AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): wyścig zapisujących skcipher wykorzystany do zapisu w kernelu.
- [Use-after-free Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): mechanizm zapisu wskaźnika rozszerzony o bufory pipe i workqueue.
- [Zapis poza granicami w strumieniach ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): wykorzystanie sterty kernela i omijanie zabezpieczeń.
- [Obejście KASLR dla statycznej mapy liniowej Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): wykrywanie adresów na potrzeby exploitów kernela arm64.
- [Obejście uprawnień GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ścieżka przez GPU Androida prowadząca do dostępu do pamięci kernela.
- [Use-after-free przy przekroczeniu limitu czasu zadania Bigwave w Pixelu](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): błąd akceleratora Androida wykorzystany do zapisu w kernelu.
{{#include ../../../banners/hacktricks-training.md}}
