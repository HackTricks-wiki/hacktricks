# Podstawy Linuksa

{{#include ../../banners/hacktricks-training.md}}

To punkt wyjścia do oceny hosta z systemem Linux. Na kolejnych stronach omówiono szeroki proces eskalacji uprawnień, praktyczne polecenia, zmienne środowiskowe oraz typowe ograniczenia wpływające na to, co można uruchomić na hoście.

- [Eskalacja uprawnień w Linuksie](linux-privilege-escalation/README.md) omawia enumerację i potencjalne lokalne ścieżki eskalacji. Krótszą listę zadań znajdziesz na [liście kontrolnej eskalacji uprawnień](../main-system-information/linux-privilege-escalation-checklist.md).
- [Uruchamianie powłoki, aliasy i historia](shell-startup-aliases-and-history.md) wyjaśnia rozpoznawanie poleceń, wykonywanie plików startowych oraz wskazówki zawarte w historii.
- [Przydatne polecenia Linuksa](useful-linux-commands.md) zawiera polecenia do sprawdzania plików, procesów, usług i środowiska.
- [Zmienne środowiskowe Linuksa](linux-environment-variables.md) wyjaśnia, jak wartości środowiskowe wpływają na wykonywanie poleceń i gdzie mogą występować poufne wartości.
- [Omijanie ograniczeń Linuksa](bypass-linux-restrictions/README.md) omawia ograniczone powłoki i środowiska uruchomieniowe, w tym zabezpieczenia systemu plików, `noexec` oraz systemy distroless.

## Eksploatacja natywnych plików binarnych

Gdy ocena prowadzi do podatnego pliku wykonywalnego Linuksa, skorzystaj z odpowiednich materiałów w sekcji Binary Exploitation:

- [Format ELF i działanie loadera](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) oraz [zabezpieczenia plików binarnych i sposoby ich omijania](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) wyjaśniają układ pliku wykonywalnego i mechanizmy ograniczające ataki.
- [Eksploatacja stosu](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) i [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) omawiają ataki na przepływ sterowania.
- [Eksploatacja sterty libc](../../binary-exploitation/libc-heap/README.md) i [format strings](../../binary-exploitation/format-strings/README.md) omawiają inne typowe ścieżki wykorzystujące uszkodzenie pamięci.

Studia przypadków dotyczące jądra są dostępne w materiałach [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
