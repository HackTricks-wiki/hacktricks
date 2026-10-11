# Podstawy Linuxa

{{#include ../../banners/hacktricks-training.md}}

To punkt wyjścia do oceny hostów Linux. Strony obejmują szeroki proces eskalacji uprawnień, praktyczne polecenia, zmienne środowiskowe oraz typowe ograniczenia wpływające na to, co można uruchomić na hoście.

- [Eskalacja uprawnień w Linuxie](linux-privilege-escalation/README.md) omawia enumerację i potencjalne lokalne ścieżki eskalacji. Krótszą listę zadań znajdziesz na [liście kontrolnej eskalacji uprawnień](../main-system-information/linux-privilege-escalation-checklist.md).
- [Uruchamianie powłoki, aliasy i historia](shell-startup-aliases-and-history.md) wyjaśnia rozpoznawanie poleceń, wykonywanie plików startowych oraz wskazówki zawarte w historii.
- [Przydatne polecenia Linuxa](useful-linux-commands.md) to zbiór poleceń do sprawdzania plików, procesów, usług i środowiska.
- [Zmienne środowiskowe Linuxa](linux-environment-variables.md) wyjaśnia, jak wartości środowiskowe wpływają na wykonywanie programów i gdzie mogą pojawić się poufne dane.
- [Omijanie ograniczeń Linuxa](bypass-linux-restrictions/README.md) omawia ograniczone powłoki i środowiska uruchomieniowe, w tym zabezpieczenia systemu plików, `noexec` oraz systemy distroless.

## Natywna eksploatacja binarna

Gdy ocena obejmuje podatny plik wykonywalny Linuxa, skorzystaj z odpowiednich materiałów w Binary Exploitation:

- [Format ELF i działanie loadera](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) oraz [zabezpieczenia binarne i ich omijanie](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) objaśniają strukturę pliku wykonywalnego i mechanizmy ograniczające.
- [Eksploatacja stosu](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) i [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) omawiają ataki na przepływ sterowania.
- [Eksploatacja sterty libc](../../binary-exploitation/libc-heap/README.md) i [ciągi formatujące](../../binary-exploitation/format-strings/README.md) omawiają inne typowe ścieżki wykorzystujące uszkodzenie pamięci.

Studia przypadków dotyczące jądra są dostępne w materiałach [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
