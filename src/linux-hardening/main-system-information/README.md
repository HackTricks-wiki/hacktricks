# Główne informacje o systemie

{{#include ../../banners/hacktricks-training.md}}

Przed wyborem lokalnej techniki eskalacji sprawdź kernel hosta, system plików, uprzywilejowane helpery i dostępne drogi ucieczki. [Lista kontrolna eskalacji uprawnień](linux-privilege-escalation-checklist.md) przedstawia zwięzłą kolejność działań.

- [Ocena podatności kernela i ekspozycja w czasie działania](kernel-vulnerability-assessment.md) sprawdza, czy kompilacja ma zastosowanie, czy podatność jest osiągalna i jakie zabezpieczenia są aktywne.
- [Moduły kernela i nadużywanie modprobe](kernel-modules-and-modprobe.md) omawia ładowanie modułów i ekspozycję ścieżek helperów.
- [Nadużywanie poleceń sudo](sudo-command-abuse.md) analizuje, w jaki sposób delegowane polecenia mogą przekraczać granice uprawnień.
- [Symlinki, hardlinki i deskryptory plików](filesystem-links-and-file-descriptors.md) omawia przekierowywanie ścieżek oraz odziedziczone lub usunięte, ale nadal otwarte pliki.
- [System plików, i-węzły i odzyskiwanie](filesystem-inodes-and-recovery.md) wyjaśnia działanie systemu plików przydatne podczas analizy.
- [Lista kontrolna: eskalacja uprawnień w Linuksie](linux-privilege-escalation-checklist.md) zawiera kontrole hosta i odnośniki do bardziej szczegółowych materiałów.
- [Ucieczka z jaili](escaping-from-limited-bash.md) omawia ograniczone powłoki i środowiska.
- [Materiały o kernelu/LPE/CVE](kernel-lpe-cves/README.md) grupują opracowania dotyczące lokalnej eskalacji uprawnień i podatności.
{{#include ../../banners/hacktricks-training.md}}
