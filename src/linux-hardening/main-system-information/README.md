# Główne informacje o systemie

{{#include ../../banners/hacktricks-training.md}}

Przed wyborem techniki lokalnej eskalacji uprawnień sprawdź kernel hosta, system plików, uprzywilejowane helpery i dostępne ścieżki ucieczki. [Lista kontrolna eskalacji uprawnień](linux-privilege-escalation-checklist.md) zawiera zwięzłą kolejność działań.

- [Ocena podatności kernela i ekspozycja w czasie działania](kernel-vulnerability-assessment.md) sprawdza zastosowanie podatności do danej kompilacji, osiągalność i aktywne zabezpieczenia.
- [Moduły kernela i nadużycia modprobe](kernel-modules-and-modprobe.md) omawia ładowanie modułów i ekspozycję ścieżek helperów.
- [Nadużycia poleceń sudo](sudo-command-abuse.md) omawia sposoby, w jakie delegowane polecenia mogą przekraczać granice uprawnień.
- [Symlinki, hardlinki i deskryptory plików](filesystem-links-and-file-descriptors.md) omawia przekierowywanie ścieżek oraz odziedziczone lub usunięte, ale otwarte pliki.
- [System plików, inody i odzyskiwanie](filesystem-inodes-and-recovery.md) wyjaśnia zachowanie systemu plików przydatne podczas analizy.
- [Lista kontrolna: eskalacja uprawnień w Linuxie](linux-privilege-escalation-checklist.md) zawiera kontrole hosta i odnośniki do bardziej szczegółowych materiałów.
- [Ucieczka z jaili](escaping-from-limited-bash.md) omawia ograniczone powłoki i restrykcyjne środowiska.
- [Materiały dotyczące kernela/LPE/CVE](kernel-lpe-cves/README.md) grupują szczegółowe opracowania lokalnej eskalacji uprawnień i podatności.
{{#include ../../banners/hacktricks-training.md}}
