# Główne informacje o systemie

{{#include ../../banners/hacktricks-training.md}}

Przed wyborem techniki lokalnej eskalacji uprawnień sprawdź kernel hosta, system plików, uprzywilejowane helpery i dostępne ścieżki ucieczki. [Lista kontrolna eskalacji uprawnień](linux-privilege-escalation-checklist.md) zawiera zwięzłą kolejność działań.

- [Ocena podatności kernela i ekspozycja w czasie działania](kernel-vulnerability-assessment.md) obejmuje sprawdzanie zastosowania do danej kompilacji, osiągalności i aktywnych mechanizmów ochrony.
- [Moduły kernela i nadużywanie modprobe](kernel-modules-and-modprobe.md) omawia ładowanie modułów i ekspozycję ścieżki helpera.
- [Nadużywanie poleceń sudo](sudo-command-abuse.md) analizuje sposoby, w jakie delegowane polecenia mogą przekraczać granice uprawnień.
- [Symlinki, hardlinki i deskryptory plików](filesystem-links-and-file-descriptors.md) omawia przekierowywanie ścieżek oraz odziedziczone lub usunięte, ale nadal otwarte pliki.
- [System plików, i-węzły i odzyskiwanie danych](filesystem-inodes-and-recovery.md) wyjaśnia zachowanie systemu plików przydatne podczas analizy.
- [Lista kontrolna: eskalacja uprawnień w Linuksie](linux-privilege-escalation-checklist.md) zawiera kontrole hosta i odsyłacze do bardziej szczegółowych materiałów.
- [Ucieczka z jaili](escaping-from-limited-bash.md) omawia ograniczone powłoki i środowiska.
- [Materiały dotyczące kernela/LPE/CVE](kernel-lpe-cves/README.md) grupują opracowania poświęcone lokalnej eskalacji uprawnień i podatnościom.
{{#include ../../banners/hacktricks-training.md}}
