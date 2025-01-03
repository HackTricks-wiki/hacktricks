# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** to nowoczesny system plików zaprojektowany w celu zastąpienia Hierarchical File System Plus (HFS+). Jego rozwój był napędzany potrzebą **ulepszonej wydajności, bezpieczeństwa i efektywności**.

Niektóre godne uwagi cechy APFS to:

1. **Współdzielenie przestrzeni**: APFS pozwala wielu woluminom na **współdzielenie tej samej podstawowej wolnej pamięci** na jednym fizycznym urządzeniu. Umożliwia to bardziej efektywne wykorzystanie przestrzeni, ponieważ woluminy mogą dynamicznie rosnąć i kurczyć się bez potrzeby ręcznego zmieniania rozmiaru lub ponownego partycjonowania.
1. Oznacza to, w porównaniu do tradycyjnych partycji na dyskach plikowych, **że w APFS różne partycje (woluminy) dzielą całą przestrzeń dyskową**, podczas gdy zwykła partycja miała zazwyczaj stały rozmiar.
2. **Migawki**: APFS obsługuje **tworzenie migawek**, które są **tylko do odczytu**, punktowymi instancjami systemu plików. Migawki umożliwiają efektywne tworzenie kopii zapasowych i łatwe przywracanie systemu, ponieważ zużywają minimalną dodatkową pamięć i mogą być szybko tworzone lub przywracane.
3. **Klonowanie**: APFS może **tworzyć klony plików lub katalogów, które dzielą tę samą pamięć** co oryginał, aż do momentu, gdy klon lub oryginalny plik zostanie zmodyfikowany. Ta funkcja zapewnia efektywny sposób tworzenia kopii plików lub katalogów bez duplikowania przestrzeni pamięci.
4. **Szyfrowanie**: APFS **natywnie obsługuje szyfrowanie całego dysku** oraz szyfrowanie na poziomie pliku i katalogu, co zwiększa bezpieczeństwo danych w różnych zastosowaniach.
5. **Ochrona przed awarią**: APFS wykorzystuje **schemat metadanych copy-on-write, który zapewnia spójność systemu plików** nawet w przypadku nagłej utraty zasilania lub awarii systemu, zmniejszając ryzyko uszkodzenia danych.

Ogólnie rzecz biorąc, APFS oferuje nowocześniejszy, elastyczny i wydajny system plików dla urządzeń Apple, z naciskiem na poprawę wydajności, niezawodności i bezpieczeństwa.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Wolumin `Data` jest zamontowany w **`/System/Volumes/Data`** (możesz to sprawdzić za pomocą `diskutil apfs list`).

Lista firmlinków znajduje się w pliku **`/usr/share/firmlinks`**.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
