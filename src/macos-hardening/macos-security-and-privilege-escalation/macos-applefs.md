# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** to nowoczesny system plików zaprojektowany jako następca Hierarchical File System Plus (HFS+). Jego rozwój wynikał z potrzeby zapewnienia **lepszej wydajności, bezpieczeństwa i efektywności**.

Najważniejsze funkcje APFS obejmują:<sup>[[1]](#references)</sup>

1. **Space Sharing**: APFS umożliwia wielu woluminom **współdzielenie tej samej bazowej wolnej przestrzeni dyskowej** na jednym urządzeniu fizycznym. Pozwala to na efektywniejsze wykorzystanie miejsca, ponieważ woluminy mogą dynamicznie zwiększać i zmniejszać swój rozmiar bez konieczności ręcznej zmiany rozmiaru lub ponownego partycjonowania.
1. Oznacza to, że w porównaniu z tradycyjnymi partycjami na dyskach plikowych **różne partycje (woluminy) w APFS współdzielą całą przestrzeń dyskową**, podczas gdy zwykła partycja zazwyczaj miała stały rozmiar.
2. **Snapshots**: APFS obsługuje **tworzenie snapshots**, czyli **tylko do odczytu** instancji systemu plików reprezentujących konkretny punkt w czasie. Snapshots umożliwiają wydajne tworzenie kopii zapasowych i łatwe przywracanie systemu, ponieważ zajmują minimalną dodatkową przestrzeń i mogą być szybko tworzone lub przywracane.
3. **Clones**: APFS może **tworzyć clones plików lub katalogów, które współdzielą tę samą przestrzeń dyskową** co oryginał, dopóki clone lub oryginalny plik nie zostanie zmodyfikowany. Funkcja ta zapewnia wydajny sposób tworzenia kopii plików lub katalogów bez duplikowania zajmowanej przestrzeni.
4. **Encryption**: APFS **natywnie obsługuje szyfrowanie całego dysku**, a także szyfrowanie poszczególnych plików i katalogów, zwiększając bezpieczeństwo danych w różnych zastosowaniach.
5. **Crash Protection**: APFS wykorzystuje **schemat metadanych copy-on-write, który zapewnia spójność systemu plików** nawet w przypadku nagłej utraty zasilania lub awarii systemu, zmniejszając ryzyko uszkodzenia danych.

Ogólnie APFS zapewnia bardziej nowoczesny, elastyczny i wydajny system plików dla urządzeń Apple, koncentrując się na zwiększonej wydajności, niezawodności i bezpieczeństwie.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Wolumin `Data` jest zamontowany w **`/System/Volumes/Data`** (możesz to sprawdzić za pomocą `diskutil apfs list`).

Listę firmlinks można znaleźć w pliku **`/usr/share/firmlinks`**.
```bash

```
## Referencje

- [1] [Przewodnik APFS - Funkcje - Dokumentacja Apple dla deweloperów](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
