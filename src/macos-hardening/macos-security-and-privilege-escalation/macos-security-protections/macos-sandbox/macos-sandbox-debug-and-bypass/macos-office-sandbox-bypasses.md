# Обходи Sandbox Office у macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Нижче наведено **історичні способи виходу з sandbox Microsoft Office для Mac**. Вони описують повторно використовувані помилки на межі довіри, але не слід вважати виправлені комбінації Office/macOS вразливими без відтворення точної версії та політики.

### Обхід sandbox Word через LaunchAgents

Уразлива програма використовувала спеціальне правило sandbox через `com.apple.security.temporary-exception.sbpl`. Воно дозволяло звичайні файли, базове ім'я яких починалося з `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Отже, для виходу з sandbox було достатньо **записати `plist`** LaunchAgent у `~/Library/LaunchAgents/~$escape.plist`.

Перегляньте [**оригінальний звіт тут**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Обхід sandbox Word через Login Items і zip

Пам'ятайте, що після першого виходу Word може записувати довільні файли, ім'я яких починається з `~$`, хоча після виправлення попередньої вразливості записувати файли в `/Library/Application Scripts` або в `/Library/LaunchAgents` було неможливо.

Уразливий sandbox дозволяв створити **Login Item**, який запускається під час входу користувача в систему. Продемонстрований спосіб вимагав прийнятної підписаної/нотариально завіреної програми та не дозволяв передавати довільні аргументи, тому додавання `bash` з reverse-shell аргументом було недостатнім.<sup>[[2]](#references)</sup>

У рамках попереднього обходу Sandbox Microsoft вимкнула можливість запису файлів у `~/Library/LaunchAgents`. Однак було виявлено, що якщо додати **zip-файл як Login Item**, `Archive Utility` просто **розпакує** його в поточному розташуванні. Оскільки за замовчуванням папка `LaunchAgents` у `~/Library` не створена, можна було **заархівувати plist у `LaunchAgents/~$escape.plist`** і **розмістити** zip-файл у **`~/Library`**, щоб після розпакування він потрапив до місця persistence.

Перегляньте [**оригінальний звіт тут**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Обхід sandbox Word через Login Items і .zshenv

(Пам'ятайте, що після першого виходу Word може записувати довільні файли, ім'я яких починається з `~$`.)

Однак попередня техніка мала обмеження: якщо папка **`~/Library/LaunchAgents`** існувала, оскільки її створило інше програмне забезпечення, вона не спрацьовувала. Тому для цього було розроблено інший ланцюжок через Login Items.

Зловмисник міг створити **`.bash_profile`** і **`.zshenv`** із payload, заархівувати їх і записати ZIP у домашній каталог **жертви** як **`~/~$escape.zip`**.

Потім ZIP-файл і **Terminal** додавалися як Login Items. Під час наступного входу Archive Utility розпаковує dotfiles у домашній каталог користувача, а shell Terminal обробляє відповідний startup-файл (`.bash_profile` для продемонстрованого шляху Bash або `.zshenv` для Zsh).<sup>[[3]](#references)</sup>

Перегляньте [**оригінальний звіт тут**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Обхід Sandbox Word через Open і змінні env

Процеси в sandbox усе ще могли запитувати запуск програм через **`open`**. Запущена програма працювала у власному контексті безпеки, а не успадковувала точний профіль sandbox Word.<sup>[[4]](#references)</sup>

Уразлива утиліта `open` мала опцію **`--env`** для передавання змінних середовища. Експлойт створював `.zshenv` усередині sandbox, встановлював `HOME` у цей каталог і запускав Terminal, щоб Zsh обробив цей файл. У наведеному ланцюжку також встановлювалася приватна змінна з помилкою в назві `__OSINSTALL_ENVIROMENT`; під час відтворення історичного PoC слід зберегти саме таке написання.<sup>[[4]](#references)</sup>

Перегляньте [**оригінальний звіт тут**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Обхід Sandbox Word через Open і stdin

Утиліта **`open`** також підтримувала параметр **`--stdin`** (а після попереднього обходу використовувати `--env` було вже неможливо).

Хоча Python application від Apple відхиляла файл скрипта з quarantine, уразливий workflow міг передати той самий скрипт через стандартний ввід, оминаючи перевірку quarantine на основі файлу:<sup>[[5]](#references)</sup>

1. Створіть файл **`~$exploit.py`** із довільними Python-командами.
2. Запустіть `open --stdin='~$exploit.py' -a Python`. Запущена Python application отримує переданий код через стандартний ввід і в уразливих версіях працює поза sandbox Word, оскільки LaunchServices створює її через `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Вихід із Sandbox – Microsoft Office у macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Драма Office у macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Вихід Office365 із Sandbox у MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Технічний аналіз CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Виявлення вразливості macOS App Sandbox escape: детальний аналіз CVE-2022-26706 – Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
