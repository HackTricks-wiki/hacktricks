# Обхід Sandbox Office у macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Обхід Sandbox Word через Launch Agents

Застосунок використовує **custom Sandbox** за допомогою entitlement **`com.apple.security.temporary-exception.sbpl`**, і цей custom sandbox дозволяє записувати файли будь-де, якщо ім'я файлу починається з `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Тому escape був таким простим, як **запис `plist`** LaunchAgent у `~/Library/LaunchAgents/~$escape.plist`.

Перегляньте [**оригінальний звіт тут**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Обхід Sandbox Word через Login Items і zip

Пам'ятайте, що після першого escape Word може записувати довільні файли, імена яких починаються з `~$`, хоча після виправлення попередньої вразливості записувати у `/Library/Application Scripts` або `/Library/LaunchAgents` стало неможливо.

Було виявлено, що із sandbox можна створити **Login Item** (застосунки, які виконуються під час входу користувача в систему). Однак ці застосунки **не виконуються, якщо** вони **не notarized**, а також **неможливо додати аргументи** (тому не можна просто запустити reverse shell за допомогою **`bash`**).

Після попереднього Sandbox bypass Microsoft вимкнула можливість запису файлів у `~/Library/LaunchAgents`. Однак було виявлено, що якщо додати **zip-файл як Login Item**, `Archive Utility` просто **розпакує** його у поточному розташуванні. Оскільки за замовчуванням папка `LaunchAgents` у `~/Library` не створена, можна було **заархівувати plist у `LaunchAgents/~$escape.plist`** і **розмістити** zip-файл у **`~/Library`**, щоб після розпакування він потрапив у потрібне місце persistence.

Перегляньте [**оригінальний звіт тут**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Обхід Sandbox Word через Login Items і .zshenv

(Пам'ятайте, що після першого escape Word може записувати довільні файли, імена яких починаються з `~$`.)

Однак попередня техніка мала обмеження: якщо папка **`~/Library/LaunchAgents`** уже існує, оскільки її створив інший software, вона не спрацює. Тому для цього було знайдено інший ланцюжок Login Items.

Атакер міг створити файли **`.bash_profile`** і **`.zshenv`** з payload для виконання, потім заархівувати їх і **записати zip-файл у папку користувача-жертви**: **`~/~$escape.zip`**.

Потім zip-файл і застосунок **`Terminal`** додавалися до **Login Items**. Коли користувач знову входив у систему, zip-файл розпаковувався у домашній папці користувача, перезаписуючи **`.bash_profile`** і **`.zshenv`**; у результаті Terminal виконував один із цих файлів (залежно від того, чи використовувався bash, чи zsh).

Перегляньте [**оригінальний звіт тут**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Обхід Sandbox Word за допомогою Open і env-змінних

Із sandboxed processes усе ще можна викликати інші processes за допомогою utility **`open`**. Крім того, ці processes виконуватимуться **у власному sandbox**.

Було виявлено, що utility open має опцію **`--env`** для запуску app із **specific env**-змінними. Тому можна було створити файл **`.zshenv`** у папці **всередині** **sandbox**, а потім використати `open` з `--env`, встановивши змінну **`HOME`** на цю папку та відкривши app **`Terminal`**, який виконає файл `.zshenv` (чомусь також було потрібно встановити змінну `__OSINSTALL_ENVIROMENT`).

Перегляньте [**оригінальний звіт тут**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Обхід Sandbox Word за допомогою Open і stdin

Utility **`open`** також підтримувала параметр **`--stdin`** (а після попереднього bypass використовувати `--env` стало неможливо).

Проблема в тому, що навіть якщо **`python`** був підписаний Apple, він **не виконуватиме** script з атрибутом **`quarantine`**. Однак можна було передати йому script через stdin, тому він не перевіряв, чи має script атрибут quarantine:

1. Створити файл **`~$exploit.py`** з довільними Python-командами.
2. Запустити _open_ **`–stdin='~$exploit.py' -a Python`**, що запускає Python app, використовуючи створений файл як його стандартний ввід. Python без проблем виконує наш code, і оскільки це дочірній process **`launchd`**, він не підпорядковується правилам sandbox Word.<sup>[[5]](#references)</sup>

## References

- [1] [Escape із Sandbox – Microsoft Office у macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama у macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Escape Sandbox Office365 у MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Виявлення вразливості macOS App Sandbox escape: детальний аналіз CVE-2022-26706 – Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
