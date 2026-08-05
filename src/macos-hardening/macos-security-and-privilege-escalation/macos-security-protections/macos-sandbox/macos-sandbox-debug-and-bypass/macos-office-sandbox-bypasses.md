# Обходи Word Sandbox у macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Обхід Word Sandbox через Launch Agents

Застосунок використовує **custom Sandbox** за допомогою entitlement **`com.apple.security.temporary-exception.sbpl`**, і цей custom sandbox дозволяє записувати файли будь-де, якщо ім'я файлу починається з `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Тому escape був таким простим, як **запис `plist`** LaunchAgent у `~/Library/LaunchAgents/~$escape.plist`.

Перегляньте [**оригінальний звіт тут**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Обхід Word Sandbox через Login Items і zip

Пам'ятайте, що після першого escape Word може записувати довільні файли, імена яких починаються з `~$`, хоча після patch попередньої vuln більше не можна було записувати до `/Library/Application Scripts` або `/Library/LaunchAgents`.

Було виявлено, що з sandbox можна створити **Login Item** (застосунки, які виконуються під час входу користувача). Однак ці застосунки **не виконуватимуться, якщо** вони **не notarized**, і **додавати args неможливо** (тому не можна просто запустити reverse shell за допомогою **`bash`**).

Після попереднього Sandbox bypass Microsoft вимкнула можливість запису файлів у `~/Library/LaunchAgents`. Однак було виявлено, що якщо додати **zip-файл як Login Item**, `Archive Utility` просто **розпакує** його в поточне розташування. Оскільки за замовчуванням папка `LaunchAgents` у `~/Library` не створена, можна було **запакувати plist у `LaunchAgents/~$escape.plist`** і **розмістити** zip-файл у **`~/Library`**, щоб після розпакування він потрапив до місця persistence.

Перегляньте [**оригінальний звіт тут**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Обхід Word Sandbox через Login Items і .zshenv

(Пам'ятайте, що після першого escape Word може записувати довільні файли, імена яких починаються з `~$`.)

Однак попередня техніка мала обмеження: якщо папка **`~/Library/LaunchAgents`** існує, оскільки її створив інший software, техніка не спрацює. Тому для цього було виявлено інший ланцюжок Login Items.

Атакер міг створити файли **`.bash_profile`** і **`.zshenv`** із payload для виконання, потім запакувати їх і **записати zip у папку користувача-жертви**: **`~/~$escape.zip`**.

Після цього zip-файл і застосунок **`Terminal`** додавалися до **Login Items**. Коли користувач повторно ввійде в систему, zip-файл буде розпаковано в папці користувача, перезаписавши **`.bash_profile`** і **`.zshenv`**, після чого terminal виконає один із цих файлів (залежно від того, bash чи zsh використовується).

Перегляньте [**оригінальний звіт тут**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Обхід Word Sandbox через Open і env variables

Із sandboxed processes усе ще можна викликати інші processes за допомогою utility **`open`**. Крім того, ці processes виконуватимуться **у власному sandbox**.

Було виявлено, що utility open має опцію **`--env`** для запуску застосунку з **певними env** variables. Тому можна було створити **файл `.zshenv`** у папці **всередині** **sandbox**, а потім використати `open` з `--env`, встановивши variable **`HOME`** на цю папку та відкривши застосунок `Terminal`, який виконає файл `.zshenv` (з певної причини також потрібно було встановити variable `__OSINSTALL_ENVIROMENT`).

Перегляньте [**оригінальний звіт тут**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Обхід Word Sandbox через Open і stdin

Utility **`open`** також підтримував параметр **`--stdin`** (а після попереднього bypass використовувати `--env` стало неможливо).

Проблема полягає в тому, що навіть якщо **`python`** був підписаний Apple, він **не виконуватиме** script з атрибутом **`quarantine`**. Однак можна було передати йому script через stdin, щоб він не перевіряв, чи має файл атрибут quarantine:

1. Створіть файл **`~$exploit.py`** із довільними Python commands.
2. Запустіть _open_ **`–stdin='~$exploit.py' -a Python`**, що запускає застосунок Python, використовуючи наш створений файл як standard input. Python без проблем виконає наш code, і оскільки це child process **`launchd`**, на нього не поширюються правила Word sandbox.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
