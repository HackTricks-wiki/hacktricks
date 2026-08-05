# Обходи Sandbox macOS Office

{{#include ../../../../../banners/hacktricks-training.md}}

### Обхід Word Sandbox через Launch Agents

Застосунок використовує **custom Sandbox** із entitlement **`com.apple.security.temporary-exception.sbpl`**, і цей custom sandbox дозволяє записувати файли будь-де, якщо ім'я файлу починається з `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Тому escaping був таким простим: потрібно було **записати `plist`** LaunchAgent у `~/Library/LaunchAgents/~$escape.plist`.

Перегляньте [**оригінальний звіт тут**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Обхід Word Sandbox через Login Items і zip

Пам'ятайте, що після першого escape Word може записувати довільні файли, імена яких починаються з `~$`, хоча після виправлення попередньої вразливості записувати в `/Library/Application Scripts` або `/Library/LaunchAgents` стало неможливо.

Було виявлено, що з sandbox можна створити **Login Item** (застосунки, які виконуються під час входу користувача в систему). Однак ці застосунки **не виконуватимуться, якщо** вони **не notarized**, а **додавати args неможливо** (тому не можна просто запустити reverse shell за допомогою **`bash`**).

Після попереднього Sandbox bypass Microsoft вимкнула можливість записувати файли в `~/Library/LaunchAgents`. Однак було виявлено, що якщо додати **zip-файл як Login Item**, `Archive Utility` просто **розпакує** його в поточному розташуванні. Оскільки за замовчуванням папка `LaunchAgents` у `~/Library` не створена, можна було **запакувати plist у `LaunchAgents/~$escape.plist`** і **розмістити** zip-файл у **`~/Library`**, щоб після розпакування він потрапив до потрібного persistence destination.

Перегляньте [**оригінальний звіт тут**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Обхід Word Sandbox через Login Items і .zshenv

(Пам'ятайте, що після першого escape Word може записувати довільні файли, імена яких починаються з `~$`).

Однак попередня техніка мала обмеження: якщо папка **`~/Library/LaunchAgents`** існувала, оскільки її створило інше програмне забезпечення, техніка не спрацьовувала. Тому для цього було виявлено інший ланцюжок Login Items.

Зловмисник міг створити файли **`.bash_profile`** і **`.zshenv`** із payload для виконання, потім запакувати їх і **записати zip у домашню папку користувача-жертви**: **`~/~$escape.zip`**.

Після цього zip-файл і застосунок **`Terminal`** додавалися до **Login Items**. Коли користувач повторно входив у систему, zip-файл розпаковувався в домашній папці користувача, перезаписуючи **`.bash_profile`** і **`.zshenv`**, унаслідок чого terminal виконував один із цих файлів (залежно від того, bash чи zsh використовується).

Перегляньте [**оригінальний звіт тут**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Обхід Word Sandbox за допомогою Open і env variables

Із sandboxed processes все ще можна викликати інші процеси за допомогою утиліти **`open`**. Крім того, ці процеси запускатимуться **у власному sandbox**.

Було виявлено, що утиліта open має опцію **`--env`** для запуску застосунку з **певними env** variables. Тому можна було створити файл **`.zshenv`** у папці **всередині** **sandbox**, а потім використати `open` з `--env`, встановивши змінну **`HOME`** у значення цієї папки та відкривши застосунок `Terminal`, який виконає файл `.zshenv` (з певної причини також потрібно було встановити змінну `__OSINSTALL_ENVIROMENT`).

Перегляньте [**оригінальний звіт тут**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Обхід Word Sandbox за допомогою Open і stdin

Утиліта **`open`** також підтримувала параметр **`--stdin`** (а після попереднього bypass використовувати `--env` стало неможливо).

Річ у тім, що хоча **`python`** був підписаний Apple, він **не виконуватиме** script із атрибутом **`quarantine`**. Однак можна було передати йому script через stdin, щоб він не перевіряв, чи має script атрибут quarantine:

1. Створіть файл **`~$exploit.py`** із довільними Python-командами.
2. Запустіть _open_ **`–stdin='~$exploit.py' -a Python`**, що запускає застосунок Python, використовуючи створений файл як його стандартний ввід. Python без проблем виконає наш код, і оскільки це дочірній процес _launchd_, на нього не поширюються правила Word sandbox.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
