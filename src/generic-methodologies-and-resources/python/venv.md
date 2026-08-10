# venv

Стандартний модуль Python `venv` створює віртуальні середовища, POSIX-скрипт активації яких — `<venv>/bin/activate`; введіть `deactivate`, щоб вийти з активного середовища.<sup>[[1]](#references)</sup> В Ubuntu пакет `python3-venv` надає цей модуль, якщо його не встановлено разом із базовим пакетом Python.<sup>[[2]](#references)</sup>
```bash
sudo apt-get install python3-venv
#Now, go to the folder you want to create the virtual environment
python3 -m venv <Dirname>
python3 -m venv pvenv #In this case the folder "pvenv" is going to be created
source <Dirname>/bin/activate
source pvenv/bin/activate #Activate the environment
#You can now install whatever python library you need
deactivate #To deactivate the virtual environment
```
Для старіших робочих процесів на основі setuptools із `setup.py bdist_wheel` встановлення `wheel` в активному середовищі надавало команду `bdist_wheel`.<sup>[[3]](#references)</sup> Поточні версії setuptools більше не потребують `wheel` для цієї команди, а сучасні рекомендації щодо packaging радять використовувати `python -m build --wheel`, а не викликати `setup.py` безпосередньо.<sup>[[4]](#references)[[5]](#references)</sup>
```text
error: invalid command 'bdist_wheel'
```

```bash
# Legacy workaround for older setuptools-based projects:
python3 -m pip install wheel

# Current build workflow:
python3 -m pip install build
python3 -m build --wheel
```
## References

- [1] [venv — Створення віртуальних середовищ — документація Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Пакунок: python3-venv — Пакунки Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Чи застарів setup.py? — Посібник користувача з пакування Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
