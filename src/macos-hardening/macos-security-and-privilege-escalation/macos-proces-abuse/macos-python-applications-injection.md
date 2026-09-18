# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via die `PYTHONWARNINGS`- en `BROWSER`-omgewingsveranderlikes

As 'n aanvaller 'n Python-proses se omgewing kan beheer, kan die kombinasie van `PYTHONWARNINGS` en `BROWSER` command execution aktiveer wanneer Python die `antigravity`-module invoer terwyl 'n vervaardigde warning option verwerk word. Die tegniek maak staat daarop dat `antigravity` 'n URL met Python se `webbrowser`-module oopmaak, wat die `BROWSER`-omgewingsveranderlike respekteer.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Via `PYTHONPATH` en `sitecustomize.py`

Tydens normale opstart voeg Python se `site`-module werfspesifieke paaie by en probeer daarna om ’n module genaamd `sitecustomize` in te voer. Deur ’n deur die aanvaller leesbare gids eerste op `PYTHONPATH` te plaas, kan ’n aanvaller wat die prosesomgewing beheer, Python ’n payload laat invoer voordat die teikenskrip uitgevoer word. Die `-S`-vlag deaktiveer outomatiese `site`-inisialisering, terwyl geïsoleerde modus (`-I`) `PYTHONPATH` ignoreer en `-s` en `-E` impliseer.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Via `PYTHONBREAKPOINT`

Sedert Python 3.7 (PEP 553) importeer en roep die ingeboude `breakpoint()` aan wat ook al deur `sys.breakpointhook` aangedui word, en daardie teiken word uit die **`PYTHONBREAKPOINT`**-omgewingsveranderlike (`package.module.callable`) geneem. Die importering van die benoemde module en die aanroep van die callable vind albei plaas voordat die debugger normaalweg sou verskyn, dus kry ’n aanvaller wat beheer oor die omgewing van ’n proses het wat ’n `breakpoint()` bereik (algemeen in instandhoudings-/debug-skripte, en soms in produksiepaaie agtergelaat) code execution.<sup>[[4]](#references)</sup>
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
Anders as `PYTHONWARNINGS`/`PYTHONPATH` vereis dit dat die teiken werklik ’n `breakpoint()`-aanroep bereik, maar dit werk ook suiwer deur die **import side effects** van die benoemde module (wys dit na enige module wat ingevoer kan word — byvoorbeeld een wat eerste op `PYTHONPATH` geplaas is — waarvan die topvlak kode uitvoer). Deur `PYTHONBREAKPOINT=0` te stel, word die hook heeltemal gedeaktiveer.

## References

- [1] [Hacking met Omgewingsveranderlikes - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Werf-spesifieke konfigurasie-hook](https://docs.python.org/3/library/site.html)
- [3] [Python-opdragreël en omgewing](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Ingeboude breakpoint() en PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
