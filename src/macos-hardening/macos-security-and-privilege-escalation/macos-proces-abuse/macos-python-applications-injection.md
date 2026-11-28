# macOS Python aplikacija: ubrizgavanje

{{#include ../../../banners/hacktricks-training.md}}

## Preko promenljivih okruženja `PYTHONWARNINGS` i `BROWSER`

Ako napadač može da kontroliše okruženje Python procesa, kombinacija promenljivih `PYTHONWARNINGS` i `BROWSER` može da pokrene izvršavanje komandi kada Python uveze modul `antigravity` tokom obrade posebno oblikovane opcije upozorenja. Tehnika se oslanja na to da `antigravity` otvara URL pomoću Python modula `webbrowser`, koji uzima u obzir promenljivu okruženja `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Preko `PYTHONPATH` i `sitecustomize.py`

Tokom uobičajenog pokretanja, Python-ov modul `site` dodaje putanje specifične za lokaciju, a zatim pokušava da uveze modul pod nazivom `sitecustomize`. Ako napadač postavi direktorijum koji može da čita na prvo mesto u `PYTHONPATH`, napadač koji kontroliše okruženje procesa može da navede Python da uveze payload pre ciljne skripte. Zastavica `-S` isključuje automatsku inicijalizaciju modula `site`, dok izolovani režim (`-I`) zanemaruje `PYTHONPATH` i podrazumeva `-s` i `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Za persistence preko upisivog korisničkog site-a umesto nasleđenog `PYTHONPATH`, pogledajte [Python `.pth`, `.start` i `usercustomize` startup fajlove](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Preko `PYTHONINSPECT` i `PYTHONSTARTUP` nakon skripte

Na CPython 3.13+, skripta pokrenuta sa `PYTHONINSPECT=1` ulazi u interaktivnu sesiju kada se završi. Ako je standardni ulaz terminal i PyREPL je dostupan, ta sesija izvršava fajl naveden u `PYTHONSTARTUP` **nakon** ciljne skripte, a pre prompta. Napadač koji kontroliše obe nasleđene promenljive i čitljiv startup fajl zato može da pokrene kod u ciljnom procesu bez izmene njegove skripte. Ovo je okidač nakon izvršavanja skripte, a ne uobičajena startup kuka.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Lanac ne izvršava startup fajl u starijim verzijama CPython-a, kada standardni ulaz nije terminal ili kada `PYTHON_BASIC_REPL` forsira osnovni REPL. `-E` i `-I` zanemaruju promenljive `PYTHON*`. Proverite stvarni interpreter i kontekst terminala pre nego što se oslonite na ovaj put.<sup>[[3]](#references)[[5]](#references)</sup>

## Preko `PYTHONBREAKPOINT`

Od Python-a 3.7 (PEP 553), ugrađeni `breakpoint()` uvozi i poziva ono na šta pokazuje `sys.breakpointhook`, a cilj se određuje preko promenljive okruženja **`PYTHONBREAKPOINT`** (`package.module.callable`). I uvoz imenovanog modula i poziv funkcije izvršavaju se pre nego što bi se debugger inače pokrenuo, pa napadač koji kontroliše okruženje procesa koji stigne do `breakpoint()` (što je uobičajeno u skriptama za održavanje/debugovanje, a ponekad se zadrži i u produkcionim putanjama) dobija izvršavanje koda.<sup>[[4]](#references)</sup>

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

Za razliku od `PYTHONWARNINGS`/`PYTHONPATH`, ovo zahteva da cilj zaista dođe do poziva `breakpoint()`, ali radi i isključivo preko **sporednih efekata pri importovanju** imenovanog modula (usmerite ga na bilo koji modul koji se može importovati — na primer, modul postavljen prvi na `PYTHONPATH` — čiji se kod izvršava na najvišem nivou). Postavljanjem vrednosti `PYTHONBREAKPOINT=0` potpuno se isključuje ova kuka.



## References

- [1] [Hakovanje pomoću promenljivih okruženja - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Kuka za konfiguraciju specifičnu za lokaciju](https://docs.python.org/3/library/site.html)
- [3] [Python komandna linija i okruženje](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Ugrađeni breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython interpreter REPL usmeravanje (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL izvršavanje datoteke za pokretanje (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
