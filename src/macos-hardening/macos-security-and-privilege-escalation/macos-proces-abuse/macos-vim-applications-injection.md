# Vim/Neovim Applications Injection in macOS

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Il linguaggio di scripting proprietario di Vim (Vimscript) può eseguire **comandi Ex arbitrari e comandi shell all'avvio** dalle variabili d'ambiente. Se un processo con privilegi maggiori (un workflow di manutenzione/root, un `sudo vim …`, un editor avviato da un altro strumento, `crontab -e`, `visudo`, `git`/`less` che invocano un editor, …) avvia Vim/Neovim con un ambiente controllato dall'attaccante, quest'ultimo ottiene l'esecuzione di codice in quel contesto.

## `VIMINIT`

Durante l'inizializzazione Vim legge ed esegue i comandi Ex presenti in **`VIMINIT`**. I comandi Ex includono `:!cmd` (esegue un comando shell) e `:call system(...)`, quindi una singola variabile consente l'esecuzione arbitraria prima che venga modificato qualsiasi file.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
Il comando `:qa!` fornito tramite stdin chiude semplicemente l'editor dopo che il payload è già stato eseguito; in uno scenario reale la vittima apre semplicemente Vim normalmente.

## `EXINIT`

Se `VIMINIT` non è impostata, Vim (e i binari compatibili `vi`/`ex`) utilizza **`EXINIT`** come fallback, eseguito nello stesso modo. È la variante dell'era vi dello stesso primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Note e limitazioni

- **Neovim** supporta anche `VIMINIT` (viene controllata prima del file `init.vim`/`init.lua` dell'utente).
- La modalità Batch/Ex (`vim -es` / `vim -Es`) **non** carica `VIMINIT`/`EXINIT`; le variabili vengono eseguite durante un avvio normale (interattivo), che rappresenta lo scenario comune per la vittima.
- I vettori correlati basati su file sono le funzionalità `exrc`/`.nvimrc` "modeline"/local-rc per-directory e `-u <vimrc>`; il percorso tramite variabile d'ambiente descritto sopra non richiede alcun file scrivibile.

## Rafforzamento

- Sanificare l'ambiente (rimuovere `VIMINIT`/`EXINIT`) prima di avviare gli editor da contesti privilegiati o automatizzati e preferire wrapper `sudo -i`/`env -i` che reimpostino l'ambiente.
- Impostare `EDITOR`/`VISUAL` su percorsi assoluti attendibili ed evitare di eseguire gli editor come root con un ambiente utente ereditato.
- Considerare il controllo dell'ambiente di un target equivalente alla code execution per qualsiasi Vim/Neovim che quest'ultimo avvii.

## References

- [1] [Documentazione di Vim — `starting.txt` (inizializzazione, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
