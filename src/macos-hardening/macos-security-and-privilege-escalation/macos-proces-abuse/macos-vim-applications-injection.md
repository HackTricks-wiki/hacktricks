# Iniezione nelle applicazioni macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Il linguaggio di scripting di Vim (Vimscript) può eseguire **comandi Ex arbitrari e comandi shell all'avvio** tramite variabili d'ambiente. Se un processo con privilegi maggiori (un workflow di manutenzione/root, un `sudo vim …`, un editor avviato da un altro strumento, `crontab -e`, `visudo`, `git`/`less` che invocano un editor, …) avvia Vim/Neovim con un ambiente influenzabile dall'attaccante, quest'ultimo ottiene l'esecuzione di codice in quel contesto.

## `VIMINIT`

Durante l'inizializzazione, Vim legge ed esegue i comandi Ex contenuti in **`VIMINIT`**. I comandi Ex includono `:!cmd` (esegue un comando shell) e `:call system(...)`, quindi una singola variabile consente l'esecuzione arbitraria prima ancora di modificare un file.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

`:qa!` passato tramite stdin nel primo esempio chiude l'editor solo dopo l'esecuzione del payload; in uno scenario reale, la vittima può aprire Vim normalmente.

`VIMINIT` viene interpretato come **un'unica riga di comando Ex**. Separa una sequenza di comandi con `|` (o con un newline letterale). Ha precedenza sul vimrc dell'utente e su `EXINIT`, quindi un payload non necessita di un file di configurazione malevolo e viene eseguito prima della normale configurazione dell'utente.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Se `VIMINIT` non è impostata, Vim (e i binari di compatibilità `vi`/`ex`) ripiega su **`EXINIT`**, che viene eseguita allo stesso modo. È la variante classica, dell'era di vi, dello stesso primitive.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## File rc locale al progetto con Vim `exrc`

Questa è un'alternativa a `VIMINIT` basata su file. Se la vittima ha abilitato `set exrc` nella propria configurazione utente, Vim carica anche `.vimrc` (poi `_vimrc` o `.exrc`) dalla **directory di lavoro**, non soltanto dalla directory del file in modifica. Inserisci un `.vimrc` locale al progetto e fai avviare Vim alla vittima da quel progetto. Su Unix, Vim applica restrizioni `secure` a un rc locale di proprietà di un altro utente, ma un archivio estratto dalla vittima normalmente assegna al file inserito la proprietà della vittima e aggira questo controllo.<sup>[[1]](#references)</sup>

Questo marker isolato mostra il trigger di avvio senza modificare la configurazione utente reale:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim è diverso: le build attuali richiedono che i file locali al progetto `.nvim.lua`, `.nvimrc` o `.exrc` siano considerati attendibili prima dell'esecuzione. L'attendibilità è associata all'hash del contenuto del file, quindi modificare un file già considerato attendibile richiede una nuova decisione. Un attaccante che può solo inserire un file in un repository non può dare per scontata l'esecuzione silenziosa tramite `exrc`; distingui questo percorso opt-in, subordinato all'attendibilità, dal percorso Lua `require()` dalla directory corrente descritto qui sotto.<sup>[[4]](#references)[[5]](#references)</sup>

Per un vimrc **utente** scrivibile, anziché uno locale al progetto, vedi [Configurazione di avvio di Vim su macOS](../../macos-auto-start-locations.md#vim-startup-configuration).

## Soppressione dell'avvio e sfruttabilità

Questa primitiva dipende da un **avvio normale**. `vim -u NONE` / `nvim -u NONE` ignorano l'inizializzazione dell'ambiente e dell'utente (e i plugin), mentre `-u <file>` usa quel file al loro posto. Anche Vim `-es`/`-Es` e Neovim `-es`, `-Es` o `-l` saltano questi passaggi di inizializzazione. Non confondere `--headless` con una modalità sicura: un normale avvio headless di Neovim elabora comunque `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Di conseguenza, convalida l'intera catena di avvio: la variabile deve sopravvivere al wrapper, alle policy di `sudo`, al job runner e alla selezione dell'editor, e il comando finale non deve forzare `-u NONE`/`NORC` o la modalità batch. Un payload affidabile può terminare autonomamente con `|qall!`, il che semplifica anche il test dei wrapper che non forniscono un TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking dei moduli Lua di Neovim dalla directory corrente

Una primitiva di injection distinta in Neovim interessa le build in cui `package.path`/`package.cpath` di Lua contengono ancora template della directory corrente come `./?.lua` o `./?.so`. Avviare Neovim da solo non basta: una configurazione o un plugin deve chiamare `require("name")` e nessun loader precedente deve risolvere quel nome. Un trigger comune è il controllo di una **dipendenza opzionale**, ad esempio `pcall(require, "optional_dep")`; inserendo `optional_dep.lua` in una directory di lavoro controllata dall'attaccante, il file viene eseguito senza abilitare la funzionalità separata di configurazione locale `'exrc'`. I moduli core `vim.*` e quelli già trovati in `'runtimepath'` non sono generalmente soggetti a shadowing, quindi individua le chiamate `require()` effettivamente mancanti/opzionali invece di indovinare i nomi.<sup>[[3]](#references)</sup>

Quanto segue riproduce la primitiva del loader con un marker innocuo:<sup>[[3]](#references)</sup>

```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```

Controlla la build in esecuzione invece di basarti solo su una stringa di versione:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream sta monitorando la rimozione del fallback della directory corrente durante il normale avvio dell’editor, mantenendo il comportamento degli script Lua (`nvim -l`). Finché la build installata lo espone ancora, inserisci questo all’**inizio** di `init.lua` (rimuove intenzionalmente i template relativi della directory corrente per i moduli Lua/C, quindi non applicarlo ai flussi di lavoro che ne hanno bisogno):<sup>[[3]](#references)</sup>

```lua
local function drop_cwd(path)
  local keep = {}
  for entry in path:gmatch("[^;]+") do
    if not entry:match("^%./") then keep[#keep + 1] = entry end
  end
  return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```

## Note e avvertenze

- **Neovim** rispetta sia `VIMINIT` sia il fallback `EXINIT`, ma la sua normale configurazione utente è `init.vim` o `init.lua`.<sup>[[2]](#references)</sup>
- Il percorso tramite variabile d'ambiente non richiede file scrivibili. I file rc locali e il current-directory module hijacking sono primitive distinte, basate su file.<sup>[[1]](#references)[[3]](#references)</sup>
- I file rc locali al progetto sono distinti dai modeline e dal fallback di `require()` nella directory corrente descritto sopra. Vim e Neovim applicano controlli diversi; vedi il workflow `exrc` locale al progetto descritto sopra.<sup>[[1]](#references)[[4]](#references)</sup>
- Le variabili di selezione dell'editor scelgono solo quale programma avviare; non garantiscono che `VIMINIT` venga passato al processo finale. Esamina l'ambiente e gli argomenti esatti al confine di esecuzione di Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Rafforzamento

- Rimuovi esplicitamente le variabili prima di avviare editor con privilegi elevati o automatizzati: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` è importante quando il chiamante deve ignorare tutte le sorgenti di avvio dell'utente.<sup>[[1]](#references)[[2]](#references)</sup>
- Imposta `EDITOR`/`VISUAL` su percorsi assoluti attendibili, evita di eseguire editor interattivi come root con un ambiente utente ereditato e assicurati che i wrapper non ripristinino `VIMINIT`/`EXINIT` dopo la sanitizzazione.<sup>[[1]](#references)[[2]](#references)</sup>
- Per Neovim, aggiorna a una build che rimuova i template di ricerca Lua/C della directory corrente durante la modalità editor, oppure rimuovili prima di caricare i plugin. Esamina il codice dei plugin per individuare chiamate `pcall(require, ...)` facoltative quando apri repository non attendibili.<sup>[[3]](#references)</sup>
- Considera il controllo dell'ambiente dell'editor, della directory di lavoro o della configurazione di avvio di un target come una possibile primitiva di esecuzione di codice nel contesto di sicurezza dell'editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentazione di Vim — `starting.txt` (inizializzazione, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentazione di Neovim — avvio e inizializzazione](https://neovim.io/doc/user/starting/)
- [3] [Issue #38966 di Neovim — fallback della directory corrente in `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Opzioni di Neovim — `exrc` locale al progetto e requisito di attendibilità](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Modifica in Neovim — file attendibili e `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
