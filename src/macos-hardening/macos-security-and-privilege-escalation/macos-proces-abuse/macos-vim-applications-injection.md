# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Il linguaggio di scripting di Vim (Vimscript) può eseguire **comandi Ex arbitrari e comandi shell all'avvio** dalle variabili d'ambiente. Se un processo con privilegi maggiori (un workflow di manutenzione/root, un `sudo vim …`, un editor avviato da un altro strumento, `crontab -e`, `visudo`, `git`/`less` che invoca un editor, …) avvia Vim/Neovim con un ambiente influenzato dall'attaccante, quest'ultimo ottiene l'esecuzione di codice in quel contesto.

## `VIMINIT`

Durante l'inizializzazione Vim legge ed esegue i comandi Ex presenti in **`VIMINIT`**. I comandi Ex includono `:!cmd` (esegue un comando shell) e `:call system(...)`, quindi una singola variabile consente un'esecuzione arbitraria prima che venga modificato qualsiasi file.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
Il `:qa!` fornito tramite stdin nel primo esempio chiude l'editor solo dopo l'esecuzione del payload; in uno scenario reale la vittima può aprire Vim normalmente.

`VIMINIT` viene interpretato come **un'unica riga di comando Ex**. Separa una catena con `|` (o con un a capo letterale). Ha precedenza sul vimrc dell'utente e su `EXINIT`, quindi un payload non necessita di un file di configurazione malevolo ed esegue il codice prima della normale configurazione dell'utente.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Se `VIMINIT` non è impostato, Vim (e i binari di compatibilità `vi`/`ex`) utilizza **`EXINIT`**, che viene eseguito nello stesso modo. È la variante classica, risalente all'epoca di vi, della stessa primitiva.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Soppressione dell'avvio e sfruttabilità

Questa primitiva dipende da un **avvio normale**. `vim -u NONE` / `nvim -u NONE` ignorano l'inizializzazione dell'ambiente/utente (e i plugin), mentre `-u <file>` usa quel file al loro posto. Anche Vim `-es`/`-Es` e Neovim `-es`, `-Es` o `-l` ignorano questi passaggi di inizializzazione. Non confondere `--headless` con una modalità sicura: un normale avvio headless di Neovim elabora comunque `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Di conseguenza, convalida l'intera catena di avvio: la variabile deve superare il wrapper, la policy di `sudo`, il job runner e la selezione dell'editor, e il comando finale non deve forzare `-u NONE`/`NORC` o la modalità batch. Un payload affidabile può terminare autonomamente con `|qall!`, rendendo più semplici anche i test dei wrapper che non forniscono una TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking dei moduli Lua nella directory corrente di Neovim

Una primitiva di injection separata di Neovim interessa le build il cui Lua `package.path`/`package.cpath` contiene ancora template della directory corrente come `./?.lua` o `./?.so`. Avviare Neovim da solo non è sufficiente: una configurazione o un plugin deve chiamare `require("name")` e nessun loader precedente deve risolvere quel nome. Un trigger comune è un **controllo delle dipendenze opzionali** come `pcall(require, "optional_dep")`; inserendo `optional_dep.lua` in una directory di lavoro controllata dall'attacker, il file viene quindi eseguito senza abilitare la funzionalità separata di configurazione locale `'exrc'`. I moduli core `vim.*` e i moduli già trovati su `'runtimepath'` generalmente non possono essere shadowed; pertanto, enumera le chiamate `require()` effettivamente mancanti/opzionali invece di indovinare i nomi.<sup>[[3]](#references)</sup>

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
Controlla la build in esecuzione invece di affidarti solo a una stringa di versione:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream monitora la rimozione del fallback della directory corrente durante il normale avvio dell’editor, mantenendo al contempo il comportamento degli script Lua (`nvim -l`). Finché la build installata lo espone ancora, inserisci questo all’**inizio** di `init.lua` (rimuove intenzionalmente i template relativi alla directory corrente per i moduli Lua/C, quindi non applicarlo ai workflow che ne richiedono l’uso):<sup>[[3]](#references)</sup>
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

- **Neovim** considera sia `VIMINIT` sia il fallback `EXINIT`, ma la sua configurazione utente normale è `init.vim` o `init.lua`.<sup>[[2]](#references)</sup>
- Il percorso tramite variabili d'ambiente non richiede alcun file scrivibile. L'hijacking del file rc locale e del modulo nella directory corrente sono primitive separate, basate su file.<sup>[[1]](#references)[[3]](#references)</sup>
- La configurazione locale del progetto è una superficie diversa dai modeline. Con l'opzione `'exrc'` di Vim abilitata, un vimrc/exrc locale di proprietà di un altro utente viene eseguito con le restrizioni di `'secure'`; tuttavia, l'estrazione di un archivio normalmente rende il file piantato di proprietà della vittima, eludendo questa protezione basata sulla proprietà. Neovim cerca inoltre `.nvim.lua`, `.nvimrc` o `.exrc` quando `'exrc'` è abilitata: non confondere questo meccanismo opt-in con il fallback di `require()` nella directory corrente descritto sopra.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Le variabili di selezione dell'editor scelgono solo quale programma viene avviato; non garantiscono che `VIMINIT` raggiunga il processo finale. Ispezionare l'ambiente e gli argomenti esatti al confine di exec di Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Rafforzamento

- Rimuovere esplicitamente le variabili prima dell'avvio di editor privilegiati o automatizzati: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` è importante quando il chiamante deve ignorare ogni sorgente di avvio dell'utente.<sup>[[1]](#references)[[2]](#references)</sup>
- Impostare `EDITOR`/`VISUAL` su percorsi assoluti attendibili, evitare di eseguire editor interattivi come root con un ambiente utente ereditato e assicurarsi che i wrapper non possano ripristinare `VIMINIT`/`EXINIT` dopo la sanitizzazione.<sup>[[1]](#references)[[2]](#references)</sup>
- Per Neovim, aggiornare a una build che rimuova i template di ricerca Lua/C dalla directory corrente durante la modalità editor oppure rimuoverli prima del caricamento dei plugin. Verificare il codice dei plugin alla ricerca di chiamate `pcall(require, ...)` opzionali quando si aprono repository non attendibili.<sup>[[3]](#references)</sup>
- Considerare il controllo sull'ambiente dell'editor, sulla directory di lavoro o sulla configurazione di avvio di una destinazione come una potenziale primitiva di esecuzione del codice nel contesto di sicurezza dell'editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentazione di Vim — `starting.txt` (inizializzazione, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentazione di Neovim — avvio e inizializzazione](https://neovim.io/doc/user/starting/)
- [3] [Issue #38966 di Neovim — fallback della directory corrente in `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
