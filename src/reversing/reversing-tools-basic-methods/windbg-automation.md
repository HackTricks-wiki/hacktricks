# Automazione di WinDbg per la strumentazione mirata

{{#include ../../banners/hacktricks-training.md}}

WinDbg e WinDbgX possono eseguire comandi del debugger all'avvio, in caso di eccezioni e quando scattano i breakpoint. Questo consente a una sessione di fuzzing o di reversing di raccogliere informazioni sullo stato solo nei punti di un percorso determinati dall'input, invece di fermarsi manualmente a ogni evento.<sup>[[1]](#references)</sup>

## Iniziare da un'eccezione utile

`-c` esegue i comandi al breakpoint iniziale del debugger. Aggiungi `;g` per riprendere l'esecuzione dopo la configurazione. In una sessione WinDbg Classic non presidiata, `-logo` scrive la finestra dei comandi in un log, `-Q` disabilita il salvataggio automatico dell'area di lavoro e `-G` ignora il breakpoint finale, così la sessione termina quando il target esce. Anche WinDbgX accetta `-c`; i comandi Startup configurati vengono eseguiti in seguito.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Per le violazioni di accesso, **`sxe av` si interrompe alla first chance**, **`sxd av` salta la first chance ma si interrompe alla second chance non gestita** e **`sxi av` ignora entrambe**. Le descrizioni di `sxi`/`sxd` nell'articolo sono invertite: Microsoft documenta `sxd` come filtro per la second chance e `sxi` come ignorare. Usa `-c` per un comando alla first chance e `-c2` per un comando alla second chance; un handler `-c` alla first chance non diventa un handler alla second chance solo perché il filtro è `sxd`. Verifica i filtri attivi con `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Il primo comando raccoglie i registri, una traccia dello stack e l’analisi dell’eccezione solo in caso di access violation non gestita. Il secondo esegue `lm` quando viene caricato un modulo. Gli eventi breakpoint (`bp`), caricamento di un modulo (`ld`) e access violation (`av`) hanno cicli di vita diversi: se si fa affidamento sui breakpoint del debugger, non ignorare globalmente `bp`.<sup>[[1]](#references)[[2]](#references)</sup>

## Attivare breakpoint costosi con un trigger controllato

Scegli una funzione visibile agli script o comunque controllata dall’input, che possa essere chiamata subito prima del percorso di interesse. Installa **action breakpoint** sulle chiamate all’allocator, al parser o alle API da ispezionare. Disattivali per ID con `bd`. Installa un **trigger breakpoint** con un comando associato che abiliti questi ID con `be`, quindi riprenda l’esecuzione con `g`; un secondo trigger controllato può disattivarli di nuovo. Verifica gli ID con `bl` prima di configurare il trigger, perché dipendono dall’ordine di creazione dei breakpoint. In questo modo i punti di controllo a basso costo sono separati dal tracing costoso, limitando le modifiche al timing e al layout dell’heap del target.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Dopo aver risolto i due simboli, usa il modello di comando riportato sotto. Sostituisci i simboli tra parentesi quadre e l’ID dell’action breakpoint restituito da `bl`; non dare per scontato che sia zero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

I comandi dei breakpoint d'azione possono stampare `@$ip` e `%y` (indirizzo con simboli), eseguire il dump degli argomenti selezionati o della memoria e poi continuare. Se un breakpoint condizionale registra solo i puntatori in un intervallo selezionato, verifica prima che l'intervallo includa effettivamente l'input di test; una condizione errata fa perdere prove senza segnalarlo.<sup>[[1]](#references)</sup>

### Trova un trigger con i simboli

Cerca in tutti i moduli caricati se non conosci il modulo che contiene l'implementazione. `bm` imposta breakpoint su ogni simbolo corrispondente; invoca la funzione visibile allo script e controlla quale breakpoint scatta. Per esempio, il sorgente richiama `Math.cos(0)` nel renderer sottoposto a debug, non in un processo browser qualsiasi.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Una volta che un hit identifica la funzione esatta, usa `lm a <symbol>` per individuare l'immagine che la contiene e `? <symbol> - <module>` per calcolare un offset relativo al modulo. WinDbg può mostrare lo stesso nome breve del modulo per un eseguibile e una DLL, quindi verifica il percorso dell'immagine prima di usare l'offset in un altro processo. Restringi i breakpoint wildcard al symbol verificato per evitare overhead.<sup>[[1]](#references)</sup>

### Trovare un candidato senza symbol

Lo script `corelan_trigscan.py` di Corelan, basato su Frida, analizza un modulo selezionato del processo alla ricerca di pattern di istruzioni floating-point, SSE, AVX e trigonometriche. Genera comandi breakpoint per WinDbg in `corelan_trigscan.bps` e file `.bps` numerati più piccoli. Eseguilo con Python e `frida-tools` sul target **senza un altro debugger collegato**; successivamente, esegui attach di WinDbg allo stesso processo/modulo e carica un batch di breakpoint gestibile.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Per un offset relativo al modulo già noto, verifica che superi le soglie prima di importare tutti i breakpoint generati:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` è la densità di istruzioni rilevanti, `--min-relevant` e `--min-total` impostano i conteggi minimi di istruzioni, mentre `--min-trig` richiede segnali forti simili a quelli delle funzioni trigonometriche. Se una funzione nota non viene individuata, passa il suo offset **relativo al modulo** a `--check-offset` per esaminarne il prologo, la densità, i conteggi e le chiamate indirette. Un wrapper sottile può avere una densità bassa e nessuna istruzione trigonometrica. Abbassa le soglie e, se cerchi wrapper, usa l'opzione effettiva dello script `--min-icall 1` (non `--min-ical`); le funzioni chiamate direttamente vengono analizzate, ma non è possibile seguire in modo affidabile i target indiretti. Batch con `--splitsize` più piccoli sono utili quando molti breakpoint generati rallentano WinDbg. Un candidato non è convalidato finché l'input previsto non fa scattare il suo breakpoint.<sup>[[1]](#references)[[6]](#references)</sup>

## Programmi di debug compatti e PyKD

Usa `.if` quando una condizione è affidabile, `.foreach` per scorrere l'output delimitato da spazi bianchi e `.for` con pseudo-registri per esplorare la memoria o le strutture. `.foreach` **non** preserva le colonne: ad esempio, l'output di `lm` con larghezza variabile è un input poco adatto, mentre `lm 1m` restituisce un nome di modulo per token. Se una condizione ipotizzata potrebbe nascondere il percorso che causa il problema, registra prima i dati senza filtri.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Gli alias creati con `as name value` sono sostituzioni testuali, non variabili tipizzate. `al` elenca gli alias, `ad name` ne elimina uno e `${name}` forza un'espansione non ambigua. Evita nomi come `bp`, `x` o `r`, perché un alias può nascondere un comando integrato. Le espressioni MASM sono adatte all'aritmetica dei puntatori, ad esempio `poi(@$t0)`; `@@c++(...)` consente di accedere ai campi tipizzati quando sono presenti i simboli, evitando offset hard-coded delle strutture.<sup>[[1]](#references)</sup>

Inserisci le sequenze di comandi più lunghe in un file di comandi. `$$><filename` unisce le righe in un unico blocco di comandi e consente di aggiungere un comando del debugger separato da un punto e virgola. Le strutture di controllo su più righe possono comunque essere fragili; mantieni ogni istruzione `.if` o `.for` su una sola riga. Lo stesso file può essere richiamato all'avvio tramite `-c`.<sup>[[1]](#references)[[8]](#references)</sup>

Per le operazioni poco pratiche nel linguaggio dei comandi, PyKD espone a Python strutture tipizzate, registri, memoria e output del debugger. Ad esempio, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` accede ai campi del PEB, `pykd.loadBytes(address, size)` legge la memoria e `pykd.dbgCommand("lm")` restituisce l'output del debugger per consentirne l'analisi. Per i dati che potrebbero non essere terminati, preferisci `loadChars`/`loadWChars` con limiti ai metodi di lettura delle stringhe senza limiti. `disasm(address).asm(instruction)` di PyKD **scrive i byte assemblati a quell'indirizzo**; se la usi per ottenere opcode in un processo attivo, salva e ripristina la memoria originale.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Debugging - Automazione e scripting di WinDBG(X) - Parte 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Impostare le eccezioni)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Abilitare un breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Disabilitare un breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Impostare un breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Sorgente Corelan trigscan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Opzioni della riga di comando di WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Eseguire un file di script](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
