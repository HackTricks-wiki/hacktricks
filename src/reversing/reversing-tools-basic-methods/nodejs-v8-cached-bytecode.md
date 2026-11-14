# Deoffuscamento statico del bytecode in cache di Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

I dati in cache di V8 sono una **rappresentazione con perdita e dipendente dalla versione**, non codice sorgente JavaScript né un eseguibile nativo convenzionale. Un flusso di lavoro statico utile consiste quindi nel rimuovere eventuali livelli di packing esterni, disassemblare la cache con la build di V8 corrispondente, convertirla in un modello intermedio di pseudocodice e applicare trasformazioni consapevoli delle dipendenze senza eseguire il campione. [View8](https://github.com/suleram/View8) e [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementano questo approccio per i payload Node.js protetti con `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Acquisire e disassemblare la cache

Per prima cosa, esamina il preload/launcher invece di dare per scontato che tutti i file `.jsc` abbiano lo stesso wrapper. Per esempio, un launcher come `node.exe -r preflight.js app.jsc` esegue `preflight.js` prima del modulo principale; nella famiglia analizzata, il preload rimuoveva un livello Brotli. Dopo averlo decompresso, identifica con precisione la generazione di Node.js/V8 del runtime incluso. Una cache prodotta da una versione di V8 può essere rifiutata o decodificata in modo errato da un'altra: perciò, crea o procurati un `v8dasm` per il tag preciso di V8 e applica le patch richieste per View8 e per la stampa delle stringhe.<sup>[[1]](#references)[[2]](#references)</sup>

Il flusso di lavoro del toolkit, che non esegue il campione, è:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` assegna identificatori stabili alle funzioni generate tra un'esecuzione e l'altra. L'output testuale serve per l'ispezione; il grafo di oggetti serializzato consente a passaggi indipendenti di preservare le relazioni tra funzioni, dichiaratori, scope e metadati. **Non è JavaScript ricostruito né eseguibile**.<sup>[[1]](#references)[[2]](#references)</sup>

### Fare triage di una cache senza compilare V8

Per una cache grezza o compressa con Brotli, `jscd` può identificare l'header ed enumerare costanti e funzioni senza caricare il campione in Node.js. Usalo per prima cosa per verificare se le tabelle delle versioni supportano il file e per dare priorità alle funzioni prima dei passaggi di deoffuscamento più specializzati di View8.<sup>[[4]](#references)</sup>

L'hash della versione è un indizio per l'identificazione, non la prova che un disassembler standalone abbia gli stessi flag o lo stesso snapshot di sola lettura del produttore.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` genera un listing compatibile con View8, quindi il comando View8 precedente può usare quell'output al posto di `v8dasm` quando la cache è supportata. Esamina le stringhe insieme all'albero delle funzioni per individuare le chiamate ai decoder e i probabili entry point; non considerare l'output JavaScript approssimativo di `jscd` come il sorgente originale. Se lo strumento rifiuta la versione o lascia segnaposto dell'heap in sola lettura, torna a una build V8 corrispondente oppure fornisci una mappa dei nomi della stessa build, invece di indovinare i nomi delle proprietà.<sup>[[4]](#references)</sup>

Per una cache all'interno di un'applicazione Electron, prima [estrai l'ASAR ed esamina i suoi entry point main e preload](../../desktop-application-security/electron-desktop-apps/). Le cache di Electron e Node possono differire nel layout dello snapshot e della compressione dei puntatori anche quando le stringhe della versione V8 corrispondono.<sup>[[4]](#references)</sup>

### Leggere lo pseudocodice View8 come IR

I nomi tipici sono `func_<name>_0x<address>`, gli argomenti sono `a0...aN`, i registri virtuali sono `r0...rN` e `ACCU` è l'accumulatore di V8. `start` è il dichiaratore radice, mentre `Scope[...]`, le variabili globali e i dizionari rappresentano valori acquisiti o condivisi dalle funzioni annidate. Non interpretare ogni espressione come sintassi JavaScript: per esempio, `!r6 === "0"` in View8 rappresenta la negazione dell'intero confronto (`r6 !== "0"`), aspetto importante quando si ricostruiscono i branch.<sup>[[1]](#references)[[3]](#references)</sup>

## Deoffuscamento basato sulle dipendenze

Applica le trasformazioni in un ordine che renda visibili gli input richiesti dal passaggio successivo e ripeti la propagazione finché l'output non si stabilizza. Un ordine pratico è:<sup>[[1]](#references)[[2]](#references)</sup>

1. Esamina la gerarchia dei dichiaratori e propaga i valori da variabili globali, registri, dizionari e riferimenti `Scope[...]`.
2. Recupera gli argomenti del decoder di stringhe e sostituisci le chiamate cifrate con testo in chiaro.
3. Unisci i chunk di stringhe adiacenti; i nomi delle proprietà e le stringhe dell'ordine del dispatcher risultanti sbloccano i passaggi successivi.
4. Appiattisci il flusso di controllo, inserisci le call proxy e i wrapper delle operazioni atomiche, e risolvi i riferimenti a funzioni contenuti nei dizionari.
5. Propaga di nuovo, perché ogni stringa, chiave o proxy risolti possono rivelare un ulteriore livello di indirezione.
6. Semplifica i thunk di inizializzazione one-shot riconosciuti e rimuovi gli helper inutilizzati solo dopo aver risolto i rispettivi call site.

### Recuperare array di stringhe RC4 con shift come black box

Un layout comune di `javascript-obfuscator` memorizza chunk RC4 codificati in Base64 in un array. I wrapper dei decoder forniscono un offset numerico e una chiave breve, talvolta con gli argomenti in ordine inverso, poi aggiungono o sottraggono costanti acquisite negli scope delle closure. Quando il decoder radice è troppo offuscato, recupera empiricamente lo shift sconosciuto degli indici dell'array, invece di ricostruire l'intera funzione.<sup>[[1]](#references)</sup>

Per un array di `N` chunk e diverse chiamate allo stesso decoder:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Non accettare uno shift basandosi su una sola decifratura stampabile: il testo cifrato errato può sembrare stampabile per caso. Usa almeno tre osservazioni distinte e accetta solo uno shift univoco che produca testo plausibile per tutte. Poi percorri il grafo wrapper/declarer, accumulando ogni addizione o sottrazione e registrando se l’argomento numerico viene per primo. Memorizza questi metadati per ogni sample, sostituisci le chiamate al decoder, concatena i blocchi di testo in chiaro adiacenti ed esporta separatamente le stringhe per il triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Preservare la semantica durante l’unflattening

Per i cicli dispatcher guidati da stringhe come `3|2|1|0|4`, decodifica la stringa dell’ordine, associa ogni confronto di stato al relativo blocco, tieni conto della notazione con condizioni negate di View8, quindi emetti i blocchi nell’ordine del dispatcher. Un `continue` annidato può rappresentare un salto anticipato al dispatcher anziché un normale passaggio al blocco successivo. Quando rimuovi il ciclo, elimina quel `continue` e sposta le istruzioni che seguivano originariamente il relativo `if` contenitore in un ramo `else` generato; eliminare semplicemente il dispatcher cambia il comportamento.<sup>[[1]](#references)</sup>

### Inline di proxy, operazioni e thunk lazy

Normalizza gli helper di inoltro come `return a0(a1, a2)` prima di sostituire i relativi punti di chiamata con chiamate dirette. Tratta allo stesso modo i wrapper per sottrazione, divisione, confronto, test di appartenenza o invocazione. Poiché il riferimento all’helper può essere memorizzato dietro una chiave di dizionario decifrata o un valore di closure, esegui la propagazione di stringhe e strutture prima e dopo l’inlining.<sup>[[1]](#references)</sup>

Riconosci anche le closure che invocano una funzione memorizzata una sola volta, ne cancellano il riferimento, memorizzano il risultato e restituiscono quel risultato nelle chiamate successive. Ridurre un thunk di questo tipo nel punto di inizializzazione rende visibile il dispatcher o la funzione-capacità sottostante, ma annota che l’esecuzione originale era **one-shot e con risultato memorizzato**, anziché modellare ogni chiamata come una nuova invocazione.<sup>[[1]](#references)</sup>

## Note sulla sicurezza e sulla validazione

- Il caricamento di `pickle` in Python può eseguire codice. Carica solo file `.pkl` generati localmente dall’esecuzione di View8 considerata attendibile; non trattare mai un pickle fornito dal sample come dato.<sup>[[2]](#references)</sup>
- L’assenza del corpo di una funzione non dimostra che la sorgente non contenesse quella funzione: V8 può serializzare una funzione lazy come metadati finché non viene compilata alla prima chiamata. Durante il triage statico, contrassegna tali funzioni come irrisolte.<sup>[[6]](#references)</sup>
- I pass basati su pattern non sono un decompilatore JavaScript generico. Mantieni le espressioni irrisolte e ispeziona manualmente le varianti ambigue dei dispatcher invece di forzare una riscrittura.<sup>[[1]](#references)[[2]](#references)</sup>
- I nomi delle funzioni suggeriti da un LLM sono indicazioni per orientarsi, non prove. Se li usi, elabora prima le dipendenze foglia, ma verifica ogni etichetta rispetto al corpo, agli argomenti, alle stringhe, al flusso dei dati, alle API e agli effetti collaterali.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [La rottura del sigillo: deobfuscazione statica del bytecode V8 compilato di JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Intestazione V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache del codice di Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
