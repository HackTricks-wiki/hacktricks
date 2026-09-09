# Deobfuscation statica del bytecode memorizzato nella cache di Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

I cached data di V8 sono una **rappresentazione dipendente dalla versione e con perdita di informazioni**, non codice sorgente JavaScript né un eseguibile nativo convenzionale. Un workflow statico utile consiste quindi nel rimuovere qualsiasi packing esterno, disassemblare la cache con la build di V8 corrispondente, convertirla in un modello di pseudocodice intermedio e applicare trasformazioni consapevoli delle dipendenze senza eseguire il sample. [View8](https://github.com/suleram/View8) e [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementano questo approccio per payload Node.js protetti da `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Acquisire e disassemblare la cache

Per prima cosa, esamina il preload/launcher invece di presumere che ogni file `.jsc` abbia lo stesso wrapper. Ad esempio, un launcher come `node.exe -r preflight.js app.jsc` esegue `preflight.js` prima del modulo principale; nella famiglia analizzata, il preload rimuoveva un livello Brotli. Dopo l'unpacking, identifica l'esatta generazione di Node.js/V8 dal runtime incluso. Una cache prodotta da una versione di V8 può essere rifiutata o decodificata in modo errato da un'altra, quindi crea o ottieni un `v8dasm` per quel preciso tag V8 e applica le patch richieste da View8 e per la stampa delle stringhe.<sup>[[1]](#references)[[2]](#references)</sup>

Il workflow del toolkit che non prevede l'esecuzione è:<sup>[[2]](#references)</sup>
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
`--normalize` assegna identificatori stabili alle funzioni generate tra un'esecuzione e l'altra. L'output testuale serve per l'ispezione; il grafo degli oggetti serializzato consente a passaggi indipendenti di preservare le relazioni tra funzioni, dichiaratori, scope e metadati. **Non è JavaScript ricostruito né eseguibile**.<sup>[[1]](#references)[[2]](#references)</sup>

### Leggere il pseudocodice di View8 come un IR

I nomi tipici sono `func_<name>_0x<address>`, gli argomenti sono `a0...aN`, i registri virtuali sono `r0...rN` e `ACCU` è l'accumulatore di V8. `start` è il dichiaratore radice, mentre `Scope[...]`, le variabili globali e i dizionari modellano i valori catturati o condivisi dalle funzioni annidate. Non analizzare ogni espressione come sintassi JavaScript: per esempio, `!r6 === "0"` di View8 rappresenta la negazione del confronto completo (`r6 !== "0"`), aspetto importante durante la ricostruzione dei branch.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation consapevole delle dipendenze

Applica le trasformazioni in un ordine che esponga gli input richiesti dal passaggio successivo e ripeti la propagazione finché l'output non si stabilizza. Un ordine pratico è:<sup>[[1]](#references)[[2]](#references)</sup>

1. Attraversa la gerarchia dei dichiaratori e propaga i valori da variabili globali, registri, dizionari e riferimenti `Scope[...]`.
2. Recupera gli argomenti dei decoder di stringhe e sostituisci le chiamate cifrate con il testo in chiaro.
3. Unisci i blocchi di stringhe adiacenti; i nomi delle proprietà e le stringhe relative all'ordine del dispatcher risultanti sbloccano i passaggi successivi.
4. Rimuovi l'flattening del control flow, inlinea i proxy delle chiamate e i wrapper delle operazioni atomiche e risolvi i riferimenti alle funzioni contenuti nei dizionari.
5. Propaga nuovamente, perché ogni stringa, chiave o proxy risolto può esporre un altro livello di indirezione.
6. Comprimi i thunk di inizializzazione one-shot riconosciuti e rimuovi gli helper inutilizzati solo dopo aver risolto i relativi call site.

### Recuperare gli array di stringhe RC4 shiftati come black box

Un layout comune di `javascript-obfuscator` memorizza chunk RC4 codificati in Base64 all'interno di un array. I wrapper del decoder forniscono un offset numerico e una chiave breve, talvolta con l'ordine degli argomenti invertito, quindi aggiungono o sottraggono costanti catturate negli scope delle closure. Quando il decoder radice è troppo offuscato, recupera empiricamente lo shift sconosciuto dell'indice dell'array invece di ricostruire l'intera funzione.<sup>[[1]](#references)</sup>

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
Non accettare uno shift basato su una singola decrittazione stampabile: il ciphertext errato può sembrare stampabile per caso. Usa almeno tre osservazioni distinte e accetta solo uno shift univoco che produca testo plausibile per tutte. Quindi attraversa il grafo wrapper/declarer, accumulando ogni addizione o sottrazione e registrando se l'argomento numerico viene prima. Metti in cache questi metadati per sample, sostituisci le chiamate al decoder, concatena i chunk di plaintext adiacenti ed esporta separatamente le stringhe per il triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Preservare la semantica durante l'unflattening

Per i cicli dispatcher guidati da stringhe come `3|2|1|0|4`, decodifica la stringa dell'ordine, associa ogni confronto di stato al relativo blocco, considera la notazione delle condizioni negate di View8, quindi emetti i blocchi nell'ordine del dispatcher. Un `continue` annidato può rappresentare un salto anticipato verso il dispatcher anziché un normale fall-through. Quando rimuovi il ciclo, elimina quel `continue` e sposta le istruzioni che originariamente seguivano il relativo `if` in un ramo `else` generato; eliminare semplicemente il dispatcher modifica il comportamento.<sup>[[1]](#references)</sup>

### Inline proxy, operazioni e thunk lazy

Normalizza gli helper di forwarding come `return a0(a1, a2)` prima di sostituire i relativi call site con chiamate dirette. Tratta allo stesso modo i wrapper per sottrazione, divisione, confronto, membership test o invocazione. Poiché il riferimento all'helper può essere memorizzato a sua volta dietro una chiave di dizionario decrittata o un valore di closure, esegui la propagazione di stringhe e strutture prima e dopo l'inlining.<sup>[[1]](#references)</sup>

Riconosci inoltre le closure che invocano una funzione memorizzata una volta, ne cancellano il riferimento, mettono in cache il risultato e restituiscono tale cache nelle chiamate successive. Collassare questo thunk in un punto di inizializzazione espone il dispatcher o la capability function sottostante, ma annota che l'esecuzione originale era **one-shot e cached**, invece di modellare ogni chiamata come una nuova invocazione.<sup>[[1]](#references)</sup>

## Note sulla sicurezza e sulla validazione

- Il caricamento di `pickle` in Python può eseguire codice. Carica solo file `.pkl` generati localmente dall'esecuzione trusted di View8; non trattare mai un pickle fornito dal sample come dati.<sup>[[2]](#references)</sup>
- I pass basati su pattern non sono un decompiler JavaScript generico. Preserva le espressioni irrisolte ed esamina manualmente le varianti ambigue del dispatcher invece di forzare una riscrittura.<sup>[[1]](#references)[[2]](#references)</sup>
- I nomi delle funzioni assistiti da LLM sono indicazioni di navigazione, non prove. Se li utilizzi, elabora le dipendenze leaf-first, ma verifica ogni etichetta rispetto al body, agli argomenti, alle stringhe, al data flow, alle API e agli effetti collaterali.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Rompere il sigillo: deobfuscation statica del bytecode V8 compilato di JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
