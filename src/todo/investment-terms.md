# Termini degli investimenti

{{#include ../banners/hacktricks-training.md}}

## Spot

Il trading spot scambia un asset con consegna immediata. Un ordine limit specifica la quantità e il prezzo limite; viene eseguito solo quando il mercato può soddisfare quel prezzo o uno migliore. Un ordine market cerca invece un'esecuzione rapida ai migliori prezzi disponibili in quel momento e può subire slippage.<sup>[[4]](#references)</sup>

Un ordine stop-limit ha un prezzo stop che attiva un ordine limit. Può limitare il prezzo di esecuzione, ma non garantisce l'esecuzione se il mercato supera il limite.<sup>[[4]](#references)</sup>

## Futures

Un contratto futures è un accordo standardizzato per acquistare o vendere una determinata commodity o uno strumento finanziario a una data futura. Ad esempio, due parti potrebbero concordare un prezzo di 70.000 $ per un bitcoin, con regolamento tra sei mesi.<sup>[[1]](#references)</sup>

Se il prezzo di regolamento è 80.000 $, la posizione long guadagna e la posizione short perde rispetto al prezzo contrattuale di 70.000 $. Se è 60.000 $, la direzione si inverte. I futures effettivamente negoziati sugli exchange sono regolati al valore di mercato e normalmente chiusi o rinnovati prima della scadenza, quindi si tratta di un esempio semplificato.<sup>[[2]](#references)</sup>

Produttori e consumatori usano i futures per coprire il rischio di prezzo; altri partecipanti li usano per cercare un profitto o fornire liquidità.<sup>[[1]](#references)</sup>

- Una **posizione long** generalmente produce profitti quando il prezzo del contratto aumenta.
- Una **posizione short** generalmente produce profitti quando il prezzo del contratto diminuisce.<sup>[[2]](#references)</sup>

### Hedging con i Futures

Se un gestore di fondi prevede un calo del portafoglio, potrebbe assumere una posizione short su un contratto futures su un indice azionario sufficientemente correlato. I guadagni della copertura short possono compensare parte delle perdite del portafoglio; il basis risk fa sì che la compensazione sia raramente esatta. Un future su bitcoin coprirebbe l'esposizione al bitcoin, non automaticamente un portafoglio azionario.

Se il mercato coperto diminuisce, la posizione short sui futures può guadagnare mentre le partecipazioni perdono valore. Se aumenta, le partecipazioni possono guadagnare mentre la copertura perde. L'hedging riduce un rischio specifico, invece di creare un profitto garantito.<sup>[[1]](#references)</sup>

### Futures Perpetui

I contratti perpetui sono derivati senza una data di scadenza fissa. Le piattaforme crypto usano comunemente pagamenti periodici di funding per mantenere il loro prezzo vicino al prezzo spot sottostante; i termini variano in base alla piattaforma.<sup>[[3]](#references)</sup>

Il profitto e la perdita cambiano con il movimento del mark price. Un movimento dell'1% nel prezzo produce approssimativamente un movimento dell'1% sul valore nozionale della posizione, prima di commissioni e funding, ma la leva può trasformarlo in una variazione percentuale molto maggiore del collaterale depositato.

### Futures con Leverage

La **leva** consente a un trader di controllare una posizione nozionale più grande con un deposito di margine più piccolo. Le perdite non sono sempre limitate al margine iniziale: liquidazione, gap, commissioni e regole della piattaforma possono produrre perdite aggiuntive.<sup>[[3]](#references)</sup>

Ad esempio, 100 $ di margine con una leva 50x controllano una posizione da 5.000 $. Ignorando commissioni, funding e meccanismi di liquidazione, un movimento favorevole dell'1% produce un guadagno di 50 $ (il 50% del margine iniziale), mentre un movimento sfavorevole dell'1% produce una perdita di 50 $. Un movimento sfavorevole del 2% corrisponde a 100 $, sebbene una piattaforma normalmente liquidi la posizione prima che tutto il margine venga esaurito.

La leva amplifica sia i guadagni sia le perdite e rende possibile la liquidazione dopo un movimento sfavorevole relativamente ridotto.

## Differenze tra Futures e Opzioni

L'acquirente di un'opzione riceve un diritto, non un obbligo, di esercitare l'opzione secondo i termini del contratto. Il writer dell'opzione ha l'obbligo corrispondente se l'acquirente esercita l'opzione. L'acquirente paga al writer un premio per tale diritto.<sup>[[4]](#references)</sup>

### 1. **Obbligo vs. Diritto:**

* **Futures:** Quando acquisti o vendi un contratto futures, stipuli un **accordo vincolante** per acquistare o vendere un asset a un prezzo specifico in una data futura. Sia l'acquirente sia il venditore sono **obbligati** a rispettare il contratto alla scadenza, a meno che il contratto non venga chiuso prima.
* **Opzioni:** Con le opzioni, hai il **diritto, ma non l'obbligo**, di acquistare (nel caso di una **call option**) o vendere (nel caso di una **put option**) un asset a un prezzo specifico prima o alla data di scadenza stabilita. L'**acquirente** ha la facoltà di eseguire l'operazione, mentre il **venditore** è obbligato a completarla se l'acquirente decide di esercitare l'opzione.

### 2. **Rischio:**

* **Futures:** Entrambe le parti possono subire perdite sostanziali. Il fatto che la perdita sia matematicamente illimitata dipende dalla posizione e dall'asset sottostante: una posizione short può avere una perdita teorica illimitata, mentre una posizione long non può perdere più del valore nozionale se il sottostante non può scendere sotto zero.
* **Opzioni:** Un acquirente che non vende un'altra opzione generalmente rischia il premio pagato. Il writer di una call naked può subire una perdita teoricamente illimitata; altre strategie di vendita di opzioni presentano profili di rischio limitati o illimitati differenti.

### 3. **Costo:**

* **Futures:** Non vi è alcun costo iniziale oltre al margine richiesto per mantenere la posizione, poiché sia l'acquirente sia il venditore sono obbligati a completare l'operazione.
* **Opzioni:** L'acquirente deve pagare anticipatamente un **premio dell'opzione** per ottenere il diritto di esercitarla. Questo premio è essenzialmente il costo dell'opzione.

### 4. **Potenziale di profitto:**

* **Futures:** Il profitto o la perdita si basano sulla differenza tra il prezzo di mercato alla scadenza e il prezzo concordato nel contratto.
* **Opzioni:** L'acquirente realizza un profitto quando il mercato si muove favorevolmente oltre lo strike price di un valore superiore al premio pagato. Il venditore realizza un profitto trattenendo il premio se l'opzione non viene esercitata.

## References

- [1] [CFTC - Lo scopo economico dei mercati futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Nozioni di base sui mercati futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprendere i rischi del trading di valute virtuali](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossario CFTC - Opzione, premio ed esercizio](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
