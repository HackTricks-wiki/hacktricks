# Termini di investimento

{{#include ../../banners/hacktricks-training.md}}

## Spot

Il trading spot consiste nello scambiare un asset con consegna immediata. Un ordine limite specifica la quantità e il prezzo limite; viene eseguito solo quando il mercato può soddisfare quel prezzo o uno migliore. Un ordine a mercato, invece, cerca un'esecuzione rapida ai migliori prezzi disponibili in quel momento e può subire slippage.<sup>[[4]](#references)</sup>

Un ordine stop-limit prevede un prezzo stop che attiva un ordine limite. Può vincolare il prezzo di esecuzione, ma non ne garantisce l'esecuzione se il mercato supera il limite.<sup>[[4]](#references)</sup>

## Futures

Un contratto futures è un accordo standardizzato per acquistare o vendere una determinata commodity o uno strumento finanziario a una data futura. Per esempio, due parti potrebbero concordare un prezzo di 70.000 $ per un bitcoin, con regolamento tra sei mesi.<sup>[[1]](#references)</sup>

Se il prezzo di regolamento è 80.000 $, la posizione long guadagna e quella short perde rispetto al prezzo contrattuale di 70.000 $. Se è 60.000 $, accade il contrario. I futures effettivamente negoziati in borsa sono regolati giornalmente al valore di mercato e di solito vengono chiusi o rinnovati prima della scadenza; questo è quindi un esempio semplificato.<sup>[[2]](#references)</sup>

Produttori e consumatori usano i futures per coprirsi dal rischio di prezzo; altri partecipanti li usano per cercare un profitto o fornire liquidità.<sup>[[1]](#references)</sup>

- Una **posizione long** generalmente guadagna quando il prezzo del contratto sale.
- Una **posizione short** generalmente guadagna quando il prezzo del contratto scende.<sup>[[2]](#references)</sup>

### Copertura con i futures

Se un gestore di fondi prevede un calo del portafoglio, potrebbe vendere allo scoperto un contratto futures su un indice azionario sufficientemente correlato. I guadagni sulla copertura short possono compensare parte delle perdite del portafoglio; il rischio di base fa sì che la compensazione sia raramente esatta. Un future sul bitcoin coprirebbe l'esposizione al bitcoin, non automaticamente un portafoglio azionario.

Se il mercato coperto scende, la posizione short sui futures può guadagnare mentre le partecipazioni perdono valore. Se sale, le partecipazioni possono guadagnare mentre la copertura perde. La copertura riduce determinati rischi, ma non garantisce un profitto.<sup>[[1]](#references)</sup>

### Futures perpetui

I contratti perpetui sono derivati senza una data di scadenza fissa. Le piattaforme crypto usano comunemente pagamenti periodici di funding per mantenere il loro prezzo vicino al prezzo spot dell'asset sottostante; i termini variano da una piattaforma all'altra.<sup>[[3]](#references)</sup>

Per i test di abuso del tasso di funding sui protocolli perpetui on-chain, vedi [Sfruttamento del tasso di funding dei perpetui](perpetual-funding-rate-exploitation.md).

Il profitto e la perdita cambiano al variare del mark price. Una variazione dell'1% del prezzo produce una variazione di circa l'1% del valore nozionale della posizione, prima di commissioni e funding, ma la leva può rendere tale variazione una percentuale molto più elevata del collaterale versato.

### Futures con leva

La **leva** consente a un trader di controllare una posizione nozionale più ampia con un deposito di margine più ridotto. Le perdite non sono sempre limitate al margine iniziale: liquidazioni, gap, commissioni e regole della piattaforma possono causare ulteriori perdite.<sup>[[3]](#references)</sup>

Per esempio, 100 $ di margine con una leva 50x controllano una posizione da 5.000 $. Ignorando commissioni, funding e meccanismi di liquidazione, una variazione favorevole dell'1% produce un guadagno di 50 $ (il 50% del margine iniziale), mentre una variazione sfavorevole dell'1% produce una perdita di 50 $. Una variazione sfavorevole del 2% corrisponde a 100 $, anche se normalmente una piattaforma liquida la posizione prima che il margine si esaurisca.

La leva amplifica sia i guadagni sia le perdite e rende possibile la liquidazione anche dopo una variazione sfavorevole relativamente contenuta.

## Differenze tra futures e opzioni

L'acquirente di un'opzione riceve il diritto, ma non l'obbligo, di esercitarla secondo i termini del contratto. Chi emette l'opzione ha l'obbligo corrispondente se l'acquirente la esercita. L'acquirente paga all'emittente un premio per tale diritto.<sup>[[4]](#references)</sup>

### 1. **Obbligo vs. diritto:**

* **Futures:** Quando acquisti o vendi un contratto futures, stipuli un **accordo vincolante** per acquistare o vendere un asset a un prezzo specifico in una data futura. Sia l'acquirente sia il venditore sono **obbligati** a rispettare il contratto alla scadenza, salvo che venga chiuso prima.
* **Opzioni:** Con le opzioni hai il **diritto, ma non l'obbligo**, di acquistare (nel caso di un'**opzione call**) o vendere (nel caso di un'**opzione put**) un asset a un prezzo specifico prima o alla data di scadenza. L'**acquirente** può decidere se esercitare l'opzione, mentre il **venditore** è tenuto a eseguire l'operazione se l'acquirente decide di esercitarla.

### 2. **Rischio:**

* **Futures:** Entrambe le parti possono subire perdite sostanziali. Il fatto che la perdita sia matematicamente illimitata dipende dalla posizione e dall'asset sottostante: una posizione short può avere una perdita teorica illimitata, mentre una posizione long non può perdere più del valore nozionale se l'asset sottostante non può scendere sotto zero.
* **Opzioni:** Un acquirente che non emette un'altra opzione rischia generalmente il premio pagato. Chi emette una call scoperta può subire perdite teoricamente illimitate; le altre strategie di emissione di opzioni presentano profili di rischio diversi, limitati o illimitati.

### 3. **Costo:**

* **Futures:** Non c'è un costo iniziale oltre al margine richiesto per mantenere la posizione, poiché sia l'acquirente sia il venditore sono obbligati a completare l'operazione.
* **Opzioni:** L'acquirente deve pagare in anticipo un **premio dell'opzione** per avere il diritto di esercitarla. Questo premio è, in sostanza, il costo dell'opzione.

### 4. **Potenziale di profitto:**

* **Futures:** Il profitto o la perdita si basa sulla differenza tra il prezzo di mercato alla scadenza e il prezzo concordato nel contratto.
* **Opzioni:** L'acquirente guadagna quando il mercato si muove a suo favore oltre il prezzo d'esercizio di un importo superiore al premio pagato. Il venditore guadagna trattenendo il premio se l'opzione non viene esercitata.

## References

- [1] [CFTC - Lo scopo economico dei mercati futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Nozioni di base sui mercati futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprendere i rischi del trading di valute virtuali](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossario CFTC - Opzione, premio ed esercizio](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
