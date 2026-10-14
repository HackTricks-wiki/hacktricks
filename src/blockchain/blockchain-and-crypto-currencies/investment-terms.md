# Termini di investimento

{{#include ../../banners/hacktricks-training.md}}

## Spot

Il trading spot consiste nello scambiare un asset con consegna immediata. Un ordine limite specifica la quantità e il prezzo limite; viene eseguito solo quando il mercato può soddisfare quel prezzo o uno migliore. Un ordine a mercato punta invece a un’esecuzione rapida ai migliori prezzi disponibili in quel momento e può subire slippage.<sup>[[4]](#references)</sup>

Un ordine stop-limit ha un prezzo stop che attiva un ordine limite. Può vincolare il prezzo di esecuzione, ma non ne garantisce l’esecuzione se il mercato supera il limite.<sup>[[4]](#references)</sup>

## Futures

Un contratto futures è un accordo standardizzato per acquistare o vendere una determinata materia prima o uno strumento finanziario a una data futura. Per esempio, due parti potrebbero concordare un prezzo di $70,000 per un bitcoin con regolamento tra sei mesi.<sup>[[1]](#references)</sup>

Se il prezzo di regolamento è $80,000, la posizione long guadagna e quella short perde rispetto al prezzo contrattuale di $70,000. Se è $60,000, la situazione si inverte. I futures effettivamente negoziati in borsa sono contabilizzati al valore di mercato e di solito vengono chiusi o rinnovati prima della scadenza: si tratta quindi di un esempio semplificato.<sup>[[2]](#references)</sup>

Produttori e consumatori usano i futures per coprirsi dal rischio di prezzo; altri partecipanti li usano per cercare un profitto o fornire liquidità.<sup>[[1]](#references)</sup>

- Una **posizione long** in genere guadagna quando il prezzo del contratto sale.
- Una **posizione short** in genere guadagna quando il prezzo del contratto scende.<sup>[[2]](#references)</sup>

### Copertura con i futures

Se un gestore di fondi prevede un calo del portafoglio, potrebbe vendere allo scoperto un contratto futures su un indice azionario sufficientemente correlato. I guadagni sulla posizione di copertura short possono compensare parte delle perdite del portafoglio; il rischio di base fa sì che la compensazione sia raramente esatta. Un future sul bitcoin coprirebbe l’esposizione al bitcoin, non automaticamente quella azionaria.

Se il mercato coperto scende, la posizione futures short può guadagnare mentre le partecipazioni perdono valore. Se sale, le partecipazioni possono guadagnare mentre la copertura perde. La copertura riduce determinati rischi, ma non garantisce un profitto.<sup>[[1]](#references)</sup>

### Futures perpetui

I contratti perpetui sono derivati senza una data di scadenza fissa. Le piattaforme crypto usano comunemente pagamenti periodici di funding per mantenere il loro prezzo vicino a quello spot dell’asset sottostante; le condizioni variano da una piattaforma all’altra.<sup>[[3]](#references)</sup>

Profitti e perdite variano al muoversi del mark price. Una variazione di prezzo dell’1% produce approssimativamente una variazione dell’1% sul valore nozionale della posizione, prima di commissioni e funding, ma la leva può rendere tale variazione molto più ampia in percentuale rispetto al collaterale versato.

### Futures con leva

La **leva** consente a un trader di controllare una posizione nozionale più ampia con un deposito di margine inferiore. Le perdite non sono sempre limitate al margine iniziale: liquidazione, gap di prezzo, commissioni e regole della piattaforma possono comportare ulteriori perdite.<sup>[[3]](#references)</sup>

Per esempio, $100 di margine con una leva 50x controllano una posizione da $5,000. Ignorando commissioni, funding e meccanismi di liquidazione, una variazione favorevole dell’1% genera un guadagno di $50 (il 50% del margine iniziale), mentre una variazione sfavorevole dell’1% genera una perdita di $50. Una variazione sfavorevole del 2% equivale a $100, anche se normalmente la piattaforma liquida la posizione prima che il margine sia esaurito.

La leva amplifica sia i guadagni sia le perdite e rende possibile la liquidazione anche dopo una variazione sfavorevole relativamente ridotta.

## Differenze tra futures e opzioni

L’acquirente di un’opzione ottiene il diritto, ma non l’obbligo, di esercitarla secondo le condizioni del contratto. Chi vende l’opzione assume l’obbligo corrispondente se l’acquirente la esercita. L’acquirente paga al venditore un premio per tale diritto.<sup>[[4]](#references)</sup>

### 1. **Obbligo vs. diritto:**

* **Futures:** Quando acquisti o vendi un contratto futures, stipuli un **accordo vincolante** per acquistare o vendere un asset a un prezzo specifico in una data futura. Sia l’acquirente sia il venditore sono **obbligati** a rispettare il contratto alla scadenza, salvo che venga chiuso prima.
* **Opzioni:** Con le opzioni hai il **diritto, ma non l’obbligo**, di acquistare (nel caso di un’**opzione call**) o vendere (nel caso di un’**opzione put**) un asset a un prezzo specifico, entro o alla data di scadenza. L’**acquirente** può decidere di esercitare l’opzione, mentre il **venditore** è tenuto a eseguire l’operazione se l’acquirente decide di esercitarla.

### 2. **Rischio:**

* **Futures:** Entrambe le parti possono subire perdite ingenti. Il fatto che la perdita sia illimitata dal punto di vista matematico dipende dalla posizione e dall’asset sottostante: una posizione short può avere una perdita teorica illimitata, mentre una posizione long non può perdere più del valore nozionale se l’asset sottostante non può scendere sotto zero.
* **Opzioni:** Un acquirente che non vende a sua volta un’altra opzione rischia generalmente il premio pagato. Chi vende una call scoperta può subire perdite teoricamente illimitate; altre strategie di vendita di opzioni presentano profili di rischio diversi, limitati o illimitati.

### 3. **Costo:**

* **Futures:** Non ci sono costi iniziali oltre al margine richiesto per mantenere la posizione, poiché sia l’acquirente sia il venditore sono obbligati a completare l’operazione.
* **Opzioni:** L’acquirente deve pagare in anticipo un **premio dell’opzione** per ottenere il diritto di esercitarla. Questo premio rappresenta, in sostanza, il costo dell’opzione.

### 4. **Potenziale di profitto:**

* **Futures:** Il profitto o la perdita dipende dalla differenza tra il prezzo di mercato alla scadenza e il prezzo concordato nel contratto.
* **Opzioni:** L’acquirente ottiene un profitto quando il mercato si muove a suo favore oltre il prezzo di esercizio di un importo superiore al premio pagato. Il venditore guadagna trattenendo il premio se l’opzione non viene esercitata.

## References

- [1] [CFTC - Lo scopo economico dei mercati futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Nozioni di base sul mercato dei futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprendere i rischi del trading di valute virtuali](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossario CFTC - Opzione, premio ed esercizio](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
