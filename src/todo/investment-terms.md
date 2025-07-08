# Termini di Investimento

{{#include /banners/hacktricks-training.md}}

## Spot

Questo è il modo più basilare per fare trading. Puoi **indicare l'importo dell'asset e il prezzo** che desideri comprare o vendere, e ogni volta che quel prezzo viene raggiunto l'operazione viene eseguita.

Di solito puoi anche utilizzare il **prezzo di mercato attuale** per effettuare la transazione il più rapidamente possibile al prezzo attuale.

**Stop Loss - Limit**: Puoi anche indicare l'importo e il prezzo degli asset da comprare o vendere, indicando anche un prezzo inferiore per comprare o vendere nel caso venga raggiunto (per fermare le perdite).

## Futures

Un future è un contratto in cui 2 parti raggiungono un accordo per **acquisire qualcosa in futuro a un prezzo fisso**. Ad esempio, vendere 1 bitcoin tra 6 mesi a 70.000$.

Ovviamente, se tra 6 mesi il valore del bitcoin è 80.000$, la parte venditrice perde denaro e la parte acquirente guadagna. Se tra 6 mesi il valore del bitcoin è 60.000$, succede il contrario.

Tuttavia, questo è interessante, ad esempio, per le aziende che stanno generando un prodotto e hanno bisogno di avere la sicurezza di poterlo vendere a un prezzo che copra i costi. O per le aziende che vogliono garantire prezzi fissi in futuro per qualcosa anche se più alti.

Sebbene negli scambi questo venga solitamente utilizzato per cercare di realizzare un profitto.

* Nota che una "Posizione Long" significa che qualcuno sta scommettendo che un prezzo aumenterà
* Mentre una "Posizione Short" significa che qualcuno sta scommettendo che un prezzo scenderà

### Hedging Con i Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Se un gestore di fondi teme che alcune azioni scenderanno, potrebbe prendere una posizione short su alcuni asset come bitcoin o contratti futures S\&P 500. Questo sarebbe simile a comprare o possedere alcuni asset e creare un contratto per vendere quelli a un prezzo maggiore in un momento futuro.

Nel caso in cui il prezzo scenda, il gestore del fondo guadagnerà benefici perché venderà gli asset a un prezzo maggiore. Se il prezzo degli asset aumenta, il gestore non guadagnerà quel beneficio ma manterrà comunque i suoi asset.

### Futures Perpetui

**Questi sono "futures" che dureranno indefinitamente** (senza una data di scadenza del contratto). È molto comune trovarli, ad esempio, negli scambi di criptovalute dove puoi entrare e uscire dai futures in base al prezzo delle criptovalute.

Nota che in questi casi i benefici e le perdite possono essere in tempo reale; se il prezzo aumenta dell'1%, guadagni l'1%, se il prezzo diminuisce dell'1%, lo perderai.

### Futures con Leva

**La leva** ti consente di controllare una posizione più grande nel mercato con una minore quantità di denaro. Fondamentalmente ti consente di "scommettere" molto più denaro di quanto hai, rischiando solo il denaro che hai effettivamente.

Ad esempio, se apri una posizione future nel BTC/USDT con 100$ a una leva di 50x, questo significa che se il prezzo aumenta dell'1%, guadagneresti 1x50 = 50% del tuo investimento iniziale (50$). E quindi avrai 150$.\
Tuttavia, se il prezzo diminuisce dell'1%, perderai il 50% dei tuoi fondi (59$ in questo caso). E se il prezzo diminuisce del 2%, perderai tutta la tua scommessa (2x50 = 100%).

Pertanto, la leva consente di controllare l'importo di denaro su cui scommetti, aumentando i guadagni e le perdite.

## Differenze tra Futures e Opzioni

La principale differenza tra futures e opzioni è che il contratto è facoltativo per l'acquirente: può decidere di eseguirlo o meno (di solito lo farà solo se ne trarrà beneficio). Il venditore deve vendere se l'acquirente desidera utilizzare l'opzione.\
Tuttavia, l'acquirente pagherà una commissione al venditore per aprire l'opzione (quindi il venditore, che apparentemente sta assumendo più rischi, inizia a guadagnare denaro).

### 1. **Obbligo vs. Diritto:**

* **Futures:** Quando acquisti o vendi un contratto futures, stai entrando in un **accordo vincolante** per acquistare o vendere un asset a un prezzo specifico in una data futura. Sia l'acquirente che il venditore sono **obbligati** a rispettare il contratto alla scadenza (a meno che il contratto non venga chiuso prima).
* **Opzioni:** Con le opzioni, hai il **diritto, ma non l'obbligo**, di acquistare (nel caso di un **call option**) o vendere (nel caso di un **put option**) un asset a un prezzo specifico prima o alla scadenza. L'**acquirente** ha l'opzione di eseguire, mentre il **venditore** è obbligato a completare l'operazione se l'acquirente decide di esercitare l'opzione.

### 2. **Rischio:**

* **Futures:** Sia l'acquirente che il venditore assumono un **rischio illimitato** perché sono obbligati a completare il contratto. Il rischio è la differenza tra il prezzo concordato e il prezzo di mercato alla data di scadenza.
* **Opzioni:** Il rischio dell'acquirente è limitato al **premio** pagato per acquistare l'opzione. Se il mercato non si muove a favore del titolare dell'opzione, può semplicemente lasciare scadere l'opzione. Tuttavia, il **venditore** (scrittore) dell'opzione ha un rischio illimitato se il mercato si muove significativamente contro di lui.

### 3. **Costo:**

* **Futures:** Non ci sono costi iniziali oltre al margine richiesto per mantenere la posizione, poiché sia l'acquirente che il venditore sono obbligati a completare l'operazione.
* **Opzioni:** L'acquirente deve pagare un **premio per l'opzione** in anticipo per il diritto di esercitare l'opzione. Questo premio è essenzialmente il costo dell'opzione.

### 4. **Potenziale di Profitto:**

* **Futures:** Il profitto o la perdita si basa sulla differenza tra il prezzo di mercato alla scadenza e il prezzo concordato nel contratto.
* **Opzioni:** L'acquirente guadagna quando il mercato si muove favorevolmente oltre il prezzo di esercizio di più del premio pagato. Il venditore guadagna mantenendo il premio se l'opzione non viene esercitata.

{{#include /banners/hacktricks-training.md}}
