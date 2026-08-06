# Termini degli investimenti

{{#include ../banners/hacktricks-training.md}}

## Spot

Questo è il modo più basilare per fare trading. Puoi **indicare la quantità dell'asset e il prezzo** al quale vuoi acquistare o vendere e, ogni volta che viene raggiunto quel prezzo, l'operazione viene eseguita.

Di solito puoi anche usare il **prezzo corrente di mercato** per eseguire la transazione il più rapidamente possibile al prezzo corrente.

**Stop Loss - Limit**: puoi anche indicare la quantità e il prezzo degli asset da acquistare o vendere, specificando inoltre un prezzo più basso al quale acquistare o vendere nel caso venga raggiunto (per limitare le perdite).

## Futures

Un future è un contratto in cui 2 parti concordano di **acquistare qualcosa in futuro a un prezzo fisso**. Per esempio, vendere 1 bitcoin tra 6 mesi a 70.000$.

Ovviamente, se dopo 6 mesi il valore del bitcoin è di 80.000$, il venditore perde denaro e l'acquirente lo guadagna. Se dopo 6 mesi il valore del bitcoin è di 60.000$, accade il contrario.

Tuttavia, questo è interessante, per esempio, per le aziende che producono un prodotto e hanno bisogno della certezza di poterlo vendere a un prezzo sufficiente a coprire i costi. Oppure per le aziende che vogliono assicurarsi prezzi fissi in futuro per qualcosa, anche se più elevati.

Sebbene negli exchange venga solitamente utilizzato per cercare di ottenere un profitto.

* Nota che una "posizione Long" significa che qualcuno sta scommettendo sul fatto che il prezzo aumenterà
* Mentre una "posizione short" significa che qualcuno sta scommettendo sul fatto che il prezzo diminuirà

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Se un gestore di fondi teme che alcune azioni scenderanno, potrebbe assumere una posizione short su alcuni asset, come bitcoin o contratti futures sull'S\&P 500. Questo sarebbe simile all'acquistare o possedere alcuni asset e creare un contratto per venderli in futuro a un prezzo più elevato.

Nel caso in cui il prezzo scenda, il gestore del fondo otterrà un profitto perché venderà gli asset a un prezzo più elevato. Se il prezzo degli asset aumenta, il gestore non otterrà quel profitto, ma manterrà comunque i suoi asset.

### Perpetual Futures

**Questi sono "futures" che durano indefinitamente** (senza una data di scadenza del contratto). È molto comune trovarli, per esempio, negli exchange crypto, dove puoi entrare e uscire dai futures in base al prezzo delle crypto.

Nota che in questi casi il profitto e la perdita possono verificarsi in tempo reale: se il prezzo aumenta dell'1%, guadagni l'1%; se il prezzo diminuisce dell'1%, lo perdi.

### Futures with Leverage

La **Leverage** ti consente di controllare una posizione più grande sul mercato con una quantità di denaro minore. In pratica, ti permette di "scommettere" molto più denaro di quello che possiedi, rischiando solo il denaro che hai effettivamente.

Per esempio, se apri una posizione future su BTC/USDT con 100$ e una leva 50x, significa che, se il prezzo aumenta dell'1%, guadagnerai 1x50 = il 50% del tuo investimento iniziale (50$). E quindi avrai 150$.\
Tuttavia, se il prezzo diminuisce dell'1%, perderai il 50% dei tuoi fondi (59$ in questo caso). E se il prezzo diminuisce del 2%, perderai tutta la tua scommessa (2x50 = 100%).

Pertanto, la leva consente di controllare la quantità di denaro scommessa, aumentando al contempo i guadagni e le perdite.

## Differenze tra Futures e Options

La differenza principale tra futures e options è che il contratto è facoltativo per l'acquirente: può decidere se eseguirlo o meno (di solito lo farà solo se ne trarrà beneficio). Il venditore deve vendere se l'acquirente vuole utilizzare l'opzione.\
Tuttavia, l'acquirente pagherà una commissione al venditore per l'apertura dell'opzione (quindi il venditore, che apparentemente si assume un rischio maggiore, inizia a guadagnare del denaro).

### 1. **Obbligo vs. Diritto:**

* **Futures:** Quando acquisti o vendi un contratto futures, stai stipulando un **accordo vincolante** per acquistare o vendere un asset a un prezzo specifico in una data futura. Sia l'acquirente sia il venditore sono **obbligati** a rispettare il contratto alla scadenza (a meno che il contratto non venga chiuso prima).
* **Options:** Con le options, hai il **diritto, ma non l'obbligo**, di acquistare (nel caso di una **call option**) o vendere (nel caso di una **put option**) un asset a un prezzo specifico prima o alla scadenza stabilita. L'**acquirente** ha la possibilità di eseguire l'operazione, mentre il **venditore** è obbligato a completarla se l'acquirente decide di esercitare l'opzione.

### 2. **Rischio:**

* **Futures:** Sia l'acquirente sia il venditore assumono un **rischio illimitato**, perché sono obbligati a completare il contratto. Il rischio corrisponde alla differenza tra il prezzo concordato e il prezzo di mercato alla data di scadenza.
* **Options:** Il rischio dell'acquirente è limitato al **premio** pagato per acquistare l'opzione. Se il mercato non si muove a favore del titolare dell'opzione, questi può semplicemente lasciarla scadere. Tuttavia, il **venditore** (writer) dell'opzione ha un rischio illimitato se il mercato si muove significativamente contro di lui.

### 3. **Costo:**

* **Futures:** Non vi è alcun costo iniziale oltre al margine richiesto per mantenere la posizione, poiché sia l'acquirente sia il venditore sono obbligati a completare l'operazione.
* **Options:** L'acquirente deve pagare in anticipo un **premio dell'opzione** per ottenere il diritto di esercitarla. Questo premio rappresenta essenzialmente il costo dell'opzione.

### 4. **Potenziale di profitto:**

* **Futures:** Il profitto o la perdita si basa sulla differenza tra il prezzo di mercato alla scadenza e il prezzo concordato nel contratto.
* **Options:** L'acquirente ottiene un profitto quando il mercato si muove favorevolmente oltre lo strike price per un importo superiore al premio pagato. Il venditore ottiene un profitto trattenendo il premio se l'opzione non viene esercitata.

{{#include ../banners/hacktricks-training.md}}
