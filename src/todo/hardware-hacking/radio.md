# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)è un analizzatore di segnali digitali gratuito per GNU/Linux e macOS, progettato per estrarre informazioni da segnali radio sconosciuti. Supporta una varietà di dispositivi SDR tramite SoapySDR e consente la demodulazione regolabile di segnali FSK, PSK e ASK, decodifica video analogico, analisi di segnali burst e ascolto di canali vocali analogici (tutto in tempo reale).

### Configurazione di base

Dopo l'installazione ci sono alcune cose che potresti considerare di configurare.\
Nelle impostazioni (il secondo pulsante della scheda) puoi selezionare il **dispositivo SDR** o **selezionare un file** da leggere e quale frequenza sintonizzare e il tasso di campionamento (raccomandato fino a 2.56Msps se il tuo PC lo supporta)\\

![](<../../images/image (245).png>)

Nel comportamento della GUI è consigliato abilitare alcune cose se il tuo PC lo supporta:

![](<../../images/image (472).png>)

> [!NOTE]
> Se ti rendi conto che il tuo PC non cattura nulla, prova a disabilitare OpenGL e abbassare il tasso di campionamento.

### Usi

- Per **catturare un po' di un segnale e analizzarlo** basta mantenere premuto il pulsante "Push to capture" finché ne hai bisogno.

![](<../../images/image (960).png>)

- Il **Tuner** di SigDigger aiuta a **catturare segnali migliori** (ma può anche degradarli). Idealmente inizia da 0 e continua a **aumentarlo fino a** trovare che il **rumore** introdotto è **maggiore** del **miglioramento del segnale** di cui hai bisogno).

![](<../../images/image (1099).png>)

### Sincronizzazione con il canale radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincronizza con il canale che vuoi ascoltare, configura l'opzione "Anteprima audio a banda base", configura la larghezza di banda per ottenere tutte le informazioni inviate e poi imposta il Tuner al livello prima che il rumore inizi realmente ad aumentare:

![](<../../images/image (585).png>)

## Trucchi interessanti

- Quando un dispositivo sta inviando burst di informazioni, di solito la **prima parte sarà un preambolo**, quindi **non** devi **preoccuparti** se **non trovi informazioni** lì **o se ci sono alcuni errori**.
- Nei frame di informazioni di solito dovresti **trovare diversi frame ben allineati tra loro**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Dopo aver recuperato i bit potresti doverli elaborare in qualche modo**. Ad esempio, nella codifica Manchester un up+down sarà un 1 o 0 e un down+up sarà l'altro. Quindi coppie di 1 e 0 (up e down) saranno un vero 1 o un vero 0.
- Anche se un segnale utilizza la codifica Manchester (è impossibile trovare più di due 0 o 1 di seguito), potresti **trovare diversi 1 o 0 insieme nel preambolo**!

### Scoprire il tipo di modulazione con IQ

Ci sono 3 modi per memorizzare informazioni nei segnali: modulando l'**ampiezza**, la **frequenza** o la **fase**.\
Se stai controllando un segnale ci sono diversi modi per cercare di capire cosa viene utilizzato per memorizzare informazioni (trova più modi di seguito) ma uno buono è controllare il grafico IQ.

![](<../../images/image (788).png>)

- **Rilevamento AM**: Se nel grafico IQ appare ad esempio **2 cerchi** (probabilmente uno in 0 e l'altro in un'ampiezza diversa), potrebbe significare che questo è un segnale AM. Questo perché nel grafico IQ la distanza tra 0 e il cerchio è l'ampiezza del segnale, quindi è facile visualizzare diverse ampiezze utilizzate.
- **Rilevamento PM**: Come nell'immagine precedente, se trovi piccoli cerchi non correlati tra loro probabilmente significa che viene utilizzata una modulazione di fase. Questo perché nel grafico IQ, l'angolo tra il punto e il 0,0 è la fase del segnale, quindi significa che vengono utilizzate 4 fasi diverse.
- Nota che se le informazioni sono nascoste nel fatto che una fase è cambiata e non nella fase stessa, non vedrai fasi diverse chiaramente differenziate.
- **Rilevamento FM**: IQ non ha un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare FM, dovresti **vedere solo fondamentalmente un cerchio** in questo grafico.\
Inoltre, una frequenza diversa è "rappresentata" dal grafico IQ da un'**accelerazione di velocità attraverso il cerchio** (quindi in SysDigger selezionando il segnale il grafico IQ viene popolato, se trovi un'accelerazione o un cambiamento di direzione nel cerchio creato potrebbe significare che questo è FM):

## Esempio AM

{% file src="../../images/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Scoprire AM

#### Controllare l'inviluppo

Controllando le informazioni AM con [**SigDigger** ](https://github.com/BatchDrake/SigDigger) e semplicemente guardando l'**inviluppo** puoi vedere diversi livelli di ampiezza chiari. Il segnale utilizzato sta inviando impulsi con informazioni in AM, ecco come appare un impulso:

![](<../../images/image (590).png>)

Ecco come appare parte del simbolo con l'onda:

![](<../../images/image (734).png>)

#### Controllare l'istogramma

Puoi **selezionare l'intero segnale** dove si trovano le informazioni, selezionare la modalità **Ampiezza** e **Selezione** e cliccare su **Istogramma.** Puoi osservare che si trovano solo 2 livelli chiari

![](<../../images/image (264).png>)

Ad esempio, se selezioni Frequenza invece di Ampiezza in questo segnale AM trovi solo 1 frequenza (non c'è modo che le informazioni modulate in frequenza stiano usando solo 1 frequenza).

![](<../../images/image (732).png>)

Se trovi molte frequenze probabilmente questo non sarà un FM, probabilmente la frequenza del segnale è stata solo modificata a causa del canale.

#### Con IQ

In questo esempio puoi vedere come c'è un **grande cerchio** ma anche **molti punti al centro.**

![](<../../images/image (222).png>)

### Ottenere il tasso di simboli

#### Con un simbolo

Seleziona il simbolo più piccolo che puoi trovare (così sei sicuro che sia solo 1) e controlla la "Frequenza di selezione". In questo caso sarebbe 1.013kHz (quindi 1kHz).

![](<../../images/image (78).png>)

#### Con un gruppo di simboli

Puoi anche indicare il numero di simboli che stai per selezionare e SigDigger calcolerà la frequenza di 1 simbolo (più simboli selezionati, meglio è probabilmente). In questo scenario ho selezionato 10 simboli e la "Frequenza di selezione" è 1.004 Khz:

![](<../../images/image (1008).png>)

### Ottenere i bit

Avendo trovato che questo è un segnale **modulato in AM** e il **tasso di simboli** (e sapendo che in questo caso qualcosa up significa 1 e qualcosa down significa 0), è molto facile **ottenere i bit** codificati nel segnale. Quindi, seleziona il segnale con informazioni e configura il campionamento e la decisione e premi campione (controlla che **Ampiezza** sia selezionato, il **Tasso di simboli** scoperto è configurato e il **recupero dell'orologio di Gadner** è selezionato):

![](<../../images/image (965).png>)

- **Sincronizza con gli intervalli di selezione** significa che se hai precedentemente selezionato intervalli per trovare il tasso di simboli, quel tasso di simboli sarà utilizzato.
- **Manuale** significa che il tasso di simboli indicato sarà utilizzato
- Nella **Selezione a intervallo fisso** indichi il numero di intervalli che dovrebbero essere selezionati e calcola il tasso di simboli da esso
- **Recupero dell'orologio di Gadner** è di solito la migliore opzione, ma devi comunque indicare un tasso di simboli approssimativo.

Premendo campione appare questo:

![](<../../images/image (644).png>)

Ora, per far capire a SigDigger **dove si trova l'intervallo** del livello che trasporta informazioni devi cliccare sul **livello più basso** e mantenere premuto fino al livello più alto:

![](<../../images/image (439).png>)

Se ci fossero stati ad esempio **4 diversi livelli di ampiezza**, dovresti configurare i **Bit per simbolo a 2** e selezionare dal più piccolo al più grande.

Infine **aumentando** lo **Zoom** e **cambiando la dimensione della riga** puoi vedere i bit (e puoi selezionare tutto e copiare per ottenere tutti i bit):

![](<../../images/image (276).png>)

Se il segnale ha più di 1 bit per simbolo (ad esempio 2), SigDigger **non ha modo di sapere quale simbolo è** 00, 01, 10, 11, quindi utilizzerà diverse **scale di grigio** per rappresentare ciascuno (e se copi i bit utilizzerà **numeri da 0 a 3**, dovrai trattarli).

Inoltre, usa **codificazioni** come **Manchester**, e **up+down** può essere **1 o 0** e un down+up può essere un 1 o 0. In quei casi devi **trattare gli up ottenuti (1) e i down (0)** per sostituire le coppie di 01 o 10 come 0 o 1.

## Esempio FM

{% file src="../../images/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Scoprire FM

#### Controllare le frequenze e l'onda

Esempio di segnale che invia informazioni modulate in FM:

![](<../../images/image (725).png>)

Nell'immagine precedente puoi osservare abbastanza bene che **vengono utilizzate 2 frequenze** ma se **osservi** l'**onda** potresti **non essere in grado di identificare correttamente le 2 diverse frequenze**:

![](<../../images/image (717).png>)

Questo perché ho catturato il segnale in entrambe le frequenze, quindi una è approssimativamente l'altra in negativo:

![](<../../images/image (942).png>)

Se la frequenza sincronizzata è **più vicina a una frequenza che all'altra** puoi facilmente vedere le 2 diverse frequenze:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Controllare l'istogramma

Controllando l'istogramma delle frequenze del segnale con informazioni puoi facilmente vedere 2 segnali diversi:

![](<../../images/image (871).png>)

In questo caso se controlli l'**istogramma dell'ampiezza** troverai **solo un'ampiezza**, quindi **non può essere AM** (se trovi molte ampiezze potrebbe essere perché il segnale ha perso potenza lungo il canale):

![](<../../images/image (817).png>)

E questo sarebbe l'istogramma di fase (che rende molto chiaro che il segnale non è modulato in fase):

![](<../../images/image (996).png>)

#### Con IQ

IQ non ha un campo per identificare le frequenze (la distanza dal centro è ampiezza e l'angolo è fase).\
Pertanto, per identificare FM, dovresti **vedere solo fondamentalmente un cerchio** in questo grafico.\
Inoltre, una frequenza diversa è "rappresentata" dal grafico IQ da un'**accelerazione di velocità attraverso il cerchio** (quindi in SysDigger selezionando il segnale il grafico IQ viene popolato, se trovi un'accelerazione o un cambiamento di direzione nel cerchio creato potrebbe significare che questo è FM):

![](<../../images/image (81).png>)

### Ottenere il tasso di simboli

Puoi usare la **stessa tecnica di quella utilizzata nell'esempio AM** per ottenere il tasso di simboli una volta che hai trovato le frequenze che trasportano simboli.

### Ottenere i bit

Puoi usare la **stessa tecnica di quella utilizzata nell'esempio AM** per ottenere i bit una volta che hai **trovato che il segnale è modulato in frequenza** e il **tasso di simboli**.

{{#include ../../banners/hacktricks-training.md}}
