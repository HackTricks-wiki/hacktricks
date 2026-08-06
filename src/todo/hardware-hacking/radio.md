# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)è un analizzatore gratuito di segnali digitali per GNU/Linux e macOS, progettato per estrarre informazioni da segnali radio sconosciuti. Supporta diversi dispositivi SDR tramite SoapySDR e consente la demodulazione regolabile di segnali FSK, PSK e ASK, la decodifica di video analogici, l'analisi di segnali burst e l'ascolto di canali vocali analogici (tutto in tempo reale).<sup>[[1]](#references)</sup>

### Configurazione di base

Dopo l'installazione ci sono alcune impostazioni che potresti configurare.\
Nelle impostazioni (il secondo pulsante della scheda) puoi selezionare il **dispositivo SDR** o **selezionare un file** da leggere, oltre alla frequenza da sintonizzare e al Sample rate (si consiglia un valore fino a 2.56Msps se il PC lo supporta).

![Impostazioni di SigDigger con opzioni per dispositivo SDR, file di input, frequenza e sample rate](<../../images/image (245).png>)

Nel comportamento della GUI è consigliabile abilitare alcune opzioni, se il PC le supporta:

![SigDigger - Configurazione di base: nel comportamento della GUI è consigliabile abilitare alcune opzioni, se il PC le supporta](<../../images/image (472).png>)

> [!TIP]
> Se ti accorgi che il PC non sta catturando i dati, prova a disabilitare OpenGL e a ridurre il sample rate.

### Utilizzi

- Per **catturare una porzione di segnale e analizzarla**, tieni premuto il pulsante "Push to capture" per tutto il tempo necessario.

![Configurazione di base - Utilizzi: per catturare una porzione di segnale e analizzarla, tieni premuto il pulsante "Push to capture" per tutto il tempo necessario](<../../images/image (960).png>)

- Il **Tuner** di SigDigger aiuta a **catturare segnali migliori** (ma può anche peggiorarli). Idealmente, inizia da 0 e continua ad **aumentarlo finché** il **rumore** introdotto non diventa **maggiore del miglioramento del segnale** che ti serve.

![Controllo del tuner di SigDigger regolato per migliorare il segnale radio catturato](<../../images/image (1099).png>)

### Sincronizzazione con un canale radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronizzati con il canale che vuoi ascoltare, configura l'opzione "Baseband audio preview", imposta la bandwidth in modo da ottenere tutte le informazioni trasmesse e poi imposta il Tuner al livello precedente all'inizio dell'aumento significativo del rumore:<sup>[[1]](#references)</sup>

![Canale radio sincronizzato con SigDigger, anteprima audio baseband e bandwidth configurata](<../../images/image (585).png>)

## Trucchi interessanti

- Quando un dispositivo invia burst di informazioni, solitamente la **prima parte è un preambolo**, quindi **non devi preoccuparti** se **non trovi informazioni** al suo interno **o se contiene alcuni errori**.
- Nei frame di informazioni dovresti solitamente **trovare frame diversi ben allineati tra loro**:

![Sincronizzazione con un canale radio - Trucchi interessanti: nei frame di informazioni dovresti solitamente trovare frame diversi ben allineati tra loro](<../../images/image (1076).png>)

![Sincronizzazione con un canale radio - Trucchi interessanti: nei frame di informazioni dovresti solitamente trovare frame diversi ben allineati tra loro](<../../images/image (597).png>)

- **Dopo aver recuperato i bit potresti doverli elaborare in qualche modo**. Ad esempio, nella codifica Manchester, un up+down rappresenta 1 o 0 e un down+up rappresenta l'altro valore. Quindi le coppie di 1 e 0 (up e down) rappresenteranno un 1 o uno 0 reale.
- Anche se un segnale utilizza la codifica Manchester (è impossibile trovare più di due 0 o 1 consecutivi), potresti **trovare diversi 1 o 0 consecutivi nel preambolo**!

### Identificare il tipo di modulazione con IQ

Esistono 3 modi per memorizzare informazioni nei segnali: modulando **ampiezza**, **frequenza** o **fase**.\
Se stai analizzando un segnale, esistono diversi modi per cercare di capire quale tecnica viene utilizzata per memorizzare le informazioni (vedi altri metodi sotto), ma un metodo efficace consiste nel controllare il grafico IQ.

![Grafico IQ di SigDigger usato per identificare se un segnale utilizza modulazione di ampiezza, frequenza o fase](<../../images/image (788).png>)

- **Rilevare AM**: se nel grafico IQ compaiono, ad esempio, **2 cerchi** (probabilmente uno a 0 e l'altro a un'ampiezza diversa), potrebbe significare che si tratta di un segnale AM. Nel grafico IQ, infatti, la distanza tra lo 0 e il cerchio rappresenta l'ampiezza del segnale, quindi è facile visualizzare le diverse ampiezze utilizzate.
- **Rilevare PM**: come nell'immagine precedente, se trovi piccoli cerchi non correlati tra loro, probabilmente viene utilizzata una modulazione di fase. Nel grafico IQ, infatti, l'angolo tra il punto e lo 0,0 rappresenta la fase del segnale, quindi ciò significa che vengono utilizzate 4 fasi diverse.
- Nota che, se l'informazione è nascosta nel fatto che una fase cambia e non nella fase in sé, non vedrai fasi diverse chiaramente differenziate.
- **Rilevare FM**: IQ non dispone di un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare FM, in questo grafico dovresti **vedere essenzialmente solo un cerchio**.\
Inoltre, una frequenza diversa è "rappresentata" nel grafico IQ da una **variazione di velocità lungo il cerchio** (quindi, in SysDigger, selezionando il segnale il grafico IQ viene popolato; se trovi un'accelerazione o un cambio di direzione nel cerchio creato, potrebbe significare che si tratta di FM):

## Esempio AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificare AM

#### Controllare l'envelope

Controllando le informazioni AM con [**SigDigger** ](https://github.com/BatchDrake/SigDigger) e osservando semplicemente l'**envelope**, puoi vedere diversi livelli di ampiezza distinti. Il segnale utilizzato invia impulsi contenenti informazioni in AM; questo è l'aspetto di un impulso:<sup>[[1]](#references)</sup>

![Envelope del segnale AM in SigDigger con livelli di ampiezza degli impulsi distinti](<../../images/image (590).png>)

Questo è invece l'aspetto di una parte del simbolo con la forma d'onda:

![Identificare AM - Controllare l'envelope: aspetto di una parte del simbolo con la forma d'onda](<../../images/image (734).png>)

#### Controllare l'istogramma

Puoi **selezionare l'intero segnale** in cui sono presenti le informazioni, selezionare la modalità **Amplitude** e **Selection**, quindi fare clic su **Histogram.** Puoi osservare che sono presenti solo 2 livelli distinti.

![Istogramma dell'ampiezza di SigDigger che mostra due livelli distinti per il segnale AM selezionato](<../../images/image (264).png>)

Ad esempio, se selezioni Frequency invece di Amplitude in questo segnale AM, trovi una sola frequenza (non è possibile che un'informazione modulata in frequenza utilizzi una sola frequenza).

![Istogramma della frequenza di SigDigger per il segnale AM che mostra una sola frequenza](<../../images/image (732).png>)

Se trovi molte frequenze, probabilmente non si tratta di FM; la frequenza del segnale è stata probabilmente modificata semplicemente dal canale.

#### Con IQ

In questo esempio puoi vedere un **cerchio grande**, ma anche **molti punti al centro**.

![Controllare l'istogramma - Con IQ: esempio con un cerchio grande e molti punti al centro](<../../images/image (222).png>)

### Ottenere il Symbol Rate

#### Con un simbolo

Seleziona il simbolo più piccolo che riesci a trovare (così puoi essere certo che sia uno solo) e controlla "Selection freq". In questo caso sarebbe 1.013kHz (quindi 1kHz).

![Ottenere il Symbol Rate - Con un simbolo: seleziona il simbolo più piccolo e controlla "Selection freq". In questo caso sarebbe 1.013kHz (quindi 1kHz)](<../../images/image (78).png>)

#### Con un gruppo di simboli

Puoi anche indicare il numero di simboli che vuoi selezionare e SigDigger calcolerà la frequenza di 1 simbolo (probabilmente, più simboli selezioni, migliore sarà il risultato). In questo scenario ho selezionato 10 simboli e "Selection freq" è 1.004 Khz:

![Calcolo del symbol rate di SigDigger utilizzando un gruppo selezionato di dieci simboli](<../../images/image (1008).png>)

### Ottenere i bit

Dopo aver stabilito che si tratta di un segnale **modulato in AM** e aver trovato il **symbol rate** (sapendo che in questo caso un valore alto indica 1 e uno basso indica 0), è molto semplice **ottenere i bit** codificati nel segnale. Seleziona quindi il segnale contenente le informazioni, configura il campionamento e la decisione, quindi premi sample (verifica che sia selezionato **Amplitude**, che sia configurato il **Symbol rate** individuato e che sia selezionato **Gadner clock recovery**):

![Pannello Get Bits di SigDigger configurato per il campionamento AM, il symbol rate e il recupero del clock Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa che, se in precedenza hai selezionato intervalli per trovare il symbol rate, verrà utilizzato quel symbol rate.
- **Manual** significa che verrà utilizzato il symbol rate indicato.
- In **Fixed interval selection** indichi il numero di intervalli da selezionare e il programma calcola il symbol rate in base a essi.
- **Gadner clock recovery** è solitamente l'opzione migliore, ma devi comunque indicare un symbol rate approssimativo.

Premendo sample viene visualizzato quanto segue:

![Con un gruppo di simboli - Ottenere i bit: risultato visualizzato premendo sample](<../../images/image (644).png>)

Ora, per fare in modo che SigDigger riconosca **l'intervallo** del livello che contiene le informazioni, devi fare clic sul **livello inferiore** e mantenere premuto il pulsante fino al livello più alto:

![Selezione dell'intervallo dei livelli in SigDigger, dal livello di ampiezza inferiore a quello superiore](<../../images/image (439).png>)

Se, ad esempio, fossero stati presenti **4 livelli di ampiezza diversi**, avresti dovuto configurare **Bits per symbol** su 2 e selezionare dal livello più basso a quello più alto.

Infine, **aumentando** lo **Zoom** e **modificando la Row size**, puoi visualizzare i bit (puoi anche selezionare tutto e copiarlo per ottenere tutti i bit):

![Con un gruppo di simboli - Ottenere i bit: aumentando lo Zoom e modificando la Row size puoi visualizzare i bit](<../../images/image (276).png>)

Se il segnale ha più di 1 bit per simbolo (ad esempio 2), SigDigger non ha modo di sapere quale simbolo corrisponda a 00, 01, 10 o 11, quindi utilizzerà diverse **scale di grigio** per rappresentarli (e, se copi i bit, utilizzerà **numeri da 0 a 3**, che dovrai elaborare).

Inoltre, utilizza **codifiche** come **Manchester**, in cui up+down può rappresentare **1 o 0** e down+up può rappresentare 1 o 0. In questi casi devi **elaborare gli up (1) e i down (0)** ottenuti per sostituire le coppie 01 o 10 con 0 o 1.

## Esempio FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificare FM

#### Controllare le frequenze e la forma d'onda

Esempio di segnale che invia informazioni modulate in FM:

![Identificare FM - Controllare le frequenze e la forma d'onda: esempio di segnale che invia informazioni modulate in FM](<../../images/image (725).png>)

Nell'immagine precedente puoi osservare abbastanza chiaramente che vengono utilizzate **2 frequenze**, ma se **osservi** la **forma d'onda** potresti n**on riuscire a identificare correttamente le 2 frequenze diverse**:

![Forma d'onda FM di SigDigger in cui le due frequenze sono difficili da distinguere direttamente](<../../images/image (717).png>)

Questo accade perché ho catturato il segnale su entrambe le frequenze, quindi una è approssimativamente l'opposto negativo dell'altra:

![Cattura FM di SigDigger che mostra le due frequenze come approssimativi negativi l'una dell'altra](<../../images/image (942).png>)

Se la frequenza sincronizzata è **più vicina a una frequenza che all'altra**, puoi vedere facilmente le 2 frequenze diverse:

![Identificare FM - Controllare le frequenze e la forma d'onda: se la frequenza sincronizzata è più vicina a una frequenza che all'altra, puoi vedere facilmente le 2 frequenze diverse](<../../images/image (422).png>)

![Identificare FM - Controllare le frequenze e la forma d'onda: se la frequenza sincronizzata è più vicina a una frequenza che all'altra, puoi vedere facilmente le 2 frequenze diverse](<../../images/image (488).png>)

#### Controllare l'istogramma

Controllando l'istogramma della frequenza del segnale contenente informazioni, puoi vedere facilmente 2 segnali diversi:

![Controllare le frequenze e la forma d'onda - Controllare l'istogramma: controllando l'istogramma della frequenza del segnale contenente informazioni puoi vedere facilmente 2 segnali diversi](<../../images/image (871).png>)

In questo caso, se controlli l'**istogramma dell'ampiezza**, troverai **una sola ampiezza**, quindi **non può essere AM** (se trovi molte ampiezze, potrebbe essere perché il segnale ha perso potenza lungo il canale):

![Istogramma dell'ampiezza di SigDigger per un segnale FM che mostra un singolo livello di ampiezza](<../../images/image (817).png>)

Questo è l'istogramma della fase (che rende molto chiaro che il segnale non è modulato in fase):

![Controllare le frequenze e la forma d'onda - Controllare l'istogramma: istogramma della fase che mostra chiaramente che il segnale non è modulato in fase](<../../images/image (996).png>)

#### Con IQ

IQ non dispone di un campo per identificare le frequenze (la distanza dal centro è l'ampiezza e l'angolo è la fase).\
Pertanto, per identificare FM, in questo grafico dovresti **vedere essenzialmente solo un cerchio**.\
Inoltre, una frequenza diversa è "rappresentata" nel grafico IQ da una **variazione di velocità lungo il cerchio** (quindi, in SysDigger, selezionando il segnale il grafico IQ viene popolato; se trovi un'accelerazione o un cambio di direzione nel cerchio creato, potrebbe significare che si tratta di FM):

![Grafico IQ di SigDigger in cui FM appare come variazioni di accelerazione attorno al cerchio](<../../images/image (81).png>)

### Ottenere il Symbol Rate

Puoi utilizzare la **stessa tecnica usata nell'esempio AM** per ottenere il symbol rate, dopo aver trovato le frequenze che trasportano i simboli.

### Ottenere i bit

Puoi utilizzare la **stessa tecnica usata nell'esempio AM** per ottenere i bit, dopo aver **stabilito che il segnale è modulato in frequenza** e aver trovato il **symbol rate**.

## Riferimenti

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
