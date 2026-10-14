# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) è un analizzatore gratuito di segnali digitali per GNU/Linux e macOS, progettato per estrarre informazioni da segnali radio sconosciuti. Supporta i dispositivi SDR tramite SoapySDR e offre strumenti di demodulazione e analisi in tempo reale per FSK, PSK, ASK, video analogico, segnali a raffiche e canali vocali analogici.<sup>[[1]](#references)</sup>

### Configurazione di base

Dopo l'installazione, ci sono alcune impostazioni che potresti voler configurare.\
Nelle impostazioni (il secondo pulsante della scheda), seleziona un **dispositivo SDR** o un file di input, la frequenza da sintonizzare e il sample rate. Un valore fino a 2.56 Msps può essere pratico, se supportato dal sistema host.

![Impostazioni di SigDigger con le opzioni per dispositivo SDR, file di input, frequenza e sample rate](<../../images/image (245).png>)

Per il comportamento della GUI, è consigliabile abilitare alcune opzioni, se il PC le supporta:

![SigDigger - Configurazione di base: per il comportamento della GUI è consigliabile abilitare alcune opzioni, se il PC le supporta](<../../images/image (472).png>)

> [!TIP]
> Se ti accorgi che il PC non acquisisce i dati, prova a disabilitare OpenGL e a ridurre il sample rate.

### Utilizzi

- Per **acquisire un tratto del segnale e analizzarlo**, tieni premuto il pulsante "Push to capture" per il tempo necessario.

![Configurazione di base - Utilizzi: per acquisire un tratto del segnale e analizzarlo, tieni premuto il pulsante "Push to capture" per il tempo necessario](<../../images/image (960).png>)

- Il **Tuner** di SigDigger aiuta a **catturare segnali migliori** (ma può anche peggiorarli). Idealmente, parti da 0 e **aumenta il valore finché** il **rumore** introdotto non diventa **maggiore** del **miglioramento del segnale** che ti serve.

![Controllo Tuner di SigDigger regolato per migliorare il segnale radio acquisito](<../../images/image (1099).png>)

### Sincronizzazione con un canale radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronizzati con il canale che vuoi ascoltare, configura l'opzione "Baseband audio preview", imposta la larghezza di banda per ricevere tutte le informazioni trasmesse e regola il Tuner appena prima che il rumore inizi ad aumentare sensibilmente:<sup>[[1]](#references)</sup>

![Canale radio sincronizzato in SigDigger con l'anteprima audio in banda base e la larghezza di banda configurate](<../../images/image (585).png>)

## Trucchi interessanti

- Quando un dispositivo invia informazioni a raffiche, di solito la **prima parte è un preambolo**: quindi **non** devi **preoccuparti** se **non trovi informazioni** in quella parte **o se contiene alcuni errori**.
- Nei frame di informazioni, di solito dovresti **trovare frame diversi ben allineati tra loro**:

![Sincronizzazione con un canale radio - Trucchi interessanti: nei frame di informazioni, di solito dovresti trovare frame diversi ben allineati tra loro](<../../images/image (1076).png>)

![Sincronizzazione con un canale radio - Trucchi interessanti: nei frame di informazioni, di solito dovresti trovare frame diversi ben allineati tra loro](<../../images/image (597).png>)

- **Dopo aver recuperato le transizioni di livello, potrebbe essere necessario decodificarle.** Nella codifica Manchester, una direzione della transizione rappresenta `0` e la direzione opposta rappresenta `1`; la polarità esatta dipende dalla convenzione utilizzata.
- Un preambolo può contenere una sequenza dello stesso livello campionato anche quando il payload usa la codifica Manchester: individua quindi il confine del frame prima di decodificarlo.

### Individuare il tipo di modulazione con IQ

Esistono 3 modi per codificare le informazioni nei segnali: modulando l'**ampiezza**, la **frequenza** o la **fase**.\
Per capire quale metodo viene usato per codificare le informazioni in un segnale, si possono provare diversi approcci (vedi altri metodi sotto), ma un buon metodo consiste nel controllare il grafico IQ.

![Grafico IQ di SigDigger utilizzato per determinare se un segnale usa la modulazione di ampiezza, frequenza o fase](<../../images/image (788).png>)

- **Rilevamento AM**: se nel grafico IQ compaiono, ad esempio, **2 cerchi** (probabilmente uno in 0 e l'altro a un'ampiezza diversa), potrebbe trattarsi di un segnale AM. Nel grafico IQ, infatti, la distanza tra lo 0 e il cerchio corrisponde all'ampiezza del segnale, quindi è facile visualizzare le diverse ampiezze utilizzate.
- **Rilevamento PM**: come nell'immagine precedente, se trovi piccoli cerchi non correlati tra loro, probabilmente viene usata una modulazione di fase. Nel grafico IQ, infatti, l'angolo tra il punto e lo 0,0 corrisponde alla fase del segnale, il che significa che vengono usate 4 fasi diverse.
  - Nota che, se l'informazione è codificata nel fatto che la fase cambia e non nella fase stessa, non vedrai fasi diverse chiaramente distinguibili.
- **Rilevamento FM**: IQ non ha un campo per identificare le frequenze (la distanza dal centro corrisponde all'ampiezza e l'angolo alla fase).\
  Pertanto, per identificare la FM, in questo grafico dovresti **vedere essenzialmente solo un cerchio**.\
  Inoltre, uno scostamento di frequenza cambia la velocità di rotazione intorno al cerchio IQ. In SigDigger, un cambiamento della velocità o della direzione di rotazione può quindi indicare la FM.

## Esempio AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Individuare la AM

#### Controllare l'inviluppo

Quando esamini dati AM con [**SigDigger**](https://github.com/BatchDrake/SigDigger), l'**inviluppo** del segnale può rivelare livelli di ampiezza distinti. Il segnale di esempio trasmette informazioni sotto forma di impulsi modulati in ampiezza; un impulso è simile a questo:<sup>[[1]](#references)</sup>

![Inviluppo del segnale AM in SigDigger con livelli di ampiezza degli impulsi ben distinti](<../../images/image (590).png>)

Ecco come appare una parte del simbolo con la forma d'onda:

![Individuare la AM - Controllare l'inviluppo: ecco come appare una parte del simbolo con la forma d'onda](<../../images/image (734).png>)

#### Controllare l'istogramma

Puoi **selezionare tutto il segnale** contenente le informazioni, selezionare la modalità **Amplitude** e **Selection**, quindi fare clic su **Histogram**. Si possono osservare solo 2 livelli distinti.

![Istogramma di ampiezza in SigDigger che mostra due livelli distinti per il segnale AM selezionato](<../../images/image (264).png>)

Ad esempio, se in questo segnale AM selezioni Frequency invece di Amplitude, trovi una sola frequenza (non è possibile che informazioni modulate in frequenza usino una sola frequenza).

![Istogramma delle frequenze in SigDigger per il segnale AM, che mostra una sola frequenza](<../../images/image (732).png>)

Se trovi molte frequenze, probabilmente non si tratta di FM: la frequenza del segnale potrebbe essere stata modificata semplicemente a causa del canale.

#### Con IQ

In questo esempio puoi vedere un **cerchio grande**, ma anche **molti punti al centro**.

![Controllare l'istogramma - Con IQ: in questo esempio puoi vedere un cerchio grande, ma anche molti punti al centro](<../../images/image (222).png>)

### Determinare il symbol rate

#### Con un simbolo

Seleziona l'intervallo più piccolo che contiene chiaramente un simbolo e controlla **Selection freq**. In questo esempio è 1.013 kHz, cioè circa 1 kHz.

![Determinare il symbol rate - Con un simbolo: seleziona l'intervallo più piccolo che riesci a individuare (così puoi essere certo che contenga un solo simbolo) e controlla "Selection freq". In questo caso è 1.013 kHz (quindi 1 kHz).](<../../images/image (78).png>)

#### Con un gruppo di simboli

Puoi anche indicare il numero di simboli da selezionare: SigDigger calcolerà la frequenza di un simbolo (probabilmente, più simboli selezioni e meglio è). In questo caso ho selezionato 10 simboli e "Selection freq" è 1.004 kHz:

![Calcolo del symbol rate in SigDigger usando un gruppo selezionato di dieci simboli](<../../images/image (1008).png>)

### Ottenere i bit

Dopo aver identificato la AM e stimato il **symbol rate**, seleziona la regione del segnale, configura il campionamento dell'ampiezza e i livelli decisionali, scegli **Gardner clock recovery** e premi **Sample**:

![Pannello Get Bits di SigDigger configurato per il campionamento AM, il symbol rate e il recupero del clock Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa che verrà usato il symbol rate ricavato dagli intervalli selezionati in precedenza.
- **Manual** significa che verrà usato il symbol rate indicato.
- In **Fixed interval selection** indichi il numero di intervalli da selezionare e il programma calcola il symbol rate in base a questo valore.
- **Gardner clock recovery** è un'impostazione predefinita utile, ma richiede comunque un symbol rate approssimativo.

Premendo Sample, appare questa schermata:

![Con un gruppo di simboli - Ottenere i bit: premendo Sample, appare questa schermata](<../../images/image (644).png>)

Ora, per indicare a SigDigger **qual è l'intervallo** del livello che contiene le informazioni, fai clic sul **livello inferiore** e tieni premuto fino al livello più alto:

![Selezione dell'intervallo di livelli in SigDigger dal livello di ampiezza più basso a quello più alto](<../../images/image (439).png>)

Se, ad esempio, ci fossero stati **4 livelli di ampiezza diversi**, avresti dovuto impostare **Bits per symbol** su 2 e selezionare dal livello più basso a quello più alto.

Infine, **aumentando** lo **Zoom** e **modificando Row size** puoi vedere i bit (puoi selezionarli tutti e copiarli per ottenere l'intera sequenza):

![Con un gruppo di simboli - Ottenere i bit: infine, aumentando lo Zoom e modificando Row size puoi vedere i bit (puoi selezionarli tutti e copiarli per ottenere l'intera sequenza)](<../../images/image (276).png>)

Se il segnale ha più di 1 bit per simbolo (ad esempio 2), SigDigger **non può sapere quale simbolo corrisponde a** 00, 01, 10 o 11; userà quindi diverse **sfumature di grigio** per rappresentarli (e, se copi i bit, userà **numeri da 0 a 3**, che dovrai elaborare).

Per le codifiche di linea come **Manchester**, converti ogni coppia di transizioni valida (`01` o `10`) in un bit di dati secondo la convenzione usata dal protocollo.

## Esempio FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Individuare la FM

#### Controllare le frequenze e la forma d'onda

Esempio di segnale che trasmette informazioni modulate in FM:

![Individuare la FM - Controllare le frequenze e la forma d'onda: esempio di segnale che trasmette informazioni modulate in FM](<../../images/image (725).png>)

Lo spettro mostra chiaramente **due frequenze**, anche se può essere difficile distinguerle nella forma d'onda nel dominio del tempo:

![Forma d'onda FM in SigDigger, in cui è difficile distinguere direttamente le due frequenze](<../../images/image (717).png>)

Questo accade perché l'acquisizione è centrata tra le due frequenze, quindi i loro scostamenti di frequenza sono approssimativamente opposti:

![Acquisizione FM in SigDigger che mostra le due frequenze come valori approssimativamente opposti](<../../images/image (942).png>)

Se la frequenza di sincronizzazione è **più vicina a una frequenza che all'altra**, puoi vedere facilmente le 2 frequenze diverse:

![Individuare la FM - Controllare le frequenze e la forma d'onda: se la frequenza di sincronizzazione è più vicina a una frequenza che all'altra, puoi vedere facilmente le 2 frequenze diverse](<../../images/image (422).png>)

![Individuare la FM - Controllare le frequenze e la forma d'onda: se la frequenza di sincronizzazione è più vicina a una frequenza che all'altra, puoi vedere facilmente le 2 frequenze diverse](<../../images/image (488).png>)

#### Controllare l'istogramma

Controllando l'istogramma delle frequenze del segnale che contiene informazioni, puoi vedere facilmente 2 segnali diversi:

![Controllare le frequenze e la forma d'onda - Controllare l'istogramma: controllando l'istogramma delle frequenze del segnale che contiene informazioni, puoi vedere facilmente 2 segnali diversi](<../../images/image (871).png>)

In questo caso, se controlli l'**istogramma dell'ampiezza**, troverai **una sola ampiezza**, quindi **non può essere AM** (se trovi molte ampiezze, potrebbe essere perché il segnale ha perso potenza lungo il canale):

![Istogramma dell'ampiezza in SigDigger per un segnale FM, che mostra un solo livello di ampiezza](<../../images/image (817).png>)

Questo è l'istogramma della fase (che mostra chiaramente che il segnale non è modulato in fase):

![Controllare le frequenze e la forma d'onda - Controllare l'istogramma: ecco l'istogramma della fase, che mostra chiaramente che il segnale non è modulato in fase](<../../images/image (996).png>)

#### Con IQ

IQ non ha un campo per identificare le frequenze (la distanza dal centro corrisponde all'ampiezza e l'angolo alla fase).\
Pertanto, per identificare la FM, in questo grafico dovresti **vedere essenzialmente solo un cerchio**.\
Inoltre, uno scostamento di frequenza cambia la velocità di rotazione intorno al cerchio IQ. In SigDigger, un cambiamento della velocità o della direzione di rotazione può quindi indicare la FM:

![Grafico IQ di SigDigger in cui la FM appare come variazioni di accelerazione intorno al cerchio](<../../images/image (81).png>)

### Determinare il symbol rate

Puoi usare **la stessa tecnica dell'esempio AM** per determinare il symbol rate, una volta individuate le frequenze che trasportano i simboli.

### Ottenere i bit

Puoi usare **la stessa tecnica dell'esempio AM** per ottenere i bit, dopo aver **verificato che il segnale è modulato in frequenza** e aver determinato il **symbol rate**.

## References

- [1] [SigDigger - Analizzatore gratuito di segnali digitali per GNU/Linux e macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
