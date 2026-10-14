# Radio

{{#include ../../banners/hacktricks-training.md}}

Per le attività specifiche dei protocolli successive all'identificazione del segnale, consulta [test RFID/NFC, sub-GHz, infrarossi, BLE e LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) è un analizzatore gratuito di segnali digitali per GNU/Linux e macOS, progettato per estrarre informazioni da segnali radio sconosciuti. Supporta dispositivi SDR tramite SoapySDR e fornisce strumenti di demodulazione e analisi in tempo reale per FSK, PSK, ASK, video analogico, segnali a burst e canali vocali analogici.<sup>[[1]](#references)</sup>

### Configurazione di base

Dopo l'installazione, puoi prendere in considerazione alcune configurazioni.\
Nelle impostazioni (il pulsante della seconda scheda), seleziona un **dispositivo SDR** o un file di input, la frequenza da sintonizzare e la frequenza di campionamento. Una frequenza fino a 2.56 Msps può essere pratica, se supportata dal sistema host.

![Impostazioni di SigDigger con le opzioni per il dispositivo SDR, il file di input, la frequenza e la frequenza di campionamento](<../../images/image (245).png>)

Nel comportamento della GUI è consigliabile abilitare alcune opzioni, se il tuo PC le supporta:

![SigDigger - Configurazione di base: nel comportamento della GUI è consigliabile abilitare alcune opzioni, se il tuo PC le supporta](<../../images/image (472).png>)

> [!TIP]
> Se ti accorgi che il tuo PC non sta acquisendo i dati, prova a disabilitare OpenGL e ad abbassare la frequenza di campionamento.

### Utilizzi

- Per **acquisire un tratto del segnale e analizzarlo**, tieni premuto il pulsante "Push to capture" per tutto il tempo necessario.

![Configurazione di base - Utilizzi: per acquisire un tratto del segnale e analizzarlo, tieni premuto il pulsante "Push to capture" per tutto il tempo necessario](<../../images/image (960).png>)

- Il **Tuner** di SigDigger aiuta a **catturare segnali migliori** (ma può anche peggiorarli). Idealmente, inizia da 0 e continua ad **aumentare il valore finché** il **rumore** introdotto non diventa **maggiore** del **miglioramento del segnale** che ti serve.

![Controllo del tuner di SigDigger regolato per migliorare il segnale radio acquisito](<../../images/image (1099).png>)

### Sincronizzazione con il canale radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronizzati con il canale che vuoi ascoltare, configura l'opzione "Baseband audio preview", imposta la larghezza di banda per acquisire tutte le informazioni trasmesse e regola il Tuner al livello precedente al punto in cui il rumore inizia ad aumentare sensibilmente:<sup>[[1]](#references)</sup>

![Canale radio sincronizzato in SigDigger con l'anteprima audio in banda base e la larghezza di banda configurata](<../../images/image (585).png>)

## Trucchi interessanti

- Quando un dispositivo trasmette burst di informazioni, di solito la **prima parte è un preambolo**; quindi, **non** devi **preoccuparti** se **non trovi informazioni** in quella parte **o se contiene alcuni errori**.
- Nei frame di informazioni, di solito dovresti **trovare frame diversi ben allineati tra loro**:

![Sincronizzazione con il canale radio - Trucchi interessanti: nei frame di informazioni, di solito dovresti trovare frame diversi ben allineati tra loro](<../../images/image (1076).png>)

![Sincronizzazione con il canale radio - Trucchi interessanti: nei frame di informazioni, di solito dovresti trovare frame diversi ben allineati tra loro](<../../images/image (597).png>)

- **Dopo aver recuperato le transizioni di livello, potrebbe essere necessario decodificarle.** Nella codifica Manchester, una direzione di transizione rappresenta `0` e quella opposta rappresenta `1`; la polarità esatta dipende dalla convenzione utilizzata.
- Un preambolo può contenere una sequenza di campioni tutti allo stesso livello, anche se il payload usa la codifica Manchester; individua quindi il confine del frame prima di decodificarlo.

### Identificare il tipo di modulazione tramite IQ

Esistono 3 modi per codificare informazioni nei segnali: modulando **ampiezza**, **frequenza** o **fase**.\
Se stai esaminando un segnale, puoi provare in diversi modi a capire quale metodo viene usato per codificare le informazioni (per altri metodi, vedi sotto), ma un buon modo consiste nel controllare il grafico IQ.

![Grafico IQ di SigDigger usato per identificare se un segnale utilizza la modulazione di ampiezza, frequenza o fase](<../../images/image (788).png>)

- **Rilevamento AM**: se nel grafico IQ compaiono, ad esempio, **2 cerchi** (probabilmente uno in corrispondenza dello 0 e l'altro a un'ampiezza diversa), potrebbe trattarsi di un segnale AM. Nel grafico IQ, infatti, la distanza tra lo 0 e il cerchio corrisponde all'ampiezza del segnale, quindi è facile visualizzare le diverse ampiezze utilizzate.
- **Rilevamento PM**: come nell'immagine precedente, se trovi cerchi piccoli e indipendenti tra loro, probabilmente viene usata una modulazione di fase. Nel grafico IQ, infatti, l'angolo tra il punto e lo 0,0 corrisponde alla fase del segnale; questo significa che vengono usate 4 fasi diverse.
  - Nota che, se l'informazione è codificata nel cambiamento di fase e non nella fase stessa, non vedrai fasi diverse chiaramente distinguibili.
- **Rilevamento FM**: IQ non dispone di un campo per identificare le frequenze (la distanza dal centro corrisponde all'ampiezza e l'angolo alla fase).\
  Perciò, per identificare la FM, in questo grafico dovresti **vedere essenzialmente solo un cerchio**.\
  Inoltre, uno scostamento di frequenza cambia la velocità di rotazione lungo il cerchio IQ. In SigDigger, una variazione della velocità o della direzione di rotazione può quindi indicare la FM.

## Esempio AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificare la AM

#### Esaminare l'inviluppo

Quando esamini dati AM con [**SigDigger**](https://github.com/BatchDrake/SigDigger), l'**inviluppo** del segnale può rivelare livelli di ampiezza distinti. Il segnale di esempio trasmette informazioni sotto forma di impulsi modulati in ampiezza; un impulso appare così:<sup>[[1]](#references)</sup>

![Inviluppo del segnale AM in SigDigger con livelli di ampiezza degli impulsi ben distinti](<../../images/image (590).png>)

Ecco come appare una parte del simbolo nella forma d'onda:

![Identificare la AM - Esaminare l'inviluppo: ecco come appare una parte del simbolo nella forma d'onda](<../../images/image (734).png>)

#### Esaminare l'istogramma

Puoi **selezionare l'intero segnale** in cui si trovano le informazioni, selezionare la modalità **Amplitude** e **Selection** e fare clic su **Histogram**. Puoi osservare che sono presenti solo 2 livelli ben distinti.

![Istogramma dell'ampiezza in SigDigger, con due livelli ben distinti per il segnale AM selezionato](<../../images/image (264).png>)

Per esempio, se in questo segnale AM selezioni Frequency invece di Amplitude, troverai una sola frequenza (è impossibile che informazioni modulate in frequenza usino una sola frequenza).

![Istogramma delle frequenze in SigDigger per il segnale AM, con una sola frequenza](<../../images/image (732).png>)

Se trovi molte frequenze, probabilmente non si tratta di FM: la frequenza del segnale potrebbe essere stata alterata dal canale.

#### Con IQ

In questo esempio puoi vedere un **cerchio grande**, ma anche **molti punti al centro**.

![Esaminare l'istogramma - Con IQ: in questo esempio puoi vedere un cerchio grande, ma anche molti punti al centro](<../../images/image (222).png>)

### Ottenere il symbol rate

#### Con un simbolo

Seleziona l'intervallo più piccolo che contiene chiaramente un simbolo e controlla **Selection freq**. In questo esempio è 1.013 kHz, ovvero circa 1 kHz.

![Ottenere il symbol rate - Con un simbolo: seleziona l'intervallo più piccolo che riesci a trovare (così sei sicuro che contenga un solo simbolo) e controlla "Selection freq". In questo caso sarebbe 1.013 kHz (quindi 1 kHz).](<../../images/image (78).png>)

#### Con un gruppo di simboli

Puoi anche indicare il numero di simboli da selezionare e SigDigger calcolerà la frequenza di un singolo simbolo (probabilmente, più simboli selezioni, migliore sarà il risultato). In questo caso ho selezionato 10 simboli e "Selection freq" è 1.004 Khz:

![Calcolo del symbol rate in SigDigger usando un gruppo selezionato di dieci simboli](<../../images/image (1008).png>)

### Ottenere i bit

Dopo aver identificato la AM e stimato il **symbol rate**, seleziona la regione del segnale, configura il campionamento dell'ampiezza e i livelli decisionali, scegli **Gardner clock recovery** e premi **Sample**:

![Pannello Get Bits di SigDigger configurato per il campionamento AM, il symbol rate e il recupero del clock Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa che verrà usato il symbol rate individuato selezionando gli intervalli in precedenza.
- **Manual** significa che verrà usato il symbol rate indicato.
- In **Fixed interval selection** indichi il numero di intervalli da selezionare e il symbol rate viene calcolato a partire da questi.
- **Gardner clock recovery** è una buona impostazione predefinita, ma richiede comunque un symbol rate approssimativo.

Dopo aver premuto Sample, apparirà questa schermata:

![Con un gruppo di simboli - Ottenere i bit: dopo aver premuto Sample, apparirà questa schermata](<../../images/image (644).png>)

Ora, per far capire a SigDigger **qual è l'intervallo dei livelli che trasportano le informazioni**, fai clic sul **livello più basso** e tieni premuto il pulsante fino al livello più alto:

![Selezione dell'intervallo di livelli in SigDigger, dal livello di ampiezza più basso a quello più alto](<../../images/image (439).png>)

Se, per esempio, ci fossero stati **4 livelli di ampiezza diversi**, avresti dovuto impostare **Bits per symbol** su 2 e selezionare dal livello più basso a quello più alto.

Infine, **aumentando** lo **Zoom** e **modificando la Row size**, puoi visualizzare i bit (puoi selezionarli tutti e copiarli per ottenere l'intera sequenza):

![Con un gruppo di simboli - Ottenere i bit: infine, aumentando lo Zoom e modificando la Row size, puoi visualizzare i bit (puoi selezionarli tutti e copiarli per ottenere l'intera sequenza)](<../../images/image (276).png>)

Se il segnale ha più di 1 bit per simbolo (per esempio 2), SigDigger **non può sapere quale simbolo corrisponde a** 00, 01, 10 o 11, quindi rappresenterà ciascuno con una **tonalità di grigio** diversa (e quando copi i bit userà **numeri da 0 a 3**, che dovrai elaborare).

Per codifiche di linea come **Manchester**, converti ogni coppia di transizioni valida (`01` o `10`) in un bit di dati, secondo la convenzione utilizzata dal protocollo.

## Esempio FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificare la FM

#### Esaminare le frequenze e la forma d'onda

Esempio di segnale che trasmette informazioni modulate in FM:

![Identificare la FM - Esaminare le frequenze e la forma d'onda: esempio di segnale che trasmette informazioni modulate in FM](<../../images/image (725).png>)

Lo spettro mostra chiaramente **due frequenze**, anche se può essere difficile distinguerle nella forma d'onda nel dominio del tempo:

![Forma d'onda FM in SigDigger, in cui è difficile distinguere direttamente le due frequenze](<../../images/image (717).png>)

Questo accade perché l'acquisizione è centrata tra le due frequenze, quindi i loro scostamenti di frequenza sono all'incirca opposti:

![Acquisizione FM in SigDigger che mostra le due frequenze come scostamenti approssimativamente opposti](<../../images/image (942).png>)

Se la frequenza di sincronizzazione è **più vicina a una frequenza che all'altra**, puoi vedere facilmente le 2 frequenze distinte:

![Identificare la FM - Esaminare le frequenze e la forma d'onda: se la frequenza di sincronizzazione è più vicina a una frequenza che all'altra, puoi vedere facilmente le 2 frequenze distinte](<../../images/image (422).png>)

![Identificare la FM - Esaminare le frequenze e la forma d'onda: se la frequenza di sincronizzazione è più vicina a una frequenza che all'altra, puoi vedere facilmente le 2 frequenze distinte](<../../images/image (488).png>)

#### Esaminare l'istogramma

Esaminando l'istogramma delle frequenze del segnale contenente le informazioni, puoi vedere facilmente 2 segnali diversi:

![Esaminare le frequenze e la forma d'onda - Esaminare l'istogramma: esaminando l'istogramma delle frequenze del segnale contenente le informazioni, puoi vedere facilmente 2 segnali diversi](<../../images/image (871).png>)

In questo caso, se esamini l'**istogramma dell'ampiezza**, troverai **una sola ampiezza**, quindi **non può trattarsi di AM** (se trovi molte ampiezze, potrebbe essere perché il segnale ha perso potenza lungo il canale):

![Istogramma dell'ampiezza in SigDigger per un segnale FM, con un solo livello di ampiezza](<../../images/image (817).png>)

Questo è l'istogramma della fase, che mostra chiaramente che il segnale non è modulato in fase:

![Esaminare le frequenze e la forma d'onda - Esaminare l'istogramma: ecco l'istogramma della fase, che mostra chiaramente che il segnale non è modulato in fase](<../../images/image (996).png>)

#### Con IQ

IQ non dispone di un campo per identificare le frequenze (la distanza dal centro corrisponde all'ampiezza e l'angolo alla fase).\
Perciò, per identificare la FM, in questo grafico dovresti **vedere essenzialmente solo un cerchio**.\
Inoltre, uno scostamento di frequenza cambia la velocità di rotazione lungo il cerchio IQ. In SigDigger, una variazione della velocità o della direzione di rotazione può quindi indicare la FM:

![Grafico IQ di SigDigger in cui la FM appare come variazioni della velocità di rotazione lungo il cerchio](<../../images/image (81).png>)

### Ottenere il symbol rate

Una volta trovate le frequenze che trasportano i simboli, puoi usare la **stessa tecnica dell'esempio AM** per ottenere il symbol rate.

### Ottenere i bit

Dopo aver **stabilito che il segnale è modulato in frequenza** e aver trovato il **symbol rate**, puoi usare la **stessa tecnica dell'esempio AM** per ottenere i bit.

## References

- [1] [SigDigger - Analizzatore gratuito di segnali digitali per GNU/Linux e macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
