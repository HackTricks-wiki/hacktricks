# Infrarossi

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano gli infrarossi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d'onda degli IR va da **0,7 a 1000 micron**. I telecomandi domestici usano un segnale IR per la trasmissione dei dati e operano nell'intervallo di lunghezze d'onda compreso tra 0,75 e 1,4 micron. Un microcontrollore nel telecomando fa lampeggiare un LED a infrarossi a una frequenza specifica, trasformando il segnale digitale in un segnale IR.<sup>[[1]](#references)</sup>

Per ricevere i segnali IR si usa un **fotoricevitore**. Questo **converte la luce IR in impulsi di tensione**, che sono già **segnali digitali**. Di solito, all'interno del ricevitore è presente un **filtro per la luce scura**, che lascia passare **solo la lunghezza d'onda desiderata** ed elimina il rumore.

### Varietà di protocolli IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

I protocolli IR differiscono per 3 fattori:

- codifica dei bit
- struttura dei dati
- frequenza portante — spesso nell'intervallo 36..38 kHz

#### Modalità di codifica dei bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

I bit vengono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell'impulso è costante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

I bit vengono codificati modulando la larghezza dell'impulso. La larghezza dello spazio dopo il burst di impulsi è costante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

È anche nota come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra il burst di impulsi e lo spazio. "Da spazio a burst di impulsi" indica la logica "0", mentre "da burst di impulsi a spazio" indica la logica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinazione delle precedenti e altre modalità esotiche**

> [!TIP]
> Esistono protocolli IR che **cercano di diventare universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Sfortunatamente, il fatto che siano i più famosi **non significa che siano i più comuni**. Nel mio ambiente ho incontrato solo due telecomandi NEC e nessun telecomando RC5.
>
> I produttori amano usare protocolli IR unici e proprietari, anche all'interno della stessa categoria di dispositivi (ad esempio, i TV-box). Di conseguenza, i telecomandi di aziende diverse e talvolta di modelli diversi della stessa azienda non sono in grado di funzionare con altri dispositivi dello stesso tipo.

### Analisi di un segnale IR

Il modo più affidabile per vedere l'aspetto del segnale IR di un telecomando è usare un oscilloscopio. Questo non demodula né inverte il segnale ricevuto, ma lo visualizza semplicemente "così com'è". È utile per il testing e il debugging. Mostrerò il segnale previsto usando come esempio il protocollo IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Di solito, all'inizio di un pacchetto codificato è presente un preambolo. Questo consente al ricevitore di determinare il livello di guadagno e lo sfondo. Esistono anche protocolli senza preambolo, ad esempio Sharp.

Successivamente vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica dei bit sono determinati dal protocollo specifico.

Il **protocollo IR NEC** contiene un comando breve e un codice di ripetizione, che viene inviato mentre il pulsante è premuto. Sia il comando sia il codice di ripetizione hanno lo stesso preambolo all'inizio.

Il **comando** NEC, oltre al preambolo, è costituito da un byte di indirizzo e da un byte contenente il numero del comando, tramite i quali il dispositivo comprende cosa deve eseguire. I byte di indirizzo e del numero del comando vengono duplicati con valori invertiti, per verificare l'integrità della trasmissione. Alla fine del comando è presente un ulteriore bit di stop.

Il **codice di ripetizione** contiene un "1" dopo il preambolo, che funge da bit di stop.

Per la **logica "0" e "1"**, NEC usa il Pulse Distance Encoding: prima viene trasmesso un burst di impulsi, seguito da una pausa la cui durata determina il valore del bit.

### Condizionatori d'aria

A differenza degli altri telecomandi, **i condizionatori d'aria non trasmettono solo il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando viene premuto un pulsante, per garantire che **il condizionatore e il telecomando siano sincronizzati**.\
Questo evita che un condizionatore impostato a 20 °C venga portato a 21 °C con un telecomando e che, quando viene usato un altro telecomando, che indica ancora una temperatura di 20 °C, la temperatura venga "aumentata" a 21 °C (e non a 22 °C, pensando che sia già a 21 °C).

---

## Attacchi e ricerca offensiva <a href="#attacks" id="attacks"></a>

È possibile attaccare gli infrarossi con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Compromissione di Smart-TV / Set-top Box (EvilScreen)

Recenti ricerche accademiche (EvilScreen, 2022) hanno dimostrato che **i telecomandi multicanale che combinano gli infrarossi con Bluetooth o Wi-Fi possono essere usati per dirottare completamente le moderne smart-TV**. L'attacco combina codici di servizio IR con privilegi elevati e pacchetti Bluetooth autenticati, aggirando l'isolamento tra i canali e consentendo l'avvio arbitrario di app, l'attivazione del microfono o il ripristino delle impostazioni di fabbrica senza accesso fisico. Otto TV diffuse di diversi produttori — tra cui un modello Samsung che dichiarava la conformità a ISO/IEC 27001 — sono risultate vulnerabili. La mitigazione richiede correzioni del firmware da parte del produttore oppure la disattivazione completa dei ricevitori IR inutilizzati.<sup>[[2]](#references)</sup>

### Esfiltrazione di dati da reti isolate tramite LED IR (famiglia aIR-Jumper)

Le telecamere di sicurezza, i router e persino le chiavette USB malevole spesso includono **LED IR per la visione notturna**. Le ricerche mostrano che il malware può modulare questi LED (<10–20 kbit/s con OOK semplice) per **esfiltrare segreti attraverso pareti e finestre** verso una telecamera esterna posta a decine di metri di distanza. Poiché la luce è al di fuori dello spettro visibile, gli operatori raramente se ne accorgono. Contromisure:

* Schermare fisicamente o rimuovere i LED IR nelle aree sensibili
* Monitorare il duty cycle dei LED della telecamera e l'integrità del firmware
* Installare filtri IR-cut su finestre e telecamere di sorveglianza

Un attaccante può anche usare potenti proiettori IR per **infiltrare** comandi nella rete, trasmettendo dati verso telecamere non sicure.

### Brute-force a lunga distanza e protocolli estesi con Flipper Zero 1.0

Il firmware 1.0 (settembre 2024) ha aggiunto **decine di protocolli IR aggiuntivi e moduli amplificatori esterni opzionali**. Combinato con la modalità brute-force del telecomando universale, un Flipper può disabilitare o riconfigurare la maggior parte dei televisori e dei condizionatori presenti negli spazi pubblici fino a 30 m di distanza, usando un diodo ad alta potenza.

---

## Tooling ed esempi pratici <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – ricetrasmettitore portatile con modalità di apprendimento, replay e dictionary-bruteforce (vedi sopra).
* **Arduino / ESP32** + LED IR / ricevitore TSOP38xx – analizzatore/trasmettitore fai-da-te economico. Da combinare con la libreria `Arduino-IRremote` (la v4.x supporta più di 40 protocolli).
* **Analizzatori logici** (Saleae/FX2) – acquisiscono le temporizzazioni grezze quando il protocollo è sconosciuto.
* **Smartphone con IR-blaster** (ad esempio Xiaomi) – test sul campo rapido, ma con portata limitata.

### Software

* **`Arduino-IRremote`** – libreria C++ mantenuta attivamente:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decoder con GUI che importano acquisizioni grezze, identificano automaticamente il protocollo e generano codice Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – ricevono e iniettano segnali IR dalla riga di comando:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Misure difensive <a href="#defense" id="defense"></a>

* Disabilitare o coprire i ricevitori IR sui dispositivi installati negli spazi pubblici quando non sono necessari.
* Applicare il *pairing* o verifiche crittografiche tra smart-TV e telecomandi; isolare i codici di “servizio” con privilegi elevati.
* Installare filtri IR-cut o rilevatori a onda continua intorno alle aree classificate per interrompere i canali ottici covert.
* Monitorare l'integrità del firmware delle telecamere e degli apparecchi IoT che espongono LED IR controllabili.

## Riferimenti

- [1] [Articolo del blog di Flipper Zero sugli infrarossi](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: dirottamento delle Smart TV tramite imitazione del telecomando](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
