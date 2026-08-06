# Infrarossi

{{#include ../../banners/hacktricks-training.md}}

## Come funziona l'infrarosso <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d'onda IR va da **0,7 a 1000 micron**. I telecomandi domestici utilizzano un segnale IR per la trasmissione dei dati e operano nell'intervallo di lunghezze d'onda compreso tra 0.75 e 1.4 micron. Un microcontroller nel telecomando fa lampeggiare un LED infrarosso a una frequenza specifica, convertendo il segnale digitale in un segnale IR.

Per ricevere segnali IR viene utilizzato un **fotodetector**. Questo **converte la luce IR in impulsi di tensione**, che sono già **segnali digitali**. Di solito, all'interno del ricevitore è presente un **filtro per la luce ambientale**, che lascia passare **solo la lunghezza d'onda desiderata** ed elimina il rumore.<sup>[[1]](#references)</sup>

### Varietà di protocolli IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

I protocolli IR differiscono per 3 fattori:<sup>[[1]](#references)</sup>

- codifica dei bit
- struttura dei dati
- frequenza portante — spesso nell'intervallo 36..38 kHz

#### Metodi di codifica dei bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codifica Pulse Distance**

I bit vengono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell'impulso è costante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codifica Pulse Width**

I bit vengono codificati modulando la larghezza dell'impulso. La larghezza dello spazio dopo il burst dell'impulso è costante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codifica di fase**

È nota anche come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra il burst dell'impulso e lo spazio. "Da spazio a burst dell'impulso" indica la logica "0", mentre "da burst dell'impulso a spazio" indica la logica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinazione dei precedenti e altri metodi esotici**

> [!TIP]
> Esistono protocolli IR che **cercano di diventare universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Sfortunatamente, il più famoso **non significa il più comune**. Nel mio ambiente ho incontrato solo due telecomandi NEC e nessun telecomando RC5.
>
> I produttori amano utilizzare protocolli IR unici proprietari, anche all'interno della stessa categoria di dispositivi (ad esempio, i TV-box). Pertanto, i telecomandi di aziende diverse e, talvolta, di modelli diversi della stessa azienda, non sono in grado di funzionare con altri dispositivi dello stesso tipo.

### Analisi di un segnale IR

Il modo più affidabile per vedere l'aspetto del segnale IR di un telecomando è utilizzare un oscilloscopio. Questo non demodula né inverte il segnale ricevuto, ma lo visualizza semplicemente "così com'è". È utile per i test e il debugging. Mostrerò il segnale previsto usando come esempio il protocollo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Di solito, all'inizio di un pacchetto codificato è presente un preambolo. Questo consente al ricevitore di determinare il livello di guadagno e il segnale di fondo. Esistono anche protocolli senza preambolo, ad esempio Sharp.

Successivamente vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica dei bit sono determinati dal protocollo specifico.

Il **protocollo IR NEC** contiene un comando breve e un codice di ripetizione, inviato mentre il pulsante è premuto. Sia il comando sia il codice di ripetizione hanno lo stesso preambolo all'inizio.

Il **comando** NEC, oltre al preambolo, è composto da un byte di indirizzo e da un byte del numero di comando, attraverso i quali il dispositivo comprende cosa deve essere eseguito. I byte di indirizzo e del numero di comando vengono duplicati con valori inversi per verificare l'integrità della trasmissione. Alla fine del comando è presente un bit di stop aggiuntivo.

Il **codice di ripetizione** contiene un "1" dopo il preambolo, che rappresenta un bit di stop.

Per la **logica "0" e "1"**, NEC utilizza la codifica Pulse Distance: prima viene trasmesso un burst dell'impulso, seguito da una pausa, la cui lunghezza determina il valore del bit.

### Condizionatori

A differenza degli altri telecomandi, **i condizionatori non trasmettono soltanto il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando viene premuto un pulsante, per assicurarsi che **il condizionatore e il telecomando siano sincronizzati**.\
In questo modo si evita che una macchina impostata a 20 ºC venga portata a 21 ºC con un telecomando e che, usando poi un altro telecomando che indica ancora 20 ºC, la temperatura venga "aumentata" a 21 ºC (anziché a 22 ºC, pensando che sia impostata a 21 ºC).<sup>[[1]](#references)</sup>

---

## Attacchi e ricerca offensiva <a href="#attacks" id="attacks"></a>

È possibile attaccare l'infrarosso con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Takeover di Smart-TV / Set-top Box (EvilScreen)

Recenti studi accademici (EvilScreen, 2022) hanno dimostrato che **i telecomandi multicanale che combinano l'infrarosso con Bluetooth o Wi-Fi possono essere sfruttati per effettuare il hijacking completo delle moderne smart-TV**. L'attacco combina codici di servizio IR con privilegi elevati e pacchetti Bluetooth autenticati, aggirando l'isolamento tra i canali e consentendo l'avvio arbitrario di app, l'attivazione del microfono o il ripristino delle impostazioni di fabbrica senza accesso fisico. È stata confermata la vulnerabilità di otto TV diffuse di diversi produttori, tra cui un modello Samsung che dichiarava la conformità alla norma ISO/IEC 27001. La mitigazione richiede correzioni del firmware da parte del produttore o la disabilitazione completa dei ricevitori IR inutilizzati.<sup>[[2]](#references)</sup>

### Esfiltrazione di dati da reti air-gapped tramite LED IR (famiglia aIR-Jumper)

Le videocamere di sicurezza, i router e persino le chiavette USB malevole spesso includono **LED IR per la visione notturna**. Le ricerche dimostrano che il malware può modulare questi LED (<10–20 kbit/s con un semplice OOK) per **esfiltrare segreti attraverso pareti e finestre** verso una videocamera esterna posta a decine di metri di distanza.<sup>[[3]](#references)</sup> Poiché la luce è al di fuori dello spettro visibile, gli operatori raramente se ne accorgono. Contromisure:

* Schermare fisicamente o rimuovere i LED IR nelle aree sensibili
* Monitorare il duty cycle dei LED delle videocamere e l'integrità del firmware
* Implementare filtri IR-cut sulle finestre e sulle videocamere di sorveglianza

Un attaccante può anche utilizzare proiettori IR potenti per **infiltrare** comandi nella rete, trasmettendo dati verso videocamere non sicure.

### Brute-force a lunga distanza e protocolli estesi con Flipper Zero 1.0

Il firmware 1.0 (settembre 2024) ha aggiunto **decine di protocolli IR aggiuntivi e moduli amplificatori esterni opzionali**. Combinato con la modalità brute-force del telecomando universale, un Flipper può disabilitare o riconfigurare la maggior parte dei televisori e dei condizionatori presenti negli spazi pubblici fino a 30 m di distanza, utilizzando un diodo ad alta potenza.

---

## Tooling ed esempi pratici <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceiver portatile con modalità di apprendimento, replay e dictionary-bruteforce (vedi sopra).
* **Arduino / ESP32** + LED IR / ricevitore TSOP38xx – analizzatore/trasmettitore DIY economico. Da combinare con la libreria `Arduino-IRremote` (la v4.x supporta più di 40 protocolli).
* **Logic analyser** (Saleae/FX2) – acquisiscono i timing grezzi quando il protocollo è sconosciuto.
* **Smartphone con IR-blaster** (ad esempio, Xiaomi) – utile per test rapidi sul campo, ma con portata limitata.

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
* **IRscrutinizer / AnalysIR** – decoder GUI che importano acquisizioni grezze, identificano automaticamente il protocollo e generano codice Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – ricevono e iniettano segnali IR dalla command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Misure difensive <a href="#defense" id="defense"></a>

* Disabilitare o coprire i ricevitori IR sui dispositivi installati negli spazi pubblici quando non sono necessari.
* Imporre il *pairing* o verifiche crittografiche tra smart-TV e telecomandi; isolare i codici di "servizio" con privilegi elevati.
* Implementare filtri IR-cut o rilevatori a onda continua intorno alle aree classificate per interrompere i canali ottici covert.
* Monitorare l'integrità del firmware delle videocamere e degli apparecchi IoT che espongono LED IR controllabili.

## Riferimenti

- [1] [Articolo del blog di Flipper Zero sull'infrarosso](https://blog.flipperzero.one/infrared/)
- [2] [Attacco EvilScreen: hijacking delle Smart TV tramite imitazione di telecomandi multicanale (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: esfiltrazione/infiltrazione covert da reti air-gapped tramite videocamere di sicurezza e infrarossi (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
