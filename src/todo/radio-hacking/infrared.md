# Infrarosso

{{#include ../../banners/hacktricks-training.md}}

## Come funziona l'infrarosso <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d'onda IR va da **0,7 a 1000 micron**. I telecomandi domestici usano un segnale IR per la trasmissione dei dati e operano nell'intervallo di lunghezze d'onda compreso tra 0,75 e 1,4 micron. Un microcontrollore nel telecomando fa lampeggiare un LED infrarosso a una frequenza specifica, convertendo il segnale digitale in un segnale IR.

Per ricevere i segnali IR viene utilizzato un **fotodetettore**. Questo **converte la luce IR in impulsi di tensione**, che sono già **segnali digitali**. Di solito, all'interno del ricevitore è presente un **filtro per la luce parassita**, che lascia passare **solo la lunghezza d'onda desiderata** ed elimina il rumore.<sup>[[1]](#references)</sup>

### Varietà di protocolli IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

I protocolli IR differiscono per 3 fattori:<sup>[[1]](#references)</sup>

- codifica dei bit
- struttura dei dati
- frequenza della portante — spesso nell'intervallo 36..38 kHz

#### Modalità di codifica dei bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codifica della distanza degli impulsi**

I bit vengono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell'impulso è costante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codifica della larghezza degli impulsi**

I bit vengono codificati modulando la larghezza dell'impulso. La larghezza dello spazio dopo il burst dell'impulso è costante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codifica di fase**

È anche nota come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra il burst dell'impulso e lo spazio. "Da spazio a burst dell'impulso" indica la logica "0", mentre "da burst dell'impulso a spazio" indica la logica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinazione delle precedenti e altre modalità esotiche**

> [!TIP]
> Esistono protocolli IR che **cercano di diventare universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Purtroppo, **più famoso non significa più comune**. Nel mio ambiente ho incontrato solo due telecomandi NEC e nessun telecomando RC5.
>
> I produttori amano usare i propri protocolli IR unici, persino all'interno della stessa gamma di dispositivi (ad esempio, i TV-box). Pertanto, i telecomandi di aziende diverse e talvolta di modelli diversi della stessa azienda non sono in grado di funzionare con altri dispositivi dello stesso tipo.

### Analisi di un segnale IR

Il modo più affidabile per vedere l'aspetto del segnale IR di un telecomando consiste nell'utilizzare un oscilloscopio. Questo non demodula né inverte il segnale ricevuto, ma lo visualizza semplicemente "così com'è". È utile per i test e il debugging. Mostrerò il segnale previsto usando come esempio il protocollo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Di solito, all'inizio di un pacchetto codificato è presente un preambolo. Questo consente al ricevitore di determinare il livello di guadagno e il rumore di fondo. Esistono anche protocolli privi di preambolo, come Sharp.

Successivamente vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica dei bit sono determinati dal protocollo specifico.

Il **protocollo IR NEC** contiene un comando breve e un codice di ripetizione, che viene inviato mentre il pulsante è premuto. Sia il comando sia il codice di ripetizione hanno lo stesso preambolo all'inizio.

Il **comando** NEC, oltre al preambolo, è costituito da un byte di indirizzo e da un byte del numero di comando, tramite i quali il dispositivo comprende quale operazione deve eseguire. I byte di indirizzo e del numero di comando sono duplicati con valori invertiti, per verificare l'integrità della trasmissione. Alla fine del comando è presente un bit di stop aggiuntivo.

Il **codice di ripetizione** contiene un "1" dopo il preambolo, che costituisce un bit di stop.

Per la **logica "0" e "1"**, NEC utilizza la codifica della distanza degli impulsi: prima viene trasmesso un burst dell'impulso, seguito da una pausa, la cui lunghezza determina il valore del bit.

### Condizionatori d'aria

A differenza degli altri telecomandi, **i condizionatori d'aria non trasmettono solo il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando viene premuto un pulsante, per garantire che **il climatizzatore e il telecomando siano sincronizzati**.\
Questo evita che una macchina impostata a 20 ºC venga portata a 21 ºC con un telecomando e che, quando viene utilizzato un altro telecomando che indica ancora una temperatura di 20 ºC per aumentare ulteriormente la temperatura, questa venga "aumentata" a 21 ºC (anziché a 22 ºC, pensando che sia impostata a 21 ºC).<sup>[[1]](#references)</sup>

---

## Attacchi e Offensive Research <a href="#attacks" id="attacks"></a>

È possibile attaccare l'infrarosso con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Takeover di Smart-TV / Set-top Box (EvilScreen)

Recenti ricerche accademiche (EvilScreen, 2022) hanno dimostrato che **i telecomandi multicanale che combinano l'infrarosso con Bluetooth o Wi-Fi possono essere utilizzati per prendere completamente il controllo delle smart-TV moderne**. L'attacco concatena codici di servizio IR con privilegi elevati a pacchetti Bluetooth autenticati, aggirando l'isolamento tra i canali e consentendo l'avvio arbitrario di app, l'attivazione del microfono o il ripristino delle impostazioni di fabbrica senza accesso fisico. Otto TV diffuse di diversi produttori — tra cui un modello Samsung che dichiarava la conformità a ISO/IEC 27001 — sono risultate vulnerabili. La mitigazione richiede correzioni del firmware da parte del produttore o la disabilitazione completa dei ricevitori IR inutilizzati.<sup>[[2]](#references)</sup>

### Esfiltrazione di dati da reti air-gapped tramite LED IR (famiglia aIR-Jumper)

Le telecamere di sicurezza includono comunemente **LED IR per la visione notturna**. Il prototipo aIR-Jumper ha dimostrato che il malware in grado di controllare questi LED poteva **esfiltrare segreti attraverso le finestre** verso una telecamera esterna a una velocità massima di **20 bit/s per telecamera di sorveglianza**, su distanze di decine di metri. Nella direzione inversa, i ricercatori hanno dimostrato un'infiltrazione a più di **100 bit/s** su distanze da centinaia di metri a chilometri.<sup>[[3]](#references)</sup> Poiché la luce si trova al di fuori dello spettro visibile, gli operatori potrebbero non accorgersene. Le contromisure includono:

* Schermare fisicamente o rimuovere i LED IR nelle aree sensibili
* Monitorare il duty-cycle dei LED delle telecamere e l'integrità del firmware
* Installare filtri IR-cut su finestre e telecamere di sorveglianza

Un attaccante può anche utilizzare proiettori IR potenti per **infiltrare** comandi nella rete, inviando dati tramite flash verso telecamere non sicure.

### Brute-Force a lunga distanza e protocolli estesi con Flipper Zero 1.0

Il firmware 1.0 (settembre 2024) ha ampliato la libreria dei telecomandi universali e aggiunto il caricamento dinamico dei file di asset infrarossi da microSD.<sup>[[4]](#references)</sup> Le funzioni di apprendimento e telecomando universale possono riprodurre o tentare comandi noti contro TV e condizionatori d'aria nelle vicinanze. La portata dipende fortemente dall'emettitore, dall'ottica, dalla luce ambientale e dal ricevitore; hardware IR esterno può estenderla, ma non si deve presumere una distanza fissa.

---

## Strumenti ed esempi pratici <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – ricetrasmettitore portatile con modalità di apprendimento, replay e dictionary-bruteforce (vedi sopra).
* **Arduino / ESP32** + LED IR / ricevitore TSOP38xx – analizzatore/trasmettitore DIY economico. Da combinare con la libreria `Arduino-IRremote` (la v4.x supporta più di 40 protocolli).
* **Analizzatori logici** (Saleae/FX2) – acquisiscono le temporizzazioni grezze quando il protocollo è sconosciuto.
* **Smartphone con IR-blaster** (ad esempio, Xiaomi) – test rapido sul campo, ma con portata limitata.

### Software

* **`Arduino-IRremote`** – libreria C++ mantenuta attivamente:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decoder GUI che importano acquisizioni grezze, identificano automaticamente il protocollo e generano codice Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – ricevono e iniettano segnali IR dalla riga di comando:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Misure difensive <a href="#defense" id="defense"></a>

* Disabilitare o coprire i ricevitori IR sui dispositivi installati negli spazi pubblici quando non sono necessari.
* Applicare il *pairing* o controlli crittografici tra smart-TV e telecomandi; isolare i codici di "servizio" privilegiati.
* Installare filtri IR-cut o rilevatori a onda continua intorno alle aree classificate, per interrompere i covert channel ottici.
* Monitorare l'integrità del firmware delle telecamere e degli apparecchi IoT che espongono LED IR controllabili.

## References

- [1] [Articolo del blog di Flipper Zero sull'infrarosso](https://blog.flipperzero.one/infrared/)
- [2] [Attacco EvilScreen: Hijacking delle Smart TV tramite imitazione di telecomandi multicanale (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Esfiltrazione/Infiltrazione covert da reti air-gap tramite telecamere di sicurezza e infrarossi (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog di Flipper Zero - Firmware 1.0 rilasciato](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentazione sull'utilizzo e sui protocolli](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
