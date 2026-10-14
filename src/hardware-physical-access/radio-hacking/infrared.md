# Infrarossi

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano gli infrarossi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luce infrarossa è invisibile agli esseri umani**. La lunghezza d’onda degli infrarossi va da **0,7 a 1000 micron**. I telecomandi domestici usano un segnale IR per la trasmissione dei dati e operano nell’intervallo di lunghezze d’onda tra 0,75 e 1,4 micron. Un microcontrollore nel telecomando fa lampeggiare un LED a infrarossi a una frequenza specifica, trasformando il segnale digitale in un segnale IR.

Per ricevere i segnali IR si usa un **fotoricevitore**. Questo **converte la luce IR in impulsi di tensione**, che sono già **segnali digitali**. Di solito, all’interno del ricevitore c’è un **filtro per la luce**, che lascia passare **solo la lunghezza d’onda desiderata** ed elimina il rumore.<sup>[[1]](#references)</sup>

### Varietà di protocolli IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

I protocolli IR si differenziano per 3 fattori:<sup>[[1]](#references)</sup>

- codifica dei bit
- struttura dei dati
- frequenza portante — spesso nell’intervallo 36..38 kHz

#### Metodi di codifica dei bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codifica a distanza degli impulsi**

I bit vengono codificati modulando la durata dello spazio tra gli impulsi. La larghezza dell’impulso stesso è costante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codifica a larghezza d’impulso**

I bit vengono codificati modulando la larghezza dell’impulso. La durata dello spazio dopo il treno di impulsi è costante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codifica di fase**

È nota anche come codifica Manchester. Il valore logico è definito dalla polarità della transizione tra il treno di impulsi e lo spazio. «Da spazio a treno di impulsi» indica la logica «0», mentre «da treno di impulsi a spazio» indica la logica «1».

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinazioni dei metodi precedenti e altri metodi esotici**

> [!TIP]
> Esistono protocolli IR che **tentano di diventare universali** per diversi tipi di dispositivi. I più famosi sono RC5 e NEC. Purtroppo, **il più famoso non significa il più comune**. Nel mio ambiente ho incontrato solo due telecomandi NEC e nessuno RC5.
>
> I produttori amano usare protocolli IR proprietari, anche all’interno della stessa categoria di dispositivi (per esempio, i TV-box). Di conseguenza, i telecomandi di aziende diverse e, a volte, quelli di modelli diversi della stessa azienda, non funzionano con altri dispositivi dello stesso tipo.

### Esplorare un segnale IR

Il modo più affidabile per vedere l’aspetto del segnale IR di un telecomando è usare un oscilloscopio. Non demodula né inverte il segnale ricevuto: lo mostra semplicemente «così com’è». È utile per i test e il debugging. Mostrerò il segnale previsto usando come esempio il protocollo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Di solito, all’inizio di un pacchetto codificato c’è un preambolo. Questo consente al ricevitore di determinare il livello di guadagno e il segnale di fondo. Esistono anche protocolli senza preambolo, per esempio Sharp.

Poi vengono trasmessi i dati. La struttura, il preambolo e il metodo di codifica dei bit dipendono dal protocollo specifico.

Il **protocollo IR NEC** contiene un comando breve e un codice di ripetizione, trasmesso mentre il pulsante è premuto. Sia il comando sia il codice di ripetizione hanno lo stesso preambolo iniziale.

Il **comando** NEC, oltre al preambolo, consiste in un byte di indirizzo e un byte con il numero del comando, che indica al dispositivo cosa deve eseguire. I byte di indirizzo e del numero del comando sono duplicati con i valori invertiti, per verificare l’integrità della trasmissione. Alla fine del comando c’è un bit di stop aggiuntivo.

Il **codice di ripetizione** ha un «1» dopo il preambolo, che funge da bit di stop.

Per la **logica «0» e «1»**, NEC usa la codifica a distanza degli impulsi: prima viene trasmesso un treno di impulsi, seguito da una pausa la cui durata determina il valore del bit.

### Condizionatori d’aria

A differenza degli altri telecomandi, **quelli dei condizionatori d’aria non trasmettono solo il codice del pulsante premuto**. Trasmettono anche **tutte le informazioni** quando viene premuto un pulsante, per assicurare che **il condizionatore e il telecomando siano sincronizzati**.\
In questo modo, se un condizionatore impostato a 20ºC viene portato a 21ºC con un telecomando e poi si usa un altro telecomando, che ha ancora la temperatura impostata a 20ºC, per aumentarla ulteriormente, la temperatura verrà «aumentata» a 21ºC (e non a 22ºC, come se fosse già a 21ºC).<sup>[[1]](#references)</sup>

---

## Attacchi e ricerca offensiva <a href="#attacks" id="attacks"></a>

Puoi attaccare gli infrarossi con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Presa di controllo di Smart-TV / set-top box (EvilScreen)

Un recente lavoro accademico (EvilScreen, 2022) ha dimostrato che **i telecomandi multicanale che combinano gli infrarossi con Bluetooth o Wi-Fi possono essere sfruttati per prendere completamente il controllo delle smart-TV moderne**. L’attacco concatena codici IR di servizio con privilegi elevati e pacchetti Bluetooth autenticati, aggirando l’isolamento dei canali e consentendo l’avvio arbitrario di app, l’attivazione del microfono o il ripristino delle impostazioni di fabbrica senza accesso fisico. È stata confermata la vulnerabilità di otto TV diffuse di diversi produttori, tra cui un modello Samsung che dichiarava la conformità a ISO/IEC 27001. Per mitigare il problema sono necessarie correzioni del firmware da parte dei produttori o la disattivazione completa dei ricevitori IR inutilizzati.<sup>[[2]](#references)</sup>

### Esfiltrazione di dati tramite LED IR da sistemi isolati dalla rete (famiglia aIR-Jumper)

Le telecamere di sicurezza includono spesso **LED IR per la visione notturna**. Il prototipo aIR-Jumper ha dimostrato che un malware in grado di controllare questi LED può **esfiltrare segreti attraverso le finestre** verso una telecamera esterna, a una velocità fino a **20 bit/s per telecamera di sorveglianza** e su distanze di decine di metri. Nella direzione opposta, i ricercatori hanno dimostrato l’infiltrazione a oltre **100 bit/s**, su distanze che vanno da centinaia di metri a chilometri.<sup>[[3]](#references)</sup> Poiché la luce è al di fuori dello spettro visibile, gli operatori potrebbero non accorgersene. Le contromisure includono:

* Schermare fisicamente o rimuovere i LED IR nelle aree sensibili
* Monitorare il ciclo di attività dei LED della telecamera e l’integrità del firmware
* Installare filtri IR-cut su finestre e telecamere di sorveglianza

Un attaccante può anche usare potenti proiettori IR per **infiltrare** comandi nella rete, inviando dati a telecamere non sicure tramite impulsi luminosi.

### Brute force a lungo raggio e protocolli estesi con Flipper Zero 1.0

Il firmware 1.0 (settembre 2024) ha ampliato la libreria dei telecomandi universali e aggiunto il caricamento dinamico di file di risorse a infrarossi da microSD.<sup>[[4]](#references)</sup> Le funzioni di apprendimento e di telecomando universale possono riprodurre o provare comandi noti sulle TV e sui condizionatori nelle vicinanze. La portata dipende molto dall’emettitore, dalle ottiche, dalla luce ambientale e dal ricevitore; l’hardware IR esterno può estenderla, ma non bisogna presumere una distanza fissa.

---

## Strumenti ed esempi pratici <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – ricetrasmettitore portatile con modalità di apprendimento, riproduzione e brute force tramite dizionario (vedi sopra).
* **Arduino / ESP32** + LED IR / ricevitore TSOP38xx – analizzatore/trasmettitore fai da te economico. Da usare con la libreria `Arduino-IRremote` (la v4.x supporta oltre 40 protocolli).
* **Analizzatori logici** (Saleae/FX2) – acquisiscono le temporizzazioni grezze quando il protocollo è sconosciuto.
* **Smartphone con IR-blaster** (ad esempio, Xiaomi) – utile per test rapidi sul campo, ma con portata limitata.

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
* **IRscrutinizer / AnalysIR** – decodificatori con interfaccia grafica che importano acquisizioni raw, identificano automaticamente il protocollo e generano codice Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – ricevono e iniettano segnali IR dalla riga di comando:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Misure difensive <a href="#defense" id="defense"></a>

* Disabilitare o coprire i ricevitori IR sui dispositivi installati in spazi pubblici quando non sono necessari.
* Applicare il *pairing* o controlli crittografici tra smart TV e telecomandi; isolare i codici di “servizio” privilegiati.
* Installare filtri IR-cut o rilevatori a onda continua intorno alle aree classificate per interrompere i canali covert ottici.
* Monitorare l’integrità del firmware di telecamere e dispositivi IoT che espongono LED IR controllabili.

## References

- [1] [Post del blog sull’infrarosso di Flipper Zero](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: dirottamento di smart TV tramite imitazione del controllo remoto multicanale (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: esfiltrazione/infiltrazione covert attraverso un air gap tramite telecamere di sicurezza e infrarossi (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog di Flipper Zero - Rilasciato il firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentazione sull’uso e sui protocolli](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
