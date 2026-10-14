# Realizzare un cloner mobile HID MaxiProx 125 kHz portatile

{{#include ../../banners/hacktricks-training.md}}

## Obiettivo
Trasformare un lettore HID MaxiProx 5375 a lungo raggio da 125 kHz, alimentato dalla rete elettrica, in un cloner di badge portatile a batteria, utilizzabile sul campo e in grado di acquisire in modo silenzioso le card di prossimità durante le valutazioni della sicurezza fisica.

La conversione descritta si basa sulla serie di ricerche di TrustedSec “Let’s Clone a Cloner – Part 3: Putting It All Together” e combina considerazioni meccaniche, elettriche e RF affinché il dispositivo finale possa essere riposto in uno zaino e usato immediatamente sul posto.<sup>[[1]](#references)</sup>

> [!warning]
> La manipolazione di apparecchiature alimentate dalla rete elettrica e di power-bank agli ioni di litio può essere pericolosa. Verifica ogni collegamento **prima** di alimentare il circuito e mantieni antenne, cavi coassiali e piani di massa esattamente come nel progetto originale, per evitare di compromettere la sintonia del lettore.

## Elenco dei componenti (BOM)

* Lettore HID MaxiProx 5375 (o qualsiasi lettore HID Prox® a lungo raggio da 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand basato su ESP32)
* Modulo trigger USB-PD (Power-Delivery) in grado di negoziare 12 V @ ≥3 A
* Power-bank USB-C da 100 W (con profilo PD a 12 V)
* Cavo di cablaggio in silicone da 26 AWG – rosso/bianco
* Interruttore a levetta SPST da pannello (per il beeper kill-switch)
* Protezione per interruttore NKK AT4072 / cappuccio anti-attivazione accidentale
* Saldatore, treccia dissaldante e pompetta dissaldante
* Utensili manuali adatti all’ABS: sega da traforo, taglierino, lime piatte e a mezzatonda
* Punte da trapano da 1/16″ (1,5 mm) e 1/8″ (3 mm)
* Nastro biadesivo 3 M VHB e fascette

## 1. Sottosistema di alimentazione

1. Dissalda e rimuovi la scheda secondaria del convertitore buck originale, usata per generare 5 V per la PCB logica.
2. Monta un trigger USB-PD accanto all’ESP RFID Tool e porta la presa USB-C del trigger all’esterno dell’involucro.
3. Il trigger PD negozia 12 V dal power-bank e li invia direttamente al MaxiProx (il lettore richiede normalmente 10–14 V). Una linea secondaria da 5 V viene prelevata dalla scheda ESP per alimentare eventuali accessori.
4. Posiziona il pacco batteria da 100 W a filo contro il distanziale interno, in modo che **nessun** cavo di alimentazione passi sopra l’antenna in ferrite, preservando le prestazioni RF.

## 2. Beeper kill-switch – funzionamento silenzioso

1. Individua i due contatti dell’altoparlante sulla scheda logica del MaxiProx.
2. Pulisci entrambi i contatti con la treccia dissaldante, poi risalda solo il contatto **negativo**.
3. Salda cavi da 26 AWG (bianco = negativo, rosso = positivo) ai contatti del beeper e falli passare attraverso una fessura appena praticata fino a un interruttore SPST da pannello.
4. Quando l’interruttore è aperto, il circuito del beeper è interrotto e il lettore funziona in completo silenzio: l’ideale per acquisire badge di nascosto.
5. Monta sull’interruttore una protezione di sicurezza a molla NKK AT4072. Allarga con cautela il foro usando una sega da traforo o una lima finché la protezione non scatta sul corpo dell’interruttore. La protezione evita l’attivazione accidentale nello zaino.

## 3. Involucro e lavorazioni meccaniche

• Usa tronchesine a taglio raso, poi un coltello e una lima per *rimuovere* il “rigonfiamento” interno in ABS, così che la grande batteria USB-C poggi piatta sul distanziale.
• Ricava due scanalature parallele nella parete dell’involucro per il cavo USB-C: bloccheranno la batteria in posizione ed elimineranno movimenti e vibrazioni.
• Crea un’apertura rettangolare per il pulsante di **accensione** della batteria:
  1. Fissa con del nastro una sagoma di carta sul punto desiderato.
  2. Pratica fori pilota da 1/16″ in tutti e quattro gli angoli.
  3. Allargali con una punta da 1/8″.
  4. Unisci i fori con una sega da traforo; rifinisci i bordi con una lima.  
  ✱  È stato *evitato* l’uso di un Dremel rotativo: la punta ad alta velocità fonde l’ABS spesso e lascia un bordo irregolare.

## 4. Assemblaggio finale

1. Reinstalla la scheda logica del MaxiProx e risalda il cavetto SMA al contatto di massa della PCB del lettore.
2. Fissa l’ESP RFID Tool e il trigger USB-PD usando il nastro 3 M VHB.
3. Sistema tutti i cavi con fascette, mantenendo i cavi di alimentazione **lontani** dalla spira dell’antenna.
4. Stringi le viti dell’involucro finché la batteria non è leggermente compressa; l’attrito interno impedirà al pacco di spostarsi quando il dispositivo rincula a ogni lettura di una card.

## 5. Test di portata e schermatura

* Con una card di test **Pupa** da 125 kHz, il cloner portatile ha ottenuto letture costanti fino a **≈ 8 cm** in aria libera, identiche a quelle ottenute con l’alimentazione di rete.<sup>[[1]](#references)</sup>
* Posizionare il lettore in una cassetta metallica a pareti sottili (per simulare il banco di una hall bancaria) ha ridotto la portata a ≤ 2 cm, confermando che gli involucri metallici di dimensioni considerevoli agiscono da efficaci schermature RF.<sup>[[1]](#references)</sup>

## Procedura d’uso

1. Carica la batteria USB-C, collegala e aziona l’interruttore principale.
2. (Opzionale) Apri la protezione del beeper e attiva il feedback acustico durante i test al banco; blocca l’interruttore prima dell’uso sul campo in modo discreto.
3. Passa accanto alla persona che porta il badge bersaglio: il MaxiProx alimenterà la card e l’ESP RFID Tool acquisirà il flusso Wiegand.
4. Scarica le credenziali acquisite tramite Wi-Fi o USB-UART e riutilizzale o clonale secondo necessità.

## Risoluzione dei problemi

| Sintomo | Causa probabile | Soluzione |
|---------|--------------|------|
| Il lettore si riavvia quando viene presentata una card | Il trigger PD ha negoziato 9 V anziché 12 V | Verifica i ponticelli del trigger / prova un cavo USB-C di potenza superiore |
| Nessuna portata di lettura | La batteria o i cavi si trovano *sopra* l’antenna | Sposta i cavi e mantieni 2 cm di distanza dalla spira in ferrite |
| Il beeper emette ancora dei bip | L’interruttore è stato collegato sul cavo positivo invece che su quello negativo | Sposta il kill-switch in modo da interrompere la traccia **negativa** dell’altoparlante |

## References

- [1] [Cloniamo un clone – Parte 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}