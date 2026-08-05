# Costruire un clonatore mobile HID MaxiProx 125 kHz portatile

{{#include ../../banners/hacktricks-training.md}}

## Obiettivo
Trasformare un lettore HID MaxiProx 5375 a lungo raggio da 125 kHz, alimentato dalla rete elettrica, in un clonatore di badge alimentato a batteria e utilizzabile sul campo, in grado di raccogliere silenziosamente le proximity card durante le valutazioni di sicurezza fisica.

La conversione descritta si basa sulla serie di ricerche di TrustedSec “Let’s Clone a Cloner – Part 3: Putting It All Together” e combina considerazioni meccaniche, elettriche e RF, così che il dispositivo finale possa essere trasportato in uno zaino e utilizzato immediatamente sul posto.<sup>[[1]](#references)</sup>

> [!warning]
> La manipolazione di apparecchiature alimentate dalla rete elettrica e di power-bank agli ioni di litio può essere pericolosa. Verificare ogni collegamento **prima** di alimentare il circuito e mantenere antenne, cavi coassiali e piani di massa esattamente come nella progettazione di fabbrica, per evitare di desintonizzare il lettore.

## Distinta materiali (BOM)

* Lettore HID MaxiProx 5375 (o qualsiasi lettore HID Prox® a lungo raggio da 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand basato su ESP32)
* Modulo trigger USB-PD (Power-Delivery) in grado di negoziare 12 V a ≥3 A
* Power-bank USB-C da 100 W (fornisce il profilo PD da 12 V)
* Cavo per cablaggio da 26 AWG con isolamento in silicone – rosso/bianco
* Interruttore a levetta SPST da pannello (per il kill-switch del beep)
* Protezione per interruttore NKK AT4072 / cappuccio anti-attivazione accidentale
* Saldatore, trecciola dissaldante e pompa dissaldante
* Utensili manuali compatibili con ABS: sega da traforo, taglierino, lime piatte e semitonde
* Punte da trapano da 1/16″ (1,5 mm) e 1/8″ (3 mm)
* Nastro biadesivo VHB 3 M e fascette

## 1. Sotto-sistema di alimentazione

1. Dissaldare e rimuovere la scheda figlia del buck-converter di fabbrica utilizzata per generare 5 V per la PCB logica.
2. Montare un trigger USB-PD accanto all’ESP RFID Tool e portare il connettore USB-C del trigger all’esterno dell’enclosure.
3. Il trigger PD negozia 12 V dal power-bank e li fornisce direttamente al MaxiProx (il lettore richiede nativamente 10–14 V). Una rail secondaria da 5 V viene prelevata dalla scheda ESP per alimentare eventuali accessori.
4. Il battery pack da 100 W viene posizionato a filo contro il distanziale interno, in modo che **non** vi siano cavi di alimentazione disposti sopra l’antenna in ferrite, preservando le prestazioni RF.

## 2. Beeper Kill-Switch – Funzionamento silenzioso

1. Individuare i due pad dello speaker sulla scheda logica del MaxiProx.
2. Dissaldare completamente *entrambi* i pad, quindi risaldare solo il pad **negativo**.
3. Saldare cavi da 26 AWG (bianco = negativo, rosso = positivo) ai pad del beeper e portarli attraverso una nuova fessura fino a un interruttore SPST da pannello.
4. Quando l’interruttore è aperto, il circuito del beeper viene interrotto e il lettore funziona in completo silenzio, ideale per la raccolta covert di badge.
5. Installare una protezione di sicurezza a molla NKK AT4072 sopra la levetta. Allargare con cautela il foro usando una sega da traforo / lima finché la protezione scatta sul corpo dell’interruttore. La protezione impedisce l’attivazione accidentale all’interno dello zaino.

## 3. Enclosure e lavorazione meccanica

• Usare prima una tronchesina a filo e poi un coltello e una lima per *rimuovere* il “rigonfiamento” interno in ABS, così che la grande batteria USB-C poggi piatta sul distanziale.
• Ricavare due scanalature parallele nella parete dell’enclosure per il cavo USB-C; questo blocca la batteria in posizione ed elimina movimenti e vibrazioni.
• Creare un’apertura rettangolare per il pulsante di **alimentazione** della batteria:
1. Applicare una sagoma di carta sulla posizione.
2. Praticare fori pilota da 1/16″ nei quattro angoli.
3. Allargare con una punta da 1/8″.
4. Unire i fori con una sega da traforo; rifinire i bordi con una lima.
✱  È stato *evitato* un Dremel rotativo: la punta ad alta velocità fonde l’ABS spesso e lascia un bordo antiestetico.

## 4. Assemblaggio finale

1. Reinstallare la scheda logica del MaxiProx e risaldare il pigtail SMA al pad di massa della PCB del lettore.
2. Fissare l’ESP RFID Tool e il trigger USB-PD usando VHB 3 M.
3. Ordinare tutti i cavi con fascette, mantenendo i conduttori di alimentazione **lontani** dal loop dell’antenna.
4. Stringere le viti dell’enclosure finché la batteria non risulta leggermente compressa; l’attrito interno impedisce al pack di spostarsi quando il dispositivo rincula dopo ogni lettura della card.

## 5. Test di portata e schermatura

* Utilizzando una card di test **Pupa** da 125 kHz, il clonatore portatile ha ottenuto letture costanti a **≈ 8 cm** all’aria libera, identiche a quelle ottenute durante il funzionamento alimentato dalla rete.<sup>[[1]](#references)</sup>
* Posizionando il lettore all’interno di una sottile cassetta metallica (per simulare una scrivania nella hall di una banca), la portata si è ridotta a ≤ 2 cm, confermando che gli involucri metallici consistenti agiscono come efficaci schermature RF.<sup>[[1]](#references)</sup>

## Flusso operativo

1. Caricare la batteria USB-C, collegarla e attivare l’interruttore principale di alimentazione.
2. (Facoltativo) Aprire la protezione del beeper e abilitare il feedback acustico durante i test sul banco; bloccarla prima dell’uso covert sul campo.
3. Passare accanto al titolare del badge target: il MaxiProx alimenterà la card e l’ESP RFID Tool acquisirà il flusso Wiegand.
4. Esportare le credenziali acquisite tramite Wi-Fi o USB-UART e riprodurle/clonarle secondo necessità.

## Risoluzione dei problemi

| Sintomo | Causa probabile | Soluzione |
|---------|-----------------|-----------|
| Il lettore si riavvia quando viene presentata una card | Il trigger PD ha negoziato 9 V invece di 12 V | Verificare i jumper del trigger / provare un cavo USB-C più potente |
| Nessuna portata di lettura | La batteria o il cablaggio si trovano *sopra* l’antenna | Reindirizzare i cavi e mantenere 2 cm di distanza attorno al loop in ferrite |
| Il beeper emette ancora dei beep | L’interruttore è stato cablato sul conduttore positivo invece che su quello negativo | Spostare il kill-switch in modo da interrompere la traccia dello speaker **negativa** |

## Riferimenti

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
