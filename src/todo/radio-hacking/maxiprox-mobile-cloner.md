# Costruire un Cloner Mobile HID MaxiProx 125 kHz Portatile

{{#include ../../banners/hacktricks-training.md}}

## Obiettivo
Trasformare un lettore HID MaxiProx 5375 a lungo raggio da 125 kHz alimentato a rete in un cloner di badge portatile, alimentato a batteria, che raccoglie silenziosamente le carte di prossimità durante le valutazioni di sicurezza fisica.

La conversione trattata qui si basa sulla serie di ricerche di TrustedSec “Let’s Clone a Cloner – Part 3: Putting It All Together” e combina considerazioni meccaniche, elettriche e RF affinché il dispositivo finale possa essere riposto in uno zaino e utilizzato immediatamente sul campo.

> [!warning]
> Manipolare attrezzature alimentate a rete e power bank agli ioni di litio può essere pericoloso. Verifica ogni connessione **prima** di energizzare il circuito e mantieni le antenne, il coassiale e i piani di massa esattamente come erano nel design di fabbrica per evitare di disaccordare il lettore.

## Distinta dei Materiali (BOM)

* Lettore HID MaxiProx 5375 (o qualsiasi lettore HID Prox® a lungo raggio da 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand basato su ESP32)
* Modulo trigger USB-PD (Power-Delivery) in grado di negoziare 12 V @ ≥3 A
* Power bank USB-C da 100 W (fornisce profilo PD a 12 V)
* Filo di collegamento in silicone da 26 AWG – rosso/bianco
* Interruttore a levetta SPST da pannello (per interruttore di disattivazione del beeper)
* Cappuccio di protezione NKK AT4072 / cappuccio anti-incidenti
* Saldatore, treccia per dissaldare e pompa per dissaldare
* Utensili manuali in ABS: seghetto, coltello multiuso, lime piatte e a mezzo tondo
* Punte da trapano da 1/16″ (1,5 mm) e 1/8″ (3 mm)
* Nastro biadesivo 3 M VHB e fascette

## 1. Sottosistema di Alimentazione

1. Dissaldare e rimuovere la scheda figlia del convertitore buck di fabbrica utilizzata per generare 5 V per la PCB logica.
2. Montare un trigger USB-PD accanto all'ESP RFID Tool e portare il connettore USB-C del trigger all'esterno dell'involucro.
3. Il trigger PD negozia 12 V dal power bank e lo fornisce direttamente al MaxiProx (il lettore si aspetta nativamente 10–14 V). Una linea secondaria da 5 V è prelevata dalla scheda ESP per alimentare eventuali accessori.
4. Il pacco batteria da 100 W è posizionato a filo contro il distanziatore interno in modo che non ci siano **cavi di alimentazione** appesi all'antenna in ferrite, preservando le prestazioni RF.

## 2. Interruttore di Disattivazione del Beeper – Funzionamento Silenzioso

1. Individuare i due pad del diffusore sulla scheda logica del MaxiProx.
2. Pulire *entrambi* i pad, quindi risaldare solo il pad **negativo**.
3. Saldare fili da 26 AWG (bianco = negativo, rosso = positivo) ai pad del beeper e portarli attraverso una fessura appena tagliata a un interruttore SPST da pannello.
4. Quando l'interruttore è aperto, il circuito del beeper è interrotto e il lettore funziona in completo silenzio – ideale per la raccolta furtiva di badge.
5. Montare un cappuccio di sicurezza a molla NKK AT4072 sopra l'interruttore. Allargare con attenzione il foro con un seghetto / lima fino a farlo scattare sopra il corpo dell'interruttore. La protezione previene attivazioni accidentali all'interno di uno zaino.

## 3. Involucro e Lavoro Meccanico

• Utilizzare tronchesi a filo e poi un coltello e una lima per *rimuovere* il “bump-out” interno in ABS in modo che la grande batteria USB-C si adagi piatta sul distanziatore.
• Intagliare due canali paralleli nella parete dell'involucro per il cavo USB-C; questo blocca la batteria in posizione ed elimina movimento/vibrazione.
• Creare un'apertura rettangolare per il pulsante di **alimentazione** della batteria:
1. Attaccare uno stencil di carta sopra la posizione.
2. Forare fori pilota da 1/16″ in tutti e quattro gli angoli.
3. Allargare con una punta da 1/8″.
4. Unire i fori con un seghetto; rifinire i bordi con una lima.
✱  Un Dremel rotativo è stato *evitato* – la punta ad alta velocità fonde l'ABS spesso e lascia un bordo brutto.

## 4. Assemblaggio Finale

1. Reinstallare la scheda logica del MaxiProx e risaldare il pigtail SMA al pad di massa della PCB del lettore.
2. Montare l'ESP RFID Tool e il trigger USB-PD utilizzando 3 M VHB.
3. Sistemare tutti i cablaggi con fascette, mantenendo i cavi di alimentazione **lontani** dal loop dell'antenna.
4. Serrare le viti dell'involucro fino a quando la batteria è leggermente compressa; l'attrito interno impedisce al pacco di spostarsi quando il dispositivo si ritrae dopo ogni lettura della carta.

## 5. Test di Portata e Schermatura

* Utilizzando una carta di test **Pupa** da 125 kHz, il cloner portatile ha ottenuto letture costanti a **≈ 8 cm** in aria libera – identico al funzionamento alimentato a rete.
* Posizionando il lettore all'interno di una cassetta di metallo a parete sottile (per simulare un banco di lobby di una banca) la portata è stata ridotta a ≤ 2 cm, confermando che involucri metallici sostanziali agiscono come efficaci schermi RF.

## Flusso di Utilizzo

1. Caricare la batteria USB-C, collegarla e attivare l'interruttore di alimentazione principale.
2. (Opzionale) Aprire la protezione del beeper e abilitare il feedback acustico durante il test in laboratorio; bloccarlo prima dell'uso furtivo sul campo.
3. Passare accanto al titolare del badge target – il MaxiProx energizzerà la carta e l'ESP RFID Tool catturerà il flusso Wiegand.
4. Scaricare le credenziali catturate tramite Wi-Fi o USB-UART e riprodurre/clonare secondo necessità.

## Risoluzione dei Problemi

| Sintomo | Probabile Causa | Soluzione |
|---------|------------------|-----------|
| Il lettore si riavvia quando viene presentata la carta | Il trigger PD ha negoziato 9 V invece di 12 V | Verificare i jumper del trigger / provare un cavo USB-C ad alta potenza |
| Nessuna portata di lettura | Batteria o cablaggio posizionati *sopra* l'antenna | Riposizionare i cavi e mantenere 2 cm di distanza attorno al loop in ferrite |
| Il beeper continua a suonare | Interruttore cablato sul cavo positivo invece che su quello negativo | Spostare l'interruttore di disattivazione per interrompere il **traccia** del diffusore negativo |

## Riferimenti

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
