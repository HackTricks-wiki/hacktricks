# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)è uno strumento che può essere utilizzato con un Raspberry PI o un Arduino per cercare di identificare i pin JTAG di un chip sconosciuto.\
Nel **Arduino**, collega i **pin da 2 a 11 a 10 pin che potrebbero appartenere a un JTAG**. Carica il programma nell'Arduino e cercherà di forzare tutti i pin per scoprire se alcuni di essi appartengono a JTAG e quale sia ciascuno.\
Nel **Raspberry PI** puoi utilizzare solo **pin da 1 a 6** (6 pin, quindi andrà più lentamente testando ciascun potenziale pin JTAG).

### Arduino

In Arduino, dopo aver collegato i cavi (pin 2 a 11 ai pin JTAG e GND dell'Arduino al GND della scheda madre), **carica il programma JTAGenum nell'Arduino** e nel Monitor Serial invia un **`h`** (comando per aiuto) e dovresti vedere l'aiuto:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Configura **"No line ending" e 115200baud**.\
Invia il comando s per iniziare la scansione:

![](<../../images/image (774).png>)

Se stai contattando un JTAG, troverai una o più **righe che iniziano con FOUND!** che indicano i pin di JTAG.

{{#include ../../banners/hacktricks-training.md}}
