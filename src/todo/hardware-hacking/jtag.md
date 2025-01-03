# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)je alat koji se može koristiti sa Raspberry PI ili Arduinom da pronađe JTAG pinove sa nepoznatog čipa.\
U **Arduinu**, povežite **pinove od 2 do 11 sa 10 pinova koji potencijalno pripadaju JTAG-u**. Učitajte program u Arduino i on će pokušati da bruteforce sve pinove da vidi da li neki pin pripada JTAG-u i koji je koji.\
U **Raspberry PI** možete koristiti samo **pinove od 1 do 6** (6 pinova, tako da ćete sporije testirati svaki potencijalni JTAG pin).

### Arduino

U Arduinu, nakon povezivanja kablova (pin 2 do 11 sa JTAG pinovima i Arduino GND sa GND na matičnoj ploči), **učitajte JTAGenum program u Arduino** i u Serial Monitor pošaljite **`h`** (komanda za pomoć) i trebali biste videti pomoć:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Konfigurišite **"No line ending" i 115200baud**.\
Pošaljite komandu s da započnete skeniranje:

![](<../../images/image (774).png>)

Ako kontaktirate JTAG, pronaći ćete jedan ili više **redova koji počinju sa FOUND!** koji označavaju pinove JTAG-a.

{{#include ../../banners/hacktricks-training.md}}
