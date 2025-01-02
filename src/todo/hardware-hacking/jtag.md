# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)to narzędzie, które można używać z Raspberry PI lub Arduino, aby spróbować znaleźć piny JTAG z nieznanego układu.\
W **Arduino** podłącz **piny od 2 do 11 do 10 pinów potencjalnie należących do JTAG**. Załaduj program do Arduino, a on spróbuje brutalnie przeszukać wszystkie piny, aby sprawdzić, czy którykolwiek z nich należy do JTAG i który z nich jest którym.\
W **Raspberry PI** możesz używać tylko **pinów od 1 do 6** (6 pinów, więc testowanie każdego potencjalnego pinu JTAG będzie wolniejsze).

### Arduino

W Arduino, po podłączeniu kabli (pin 2 do 11 do pinów JTAG i GND Arduino do GND płyty głównej), **załaduj program JTAGenum do Arduino** i w Monitorze Szeregowym wyślij **`h`** (komenda pomocy), a powinieneś zobaczyć pomoc:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Skonfiguruj **"No line ending" i 115200baud**.\
Wyślij komendę s, aby rozpocząć skanowanie:

![](<../../images/image (774).png>)

Jeśli kontaktujesz się z JTAG, znajdziesz jedną lub kilka **linii zaczynających się od FOUND!**, wskazujących piny JTAG.

{{#include ../../banners/hacktricks-training.md}}
