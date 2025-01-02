# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum) is 'n hulpmiddel wat gebruik kan word met 'n Raspberry PI of 'n Arduino om te probeer JTAG-pinne van 'n onbekende chip te vind.\
In die **Arduino**, koppel die **pinnes van 2 tot 11 aan 10pinnes wat moontlik aan 'n JTAG behoort**. Laai die program in die Arduino en dit sal probeer om al die pinnes te bruteforce om te vind of enige pinnes aan JTAG behoort en watter een elkeen is.\
In die **Raspberry PI** kan jy slegs **pinnes van 1 tot 6** gebruik (6pinnes, so jy sal stadiger gaan om elke potensiële JTAG-pin te toets).

### Arduino

In Arduino, nadat jy die kabels gekoppel het (pin 2 tot 11 aan JTAG-pinne en Arduino GND aan die basisbord GND), **laai die JTAGenum-program in Arduino** en in die Serial Monitor stuur 'n **`h`** (opdrag vir hulp) en jy behoort die hulp te sien:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Konfigureer **"No line ending" en 115200baud**.\
Stuur die opdrag s om te begin skandeer:

![](<../../images/image (774).png>)

As jy 'n JTAG kontak, sal jy een of verskeie **lyne wat met FOUND! begin** vind wat die pinnes van JTAG aandui.

{{#include ../../banners/hacktricks-training.md}}
