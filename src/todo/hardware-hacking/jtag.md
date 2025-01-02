# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum) ist ein Tool, das mit einem Raspberry PI oder einem Arduino verwendet werden kann, um JTAG-Pins von einem unbekannten Chip zu finden.\
Im **Arduino** verbinden Sie die **Pins von 2 bis 11 mit 10 Pins, die potenziell zu einem JTAG gehören**. Laden Sie das Programm in den Arduino und es wird versuchen, alle Pins zu bruteforcen, um herauszufinden, ob einer der Pins zu JTAG gehört und welcher es ist.\
Im **Raspberry PI** können Sie nur **Pins von 1 bis 6** verwenden (6 Pins, daher wird es langsamer, jeden potenziellen JTAG-Pin zu testen).

### Arduino

Im Arduino, nachdem Sie die Kabel verbunden haben (Pin 2 bis 11 zu JTAG-Pins und Arduino GND zu dem GND der Basisplatine), **laden Sie das JTAGenum-Programm in Arduino** und senden Sie im Serial Monitor ein **`h`** (Befehl für Hilfe) und Sie sollten die Hilfe sehen:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Konfigurieren Sie **"No line ending" und 115200baud**.\
Senden Sie den Befehl s, um den Scan zu starten:

![](<../../images/image (774).png>)

Wenn Sie einen JTAG kontaktieren, finden Sie eine oder mehrere **Zeilen, die mit FOUND! beginnen**, die die Pins des JTAG anzeigen.

{{#include ../../banners/hacktricks-training.md}}
