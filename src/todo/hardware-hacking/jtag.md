# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum) es una herramienta que se puede usar con un Raspberry PI o un Arduino para intentar encontrar pines JTAG de un chip desconocido.\
En el **Arduino**, conecta los **pines del 2 al 11 a 10 pines que potencialmente pertenecen a un JTAG**. Carga el programa en el Arduino y intentará hacer un ataque de fuerza bruta a todos los pines para encontrar si alguno pertenece a JTAG y cuál es cada uno.\
En el **Raspberry PI** solo puedes usar **pines del 1 al 6** (6 pines, por lo que irás más lento probando cada pin potencial de JTAG).

### Arduino

En Arduino, después de conectar los cables (pin 2 a 11 a los pines JTAG y GND de Arduino a GND de la placa base), **carga el programa JTAGenum en Arduino** y en el Monitor Serial envía un **`h`** (comando para ayuda) y deberías ver la ayuda:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Configura **"Sin final de línea" y 115200baud**.\
Envía el comando s para comenzar a escanear:

![](<../../images/image (774).png>)

Si estás contactando un JTAG, encontrarás una o varias **líneas que comienzan con FOUND!** indicando los pines de JTAG.

{{#include ../../banners/hacktricks-training.md}}
