# JTAGenum

[JTAGenum](https://github.com/cyphunk/JTAGenum) es una herramienta que se puede utilizar con una Raspberry PI o un Arduino para probar los pines JTAG de un chip desconocido.\
En **Arduino**, conecta los **pines del 2 al 11 a los 10 pines que potencialmente pertenecen a un JTAG**. Carga el programa en el Arduino y tratará de probar todos los pines para encontrar si alguno pertenece a JTAG y cuál es cada uno.\
En la **Raspberry PI** solo se pueden utilizar **pines del 1 al 6** (6 pines, por lo que irás más lento probando cada pin JTAG potencial).

## Arduino

En Arduino, después de conectar los cables (pin 2 al 11 a los pines JTAG y Arduino GND a la base GND), **carga el programa JTAGenum en Arduino** y en el Monitor Serie envía una **`h`** (comando de ayuda) y deberías ver la ayuda:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configura **"No line ending" y 115200baud**.\
Envía el comando s para comenzar el escaneo:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Si estás conectado a un JTAG, encontrarás una o varias **líneas que comienzan por FOUND!** indicando los pines de JTAG.
