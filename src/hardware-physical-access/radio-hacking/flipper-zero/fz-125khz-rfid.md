# FZ - RFID de 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Para conocer los fundamentos del funcionamiento de las etiquetas de 125 kHz, consulta:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

La [introducción a RFID de baja frecuencia](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) explica las familias de etiquetas más comunes y sus formatos de datos.

## Acciones

### Leer

Usa **Leer** para capturar los datos de la etiqueta. Después de una lectura correcta, Flipper Zero puede emular la etiqueta guardada.<sup>[[1]](#references)</sup>

> [!WARNING]
> Algunos lectores de intercomunicadores intentan detectar etiquetas duplicadas grabables enviando un comando de escritura antes de leer. La emulación de Flipper Zero no permite acceder a la memoria grabable de la etiqueta de la misma manera.<sup>[[1]](#references)</sup>

### Añadir manualmente

Puedes introducir manualmente los datos de la etiqueta en Flipper Zero, guardarlos y luego emularla.<sup>[[1]](#references)</sup>

#### ID en tarjetas

A veces, una tarjeta tiene impreso en el exterior todo o parte de su ID.

- **EM Marin**

Por ejemplo, la tarjeta EM-Marin de la imagen muestra los tres últimos de sus cinco bytes de ID. Si no se puede leer la etiqueta, es posible hacer brute-force de los dos bytes que faltan.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

De forma similar, la tarjeta HID de la imagen solo muestra dos de sus tres bytes de ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Escribir

Después de leer una etiqueta o introducir su ID manualmente, Flipper Zero puede emular la credencial guardada. En el caso de las etiquetas grabables compatibles, también puede escribir los datos guardados en una tarjeta compatible.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Explorando los protocolos RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
