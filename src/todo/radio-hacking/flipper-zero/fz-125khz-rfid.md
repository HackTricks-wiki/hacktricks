# FZ - RFID de 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Para obtener información de contexto sobre cómo funcionan las tags de 125 kHz, consulta:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

La [introducción a RFID de baja frecuencia](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) explica las familias de tags comunes y sus formatos de datos.

## Acciones

### Leer

Usa **Leer** para capturar los datos de la tag. Después de una lectura exitosa, Flipper Zero puede emular la tag guardada.<sup>[[1]](#references)</sup>

> [!WARNING]
> Algunos lectores de intercomunicadores intentan detectar tags duplicadas escribibles emitiendo un comando de escritura antes de leer. Una emulación de Flipper Zero no expone la memoria escribible de la tag de la misma manera.<sup>[[1]](#references)</sup>

### Añadir manualmente

Puedes introducir manualmente los datos de la tag en Flipper Zero, guardarlos y, después, emularla.<sup>[[1]](#references)</sup>

#### IDs en tarjetas

A veces, una tarjeta tiene toda su ID o parte de ella impresa en el exterior.

- **EM Marin**

Por ejemplo, la tarjeta EM-Marin mostrada expone los últimos tres de sus cinco bytes de ID. Si no se puede leer la tag, los dos bytes que faltan pueden obtenerse mediante brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

De forma similar, la tarjeta HID mostrada imprime solo dos de los tres bytes de ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Escribir

Después de leer una tag o introducir su ID manualmente, Flipper Zero puede emular la credencial guardada. Para las tags escribibles compatibles, también puede escribir los datos guardados en una tarjeta compatible.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Inmersión en los protocolos RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
