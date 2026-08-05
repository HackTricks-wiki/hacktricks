# FZ - RFID de 125 kHz

{{#include ../../../banners/hacktricks-training.md}}


## Introducción

Para obtener más información sobre cómo funcionan los tags de 125 kHz, consulta:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Acciones

Para obtener más información sobre estos tipos de tags, [**lee esta introducción**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Leer

Intenta **leer** la información de la tarjeta. Después puede **emularla**.<sup>[[1]](#references)</sup>

> [!WARNING]
> Ten en cuenta que algunos intercomunicadores intentan protegerse contra la duplicación de claves enviando un comando de escritura antes de leer. Si la escritura tiene éxito, ese tag se considera falso. Cuando Flipper emula RFID, no hay forma de que el lector lo distinga del original, por lo que no se producen estos problemas.

### Añadir manualmente

Puedes crear **tarjetas falsas en Flipper Zero indicando los datos** manualmente y después emularlas.

#### IDs en las tarjetas

A veces, cuando obtienes una tarjeta, encontrarás el ID (o parte de él) escrito y visible en la tarjeta.

- **EM Marin**

Por ejemplo, en esta tarjeta EM-Marin física es posible **leer claramente los últimos 3 de 5 bytes**.\
Los otros 2 pueden obtenerse mediante fuerza bruta si no puedes leerlos en la tarjeta.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Lo mismo ocurre en esta tarjeta HID, donde solo se pueden encontrar 2 de los 3 bytes impresos en la tarjeta.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Escribir

Después de **copiar** una tarjeta o **introducir** el ID **manualmente**, es posible **emularla** con Flipper Zero o **escribirla** en una tarjeta real.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
