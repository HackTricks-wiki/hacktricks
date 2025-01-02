# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

Para más información sobre cómo funcionan las etiquetas de 125kHz, consulta:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Para más información sobre estos tipos de etiquetas [**lee esta introducción**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Intenta **leer** la información de la tarjeta. Luego puede **emularlas**.

> [!WARNING]
> Ten en cuenta que algunos intercomunicadores intentan protegerse de la duplicación de llaves enviando un comando de escritura antes de leer. Si la escritura tiene éxito, esa etiqueta se considera falsa. Cuando Flipper emula RFID, no hay forma de que el lector la distinga de la original, por lo que no ocurren tales problemas.

### Add Manually

Puedes crear **tarjetas falsas en Flipper Zero indicando los datos** que ingresas manualmente y luego emularla.

#### IDs on cards

A veces, cuando obtienes una tarjeta, encontrarás el ID (o parte de él) escrito en la tarjeta visible.

- **EM Marin**

Por ejemplo, en esta tarjeta EM-Marin, en la tarjeta física es posible **leer los últimos 3 de 5 bytes en claro**.\
Los otros 2 pueden ser forzados por fuerza bruta si no puedes leerlos de la tarjeta.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Lo mismo ocurre en esta tarjeta HID donde solo se pueden encontrar impresos 2 de 3 bytes en la tarjeta.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Después de **copiar** una tarjeta o **ingresar** el ID **manualmente**, es posible **emularla** con Flipper Zero o **escribirla** en una tarjeta real.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
