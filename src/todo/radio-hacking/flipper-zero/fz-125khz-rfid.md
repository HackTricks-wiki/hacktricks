# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Para mais informações sobre como funcionam as tags de 125kHz, consulte:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Para mais informações sobre esses tipos de tags [**leia esta introdução**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Tenta **ler** as informações do cartão. Em seguida, pode **emular** elas.

> [!WARNING]
> Note que alguns intercomunicadores tentam se proteger contra duplicação de chaves enviando um comando de gravação antes de ler. Se a gravação for bem-sucedida, essa tag é considerada falsa. Quando o Flipper emula RFID, não há como o leitor distinguir isso do original, então não ocorrem tais problemas.

### Add Manually

Você pode criar **cartões falsos no Flipper Zero indicando os dados** manualmente e, em seguida, emulá-los.

#### IDs on cards

Às vezes, quando você obtém um cartão, encontrará o ID (ou parte dele) escrito no cartão visivelmente.

- **EM Marin**

Por exemplo, neste cartão EM-Marin, é possível **ler os últimos 3 de 5 bytes em claro**.\
Os outros 2 podem ser forçados por força bruta se você não conseguir lê-los do cartão.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

O mesmo acontece neste cartão HID, onde apenas 2 de 3 bytes podem ser encontrados impressos no cartão.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Após **copiar** um cartão ou **inserir** o ID **manualmente**, é possível **emular** com o Flipper Zero ou **gravar** em um cartão real.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
