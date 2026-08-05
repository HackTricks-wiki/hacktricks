# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Introdução

Para mais informações sobre como as tags de 125kHz funcionam, consulte:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Ações

Para mais informações sobre esses tipos de tags, [**leia esta introdução**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Ler

Tenta **ler** as informações do cartão. Depois, é possível **emulá-lo**.<sup>[[1]](#references)</sup>

> [!WARNING]
> Observe que alguns intercomunicadores tentam se proteger contra a duplicação de chaves enviando um comando de escrita antes da leitura. Se a escrita for bem-sucedida, a tag será considerada falsa. Quando o Flipper emula RFID, não há como o leitor distingui-lo do original, portanto, esses problemas não ocorrem.

### Adicionar manualmente

Você pode criar **cartões falsos no Flipper Zero indicando os dados** manualmente e, em seguida, emulá-los.

#### IDs nos cartões

Às vezes, quando você recebe um cartão, encontrará o ID (ou parte dele) escrito de forma visível no cartão.

- **EM Marin**

Por exemplo, neste cartão EM-Marin, é possível **ler claramente os últimos 3 de 5 bytes** no cartão físico.\
Os outros 2 podem sofrer brute-force caso você não consiga lê-los no cartão.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

O mesmo acontece neste cartão HID, no qual apenas 2 dos 3 bytes podem ser encontrados impressos no cartão.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Escrever

Depois de **copiar** um cartão ou **inserir** o ID **manualmente**, é possível **emulá-lo** com o Flipper Zero ou **escrevê-lo** em um cartão real.<sup>[[1]](#references)</sup>

## Referências

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
