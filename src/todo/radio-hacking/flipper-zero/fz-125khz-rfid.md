# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Para mais informações sobre como funcionam as tags de 125kHz, consulte:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Ações

Para mais informações sobre esses tipos de tags [**leia esta introdução**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Ler

Tenta **ler** as informações do cartão. Então pode **emular** elas.

> [!WARNING]
> Note que alguns intercomunicadores tentam se proteger contra a duplicação de chaves enviando um comando de gravação antes da leitura. Se a gravação for bem-sucedida, essa tag é considerada falsa. Quando o Flipper emula RFID, não há como o leitor distinguir isso do original, então não ocorrem tais problemas.

### Adicionar Manualmente

Você pode criar **cartões falsos no Flipper Zero indicando os dados** que você insere manualmente e então emulá-los.

#### IDs nos cartões

Às vezes, quando você obtém um cartão, encontrará o ID (ou parte dele) escrito no cartão visivelmente.

- **EM Marin**

Por exemplo, neste cartão EM-Marin, é possível **ler os últimos 3 de 5 bytes em claro**.\
Os outros 2 podem ser forçados por força bruta se você não conseguir lê-los do cartão.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

O mesmo acontece neste cartão HID, onde apenas 2 de 3 bytes podem ser encontrados impressos no cartão.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Gravar

Após **copiar** um cartão ou **inserir** o ID **manualmente**, é possível **emular** com o Flipper Zero ou **gravar** em um cartão real.

## Referências

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
