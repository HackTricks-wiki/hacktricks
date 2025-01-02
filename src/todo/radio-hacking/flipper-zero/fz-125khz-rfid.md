# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Per ulteriori informazioni su come funzionano i tag a 125kHz controlla:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Per ulteriori informazioni su questi tipi di tag [**leggi questa introduzione**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Cerca di **leggere** le informazioni della carta. Poi può **emularle**.

> [!WARNING]
> Nota che alcuni citofoni cercano di proteggersi dalla duplicazione delle chiavi inviando un comando di scrittura prima della lettura. Se la scrittura ha successo, quel tag è considerato falso. Quando Flipper emula RFID non c'è modo per il lettore di distinguerlo dall'originale, quindi non si verificano tali problemi.

### Add Manually

Puoi creare **carte false in Flipper Zero indicando i dati** manualmente e poi emularli.

#### IDs on cards

A volte, quando ottieni una carta, troverai l'ID (o parte di esso) scritto sulla carta in modo visibile.

- **EM Marin**

Ad esempio, in questa carta EM-Marin nella carta fisica è possibile **leggere gli ultimi 3 di 5 byte in chiaro**.\
Gli altri 2 possono essere forzati se non riesci a leggerli dalla carta.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Lo stesso accade in questa carta HID dove solo 2 su 3 byte possono essere trovati stampati sulla carta

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Dopo aver **copiato** una carta o **inserito** l'ID **manualmente** è possibile **emularla** con Flipper Zero o **scriverla** su una carta reale.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
