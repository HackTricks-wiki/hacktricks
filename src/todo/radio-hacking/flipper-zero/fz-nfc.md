# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#id-9wrzi" id="id-9wrzi"></a>

Per informazioni su RFID e NFC, consulta la seguente pagina:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Carte NFC supportate <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oltre alle carte NFC, Flipper Zero supporta **altri tipi di carte ad alta frequenza**, come diverse carte **Mifare** Classic e Ultralight e **NTAG**.

Nuovi tipi di carte NFC verranno aggiunti all'elenco delle carte supportate. Flipper Zero supporta i seguenti **tipi di carte NFC A** (ISO 14443A):

- **Carte bancarie (EMV)** — legge solo UID, SAK e ATQA senza salvare.
- **Carte sconosciute** — legge (UID, SAK, ATQA) ed emula un UID.

Per le **carte NFC di tipo B, tipo F e tipo V**, Flipper Zero è in grado di leggere un UID senza salvarlo.

### Carte NFC di tipo A <a href="#uvusf" id="uvusf"></a>

#### Carta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero può solo leggere un UID, SAK, ATQA e i dati memorizzati sulle carte bancarie **senza salvarli**.

Schermata di lettura della carta bancariaPer le carte bancarie, Flipper Zero può solo leggere i dati **senza salvarli né emularli**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Carte sconosciute <a href="#id-37eo8" id="id-37eo8"></a>

Quando Flipper Zero **non è in grado di determinare il tipo di carta NFC**, è possibile solo **leggere e salvare** un **UID, SAK e ATQA**.

Schermata di lettura della carta sconosciutaPer le carte NFC sconosciute, Flipper Zero può emulare solo un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Carte NFC di tipo B, F e V <a href="#wyg51" id="wyg51"></a>

Per le **carte NFC di tipo B, F e V**, Flipper Zero può solo **leggere e visualizzare un UID** senza salvarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Azioni

Per un'introduzione all'NFC [**leggi questa pagina**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lettura

Flipper Zero può **leggere le carte NFC**, tuttavia **non comprende tutti i protocolli** basati su ISO 14443. Tuttavia, poiché **UID è un attributo di basso livello**, potresti trovarti in una situazione in cui **l'UID è già stato letto, ma il protocollo di trasferimento dei dati di alto livello è ancora sconosciuto**. Puoi leggere, emulare e inserire manualmente l'UID usando Flipper per i lettori primitivi che usano l'UID per l'autorizzazione.<sup>[[1]](#references)</sup>

#### Lettura dell'UID VS Lettura dei dati interni <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, la lettura dei tag a 13,56 MHz può essere suddivisa in due parti:<sup>[[1]](#references)</sup>

- **Lettura di basso livello** — legge solo UID, SAK e ATQA. Flipper cerca di dedurre il protocollo di alto livello in base a questi dati letti dalla carta. Non puoi avere una certezza del 100% al riguardo, poiché si tratta solo di un'ipotesi basata su determinati fattori.
- **Lettura di alto livello** — legge i dati dalla memoria della carta usando uno specifico protocollo di alto livello. Ciò significa leggere i dati su una Mifare Ultralight, leggere i settori di una Mifare Classic oppure leggere gli attributi della carta da PayPass/Apple Pay.

### Lettura specifica

Nel caso in cui Flipper Zero non sia in grado di trovare il tipo di carta dai dati di basso livello, in `Extra Actions` puoi selezionare `Read Specific Card Type` e **indicare** **manualmente il tipo di carta che desideri leggere**.

#### Carte bancarie EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oltre alla semplice lettura dell'UID, puoi estrarre molti più dati da una carta bancaria. È possibile **ottenere il numero completo della carta** (le 16 cifre sul lato anteriore della carta), la **data di validità** e, in alcuni casi, persino il **nome del titolare**, insieme a un elenco delle **transazioni più recenti**.\
Tuttavia, **non puoi leggere il CVV in questo modo** (le 3 cifre sul retro della carta). Inoltre, **le carte bancarie sono protette dagli attacchi di replay**, quindi copiarle con Flipper e poi provare a emularle per pagare qualcosa non funzionerà.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
