# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Per informazioni su RFID e NFC controlla la seguente pagina:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Schede NFC supportate <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oltre alle schede NFC, Flipper Zero supporta **altri tipi di schede ad alta frequenza** come diverse **Mifare** Classic e Ultralight e **NTAG**.

Nuovi tipi di schede NFC saranno aggiunti all'elenco delle schede supportate. Flipper Zero supporta i seguenti **tipi di schede NFC A** (ISO 14443A):

- **Schede bancarie (EMV)** — solo lettura di UID, SAK e ATQA senza salvataggio.
- **Schede sconosciute** — leggi (UID, SAK, ATQA) ed emula un UID.

Per **schede NFC di tipo B, tipo F e tipo V**, Flipper Zero è in grado di leggere un UID senza salvarlo.

### Schede NFC di tipo A <a href="#uvusf" id="uvusf"></a>

#### Scheda bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero può solo leggere un UID, SAK, ATQA e dati memorizzati su schede bancarie **senza salvataggio**.

Schermata di lettura della scheda bancariaPer le schede bancarie, Flipper Zero può solo leggere i dati **senza salvarli ed emularli**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Schede sconosciute <a href="#id-37eo8" id="id-37eo8"></a>

Quando Flipper Zero è **impossibilitato a determinare il tipo di scheda NFC**, allora solo un **UID, SAK e ATQA** possono essere **letti e salvati**.

Schermata di lettura della scheda sconosciutaPer le schede NFC sconosciute, Flipper Zero può emulare solo un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Schede NFC di tipo B, F e V <a href="#wyg51" id="wyg51"></a>

Per **schede NFC di tipo B, F e V**, Flipper Zero può solo **leggere e visualizzare un UID** senza salvarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Azioni

Per un'introduzione su NFC [**leggi questa pagina**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leggi

Flipper Zero può **leggere schede NFC**, tuttavia, **non comprende tutti i protocolli** basati su ISO 14443. Tuttavia, poiché **UID è un attributo a basso livello**, potresti trovarti in una situazione in cui **UID è già stato letto, ma il protocollo di trasferimento dati ad alto livello è ancora sconosciuto**. Puoi leggere, emulare e inserire manualmente UID utilizzando Flipper per i lettori primitivi che usano UID per l'autorizzazione.

#### Lettura dell'UID VS Lettura dei Dati Interni <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, la lettura delle etichette a 13.56 MHz può essere suddivisa in due parti:

- **Lettura a basso livello** — legge solo UID, SAK e ATQA. Flipper cerca di indovinare il protocollo di alto livello basato su questi dati letti dalla scheda. Non puoi essere sicuro al 100% di questo, poiché è solo un'ipotesi basata su determinati fattori.
- **Lettura ad alto livello** — legge i dati dalla memoria della scheda utilizzando un protocollo di alto livello specifico. Questo sarebbe leggere i dati su un Mifare Ultralight, leggere i settori da un Mifare Classic o leggere gli attributi della scheda da PayPass/Apple Pay.

### Leggi Specifico

Nel caso in cui Flipper Zero non sia in grado di trovare il tipo di scheda dai dati a basso livello, in `Azioni Extra` puoi selezionare `Leggi Tipo di Scheda Specifico` e **indicare manualmente** **il tipo di scheda che desideri leggere**.

#### Schede Bancarie EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Oltre a leggere semplicemente l'UID, puoi estrarre molti più dati da una scheda bancaria. È possibile **ottenere il numero completo della scheda** (le 16 cifre sul fronte della scheda), **data di validità**, e in alcuni casi anche il **nome del proprietario** insieme a un elenco delle **transazioni più recenti**.\
Tuttavia, **non puoi leggere il CVV in questo modo** (le 3 cifre sul retro della scheda). Inoltre, **le schede bancarie sono protette da attacchi di replay**, quindi copiarle con Flipper e poi cercare di emularle per pagare qualcosa non funzionerà.

## Riferimenti

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
