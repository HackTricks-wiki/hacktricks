# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#id-9wrzi" id="id-9wrzi"></a>

Per informazioni su RFID e NFC, consulta la pagina seguente:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Carte NFC supportate <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oltre alle carte NFC, Flipper Zero supporta **altri tipi di carte ad alta frequenza**, come diverse **Mifare** Classic e Ultralight e **NTAG**.

L'elenco delle capacità riportato di seguito descrive il firmware documentato dall'articolo originale e non deve essere considerato la matrice esaustiva del supporto attuale. Il firmware di Flipper ha aggiunto protocolli e modificato il comportamento NFC nel tempo; consulta la documentazione ufficiale corrente relativa al firmware installato.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Carte bancarie (EMV)** — legge solo UID, SAK e ATQA senza salvare.
- **Carte sconosciute** — legge UID, SAK e ATQA ed emula un UID.

Per le **carte NFC di tipo B, F e V**, il firmware documentato poteva leggere un UID senza salvarlo.

### Carte NFC di tipo A <a href="#uvusf" id="uvusf"></a>

#### Carta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Il firmware documentato poteva leggere UID, SAK, ATQA e i dati delle applicazioni disponibili da una carta bancaria **senza salvarli**.

Per queste carte bancarie, il firmware visualizzava i dati senza salvare o emulare la carta.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Carte sconosciute <a href="#id-37eo8" id="id-37eo8"></a>

Quando Flipper Zero è **incapace di determinare il tipo di carta NFC**, è possibile **leggere e salvare** solo un **UID, SAK e ATQA**.

Per una carta NFC sconosciuta, questa modalità può emulare solo il suo UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Carte NFC di tipo B, F e V <a href="#wyg51" id="wyg51"></a>

Nel firmware documentato dall'articolo originale, per le carte NFC di tipo B, F e V era possibile solo leggere e visualizzare un identificatore senza salvarlo.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Azioni

Per un'introduzione all'NFC, [**leggi questa pagina**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lettura

Flipper Zero può leggere le carte NFC, ma non implementa tutti i protocolli di livello superiore basati su ISO 14443. Di conseguenza, può recuperare l'UID, il SAK e l'ATQA di basso livello, lasciando sconosciuto il protocollo applicativo. Per i sistemi di accesso primitivi che autorizzano solo tramite UID, lo strumento può leggere, inserire manualmente ed emulare tale identificatore; i sistemi autenticati crittograficamente richiedono più di un UID copiato.<sup>[[1]](#references)</sup>

#### Lettura dell'UID VS Lettura dei dati interni <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, la lettura dei tag a 13,56 MHz può essere suddivisa in due parti:<sup>[[1]](#references)</sup>

- **Lettura di basso livello** — legge solo UID, SAK e ATQA. Flipper cerca di dedurre il protocollo di alto livello in base a questi dati letti dalla carta. Non è possibile avere una certezza del 100%, poiché si tratta solo di un'ipotesi basata su determinati fattori.
- **Lettura di alto livello** — legge i dati dalla memoria della carta utilizzando uno specifico protocollo di alto livello. Ciò significa leggere i dati su una Mifare Ultralight, leggere i settori di una Mifare Classic oppure leggere gli attributi della carta da PayPass/Apple Pay.

### Lettura specifica

Se Flipper Zero non è in grado di identificare il tipo di carta dai dati di basso livello, in `Extra Actions` puoi selezionare `Read Specific Card Type` e **indicare** **manualmente** il tipo di carta che desideri leggere.

#### Carte bancarie EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

I firmware meno recenti di Flipper e le carte EMV compatibili potevano esporre più del solo UID, potenzialmente includendo il PAN, la data di scadenza, il nome del titolare o il registro delle transazioni, quando tali record erano resi disponibili dalla carta. La disponibilità varia in base alla carta, all'applicazione e al firmware. Il CVV della banda magnetica stampato sulla carta non viene esposto in questo modo e la lettura di questi record non clona la capacità crittografica delle transazioni necessaria per effettuare un pagamento contactless.<sup>[[1]](#references)</sup>

## References

- [1] [Analisi dei protocolli RFID con Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentazione di Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
