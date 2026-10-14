# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#id-9wrzi" id="id-9wrzi"></a>

Per informazioni su RFID e NFC, consulta la seguente pagina:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Schede NFC supportate <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Oltre alle schede NFC, Flipper Zero supporta **altri tipi di schede ad alta frequenza**, come diverse schede **Mifare** Classic e Ultralight e **NTAG**.

L'elenco delle funzionalità riportato di seguito descrive il firmware documentato nell'articolo originale e non va considerato come una matrice di supporto esaustiva e aggiornata. Nel tempo il firmware di Flipper ha aggiunto protocolli e modificato il comportamento NFC; consulta la documentazione ufficiale aggiornata per il firmware installato.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Carte bancarie (EMV)** — legge solo UID, SAK e ATQA, senza salvare.
- **Schede sconosciute** — legge UID, SAK e ATQA ed emula un UID.

Per le **schede NFC di tipo B, F e V**, il firmware documentato poteva leggere un UID senza salvarlo.

### Schede NFC di tipo A <a href="#uvusf" id="uvusf"></a>

#### Carte bancarie (EMV) <a href="#kzmrp" id="kzmrp"></a>

Il firmware documentato poteva leggere UID, SAK, ATQA e i dati applicativi disponibili di una carta bancaria **senza salvarli**.

Per queste carte bancarie, il firmware mostrava i dati senza salvare né emulare la carta.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Schede sconosciute <a href="#id-37eo8" id="id-37eo8"></a>

Quando Flipper Zero **non è in grado di determinare il tipo di scheda NFC**, è possibile **leggere e salvare** solo **UID, SAK e ATQA**.

Per una scheda NFC sconosciuta, questa modalità può emularne solo l'UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Schede NFC di tipo B, F e V <a href="#wyg51" id="wyg51"></a>

Nel firmware documentato nell'articolo originale, per le schede NFC di tipo B, F e V era possibile leggere e visualizzare solo l'identificatore, senza salvarlo.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Azioni

Per un'introduzione a NFC, [**leggi questa pagina**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Lettura

Flipper Zero può leggere le schede NFC, ma non implementa tutti i protocolli di livello superiore basati su ISO 14443. Di conseguenza, potrebbe recuperare UID, SAK e ATQA a basso livello, lasciando sconosciuto il protocollo applicativo. Nei sistemi di accesso semplici che autorizzano solo in base all'UID, lo strumento può leggere, inserire manualmente ed emulare tale identificatore; i sistemi con autenticazione crittografica richiedono più di un UID copiato.<sup>[[1]](#references)</sup>

#### Lettura dell'UID VS lettura dei dati interni <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, la lettura dei tag a 13,56 MHz può essere suddivisa in due parti:<sup>[[1]](#references)</sup>

- **Lettura a basso livello** — legge solo UID, SAK e ATQA. Flipper prova a dedurre il protocollo di alto livello in base ai dati letti dalla scheda. Non è possibile averne la certezza assoluta, perché si tratta solo di un'ipotesi basata su determinati fattori.
- **Lettura ad alto livello** — legge i dati dalla memoria della scheda usando uno specifico protocollo di alto livello. Può trattarsi della lettura dei dati di una Mifare Ultralight, dei settori di una Mifare Classic o degli attributi della carta da PayPass/Apple Pay.

### Lettura specifica

Se Flipper Zero non è in grado di identificare il tipo di scheda dai dati a basso livello, in `Extra Actions` puoi selezionare `Read Specific Card Type` e **indicare manualmente il tipo di scheda da leggere**.

#### Carte bancarie EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

I firmware meno recenti di Flipper e le schede EMV compatibili potevano esporre più dell'UID, potenzialmente includendo PAN, data di scadenza, nome del titolare o registro delle transazioni, se tali record erano resi disponibili dalla scheda. La disponibilità varia in base alla carta, all'applicazione e al firmware. Il CVV della banda magnetica stampato sulla carta non viene esposto in questo modo; inoltre, la lettura di questi record non clona la funzionalità crittografica necessaria per effettuare un pagamento contactless.<sup>[[1]](#references)</sup>

## References

- [1] [Esplorazione dei protocolli RFID con Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentazione di Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
