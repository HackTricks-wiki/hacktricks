# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#id-9wrzi" id="id-9wrzi"></a>

Vir inligting oor RFID en NFC, kyk na die volgende bladsy:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Ondersteunde NFC-kaarte <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Afgesien van NFC-kaarte, ondersteun Flipper Zero **ander soorte hoëfrekwensiekaarte**, soos verskeie **Mifare** Classic- en Ultralight-kaarte, asook **NTAG**.

Die vermoëlys hieronder beskryf die firmware wat in die oorspronklike artikel gedokumenteer is en moet nie as die huidige, volledige ondersteuningsmatriks beskou word nie. Flipper-firmware het mettertyd protokolle bygevoeg en NFC-gedrag verander; raadpleeg die huidige amptelike dokumentasie vir die geïnstalleerde firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bankkaarte (EMV)** — lees slegs die UID, SAK en ATQA sonder om dit te stoor.
- **Onbekende kaarte** — lees die UID, SAK en ATQA en emuleer ’n UID.

Vir **NFC-kaarttipes B, F en V** kon die gedokumenteerde firmware ’n UID lees sonder om dit te stoor.

### NFC-kaarte van tipe A <a href="#uvusf" id="uvusf"></a>

#### Bankkaart (EMV) <a href="#kzmrp" id="kzmrp"></a>

Die gedokumenteerde firmware kon ’n UID, SAK, ATQA en beskikbare toepassingsdata van ’n bankkaart lees **sonder om dit te stoor**.

Vir hierdie bankkaarte het die firmware data vertoon sonder om die kaart te stoor of te emuleer.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Onbekende kaarte <a href="#id-37eo8" id="id-37eo8"></a>

Wanneer Flipper Zero **nie die NFC-kaart se tipe kan bepaal nie**, kan slegs ’n **UID, SAK en ATQA** **gelees en gestoor word**.

Vir ’n onbekende NFC-kaart kan hierdie modus slegs sy UID emuleer.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-kaarttipes B, F en V <a href="#wyg51" id="wyg51"></a>

In die firmware wat in die oorspronklike artikel gedokumenteer is, kon slegs ’n identifiseerder van NFC-kaarttipes B, F en V gelees en vertoon word, sonder om dit te stoor.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Aksies

Vir ’n inleiding tot NFC, [**lees hierdie bladsy**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Lees

Flipper Zero kan NFC-kaarte lees, maar implementeer nie elke hoërvlakprotokol wat op ISO 14443 gebou is nie. Dit kan dus die laevlak-UID, SAK en ATQA herwin terwyl die toepassingsprotokol onbekend bly. Vir eenvoudige toegangstelsels wat slegs op grond van die UID toestemming verleen, kan die instrument daardie identifiseerder lees, handmatig invoer en emuleer; stelsels met kriptografiese verifikasie vereis meer as ’n gekopieerde UID.<sup>[[1]](#references)</sup>

#### Lees die UID VS Lees die data binne-in <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper kan die lees van 13.56 MHz-etikette in twee dele verdeel word:<sup>[[1]](#references)</sup>

- **Laevlaklees** — lees slegs die UID, SAK en ATQA. Flipper probeer die hoëvlakprotokol raai op grond van hierdie data wat van die kaart gelees is. Jy kan nie 100% seker wees nie, aangesien dit net ’n aanname is wat op sekere faktore berus.
- **Hoëvlaklees** — lees die data uit die kaart se geheue deur ’n spesifieke hoëvlakprotokol te gebruik. Dit behels byvoorbeeld die lees van data op ’n Mifare Ultralight, die lees van sektore op ’n Mifare Classic, of die lees van die kaart se eienskappe vanaf PayPass/Apple Pay.

### Lees spesifiek

As Flipper Zero nie die kaarttipe uit die laevlakdata kan bepaal nie, kan jy in `Extra Actions` `Read Specific Card Type` kies en **handmatig die tipe kaart aandui wat jy wil lees**.

#### EMV-bankkaarte (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Ouer Flipper-firmware en versoenbare EMV-kaarte kon meer as die UID blootlê, moontlik insluitend die PAN, vervaldatum, kaarthouer se naam of transaksielogboek, indien die kaart daardie rekords beskikbaar gestel het. Beskikbaarheid wissel na gelang van die kaart, toepassing en firmware. Die CVV van die magnetiese streep wat op die kaart gedruk is, word nie op hierdie manier blootgelê nie, en die lees van hierdie rekords kloon nie die kriptografiese transaksievermoë wat nodig is om ’n kontaklose betaling te maak nie.<sup>[[1]](#references)</sup>

## References

- [1] [Verkenning van RFID-protokolle met Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero-dokumentasie - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
