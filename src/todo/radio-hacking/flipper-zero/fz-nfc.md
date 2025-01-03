# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Vir inligting oor RFID en NFC, kyk na die volgende bladsy:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Ondersteunde NFC-kaarte <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Behalwe vir NFC-kaarte ondersteun Flipper Zero **ander tipe Hoë-frekwensie kaarte** soos verskeie **Mifare** Classic en Ultralight en **NTAG**.

Nuwe tipes NFC-kaarte sal by die lys van ondersteunde kaarte gevoeg word. Flipper Zero ondersteun die volgende **NFC-kaarte tipe A** (ISO 14443A):

- **Bankkaarte (EMV)** — lees slegs UID, SAK, en ATQA sonder om te stoor.
- **Onbekende kaarte** — lees (UID, SAK, ATQA) en emuleer 'n UID.

Vir **NFC-kaarte tipe B, tipe F, en tipe V**, kan Flipper Zero 'n UID lees sonder om dit te stoor.

### NFC-kaarte tipe A <a href="#uvusf" id="uvusf"></a>

#### Bankkaart (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kan slegs 'n UID, SAK, ATQA, en gestoor data op bankkaarte **sonder om te stoor**.

Bankkaart lees skerm. Vir bankkaarte kan Flipper Zero slegs data lees **sonder om dit te stoor en te emuleer**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Onbekende kaarte <a href="#id-37eo8" id="id-37eo8"></a>

Wanneer Flipper Zero **nie in staat is om die tipe NFC-kaart te bepaal nie**, kan slegs 'n **UID, SAK, en ATQA** **gelees en gestoor** word.

Onbekende kaart lees skerm. Vir onbekende NFC-kaarte kan Flipper Zero slegs 'n UID emuleer.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC-kaarte tipes B, F, en V <a href="#wyg51" id="wyg51"></a>

Vir **NFC-kaarte tipes B, F, en V**, kan Flipper Zero slegs **lees en vertoon 'n UID** sonder om dit te stoor.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Aksies

Vir 'n inleiding oor NFC [**lees hierdie bladsy**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lees

Flipper Zero kan **NFC-kaarte lees**, maar dit **begryp nie al die protokolle** wat op ISO 14443 gebaseer is nie. Aangesien **UID 'n lae-vlak eienskap is**, mag jy in 'n situasie beland waar **UID reeds gelees is, maar die hoë-vlak data-oordragprotokol steeds onbekend is**. Jy kan UID lees, emuleer en handmatig invoer met Flipper vir die primitiewe lesers wat UID vir outorisering gebruik.

#### Lees die UID VS Lees die Data Binne <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper kan die lees van 13.56 MHz etikette in twee dele verdeel word:

- **Lae-vlak lees** — lees slegs die UID, SAK, en ATQA. Flipper probeer om die hoë-vlak protokol te raai op grond van hierdie data wat van die kaart gelees is. Jy kan nie 100% seker wees hiervan nie, aangesien dit net 'n aanname is gebaseer op sekere faktore.
- **Hoë-vlak lees** — lees die data uit die kaart se geheue met behulp van 'n spesifieke hoë-vlak protokol. Dit sou die lees van die data op 'n Mifare Ultralight wees, die lees van die sektore van 'n Mifare Classic, of die lees van die kaart se eienskappe van PayPass/Apple Pay.

### Lees Spesifiek

In die geval dat Flipper Zero nie in staat is om die tipe kaart van die lae-vlak data te vind nie, kan jy in `Extra Actions` `Read Specific Card Type` kies en **handmatig** **die tipe kaart wat jy wil lees, aandui**.

#### EMV Bankkaarte (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Behalwe om eenvoudig die UID te lees, kan jy baie meer data van 'n bankkaart onttrek. Dit is moontlik om **die volle kaartnommer** (die 16 syfers aan die voorkant van die kaart), **geldigheidsdatum**, en in sommige gevalle selfs die **eienaarsnaam** saam met 'n lys van die **mees onlangse transaksies** te verkry.\
E however, jy **kan nie die CVV op hierdie manier lees nie** (die 3 syfers aan die agterkant van die kaart). Ook **bankkaarte is beskerm teen herhalingsaanvalle**, so om dit met Flipper te kopieer en dan te probeer emuleer om vir iets te betaal, sal nie werk nie.

## Verwysings

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
