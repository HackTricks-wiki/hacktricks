# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#id-9wrzi" id="id-9wrzi"></a>

Vir inligting oor RFID en NFC, kyk na die volgende bladsy:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Ondersteunde NFC-kaarte <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Benewens NFC-kaarte ondersteun Flipper Zero **ander tipes hoëfrekwensiekaarte**, soos verskeie **Mifare** Classic- en Ultralight-kaarte en **NTAG**.

Nuwe tipes NFC-kaarte sal by die lys van ondersteunde kaarte gevoeg word. Flipper Zero ondersteun die volgende **NFC-kaarttipe A** (ISO 14443A):

- **Bankkaarte (EMV)** — lees slegs UID, SAK en ATQA sonder om dit te stoor.
- **Onbekende kaarte** — lees (UID, SAK, ATQA) en emuleer ’n UID.

Vir **NFC-kaarttipes B, F en V** kan Flipper Zero ’n UID lees sonder om dit te stoor.

### NFC-kaarttipe A <a href="#uvusf" id="uvusf"></a>

#### Bankkaart (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kan slegs ’n UID, SAK, ATQA en gestoorde data op bankkaarte lees **sonder om dit te stoor**.

Bankkaart-leesskermVir bankkaarte kan Flipper Zero slegs data lees **sonder om dit te stoor en te emuleer**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Onbekende kaarte <a href="#id-37eo8" id="id-37eo8"></a>

Wanneer Flipper Zero **nie die NFC-kaart se tipe kan bepaal nie**, kan slegs ’n **UID, SAK en ATQA** **gelees en gestoor** word.

Onbekende-kaart-leesskermVir onbekende NFC-kaarte kan Flipper Zero slegs ’n UID emuleer.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-kaarttipes B, F en V <a href="#wyg51" id="wyg51"></a>

Vir **NFC-kaarttipes B, F en V** kan Flipper Zero slegs **’n UID lees en vertoon** sonder om dit te stoor.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Aksies

Vir ’n inleiding tot NFC, [**lees hierdie bladsy**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lees

Flipper Zero kan **NFC-kaarte lees**, maar dit **verstaan nie al die protokolle** wat op ISO 14443 gebaseer is nie. Omdat **UID ’n laevlak-kenmerk is**, kan jy egter in ’n situasie beland waar **UID reeds gelees is, maar die hoëvlak-d data-oordragprotokol steeds onbekend is**. Jy kan UID met Flipper lees, emuleer en handmatig invoer vir die primitiewe lesers wat UID vir magtiging gebruik.<sup>[[1]](#references)</sup>

#### Lees die UID TEENOOR Lees die Data Binne-in <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper kan die lees van 13.56 MHz-kaarte in twee dele verdeel word:<sup>[[1]](#references)</sup>

- **Laevlak-lees** — lees slegs die UID, SAK en ATQA. Flipper probeer om die hoëvlak-protokol te raai op grond van hierdie data wat van die kaart gelees is. Jy kan nie 100% seker hiervan wees nie, aangesien dit slegs ’n aanname is wat op sekere faktore gebaseer is.
- **Hoëvlak-lees** — lees die data uit die kaart se geheue met behulp van ’n spesifieke hoëvlak-protokol. Dit kan beteken dat die data op ’n Mifare Ultralight gelees word, die sektore van ’n Mifare Classic gelees word, of die kaart se eienskappe van PayPass/Apple Pay gelees word.

### Lees spesifiek

Indien Flipper Zero nie in staat is om die kaart se tipe uit die laevlak-data te bepaal nie, kan jy in `Extra Actions` `Read Specific Card Type` kies en **handmatig** **die tipe kaart aandui wat jy wil lees**.

#### EMV-bankkaarte (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Benewens die eenvoudige lees van die UID, kan jy baie meer data uit ’n bankkaart onttrek. Dit is moontlik om **die volledige kaartnommer** (die 16 syfers aan die voorkant van die kaart), **geldigheidsdatum** en in sommige gevalle selfs die **eienaar se naam**, saam met ’n lys van die **mees onlangse transaksies**, te verkry.\
Jy **kan egter nie die CVV op hierdie manier lees nie** (die 3 syfers aan die agterkant van die kaart). **Bankkaarte word ook teen replay-aanvalle beskerm**, dus sal dit nie werk om dit met Flipper te kopieer en dit dan te probeer emuleer om vir iets te betaal nie.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
