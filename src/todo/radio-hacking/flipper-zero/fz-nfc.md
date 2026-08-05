# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#id-9wrzi" id="id-9wrzi"></a>

Kwa maelezo kuhusu RFID na NFC angalia ukurasa ufuatao:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Kadi za NFC zinazotumika <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Mbali na kadi za NFC, Flipper Zero inatumia **aina nyingine za kadi za high-frequency** kama vile **Mifare** Classic na Ultralight kadhaa pamoja na **NTAG**.

Aina mpya za kadi za NFC zitaongezwa kwenye orodha ya kadi zinazotumika. Flipper Zero inatumia **kadi za NFC aina A** (ISO 14443A) zifuatazo:

- **Kadi za benki (EMV)** — husoma UID, SAK, na ATQA pekee bila kuhifadhi.
- **Kadi zisizojulikana** — husoma (UID, SAK, ATQA) na kuiga UID.

Kwa **kadi za NFC aina B, aina F, na aina V**, Flipper Zero inaweza kusoma UID bila kuihifadhi.

### Kadi za NFC aina A <a href="#uvusf" id="uvusf"></a>

#### Kadi ya benki (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero inaweza kusoma UID, SAK, ATQA, na data iliyohifadhiwa kwenye kadi za benki **bila kuzihifadhi**.

Skrini ya kusoma kadi ya benkiKwa kadi za benki, Flipper Zero inaweza kusoma data pekee **bila kuihifadhi na kuiiga**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Kadi zisizojulikana <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **inaposhindwa kubaini aina ya kadi ya NFC**, basi **UID, SAK, na ATQA** pekee zinaweza **kusomwa na kuhifadhiwa**.

Skrini ya kusoma kadi isiyojulikanaKwa kadi za NFC zisizojulikana, Flipper Zero inaweza kuiga UID pekee.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Kadi za NFC aina B, F, na V <a href="#wyg51" id="wyg51"></a>

Kwa **kadi za NFC aina B, F, na V**, Flipper Zero inaweza **kusoma na kuonyesha UID** pekee bila kuihifadhi.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Vitendo

Kwa utangulizi kuhusu NFC [**soma ukurasa huu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Soma

Flipper Zero inaweza **kusoma kadi za NFC**, hata hivyo, **haielewi protocols zote** zinazotegemea ISO 14443. Hata hivyo, kwa kuwa **UID ni sifa ya kiwango cha chini**, unaweza kujikuta katika hali ambapo **UID tayari imesomwa, lakini protocol ya uhamishaji wa data ya kiwango cha juu bado haijulikani**. Unaweza kusoma, kuiga na kuingiza UID mwenyewe ukitumia Flipper kwa readers primitive zinazotumia UID kwa authorization.<sup>[[1]](#references)</sup>

#### Kusoma UID VS Kusoma Data Iliyomo Ndani <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Katika Flipper, kusoma tags za 13.56 MHz kunaweza kugawanywa katika sehemu mbili:<sup>[[1]](#references)</sup>

- **Kusoma kwa kiwango cha chini** — husoma UID, SAK, na ATQA pekee. Flipper hujaribu kukisia protocol ya kiwango cha juu kulingana na data hii iliyosomwa kutoka kwenye kadi. Huwezi kuwa na uhakika wa 100% kuhusu hili, kwa kuwa ni makadirio tu yanayotegemea vipengele fulani.
- **Kusoma kwa kiwango cha juu** — husoma data kutoka kwenye memory ya kadi kwa kutumia protocol maalum ya kiwango cha juu. Hii inaweza kuwa kusoma data kwenye Mifare Ultralight, kusoma sectors kutoka kwenye Mifare Classic, au kusoma sifa za kadi kutoka PayPass/Apple Pay.

### Soma Mahususi

Iwapo Flipper Zero haiwezi kubaini aina ya kadi kutokana na data ya kiwango cha chini, katika `Extra Actions` unaweza kuchagua `Read Specific Card Type` na **kuonyesha** **wewe mwenyewe aina ya kadi unayotaka kusoma**.

#### Kadi za Benki za EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Mbali na kusoma UID tu, unaweza kutoa data nyingi zaidi kutoka kwenye kadi ya benki. Inawezekana **kupata nambari kamili ya kadi** (tarakimu 16 zilizo mbele ya kadi), **tarehe ya kuisha muda**, na wakati mwingine hata **jina la mmiliki** pamoja na orodha ya **miamala ya hivi karibuni**.\
Hata hivyo, **huwezi kusoma CVV kwa njia hii** (tarakimu 3 zilizo nyuma ya kadi). Pia **kadi za benki zinalindwa dhidi ya replay attacks**, kwa hiyo kuzinakili kwa Flipper na kisha kujaribu kuziiga ili kulipia kitu hakutafanya kazi.<sup>[[1]](#references)</sup>

## Marejeleo

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
