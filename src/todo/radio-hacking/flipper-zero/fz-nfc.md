# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#id-9wrzi" id="id-9wrzi"></a>

Kwa maelezo kuhusu RFID na NFC tazama ukurasa ufuatao:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Kadi za NFC zinazotumika <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Mbali na kadi za NFC, Flipper Zero inatumia **aina nyingine za kadi za masafa ya juu** kama vile **Mifare** Classic na Ultralight kadhaa pamoja na **NTAG**.

Orodha ya uwezo iliyo hapa chini inaeleza firmware iliyoandikwa katika makala ya awali na haipaswi kuchukuliwa kuwa orodha kamili ya sasa ya kadi zinazotumika. Firmware ya Flipper imeongeza protocols na kubadilisha tabia ya NFC baada ya muda; angalia documentation rasmi ya sasa kwa firmware iliyosakinishwa.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Kadi za benki (EMV)** — kusoma UID, SAK, na ATQA pekee bila kuhifadhi.
- **Kadi zisizojulikana** — kusoma UID, SAK, na ATQA na ku-emulate UID.

Kwa **aina za kadi za NFC B, F, na V**, firmware iliyoandikwa ingeweza kusoma UID bila kuihifadhi.

### Kadi za NFC aina ya A <a href="#uvusf" id="uvusf"></a>

#### Kadi ya benki (EMV) <a href="#kzmrp" id="kzmrp"></a>

Firmware iliyoandikwa ingeweza kusoma UID, SAK, ATQA, na data ya application inayopatikana kutoka kwenye kadi ya benki **bila kuihifadhi**.

Kwa kadi hizi za benki, firmware ilionyesha data bila kuhifadhi au ku-emulate kadi.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Kadi zisizojulikana <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **inaposhindwa kubaini aina ya kadi ya NFC**, ni **UID, SAK, na ATQA** pekee zinazoweza **kusomwa na kuhifadhiwa**.

Kwa kadi ya NFC isiyojulikana, mode hii inaweza ku-emulate UID yake pekee.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Kadi za NFC aina ya B, F, na V <a href="#wyg51" id="wyg51"></a>

Katika firmware iliyoandikwa katika makala ya awali, kadi za NFC aina ya B, F, na V ziliweza tu kuwa na identifier iliyosomwa na kuonyeshwa bila kuihifadhi.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Vitendo

Kwa utangulizi kuhusu NFC [**soma ukurasa huu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Soma

Flipper Zero inaweza kusoma kadi za NFC lakini haiimplement kila high-level protocol inayotumia ISO 14443. Kwa hiyo inaweza kupata UID, SAK, na ATQA za low-level huku application protocol ikiwa haijulikani. Kwa mifumo ya primitive access inayoruhusu ufikiaji kwa UID pekee, tool inaweza kusoma, kuingiza manually, na ku-emulate identifier hiyo; mifumo yenye cryptographic authentication inahitaji zaidi ya UID iliyonakiliwa.<sup>[[1]](#references)</sup>

#### Kusoma UID VS Kusoma Data Iliyomo Ndani <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Katika Flipper, kusoma tags za 13.56 MHz kunaweza kugawanywa katika sehemu mbili:<sup>[[1]](#references)</sup>

- **Low-level read** — husoma UID, SAK, na ATQA pekee. Flipper hujaribu kukisia high-level protocol kwa kutegemea data hii iliyosomwa kutoka kwenye kadi. Huwezi kuwa na uhakika wa 100% kwa hili, kwa kuwa ni makisio tu yanayotegemea vigezo fulani.
- **High-level read** — husoma data kutoka kwenye memory ya kadi kwa kutumia high-level protocol maalum. Hii inaweza kuwa kusoma data kwenye Mifare Ultralight, kusoma sectors kutoka kwenye Mifare Classic, au kusoma attributes za kadi kutoka PayPass/Apple Pay.

### Soma Maalum

Iwapo Flipper Zero haiwezi kubaini aina ya kadi kutokana na data ya low-level, katika `Extra Actions` unaweza kuchagua `Read Specific Card Type` na **kuonyesha** **manually** **aina ya kadi unayotaka kusoma**.

#### Kadi za Benki za EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Firmware za zamani za Flipper na kadi za EMV zinazotangamana zingeweza kuonyesha zaidi ya UID, ikiwezekana kujumuisha PAN, tarehe ya mwisho wa matumizi, jina la mwenye kadi, au transaction log pale rekodi hizo zilipowezeshwa na kadi. Upatikanaji hutofautiana kulingana na kadi, application, na firmware. CVV ya magnetic stripe iliyochapishwa kwenye kadi haionyeshwi kwa njia hii, na kusoma rekodi hizi hakutengenezi clone yenye uwezo wa cryptographic transaction unaohitajika kufanya malipo ya contactless.<sup>[[1]](#references)</sup>

## References

- [1] [Kuingia kwa Kina katika RFID Protocols kwa Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentation ya Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
