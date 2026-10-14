# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#id-9wrzi" id="id-9wrzi"></a>

Kwa maelezo kuhusu RFID na NFC, angalia ukurasa ufuatao:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Kadi za NFC zinazotumika <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Mbali na kadi za NFC, Flipper Zero inatumia **aina nyingine za kadi za masafa ya juu** kama vile kadi kadhaa za **Mifare** Classic na Ultralight na **NTAG**.

Orodha ya uwezo iliyo hapa chini inaeleza firmware iliyorekodiwa kwenye makala ya awali na haipaswi kuchukuliwa kama jedwali kamili la sasa la kadi zinazotumika. Firmware ya Flipper imeongeza protocols na kubadilisha tabia ya NFC kadiri muda ulivyopita; angalia nyaraka rasmi za sasa za firmware iliyosakinishwa.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Kadi za benki (EMV)** — husoma UID, SAK, na ATQA pekee bila kuhifadhi.
- **Kadi zisizojulikana** — husoma UID, SAK, na ATQA na kuiga UID.

Kwa **aina za kadi za NFC B, F, na V**, firmware iliyorekodiwa ingeweza kusoma UID bila kuihifadhi.

### Kadi za NFC aina A <a href="#uvusf" id="uvusf"></a>

#### Kadi ya benki (EMV) <a href="#kzmrp" id="kzmrp"></a>

Firmware iliyorekodiwa ingeweza kusoma UID, SAK, ATQA, na data ya programu inayopatikana kutoka kwenye kadi ya benki **bila kuihifadhi**.

Kwa kadi hizi za benki, firmware ilionyesha data bila kuhifadhi au kuiga kadi.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Kadi zisizojulikana <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **inaposhindwa kutambua aina ya kadi ya NFC**, inaweza tu **kusoma na kuhifadhi** UID, SAK, na ATQA.

Kwa kadi ya NFC isiyojulikana, hali hii inaweza kuiga UID yake pekee.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Kadi za NFC aina B, F, na V <a href="#wyg51" id="wyg51"></a>

Katika firmware iliyorekodiwa kwenye makala ya awali, kwa kadi za NFC aina B, F, na V iliwezekana tu kusoma kitambulisho na kukionyesha bila kukihifadhi.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Vitendo

Kwa utangulizi kuhusu NFC, [**soma ukurasa huu**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Soma

Flipper Zero inaweza kusoma kadi za NFC lakini haitumii kila protocol ya kiwango cha juu inayotumia ISO 14443. Kwa hiyo, inaweza kupata UID, SAK, na ATQA za kiwango cha chini huku protocol ya programu ikiendelea kutotambulika. Kwa mifumo rahisi ya udhibiti wa ufikiaji inayoidhinisha kwa kutumia UID pekee, zana hii inaweza kusoma, kuweka mwenyewe, na kuiga kitambulisho hicho; mifumo inayohitaji uthibitishaji wa kriptografia huhitaji zaidi ya UID iliyonakiliwa.<sup>[[1]](#references)</sup>

#### Kusoma UID dhidi ya Kusoma Data Iliyo Ndani <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Katika Flipper, kusoma lebo za 13.56 MHz kunaweza kugawanywa katika sehemu mbili:<sup>[[1]](#references)</sup>

- **Usomaji wa kiwango cha chini** — husoma UID, SAK, na ATQA pekee. Flipper hujaribu kukisia protocol ya kiwango cha juu kwa kutumia data hii iliyosomwa kutoka kwenye kadi. Huwezi kuwa na uhakika wa 100% kwa njia hii, kwani ni dhana tu inayotegemea vipengele fulani.
- **Usomaji wa kiwango cha juu** — husoma data kutoka kwenye kumbukumbu ya kadi kwa kutumia protocol maalum ya kiwango cha juu. Hii inaweza kuwa kusoma data kwenye Mifare Ultralight, kusoma sekta za Mifare Classic, au kusoma sifa za kadi kutoka PayPass/Apple Pay.

### Soma Mahususi

Ikiwa Flipper Zero haiwezi kutambua aina ya kadi kutokana na data ya kiwango cha chini, unaweza kuchagua `Read Specific Card Type` kwenye `Extra Actions` na **kuonyesha mwenyewe aina ya kadi unayotaka kusoma**.

#### Kadi za Benki za EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Firmware za zamani za Flipper na kadi za EMV zinazooana zinaweza kuonyesha zaidi ya UID, ikiwezekana ikijumuisha PAN, tarehe ya kuisha muda, jina la mwenye kadi, au kumbukumbu ya miamala ikiwa kadi imetoa rekodi hizo. Upatikanaji hutegemea kadi, programu, na firmware. CVV ya mstari wa sumaku iliyochapishwa kwenye kadi haionekani kwa njia hii, na kusoma rekodi hizi hakunakili uwezo wa kriptografia wa miamala unaohitajika ili kufanya malipo ya kielektroniki bila kugusa.<sup>[[1]](#references)</sup>

## References

- [1] [Kuchunguza kwa Kina Protocol za RFID kwa kutumia Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Nyaraka za Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
