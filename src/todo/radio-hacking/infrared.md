# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Infrared Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa infrared hauonekani kwa binadamu**. Wavelength ya IR ni kutoka **0.7 hadi mikroni 1000**. Remote za nyumbani hutumia signal ya IR kwa uwasilishaji wa data na hufanya kazi katika wavelength ya mikroni 0.75..1.4. Microcontroller iliyo kwenye remote husababisha LED ya infrared kumeta kwa frequency maalum, na kugeuza signal ya digital kuwa signal ya IR.

Ili kupokea signal za IR hutumika **photoreceiver**. **Hubadilisha mwanga wa IR kuwa pulses za voltage**, ambazo tayari ni **signal za digital**. Kwa kawaida, kuna **filter ya mwanga hafifu ndani ya receiver**, ambayo huruhusu **wavelength inayohitajika pekee kupita** na kuondoa noise.<sup>[[1]](#references)</sup>

### Aina mbalimbali za IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols hutofautiana katika mambo 3:<sup>[[1]](#references)</sup>

- bit encoding
- muundo wa data
- carrier frequency — mara nyingi huwa katika range ya 36..38 kHz

#### Njia za Bit encoding <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits huwekwa kwa kubadilisha muda wa space kati ya pulses. Upana wa pulse yenyewe hubaki constant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits huwekwa kwa kubadilisha upana wa pulse. Upana wa space baada ya pulse burst hubaki constant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Pia inajulikana kama Manchester encoding. Thamani ya logical huamuliwa na polarity ya transition kati ya pulse burst na space. "Space to pulse burst" huwakilisha logic "0", na "pulse burst to space" huwakilisha logic "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Mchanganyiko wa zilizotangulia na nyingine za kipekee**

> [!TIP]
> Kuna IR protocols ambazo **zinajaribu kuwa universal** kwa aina kadhaa za devices. Zinazojulikana zaidi ni RC5 na NEC. Kwa bahati mbaya, **kujulikana zaidi hakumaanishi kutumika zaidi**. Katika mazingira yangu, nilikutana na remotes mbili tu za NEC na hakuna za RC5.
>
> Manufacturers hupenda kutumia IR protocols zao za kipekee, hata ndani ya range ileile ya devices (kwa mfano, TV-boxes). Kwa hiyo, remotes kutoka kampuni tofauti na wakati mwingine kutoka models tofauti za kampuni ileile, haziwezi kufanya kazi na devices nyingine za aina ileile.

### Kuchunguza signal ya IR

Njia ya kuaminika zaidi ya kuona jinsi signal ya IR ya remote inavyoonekana ni kutumia oscilloscope. Haifanyi demodulate au invert signal iliyopokelewa; huionyesha tu "kama ilivyo". Hii ni muhimu kwa testing na debugging. Nitaonyesha signal inayotarajiwa kwa kutumia mfano wa NEC IR protocol.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kwa kawaida, kuna preamble mwanzoni mwa packet iliyowekwa encoding. Hii humsaidia receiver kubaini kiwango cha gain na background. Pia kuna protocols zisizo na preamble, kwa mfano, Sharp.

Kisha data hutumwa. Muundo, preamble, na mbinu ya bit encoding huamuliwa na protocol maalum.

**NEC IR protocol** ina command fupi na repeat code, ambayo hutumwa wakati button imeshikiliwa. Command na repeat code zote zina preamble ileile mwanzoni.

NEC **command**, pamoja na preamble, ina address byte na command-number byte, ambavyo device hutumia kuelewa kinachopaswa kufanywa. Address na command-number bytes hurudiwa kwa inverse values, ili kukagua integrity ya uwasilishaji. Kuna stop bit ya ziada mwishoni mwa command.

**Repeat code** ina "1" baada ya preamble, ambayo ni stop bit.

Kwa **logic "0" na "1"**, NEC hutumia Pulse Distance Encoding: kwanza pulse burst hutumwa, kisha kuna pause ambayo urefu wake huweka value ya bit.

### Viyoyozi

Tofauti na remotes nyingine, **viyoyozi havitumii code ya button iliyobonyezwa pekee**. Pia **hutuma taarifa zote** wakati button inapobonyezwa ili kuhakikisha kwamba **kifaa cha kiyoyozi na remote vimesawazishwa**.\
Hii huzuia mashine iliyowekwa kwenye 20ºC kuongezwa hadi 21ºC kwa remote moja, kisha remote nyingine ambayo bado ina temperature ya 20ºC inapotumiwa kuongeza temperature zaidi, "iongeze" hadi 21ºC (badala ya 22ºC kwa kudhani kuwa iko kwenye 21ºC).<sup>[[1]](#references)</sup>

---

## Attacks na Utafiti wa Kiofensivu <a href="#attacks" id="attacks"></a>

Unaweza ku-attack Infrared kwa Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Utekaji wa Smart-TV / Set-top Box (EvilScreen)

Utafiti wa hivi karibuni wa kitaaluma (EvilScreen, 2022) ulionyesha kwamba **remotes za multi-channel zinazochanganya Infrared na Bluetooth au Wi-Fi zinaweza kutumiwa kuteka kabisa smart-TVs za kisasa**. Attack hii huunganisha service codes za IR zenye privileges za juu na Bluetooth packets zilizothibitishwa, na hivyo kupita channel-isolation na kuruhusu kuzinduliwa kwa apps kiholela, kuwashwa kwa microphone, au factory-reset bila access ya kimwili. TVs nane maarufu kutoka kwa vendors tofauti — ikiwemo model ya Samsung iliyodai kutii ISO/IEC 27001 — zilithibitishwa kuwa vulnerable. Mitigation inahitaji fixes za firmware kutoka kwa vendor au kuzima kabisa IR receivers zisizotumika.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration kupitia IR LEDs (aIR-Jumper family)

Security cameras kwa kawaida huwa na **IR LEDs za night-vision**. Prototype ya aIR-Jumper ilionyesha kwamba malware inayodhibiti LEDs hizo inaweza **kutoa secrets kupitia madirisha** hadi kwenye camera ya nje kwa kasi ya hadi **20 bit/s kwa kila surveillance camera** katika umbali wa makumi ya metres. Kwa upande wa kinyume, researchers walionyesha infiltration kwa zaidi ya **100 bit/s** katika umbali kutoka mamia ya metres hadi kilometres.<sup>[[3]](#references)</sup> Kwa kuwa mwanga huo uko nje ya visible spectrum, operators huenda wasiuone. Countermeasures ni pamoja na:

* Kufunika au kuondoa IR LEDs kimwili katika maeneo nyeti
* Kufuatilia duty-cycle ya camera LED na firmware integrity
* Kuweka IR-cut filters kwenye madirisha na surveillance cameras

Attacker pia anaweza kutumia IR projectors zenye nguvu **kuingiza** commands kwenye network kwa ku-flash data kurudi kwenye cameras zisizo salama.

### Long-Range Brute-Force na Extended Protocols kwa Flipper Zero 1.0

Firmware 1.0 (Septemba 2024) ilipanua universal-remotes library na kuongeza dynamic loading ya infrared asset files kutoka microSD.<sup>[[4]](#references)</sup> Learning na universal-remote functions zake zinaweza ku-replay au kujaribu commands zinazojulikana dhidi ya TVs na air conditioners zilizo karibu. Range hutegemea sana emitter, optics, ambient light, na receiver; external IR hardware inaweza kuiongeza, lakini distance maalum haipaswi kudhaniwa.

---

## Tooling na Mifano ya Kivitendo <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – portable transceiver yenye learning, replay na dictionary-bruteforce modes (tazama hapo juu).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – analyser/transmitter ya DIY ya bei nafuu. Iunganishe na `Arduino-IRremote` library (v4.x inasaidia protocols zaidi ya 40).
* **Logic analysers** (Saleae/FX2) – hunasa raw timings wakati protocol haijulikani.
* **Smartphones zenye IR-blaster** (kwa mfano, Xiaomi) – field test ya haraka lakini zenye range ndogo.

### Software

* **`Arduino-IRremote`** – C++ library inayotunzwa kikamilifu:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders zinazo-import raw captures na kutambua protocol moja kwa moja + kutengeneza Pronto/Arduino code.
* **LIRC / ir-keytable (Linux)** – hupokea na kuingiza IR kutoka command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Hatua za Kujilinda <a href="#defense" id="defense"></a>

* Zima au funika IR receivers kwenye devices zilizowekwa katika maeneo ya umma wakati hazihitajiki.
* Tekeleza *pairing* au ukaguzi wa cryptographic kati ya smart-TVs na remotes; tenga “service” codes zenye privileges.
* Weka IR-cut filters au continuous-wave detectors kuzunguka maeneo yaliyoainishwa ili kuvunja optical covert channels.
* Fuatilia firmware integrity ya cameras/IoT appliances zinazowezesha kudhibitiwa kwa IR LEDs.

## References

- [1] [Makala ya blogu ya Flipper Zero kuhusu Infrared](https://blog.flipperzero.one/infrared/)
- [2] [Attack ya EvilScreen: Utekaji wa Smart TV kupitia Kuiga Udhibiti wa Remote wa Multi-channel (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Air-Gap Exfiltration/Infiltration ya Kificho kupitia Security Cameras na Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blogu ya Flipper Zero - Firmware 1.0 Imetolewa](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - matumizi na documentation ya protocols](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
