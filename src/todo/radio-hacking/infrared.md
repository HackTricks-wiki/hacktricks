# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Infrared Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa Infrared hauonekani kwa binadamu**. Wavelength ya IR ni kutoka **mikroni 0.7 hadi 1000**. Remote za nyumbani hutumia signal ya IR kwa uwasilishaji wa data na hufanya kazi katika wavelength ya mikroni 0.75..1.4. Microcontroller iliyo ndani ya remote hufanya infrared LED iwake na kuzima kwa frequency maalum, ikibadilisha signal ya kidijitali kuwa signal ya IR.<sup>[[1]](#references)</sup>

Ili kupokea signals za IR hutumika **photoreceiver**. **Hubadilisha mwanga wa IR kuwa voltage pulses**, ambazo tayari ni **signals za kidijitali**. Kwa kawaida, kuna **dark light filter ndani ya receiver**, ambayo huruhusu **wavelength inayohitajika pekee kupita** na kuondoa noise.

### Aina Mbalimbali za IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols hutofautiana katika vipengele 3:

- bit encoding
- muundo wa data
- carrier frequency — mara nyingi katika range ya 36..38 kHz

#### Njia za Bit Encoding <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits hu-encodeiwa kwa kurekebisha muda wa space kati ya pulses. Upana wa pulse yenyewe hubaki constant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits hu-encodeiwa kwa kurekebisha upana wa pulse. Upana wa space baada ya pulse burst hubaki constant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Pia inajulikana kama Manchester encoding. Thamani ya kimantiki huamuliwa na polarity ya transition kati ya pulse burst na space. "Space to pulse burst" humaanisha logic "0", na "pulse burst to space" humaanisha logic "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Mchanganyiko wa zilizotangulia na nyingine za kipekee**

> [!TIP]
> Kuna IR protocols ambazo **zinajaribu kuwa universal** kwa aina kadhaa za devices. Maarufu zaidi ni RC5 na NEC. Kwa bahati mbaya, kuwa maarufu zaidi **hakumaanishi kuwa zinazotumika zaidi**. Katika mazingira yangu, nilikutana na remote mbili tu za NEC na hakuna za RC5.
>
> Manufacturers hupenda kutumia IR protocols zao za kipekee, hata ndani ya range ileile ya devices (kwa mfano, TV-boxes). Kwa hiyo, remotes kutoka kwa companies tofauti na wakati mwingine kutoka kwa models tofauti za company ileile, haziwezi kufanya kazi na devices nyingine za aina ileile.

### Kuchunguza IR Signal

Njia ya kuaminika zaidi ya kuona IR signal ya remote inavyoonekana ni kutumia oscilloscope. Haifanyi demodulate au invert signal iliyopokelewa; huionyesha tu "kama ilivyo". Hii ni muhimu kwa testing na debugging. Nitaonyesha signal inayotarajiwa kwa kutumia mfano wa NEC IR protocol.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kwa kawaida, kuna preamble mwanzoni mwa encoded packet. Hii humwezesha receiver kubaini level ya gain na background. Pia kuna protocols zisizo na preamble, kwa mfano, Sharp.

Kisha data hutumwa. Muundo, preamble, na njia ya bit encoding huamuliwa na protocol husika.

**NEC IR protocol** ina command fupi na repeat code, ambayo hutumwa button inaposhikiliwa. Command na repeat code zote zina preamble ileile mwanzoni.

NEC **command**, pamoja na preamble, ina address byte na command-number byte, ambazo device hutumia kuelewa kinachopaswa kufanywa. Address na command-number bytes hurudiwa kwa inverse values, ili kuangalia integrity ya transmission. Kuna stop bit ya ziada mwishoni mwa command.

**Repeat code** ina "1" baada ya preamble, ambayo ni stop bit.

Kwa **logic "0" na "1"**, NEC hutumia Pulse Distance Encoding: kwanza pulse burst hutumwa, kisha kuna pause ambayo urefu wake huweka value ya bit.

### Air Conditioners

Tofauti na remotes nyingine, **air conditioners hazitumii tu code ya button iliyobanwa**. Pia **hutuma taarifa zote** wakati button inabonyezwa ili kuhakikisha kwamba **air conditioned machine na remote zimesynchronise**.\
Hii huzuia machine iliyowekwa kwenye 20ºC kuongezwa hadi 21ºC kwa remote moja, halafu remote nyingine, ambayo bado ina temperature ya 20ºC, inapotumiwa kuongeza temperature zaidi, "iongeze" hadi 21ºC (badala ya 22ºC kwa kudhani kwamba iko kwenye 21ºC).

---

## Mashambulizi na Utafiti wa Offensive <a href="#attacks" id="attacks"></a>

Unaweza kushambulia Infrared kwa Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Utafiti wa hivi karibuni wa kitaaluma (EvilScreen, 2022) ulionyesha kwamba **remotes za multi-channel zinazochanganya Infrared na Bluetooth au Wi-Fi zinaweza kutumiwa kuteka kikamilifu smart-TVs za kisasa**. Attack hii huunganisha service codes za IR zenye high privilege na Bluetooth packets zilizothibitishwa, ikipita channel-isolation na kuruhusu kuzinduliwa kwa apps kiholela, kuamilishwa kwa microphone, au factory-reset bila access ya kimwili. TVs nane zinazotumiwa sana kutoka kwa vendors tofauti — ikiwemo Samsung model iliyodai compliance na ISO/IEC 27001 — zilithibitishwa kuwa vulnerable. Mitigation inahitaji vendor firmware fixes au kuzima kabisa IR receivers zisizotumika.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration kupitia IR LEDs (aIR-Jumper family)

Security cameras, routers au hata malicious USB sticks mara nyingi huwa na **night-vision IR LEDs**. Utafiti unaonyesha kwamba malware inaweza ku-modulate LEDs hizi (<10–20 kbit/s kwa OOK rahisi) ili **ku-exfiltrate secrets kupitia kuta na madirisha** hadi kwenye external camera iliyowekwa umbali wa makumi ya mita. Kwa sababu mwanga huu uko nje ya visible spectrum, operators mara chache hugundua. Counter-measures:

* Shield au ondoa IR LEDs kimwili katika maeneo nyeti
* Monitor camera LED duty-cycle na firmware integrity
* Deploy IR-cut filters kwenye madirisha na surveillance cameras

Attacker pia anaweza kutumia IR projectors zenye nguvu **kuingiza** commands kwenye network kwa ku-flash data kurudi kwenye cameras zisizo salama.

### Long-Range Brute-Force na Extended Protocols pamoja na Flipper Zero 1.0

Firmware 1.0 (Septemba 2024) iliongeza **IR protocols kadhaa za ziada na optional external amplifier modules**. Ikiunganishwa na universal-remote brute-force mode, Flipper inaweza kuzima au kureconfigure public TVs/ACs nyingi kutoka umbali wa hadi 30 m kwa kutumia high-power diode.

---

## Tooling na Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – portable transceiver yenye learning, replay na dictionary-bruteforce modes (tazama hapo juu).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – DIY analyser/transmitter ya bei nafuu. Iunganishe na `Arduino-IRremote` library (v4.x ina-support >40 protocols).
* **Logic analysers** (Saleae/FX2) – capture raw timings wakati protocol haijulikani.
* **Smartphones zenye IR-blaster** (kwa mfano, Xiaomi) – field test ya haraka lakini zenye range ndogo.

### Software

* **`Arduino-IRremote`** – C++ library inayodumishwa kikamilifu:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders zinazo-import raw captures na ku-identify protocol kiotomatiki, pamoja na kutengeneza Pronto/Arduino code.
* **LIRC / ir-keytable (Linux)** – receive na inject IR kutoka command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Disable au funika IR receivers kwenye devices zilizowekwa katika public spaces wakati hazihitajiki.
* Tekeleza *pairing* au cryptographic checks kati ya smart-TVs na remotes; tenga “service” codes zenye privilege.
* Deploy IR-cut filters au continuous-wave detectors kuzunguka maeneo classified ili kuvunja optical covert channels.
* Monitor firmware integrity ya cameras/IoT appliances zinazoonyesha IR LEDs zinazoweza kudhibitiwa.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
