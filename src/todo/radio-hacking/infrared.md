# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Infrared Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa Infrared hauonekani kwa binadamu**. Wavelength ya IR ni kutoka **microni 0.7 hadi 1000**. Remote za nyumbani hutumia signal ya IR kwa usambazaji wa data na hufanya kazi katika wavelength ya microni 0.75..1.4. Microcontroller iliyo kwenye remote hufanya LED ya infrared imulike kwa frequency maalum, na kubadilisha signal ya digital kuwa signal ya IR.

Ili kupokea signal za IR, hutumika **photoreceiver**. Hii **hubadilisha mwanga wa IR kuwa voltage pulses**, ambazo tayari ni **digital signals**. Kwa kawaida, kuna **dark light filter ndani ya receiver**, ambayo huruhusu **wavelength inayohitajika pekee kupita** na kuondoa noise.<sup>[[1]](#references)</sup>

### Aina Mbalimbali za IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols hutofautiana katika mambo 3:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — mara nyingi huwa katika range ya 36..38 kHz

#### Njia za Bit encoding <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits hu-encodewa kwa kubadilisha muda wa nafasi kati ya pulses. Upana wa pulse yenyewe hubaki constant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits hu-encodewa kwa kubadilisha upana wa pulse. Upana wa nafasi baada ya pulse burst hubaki constant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Pia inajulikana kama Manchester encoding. Thamani ya logical huamuliwa na polarity ya transition kati ya pulse burst na nafasi. "Space to pulse burst" humaanisha logic "0", na "pulse burst to space" humaanisha logic "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Mchanganyiko wa zilizotangulia na nyingine za kipekee**

> [!TIP]
> Kuna IR protocols ambazo **zinajaribu kuwa universal** kwa aina kadhaa za vifaa. Zinazojulikana zaidi ni RC5 na NEC. Kwa bahati mbaya, **kinachojulikana zaidi hakimaanishi kinachotumika zaidi**. Katika mazingira yangu, nilikutana na remote mbili tu za NEC na hakuna ya RC5.
>
> Manufacturers hupenda kutumia IR protocols zao za kipekee, hata ndani ya range ileile ya vifaa (kwa mfano, TV-boxes). Kwa hiyo, remote kutoka kampuni tofauti na wakati mwingine kutoka models tofauti za kampuni moja, haziwezi kufanya kazi na vifaa vingine vya aina hiyo.

### Kuchunguza Signal ya IR

Njia ya kuaminika zaidi ya kuona jinsi signal ya IR ya remote inavyoonekana ni kutumia oscilloscope. Haifanyi demodulate au invert signal iliyopokelewa; inaionyesha tu "as is". Hii ni muhimu kwa testing na debugging. Nitaonyesha signal inayotarajiwa kwa mfano wa NEC IR protocol.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kwa kawaida, kuna preamble mwanzoni mwa packet iliyo-encodewa. Hii huruhusu receiver kuamua kiwango cha gain na background. Pia kuna protocols zisizo na preamble, kwa mfano, Sharp.

Kisha data hutumwa. Muundo, preamble, na njia ya bit encoding huamuliwa na protocol husika.

**NEC IR protocol** ina command fupi na repeat code, ambayo hutumwa wakati button imeshikiliwa. Command na repeat code zote zina preamble ileile mwanzoni.

NEC **command**, pamoja na preamble, ina address byte na command-number byte, ambazo kifaa hutumia kuelewa kinachopaswa kufanywa. Address na command-number bytes hurudiwa kwa inverse values, ili kukagua integrity ya transmission. Kuna stop bit ya ziada mwishoni mwa command.

**Repeat code** ina "1" baada ya preamble, ambayo ni stop bit.

Kwa **logic "0" na "1"**, NEC hutumia Pulse Distance Encoding: kwanza, pulse burst hutumwa, kisha kuna pause ambayo urefu wake huweka thamani ya bit.

### Viyoyozi

Tofauti na remote nyingine, **viyoyozi havitumi tu code ya button iliyobonyezwa**. Pia **hutuma taarifa zote** wakati button inabonyezwa ili kuhakikisha kwamba **kifaa cha kiyoyozi na remote vimesawazishwa**.\
Hii huzuia mashine iliyowekwa kwenye 20ºC kuongezwa hadi 21ºC kwa remote moja, kisha remote nyingine ambayo bado ina temperature ya 20ºC inapotumika kuongeza temperature zaidi, "itaongeza" hadi 21ºC (badala ya 22ºC kwa kudhani kuwa temperature iko 21ºC).<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Unaweza kushambulia Infrared kwa Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Utafiti wa hivi karibuni wa kitaaluma (EvilScreen, 2022) ulionyesha kwamba **multi-channel remotes zinazochanganya Infrared na Bluetooth au Wi-Fi zinaweza kutumiwa kufanya hijack kamili ya smart-TVs za kisasa**. Attack huunganisha service codes za IR zenye high-privilege na authenticated Bluetooth packets, na kupita channel-isolation, hivyo kuruhusu kuzinduliwa kwa apps kiholela, kuwashwa kwa microphone, au factory-reset bila physical access. TVs nane zinazotumika sana kutoka kwa vendors tofauti — zikiwemo Samsung model iliyodai compliance ya ISO/IEC 27001 — zilithibitishwa kuwa vulnerable. Mitigation inahitaji vendor firmware fixes au kuzima kabisa IR receivers zisizotumika.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration kupitia IR LEDs (aIR-Jumper family)

Security cameras, routers au hata malicious USB sticks mara nyingi huwa na **night-vision IR LEDs**. Utafiti unaonyesha kwamba malware inaweza ku-modulate LEDs hizi (<10–20 kbit/s kwa OOK rahisi) ili **ku-exfiltrate secrets kupitia kuta na madirisha** kwenda kwenye external camera iliyowekwa umbali wa makumi ya mita.<sup>[[3]](#references)</sup> Kwa sababu mwanga huu uko nje ya visible spectrum, operators mara chache huutambua. Counter-measures:

* Shield au ondoa kimwili IR LEDs katika maeneo nyeti
* Monitor camera LED duty-cycle na firmware integrity
* Deploy IR-cut filters kwenye madirisha na surveillance cameras

Attacker anaweza pia kutumia IR projectors zenye nguvu **ku-infiltrate** commands kwenye network kwa ku-flash data kurudi kwenye cameras zisizo salama.

### Long-Range Brute-Force & Extended Protocols with Flipper Zero 1.0

Firmware 1.0 (September 2024) iliongeza **IR protocols kadhaa za ziada na optional external amplifier modules**. Ikiunganishwa na universal-remote brute-force mode, Flipper inaweza kuzima au kureconfigure public TVs/ACs nyingi kutoka umbali wa hadi 30 m kwa kutumia high-power diode.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – portable transceiver yenye learning, replay na dictionary-bruteforce modes (tazama hapo juu).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – analyser/transmitter rahisi na ya bei nafuu ya DIY. Iunganishe na `Arduino-IRremote` library (v4.x inasaidia >40 protocols).
* **Logic analysers** (Saleae/FX2) – hunasa raw timings wakati protocol haijulikani.
* **Smartphones zenye IR-blaster** (kwa mfano, Xiaomi) – field test ya haraka lakini zenye range ndogo.

### Software

* **`Arduino-IRremote`** – C++ library inayotunzwa kikamilifu:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders zinazo-import raw captures na kutambua protocol moja kwa moja, pamoja na kutengeneza Pronto/Arduino code.
* **LIRC / ir-keytable (Linux)** – hupokea na ku-inject IR kutoka command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Disable au funika IR receivers kwenye vifaa vilivyowekwa public spaces wakati hazihitajiki.
* Tekeleza *pairing* au cryptographic checks kati ya smart-TVs na remotes; tenga privileged “service” codes.
* Deploy IR-cut filters au continuous-wave detectors kuzunguka maeneo classified ili kuvunja optical covert channels.
* Monitor firmware integrity ya cameras/IoT appliances zenye IR LEDs zinazoweza kudhibitiwa.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
