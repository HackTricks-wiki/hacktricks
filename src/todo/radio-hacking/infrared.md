# Infrared

{{#include ../../banners/hacktricks-training.md}}

## How the Infrared Works <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa infrared hauonekani kwa wanadamu**. Urefu wa mawimbi ya IR ni kutoka **0.7 hadi 1000 microns**. Remote za nyumbani hutumia ishara ya IR kwa ajili ya uhamasishaji wa data na zinafanya kazi katika wigo wa mawimbi wa 0.75..1.4 microns. Microcontroller katika remote inafanya LED ya infrared kung'ara kwa mzunguko maalum, ikigeuza ishara ya dijitali kuwa ishara ya IR.

Ili kupokea ishara za IR, **photoreceiver** hutumiwa. In **geuza mwanga wa IR kuwa mapigo ya voltage**, ambayo tayari ni **ishara za dijitali**. Kawaida, kuna **filter ya mwanga mweusi ndani ya mpokeaji**, ambayo inaruhusu **tu wigo unaotakiwa kupita** na kuondoa kelele.

### Variety of IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokali za IR zinatofautiana katika mambo 3:

- uandishi wa bit
- muundo wa data
- mzunguko wa kubeba — mara nyingi katika wigo wa 36..38 kHz

#### Bit encoding ways <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits zinaandikwa kwa kubadilisha muda wa nafasi kati ya mapigo. Upana wa pigo lenyewe ni thabiti.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits zinaandikwa kwa kubadilisha upana wa pigo. Upana wa nafasi baada ya mlipuko wa pigo ni thabiti.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Inajulikana pia kama uandishi wa Manchester. Thamani ya mantiki inafafanuliwa na polarity ya mpito kati ya mlipuko wa pigo na nafasi. "Nafasi hadi mlipuko wa pigo" inaashiria mantiki "0", "mlipuko wa pigo hadi nafasi" inaashiria mantiki "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combination of previous ones and other exotics**

> [!TIP]
> Kuna protokali za IR ambazo **zinajaribu kuwa za ulimwengu mzima** kwa aina kadhaa za vifaa. Zile maarufu ni RC5 na NEC. Kwa bahati mbaya, maarufu **haimaanishi ya kawaida**. Katika mazingira yangu, nilikutana na remote mbili za NEC na hakuna RC5.
>
> Watengenezaji wanapenda kutumia protokali zao za IR za kipekee, hata ndani ya safu moja ya vifaa (kwa mfano, TV-boxes). Hivyo basi, remotes kutoka kampuni tofauti na wakati mwingine kutoka mifano tofauti kutoka kampuni moja, hazina uwezo wa kufanya kazi na vifaa vingine vya aina hiyo.

### Exploring an IR signal

Njia ya kuaminika zaidi kuona jinsi ishara ya IR ya remote inavyoonekana ni kutumia oscilloscope. Hii haidhauri au kubadilisha ishara iliyopokelewa, inajitokeza "kama ilivyo". Hii ni muhimu kwa ajili ya kupima na kutatua matatizo. Nitaonyesha ishara inayotarajiwa kwa mfano wa protokali ya NEC IR.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kawaida, kuna preamble mwanzoni mwa pakiti iliyowekwa. Hii inaruhusu mpokeaji kubaini kiwango cha gain na mandharinyuma. Pia kuna protokali bila preamble, kwa mfano, Sharp.

Kisha data inatumwa. Muundo, preamble, na njia ya uandishi wa bit zinatambuliwa na protokali maalum.

**Protokali ya NEC IR** ina amri fupi na nambari ya kurudia, ambayo inatumwa wakati kifungo kinaposhinikizwa. Zote, amri na nambari ya kurudia zina preamble sawa mwanzoni.

**Amri ya NEC**, mbali na preamble, inajumuisha byte ya anwani na byte ya nambari ya amri, ambayo kifaa kinaelewa kinachohitajika kutekelezwa. Byte za anwani na nambari ya amri zinajirudia kwa thamani za kinyume, ili kuangalia uadilifu wa uhamasishaji. Kuna bit ya kusitisha ya ziada mwishoni mwa amri.

**Nambari ya kurudia** ina "1" baada ya preamble, ambayo ni bit ya kusitisha.

Kwa **mantiki "0" na "1"** NEC inatumia Pulse Distance Encoding: kwanza, mlipuko wa pigo unatumwa baada ya hapo kuna pause, urefu wake unakamilisha thamani ya bit.

### Air Conditioners

Tofauti na remotes nyingine, **viyoyozi havitumii tu nambari ya kifungo kilichoshinikizwa**. Pia **hutoa taarifa zote** wakati kifungo kinaposhinikizwa ili kuhakikisha kwamba **kifaa cha viyoyozi na remote vinapatana**.\
Hii itazuia kwamba mashine iliyowekwa kama 20ºC inakuwa 21ºC kwa remote moja, na kisha wakati remote nyingine, ambayo bado ina joto kama 20ºC, inatumika kuongeza zaidi joto, itakuwa "inaongeza" hadi 21ºC (na si 22ºC ikidhani iko katika 21ºC).

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Unaweza kushambulia Infrared na Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Kazi za hivi karibuni za kitaaluma (EvilScreen, 2022) zilionyesha kwamba **remotes za multi-channel zinazochanganya Infrared na Bluetooth au Wi-Fi zinaweza kutumika vibaya ili kuchukua udhibiti wa smart-TVs za kisasa**. Shambulio linaunganisha nambari za huduma za IR zenye haki za juu pamoja na pakiti za Bluetooth zilizothibitishwa, zikiepuka kutengwa kwa channel na kuruhusu uzinduzi wa programu zisizo na mipaka, uanzishaji wa kipaza sauti, au kurejesha kiwanda bila ufikiaji wa kimwili. Televisheni nane maarufu kutoka kwa wauzaji tofauti — ikiwemo mfano wa Samsung unaodai kufuata ISO/IEC 27001 — zilithibitishwa kuwa na udhaifu. Kupunguza hatari kunahitaji marekebisho ya firmware kutoka kwa wauzaji au kuzima kabisa wapokeaji wa IR wasiotumika.

### Air-Gapped Data Exfiltration via IR LEDs (aIR-Jumper family)

Mikamera ya usalama, routers au hata flash drives za uhalifu mara nyingi zinajumuisha **LED za IR za kuona usiku**. Utafiti unaonyesha kuwa malware inaweza kubadilisha hizi LED (<10–20 kbit/s kwa OOK rahisi) ili **kuhamasisha siri kupitia kuta na madirisha** kwa kamera ya nje iliyowekwa mita kumi mbali. Kwa sababu mwanga uko nje ya wigo unaoonekana, waendeshaji mara nyingi hawaoni. Hatua za kupambana:

* Ficha kimwili au ondoa LED za IR katika maeneo nyeti
* Fuata mzunguko wa LED wa kamera na uadilifu wa firmware
* Tumia filters za IR-cut kwenye madirisha na kamera za ufuatiliaji

Mshambuliaji pia anaweza kutumia projector za IR zenye nguvu ili **kuingiza** amri ndani ya mtandao kwa kuangaza data nyuma kwa kamera zisizo salama.

### Long-Range Brute-Force & Extended Protocols with Flipper Zero 1.0

Firmware 1.0 (Septemba 2024) iliongeza **mifumo ya ziada ya IR na moduli za nguvu za nje**. Imeunganishwa na hali ya brute-force ya universal-remote, Flipper inaweza kuzima au kubadilisha mipangilio ya televisheni/AC nyingi za umma kutoka hadi mita 30 kwa kutumia diode yenye nguvu kubwa.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceiver inayoweza kubebeka yenye hali za kujifunza, kurudia na brute-force ya kamusi (ona hapo juu).
* **Arduino / ESP32** + IR LED / TSOP38xx mpokeaji – mchanganuzi/mwambazaji wa DIY wa bei nafuu. Changanya na maktaba ya `Arduino-IRremote` (v4.x inasaidia >40 protokali).
* **Logic analysers** (Saleae/FX2) – capture timings za raw wakati protokali haijulikani.
* **Smartphones with IR-blaster** (e.g., Xiaomi) – mtihani wa haraka wa uwanjani lakini una wigo mdogo.

### Software

* **`Arduino-IRremote`** – maktaba ya C++ inayodumishwa kwa ufanisi:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decoders za GUI zinazounga mkono captures za raw na kutambua protokali kiotomatiki + kuunda msimbo wa Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – pokea na ingiza IR kutoka kwa mstari wa amri:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Zima au funika wapokeaji wa IR kwenye vifaa vilivyowekwa katika maeneo ya umma wakati havihitajiki.
* Lazimisha *kuunganishwa* au ukaguzi wa kijasusi kati ya smart-TVs na remotes; tengeneza nambari za "huduma" zenye haki.
* Tumia filters za IR-cut au detectors za mawimbi ya kuendelea karibu na maeneo yaliyotengwa ili kuvunja njia za siri za macho.
* Fuata uadilifu wa firmware wa kamera/vifaa vya IoT vinavyofichua LED za IR zinazoweza kudhibitiwa.

## References

- [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- EvilScreen: Smart TV hijacking via remote control mimicry (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
