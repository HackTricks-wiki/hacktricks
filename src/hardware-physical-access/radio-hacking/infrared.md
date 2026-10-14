# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Infrared Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa infrared hauonekani kwa binadamu**. Urefu wa mawimbi ya IR ni **microni 0.7 hadi 1000**. Remote za nyumbani hutumia mawimbi ya IR kusambaza data, na hufanya kazi katika safu ya urefu wa mawimbi ya microni 0.75..1.4. Microcontroller iliyo ndani ya remote huwasha na kuzima LED ya infrared kwa masafa mahususi, na kubadilisha mawimbi ya dijitali kuwa mawimbi ya IR.

Ili kupokea mawimbi ya IR, **photoreceiver** hutumika. **Hubadilisha mwanga wa IR kuwa mipigo ya voltage**, ambayo tayari ni **mawimbi ya dijitali**. Kwa kawaida, ndani ya kipokezi kuna **kichujio cha mwanga mweusi**, kinachoruhusu **urefu wa mawimbi unaohitajika pekee kupita** na kuondoa kelele.<sup>[[1]](#references)</sup>

### Aina Mbalimbali za Itifaki za IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Itifaki za IR hutofautiana katika vipengele 3:<sup>[[1]](#references)</sup>

- usimbaji wa biti
- muundo wa data
- masafa ya carrier — mara nyingi huwa katika safu ya 36..38 kHz

#### Mbinu za usimbaji wa biti <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Usimbaji wa Umbali wa Mipigo**

Biti husimbwa kwa kubadilisha muda wa nafasi kati ya mipigo. Upana wa mpigo wenyewe hubaki thabiti.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Usimbaji wa Upana wa Mpigo**

Biti husimbwa kwa kubadilisha upana wa mpigo. Upana wa nafasi baada ya mfululizo wa mipigo hubaki thabiti.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Usimbaji wa Awamu**

Pia hujulikana kama usimbaji wa Manchester. Thamani ya kimantiki huamuliwa na uelekeo wa mabadiliko kati ya mfululizo wa mipigo na nafasi. "Nafasi hadi mfululizo wa mipigo" humaanisha mantiki "0", na "mfululizo wa mipigo hadi nafasi" humaanisha mantiki "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Mchanganyiko wa mbinu zilizotangulia na mbinu nyingine zisizo za kawaida**

> [!TIP]
> Kuna itifaki za IR **zinazojaribu kuwa za jumla** kwa aina kadhaa za vifaa. Zinazojulikana zaidi ni RC5 na NEC. Kwa bahati mbaya, **kujulikana zaidi haimaanishi kutumika zaidi**. Katika mazingira yangu, nimekutana na remote mbili tu za NEC na hakuna ya RC5.
>
> Watengenezaji hupenda kutumia itifaki zao za kipekee za IR, hata katika aina ileile ya vifaa (kwa mfano, TV-boxes). Kwa hiyo, remote za kampuni tofauti, na wakati mwingine za modeli tofauti za kampuni ileile, haziwezi kufanya kazi na vifaa vingine vya aina hiyo.

### Kuchunguza mawimbi ya IR

Njia ya kuaminika zaidi ya kuona jinsi mawimbi ya IR ya remote yanavyoonekana ni kutumia oscilloscope. Haidemodulate wala kugeuza mawimbi yaliyopokelewa; huyaonyesha tu "kama yalivyo". Hii ni muhimu kwa majaribio na utatuzi wa hitilafu. Nitaonyesha mawimbi yanayotarajiwa kwa kutumia itifaki ya NEC IR kama mfano.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kwa kawaida, kuna utangulizi mwanzoni mwa pakiti iliyosimbwa. Hii huruhusu kipokezi kubaini kiwango cha gain na mawimbi ya usuli. Pia kuna itifaki zisizo na utangulizi, kwa mfano, Sharp.

Kisha data husambazwa. Muundo, utangulizi na mbinu ya usimbaji wa biti huamuliwa na itifaki husika.

**Itifaki ya NEC IR** ina amri fupi na msimbo wa kurudia, unaotumwa wakati kitufe kimeshinikizwa. Amri na msimbo wa kurudia vyote vina utangulizi uleule mwanzoni.

**Amri** ya NEC, pamoja na utangulizi, ina baiti ya anwani na baiti ya nambari ya amri, ambazo kifaa hutumia kuelewa kitendo kinachopaswa kutekelezwa. Baiti za anwani na nambari ya amri hurudiwa kwa thamani zilizo kinyume, ili kukagua uadilifu wa usambazaji. Kuna biti ya ziada ya kusimama mwishoni mwa amri.

**Msimbo wa kurudia** una "1" baada ya utangulizi, ambayo ni biti ya kusimama.

Kwa **mantiki "0" na "1"**, NEC hutumia Usimbaji wa Umbali wa Mipigo: kwanza, mfululizo wa mipigo hutumwa, kisha hufuatiwa na pause ambayo urefu wake huweka thamani ya biti.

### Viyoyozi

Tofauti na remote nyingine, **viyoyozi havitumii tu msimbo wa kitufe kilichobonyezwa**. Pia **hutuma taarifa zote** kitufe kinapobonyezwa ili kuhakikisha kwamba **kifaa cha kiyoyozi na remote vimesawazishwa**.\
Hii huzuia kifaa kilichowekwa kwenye 20ºC kupandishwa hadi 21ºC kwa remote moja, kisha remote nyingine, ambayo bado ina halijoto ya 20ºC, ikitumika kuongeza halijoto tena, "itaiongeza" hadi 21ºC (badala ya 22ºC kwa kudhani halijoto ni 21ºC).<sup>[[1]](#references)</sup>

---

## Mashambulizi na Utafiti wa Kichokozi <a href="#attacks" id="attacks"></a>

Unaweza kushambulia Infrared kwa kutumia Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Kudhibiti Smart-TV / Set-top Box (EvilScreen)

Utafiti wa kitaaluma wa hivi majuzi (EvilScreen, 2022) ulionyesha kwamba **remote za njia nyingi zinazochanganya Infrared na Bluetooth au Wi-Fi zinaweza kutumiwa kuteka kikamilifu smart-TV za kisasa**. Shambulizi hili huunganisha misimbo ya IR ya huduma yenye ruhusa za juu na pakiti za Bluetooth zilizothibitishwa, na kukwepa utenganishaji wa njia ili kuruhusu kuwasha programu yoyote, kuwezesha maikrofoni au kurejesha mipangilio ya kiwandani bila ufikiaji wa kifaa. TV nane zinazotumika sana kutoka kwa wauzaji tofauti — ikiwemo modeli ya Samsung iliyodai kutii ISO/IEC 27001 — zilithibitishwa kuwa hatarini. Kukabiliana na hili kunahitaji marekebisho ya firmware kutoka kwa mtengenezaji au kuzima kabisa vipokezi vya IR visivyotumika.<sup>[[2]](#references)</sup>

### Kutoa Data kutoka kwa Mfumo Uliotengwa kwa Kutumia LED za IR (familia ya aIR-Jumper)

Kamera za usalama mara nyingi huwa na **LED za IR za kuona usiku**. Mfano wa aIR-Jumper ulionyesha kwamba malware inayodhibiti LED hizo inaweza **kutoa siri kupitia madirisha** hadi kwenye kamera ya nje, kwa kasi ya hadi **biti 20/s kwa kila kamera ya uangalizi** katika umbali wa makumi ya mita. Kinyume chake, watafiti walionyesha uwezekano wa kupenyeza data kwa kasi ya zaidi ya **biti 100/s** katika umbali wa mamia ya mita hadi kilomita.<sup>[[3]](#references)</sup> Kwa kuwa mwanga huo uko nje ya wigo unaoonekana, waendeshaji huenda wasiuone. Hatua za kujikinga ni pamoja na:

* Kufunika kimwili au kuondoa LED za IR katika maeneo nyeti
* Kufuatilia mzunguko wa kuwaka kwa LED za kamera na uadilifu wa firmware
* Kuweka vichujio vya IR-cut kwenye madirisha na kamera za uangalizi

Mshambulizi anaweza pia kutumia projectors zenye nguvu za IR **kupenyeza** amri kwenye mtandao kwa kuangaza data kurudi kwenye kamera zisizo salama.

### Brute-Force ya Masafa Marefu na Itifaki Zilizopanuliwa kwa Flipper Zero 1.0

Firmware 1.0 (Septemba 2024) ilipanua maktaba ya remote za jumla na kuongeza upakiaji wa moja kwa moja wa faili za infrared kutoka microSD.<sup>[[4]](#references)</sup> Kazi zake za kujifunza na remote ya jumla zinaweza kurudia au kujaribu amri zinazojulikana dhidi ya TV na viyoyozi vilivyo karibu. Masafa hutegemea sana emitter, optics, mwanga wa mazingira na kipokezi; vifaa vya nje vya IR vinaweza kuiongeza, lakini umbali maalum haupaswi kudhaniwa.

---

## Zana na Mifano ya Vitendo <a href="#tooling" id="tooling"></a>

### Vifaa

* **Flipper Zero** – transceiver inayobebeka yenye hali za kujifunza, kurudia na dictionary-bruteforce (tazama hapo juu).
* **Arduino / ESP32** + LED ya IR / kipokezi cha TSOP38xx – kichanganuzi/kisambazaji cha DIY cha bei nafuu. Changanya na maktaba ya `Arduino-IRremote` (v4.x inasaidia itifaki zaidi ya 40).
* **Logic analysers** (Saleae/FX2) – hunasa muda ghafi wakati itifaki haijulikani.
* **Simu mahiri zenye IR-blaster** (k.m., Xiaomi) – majaribio ya haraka ya uwanjani lakini zenye masafa machache.

### Programu

* **`Arduino-IRremote`** – maktaba ya C++ inayotunzwa kikamilifu:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – Vichanganuzi vya GUI vinavyoingiza rekodi ghafi, kutambua itifaki kiotomatiki na kutengeneza msimbo wa Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – pokea na ingiza IR kupitia mstari wa amri:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Hatua za Kinga <a href="#defense" id="defense"></a>

* Zima au funika vipokezi vya IR kwenye vifaa vilivyowekwa maeneo ya umma wakati havihitajiki.
* Lazimisha *pairing* au ukaguzi wa kriptografia kati ya smart-TV na rimoti; tenga misimbo ya “service” yenye upendeleo.
* Weka vichujio vya IR-cut au vitambuzi vya continuous-wave karibu na maeneo yaliyotengwa ili kuvunja njia fiche za mawasiliano za macho.
* Fuatilia uadilifu wa firmware ya kamera/vifaa vya IoT vinavyowezesha kudhibiti LED za IR.

## References

- [1] [Makala ya blogu ya Flipper Zero kuhusu Infrared](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Utekaji wa Smart TV kupitia uigaji wa udhibiti wa rimoti wa njia nyingi (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Utoaji/uingizaji fiche wa data kupitia Air-Gap kwa kutumia kamera za usalama na infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blogu ya Flipper Zero - Firmware 1.0 imetolewa](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - matumizi na nyaraka za itifaki](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
