# Infrarooi

{{#include ../../banners/hacktricks-training.md}}

## Hoe infrarooi werk <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarooi lig is onsigbaar vir mense**. Die IR-golflengte is van **0.7 tot 1000 mikron**. Huishoudelike afstandbeheerders gebruik ’n IR-sein vir dataoordrag en werk in die golflengtereeks van 0.75..1.4 mikron. ’n Mikrobeheerder in die afstandbeheerder laat ’n infrarooi-LED teen ’n spesifieke frekwensie flikker en verander die digitale sein in ’n IR-sein.

’n **Fotontvanger** word gebruik om IR-seine te ontvang. Dit **verander IR-lig in spanningspulse**, wat reeds **digitale seine** is. Gewoonlik is daar **’n donkerligfilter binne-in die ontvanger** wat **slegs die verlangde golflengte deurlaat** en geraas uitskakel.<sup>[[1]](#references)</sup>

### Verskeidenheid IR-protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-protokolle verskil op 3 faktore:<sup>[[1]](#references)</sup>

- b enkodering
- datastruktuur
- draerfrekwensie — dikwels in die reeks 36..38 kHz

#### Maniere om b enkodeer <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulssafstand-enkodering**

Bisse word geënkodeer deur die duur van die spasie tussen pulse te moduleer. Die breedte van die puls self is konstant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulswydte-enkodering**

Bisse word geënkodeer deur die pulsbreedte te moduleer. Die breedte van die spasie ná ’n pulsreeks is konstant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Fase-enkodering**

Dit staan ook bekend as Manchester-enkodering. Die logiese waarde word bepaal deur die polariteit van die oorgang tussen die pulsreeks en die spasie. “Spasie na pulsreeks” dui logika “0” aan; “pulsreeks na spasie” dui logika “1” aan.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasies van die voorafgaande en ander eksotiese metodes**

> [!TIP]
> Daar is IR-protokolle wat **universeel vir verskeie soorte toestelle wil wees**. Die bekendste is RC5 en NEC. Ongelukkig beteken **die bekendste nie die algemeenste** nie. In my omgewing het ek net twee NEC-afstandbeheerders en geen RC5-afstandbeheerders teëgekom nie.
>
> Vervaardigers hou daarvan om hul eie unieke IR-protokolle te gebruik, selfs binne dieselfde soort toestelle (byvoorbeeld TV-bokse). Daarom kan afstandbeheerders van verskillende maatskappye, en soms van verskillende modelle van dieselfde maatskappy, nie met ander toestelle van dieselfde soort werk nie.

### Ondersoek van ’n IR-sein

Die betroubaarste manier om te sien hoe die IR-sein van ’n afstandbeheerder lyk, is om ’n ossilloskoop te gebruik. Dit demoduleer of keer nie die ontvangde sein om nie; dit wys dit bloot “soos dit is”. Dit is nuttig vir toetsing en ontfouting. Ek sal die verwagte sein aan die hand van die NEC-IR-protokol wys.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar ’n aanloopreeks aan die begin van ’n geënkodeerde pakkie. Dit stel die ontvanger in staat om die versterkingsvlak en agtergrond te bepaal. Daar is ook protokolle sonder ’n aanloopreeks, byvoorbeeld Sharp.

Daarna word data versend. Die struktuur, aanloopreeks en bit-enkoderingsmetode word deur die spesifieke protokol bepaal.

Die **NEC-IR-protokol** bevat ’n kort opdrag en ’n herhalingskode wat gestuur word terwyl die knoppie ingedruk bly. Die opdrag en die herhalingskode het albei dieselfde aanloopreeks aan die begin.

Die NEC-**opdrag** bestaan, benewens die aanloopreeks, uit ’n adresgreep en ’n opdragnommergreep, wat die toestel vertel wat uitgevoer moet word. Die adres- en opdragnommergrepe word met omgekeerde waardes gedupliseer om die integriteit van die versending te kontroleer. Daar is ’n bykomende stopbis aan die einde van die opdrag.

Die **herhalingskode** het ’n “1” ná die aanloopreeks, wat ’n stopbis is.

Vir logika **“0” en “1”** gebruik NEC pulssafstand-enkodering: eers word ’n pulsreeks versend, gevolg deur ’n pouse waarvan die lengte die biswaarde bepaal.

### Lugversorgers

Anders as ander afstandbeheerders, **versend lugversorgers nie net die kode van die knoppie wat gedruk is nie**. Hulle **versend ook al die inligting** wanneer ’n knoppie gedruk word, om te verseker dat die **lugversorger en afstandbeheerder gesinchroniseer is**.\
Dit keer dat ’n lugversorger wat op 20ºC gestel is met een afstandbeheerder na 21ºC verhoog word, en dat ’n ander afstandbeheerder, wat steeds 20ºC wys, gebruik word om die temperatuur verder te verhoog, maar dit dan na 21ºC “verhoog” (in plaas van na 22ºC, omdat dit dink die temperatuur is 21ºC).<sup>[[1]](#references)</sup>

---

## Aanvalle en offensiewe navorsing <a href="#attacks" id="attacks"></a>

Jy kan infrarooi met Flipper Zero aanval:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Oorname van Smart-TV’s / set-top-bokse (EvilScreen)

Onlangse akademiese navorsing (EvilScreen, 2022) het gewys dat **multikanaal-afstandbeheerders wat infrarooi met Bluetooth of Wi-Fi kombineer, misbruik kan word om moderne Smart-TV’s heeltemal oor te neem**. Die aanval koppel IR-dienskodes met hoë voorregte aan geverifieerde Bluetooth-pakkies, omseil kanaalisolasie en laat willekeurige toepassings begin, mikrofone aktiveer of ’n fabrieksterugstelling uitvoer sonder fisiese toegang. Daar is bevestig dat agt algemene TV’s van verskillende verskaffers kwesbaar was, insluitend ’n Samsung-model wat beweer dat dit aan ISO/IEC 27001 voldoen. Versagting vereis firmware-opdaterings van die verskaffer of dat ongebruikte IR-ontvangers heeltemal gedeaktiveer word.<sup>[[2]](#references)</sup>

### Data-eksfiltrasie via IR-LED’s vanaf ’n geïsoleerde netwerk (aIR-Jumper-familie)

Sekuriteitskameras sluit dikwels **IR-LED’s vir nagsig** in. Die aIR-Jumper-prototipe het gewys dat wanware wat hierdie LED’s beheer **geheime deur vensters na ’n eksterne kamera kan eksfiltreer**, teen tot **20 bit/s per toesigkamera** oor tientalle meters. In die omgekeerde rigting het die navorsers infiltrasie teen meer as **100 bit/s** oor afstande van honderde meters tot kilometers gedemonstreer.<sup>[[3]](#references)</sup> Omdat die lig buite die sigbare spektrum val, sal operateurs dit dalk nie opmerk nie. Teenmaatreëls sluit in:

* Skerm IR-LED’s fisies af of verwyder dit in sensitiewe areas
* Monitor die dienssiklus van kamera-LED’s en firmware-integriteit
* Installeer IR-snyfilters op vensters en toesigkameras

’n Aanvaller kan ook sterk IR-projektors gebruik om opdragte in die netwerk te **infiltreer** deur data terug na onbeveiligde kameras te flits.

### Brute-force oor lang afstande en uitgebreide protokolle met Flipper Zero 1.0

Firmware 1.0 (September 2024) het die biblioteek vir universele afstandbeheerders uitgebrei en dinamiese laai van infrarooi-hulpbronlêers vanaf microSD bygevoeg.<sup>[[4]](#references)</sup> Die leer- en universele-afstandbeheerfunksies kan bekende opdragte weer speel of teen nabygeleë TV’s en lugversorgers probeer. Die reikafstand hang sterk af van die uitstraler, optika, omgewingslig en ontvanger; eksterne IR-hardeware kan dit vergroot, maar ’n vaste afstand moet nie veronderstel word nie.

---

## Gereedskap en praktiese voorbeelde <a href="#tooling" id="tooling"></a>

### Hardeware

* **Flipper Zero** – draagbare transceiver met leer-, herspeel- en dictionary-brute-force-modusse (sien hierbo).
* **Arduino / ESP32** + IR-LED / TSOP38xx-ontvanger – goedkoop selfdoen-ontleder/-sender. Kombineer dit met die `Arduino-IRremote`-biblioteek (v4.x ondersteun meer as 40 protokolle).
* **Logika-ontleders** (Saleae/FX2) – neem rou tydsberekeninge vas wanneer die protokol onbekend is.
* **Slimfone met IR-blaster** (bv. Xiaomi) – vinnige veldtoets, maar met beperkte reikafstand.

### Sagteware

* **`Arduino-IRremote`** – aktief onderhoude C++-biblioteek:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – GUI-dekodeerders wat rou opnames invoer, die protokol outomaties identifiseer en Pronto/Arduino-kode genereer.
* **LIRC / ir-keytable (Linux)** – ontvang en stuur IR vanaf die opdragreël:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Verdedigingsmaatreëls <a href="#defense" id="defense"></a>

* Deaktiveer of bedek IR-ontvangers op toestelle wat in openbare ruimtes ontplooi word wanneer dit nie nodig is nie.
* Dwing *pairing* of kriptografiese kontroles tussen slim-TV's en afstandbeheerders af; isoleer bevoorregte “diens”-kodes.
* Ontplooi IR-snyfilters of deurlopendegolfdetektors rondom geklassifiseerde gebiede om optiese versteekte kanale te onderbreek.
* Monitor die firmware-integriteit van kameras/IoT-toestelle wat beheerbare IR-LED's blootstel.

## References

- [1] [Flipper Zero-infrarooi-blogplasing](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero-blog - Firmware 1.0 vrygestel](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - gebruik- en protokoldokumentasie](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
